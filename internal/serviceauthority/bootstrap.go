package serviceauthority

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	MaximumDeploymentOfferLifetime = 7 * 24 * time.Hour
	deploymentOfferSignatureDomain = "Facets service deployment offer v1\x00"
	deploymentOfferReferenceDomain = "Facets service deployment offer reference v1\x00"
	bootstrapProofSignatureDomain  = "Facets server bootstrap deployment proof v1\x00"
)

type RouteKind string

const (
	RouteDirectHTTPS  RouteKind = "direct_https"
	RouteTorEgress    RouteKind = "tor_egress_https"
	RouteTorOnion     RouteKind = "tor_onion"
	NetworkTrustedLAN string    = "trusted_lan"
	NetworkPublic     string    = "public_internet"
	NetworkTor        string    = "tor_network"
)

type ServerAuthentication struct {
	Kind             string  `json:"kind"`
	PinnedSPKISHA256 *string `json:"pinnedSPKISHA256,omitempty"`
}

type TransportRoute struct {
	Endpoint             string               `json:"endpoint"`
	Kind                 RouteKind            `json:"kind"`
	NetworkScope         string               `json:"networkScope"`
	OnionPortability     *string              `json:"onionPortability,omitempty"`
	OnionServiceID       *string              `json:"onionServiceID,omitempty"`
	RouteID              uuid.UUID            `json:"routeID"`
	ServerAuthentication ServerAuthentication `json:"serverAuthentication"`
}

type DeploymentDescriptor struct {
	CreatedAtMilliseconds int64            `json:"createdAtMilliseconds"`
	DeploymentID          uuid.UUID        `json:"deploymentID"`
	PublicSigningKeyX963  string           `json:"publicSigningKeyX963"`
	Routes                []TransportRoute `json:"routes"`
	SigningKeyFingerprint string           `json:"signingKeyFingerprint"`
	Version               int              `json:"version"`
}

type TransportPolicy struct {
	AllowsPublicDirectBulkTransfer bool        `json:"allowsPublicDirectBulkTransfer"`
	BulkRouteIDs                   []uuid.UUID `json:"bulkRouteIDs"`
	ControlRouteIDs                []uuid.UUID `json:"controlRouteIDs"`
	MessageRouteIDs                []uuid.UUID `json:"messageRouteIDs"`
	Version                        int         `json:"version"`
}

func (policy TransportPolicy) routeIDs(class TrafficClass) []uuid.UUID {
	switch class {
	case TrafficControl:
		return policy.ControlRouteIDs
	case TrafficMessage:
		return policy.MessageRouteIDs
	case TrafficBulk:
		return policy.BulkRouteIDs
	default:
		return nil
	}
}

func (descriptor DeploymentDescriptor) Validate() error {
	public, err := canonicalP256PublicKey(descriptor.PublicSigningKeyX963)
	if err != nil || descriptor.Version != SchemaVersion ||
		descriptor.DeploymentID == uuid.Nil || descriptor.CreatedAtMilliseconds < 0 ||
		len(descriptor.Routes) == 0 ||
		hex.EncodeToString(sha256Bytes(public)) != descriptor.SigningKeyFingerprint {
		return ErrInvalid
	}
	seen := make(map[uuid.UUID]struct{}, len(descriptor.Routes))
	for index, route := range descriptor.Routes {
		if route.Validate() != nil {
			return ErrInvalid
		}
		if _, exists := seen[route.RouteID]; exists {
			return ErrInvalid
		}
		seen[route.RouteID] = struct{}{}
		if index > 0 && !uuidLess(descriptor.Routes[index-1].RouteID, route.RouteID) {
			return ErrInvalid
		}
	}
	return nil
}

func (route TransportRoute) Validate() error {
	parsed, err := url.Parse(route.Endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") || route.RouteID == uuid.Nil ||
		parsed.String() != route.Endpoint {
		return ErrInvalid
	}
	host := strings.ToLower(parsed.Hostname())
	pin := route.ServerAuthentication.PinnedSPKISHA256
	if route.ServerAuthentication.Kind == "web_pki" {
		if pin != nil {
			return ErrInvalid
		}
	} else if route.ServerAuthentication.Kind == "pinned_spki_sha256" {
		if pin == nil || !validDigest(*pin) {
			return ErrInvalid
		}
	} else {
		return ErrInvalid
	}
	switch route.Kind {
	case RouteDirectHTTPS:
		if route.NetworkScope == NetworkTor || strings.HasSuffix(host, ".onion") ||
			route.OnionServiceID != nil || route.OnionPortability != nil {
			return ErrInvalid
		}
	case RouteTorEgress:
		if route.NetworkScope != NetworkPublic || strings.HasSuffix(host, ".onion") ||
			route.OnionServiceID != nil || route.OnionPortability != nil {
			return ErrInvalid
		}
	case RouteTorOnion:
		if route.NetworkScope != NetworkTor || route.OnionServiceID == nil ||
			route.OnionPortability == nil || len(*route.OnionServiceID) != 56 ||
			host != strings.ToLower(*route.OnionServiceID)+".onion" ||
			route.ServerAuthentication.Kind != "pinned_spki_sha256" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (policy TransportPolicy) Validate(descriptor DeploymentDescriptor) error {
	if policy.Version != SchemaVersion {
		return ErrInvalid
	}
	routes := make(map[uuid.UUID]TransportRoute, len(descriptor.Routes))
	for _, route := range descriptor.Routes {
		routes[route.RouteID] = route
	}
	for _, list := range [][]uuid.UUID{
		policy.ControlRouteIDs, policy.MessageRouteIDs, policy.BulkRouteIDs,
	} {
		if len(list) == 0 {
			return ErrInvalid
		}
		seen := make(map[uuid.UUID]struct{}, len(list))
		for _, routeID := range list {
			if routeID == uuid.Nil {
				return ErrInvalid
			}
			if _, exists := routes[routeID]; !exists {
				return ErrInvalid
			}
			if _, exists := seen[routeID]; exists {
				return ErrInvalid
			}
			seen[routeID] = struct{}{}
		}
	}
	if !policy.AllowsPublicDirectBulkTransfer {
		for _, routeID := range policy.BulkRouteIDs {
			route := routes[routeID]
			if route.Kind == RouteDirectHTTPS && route.NetworkScope == NetworkPublic {
				return ErrInvalid
			}
		}
	}
	return nil
}

type DeploymentOfferPayload struct {
	Deployment            DeploymentDescriptor `json:"deployment"`
	ExpiresAtMilliseconds int64                `json:"expiresAtMilliseconds"`
	IssuedAtMilliseconds  int64                `json:"issuedAtMilliseconds"`
	TransportPolicy       TransportPolicy      `json:"transportPolicy"`
	Version               int                  `json:"version"`
}

// DeploymentOfferTemplate is the non-secret, operator-owned route policy from
// which the deployment signer issues short-lived bootstrap offers. The
// deployment private key remains in its separate protected file.
type DeploymentOfferTemplate struct {
	Deployment      DeploymentDescriptor `json:"deployment"`
	TransportPolicy TransportPolicy      `json:"transportPolicy"`
	Version         int                  `json:"version"`
}

func LoadDeploymentOfferTemplate(
	path string,
	signer *DeploymentSigner,
) (DeploymentOfferTemplate, error) {
	if strings.TrimSpace(path) == "" || signer == nil {
		return DeploymentOfferTemplate{}, ErrInvalid
	}
	data, err := readProtectedRegularFile(path, 1024*1024, 0o022)
	if err != nil || len(data) == 0 {
		return DeploymentOfferTemplate{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var template DeploymentOfferTemplate
	if err := decoder.Decode(&template); err != nil {
		return DeploymentOfferTemplate{}, ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF ||
		template.Version != SchemaVersion ||
		template.Deployment.Validate() != nil ||
		template.TransportPolicy.Validate(template.Deployment) != nil ||
		template.Deployment.DeploymentID != signer.DeploymentID() ||
		template.Deployment.PublicSigningKeyX963 != signer.PublicSigningKeyX963() ||
		template.Deployment.SigningKeyFingerprint != signer.SigningKeyFingerprint() {
		return DeploymentOfferTemplate{}, ErrInvalid
	}
	return template, nil
}

func (template DeploymentOfferTemplate) SignOffer(
	signer *DeploymentSigner,
	issuedAt time.Time,
	expiresAt time.Time,
) (DeploymentOffer, error) {
	if template.Version != SchemaVersion || signer == nil {
		return DeploymentOffer{}, ErrInvalid
	}
	return signer.SignDeploymentOffer(DeploymentOfferPayload{
		Deployment:            template.Deployment,
		ExpiresAtMilliseconds: expiresAt.UnixMilli(),
		IssuedAtMilliseconds:  issuedAt.UnixMilli(),
		TransportPolicy:       template.TransportPolicy,
		Version:               SchemaVersion,
	})
}

func (template DeploymentOfferTemplate) ContainsControlEndpoint(endpoint string) bool {
	control := make(map[uuid.UUID]struct{}, len(template.TransportPolicy.ControlRouteIDs))
	for _, routeID := range template.TransportPolicy.ControlRouteIDs {
		control[routeID] = struct{}{}
	}
	for _, route := range template.Deployment.Routes {
		if _, ok := control[route.RouteID]; ok && route.Endpoint == endpoint {
			return true
		}
	}
	return false
}

func (payload DeploymentOfferPayload) Validate(nowMilliseconds *int64) error {
	if payload.Version != SchemaVersion || payload.Deployment.Validate() != nil ||
		payload.TransportPolicy.Validate(payload.Deployment) != nil ||
		payload.IssuedAtMilliseconds < payload.Deployment.CreatedAtMilliseconds ||
		payload.ExpiresAtMilliseconds <= payload.IssuedAtMilliseconds ||
		payload.ExpiresAtMilliseconds-payload.IssuedAtMilliseconds >
			MaximumDeploymentOfferLifetime.Milliseconds() {
		return ErrInvalid
	}
	if nowMilliseconds != nil && (*nowMilliseconds < payload.IssuedAtMilliseconds ||
		*nowMilliseconds >= payload.ExpiresAtMilliseconds) {
		return ErrInvalid
	}
	return nil
}

type DeploymentOffer struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

func (signer *DeploymentSigner) SignDeploymentOffer(
	payload DeploymentOfferPayload,
) (DeploymentOffer, error) {
	if signer == nil || payload.Validate(nil) != nil ||
		payload.Deployment.DeploymentID != signer.deploymentID ||
		payload.Deployment.PublicSigningKeyX963 != signer.PublicSigningKeyX963() ||
		payload.Deployment.SigningKeyFingerprint != signer.SigningKeyFingerprint() {
		return DeploymentOffer{}, ErrInvalid
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return DeploymentOffer{}, err
	}
	signature, err := signer.signRecord(deploymentOfferSignatureDomain, encoded)
	if err != nil {
		return DeploymentOffer{}, err
	}
	return DeploymentOffer{Payload: encoded, Signature: signature}, nil
}

func (offer DeploymentOffer) VerifiedPayload(nowMilliseconds *int64) (DeploymentOfferPayload, error) {
	var payload DeploymentOfferPayload
	if verifyCanonicalRecord(offer.Payload, offer.Signature,
		deploymentOfferSignatureDomain, &payload) != nil || payload.Validate(nowMilliseconds) != nil ||
		offer.Signature.SignerID != payload.Deployment.DeploymentID ||
		offer.Signature.PublicSigningKeyX963 != payload.Deployment.PublicSigningKeyX963 ||
		offer.Signature.SigningKeyFingerprint != payload.Deployment.SigningKeyFingerprint {
		return DeploymentOfferPayload{}, ErrInvalid
	}
	return payload, nil
}

func (offer DeploymentOffer) ReferenceDigest() (string, error) {
	if _, err := offer.VerifiedPayload(nil); err != nil {
		return "", err
	}
	signature, err := json.Marshal(offer.Signature)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(deploymentOfferReferenceDomain))
	_, _ = digest.Write(offer.Payload)
	_, _ = digest.Write(signature)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

type TrustAnchor struct {
	PublicSigningKeyX963  string    `json:"publicSigningKeyX963"`
	Scope                 Scope     `json:"scope"`
	SignerID              uuid.UUID `json:"signerID"`
	SigningKeyFingerprint string    `json:"signingKeyFingerprint"`
	Version               int       `json:"version"`
}

type ManifestPayload struct {
	ActiveDeployment                    DeploymentDescriptor   `json:"activeDeployment"`
	IssuedAtMilliseconds                int64                  `json:"issuedAtMilliseconds"`
	Migration                           *MigrationAuthority    `json:"migration,omitempty"`
	MigrationPrerequisiteEvidenceDigest *string                `json:"migrationPrerequisiteEvidenceDigest,omitempty"`
	PredecessorManifestDigest           *string                `json:"predecessorManifestDigest,omitempty"`
	PreparedDeployments                 []DeploymentDescriptor `json:"preparedDeployments"`
	Revision                            uint64                 `json:"revision"`
	Scope                               Scope                  `json:"scope"`
	Transition                          string                 `json:"transition"`
	TransportPolicy                     TransportPolicy        `json:"transportPolicy"`
	ValidFromMilliseconds               int64                  `json:"validFromMilliseconds"`
	ValidUntilMilliseconds              *int64                 `json:"validUntilMilliseconds,omitempty"`
	Version                             int                    `json:"version"`
}

type Manifest struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

func (manifest Manifest) ReferenceDigest() (string, error) {
	var payload ManifestPayload
	if verifyCanonicalRecord(
		manifest.Payload,
		manifest.Signature,
		"Facets service authority manifest v1\x00",
		&payload,
	) != nil {
		return "", ErrInvalid
	}
	signature, err := json.Marshal(manifest.Signature)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("Facets service authority manifest reference v1\x00"))
	_, _ = digest.Write(manifest.Payload)
	_, _ = digest.Write(signature)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

type InitialEnrollment struct {
	Anchor          TrustAnchor     `json:"anchor"`
	DeploymentOffer DeploymentOffer `json:"deploymentOffer"`
	Manifest        Manifest        `json:"manifest"`
	Version         int             `json:"version"`
}

func (enrollment InitialEnrollment) Validate(
	expectedScope Scope,
	nowMilliseconds int64,
) (ManifestPayload, error) {
	return enrollment.validate(expectedScope, nowMilliseconds, true)
}

// ValidateForAdmissionClaim authenticates the enrollment while allowing the
// short-lived deployment offer to have expired after revision 1 was created.
// The Device Sync admission store remains responsible for rejecting an
// expired first claim and permits only an exact retry after it has committed.
func (enrollment InitialEnrollment) ValidateForAdmissionClaim(
	expectedScope Scope,
	nowMilliseconds int64,
) (ManifestPayload, error) {
	return enrollment.validate(expectedScope, nowMilliseconds, false)
}

func (enrollment InitialEnrollment) validate(
	expectedScope Scope,
	nowMilliseconds int64,
	requireCurrentOffer bool,
) (ManifestPayload, error) {
	var offerTime *int64
	if requireCurrentOffer {
		offerTime = &nowMilliseconds
	}
	offer, err := enrollment.DeploymentOffer.VerifiedPayload(offerTime)
	if err != nil || enrollment.Version != SchemaVersion || expectedScope.Validate() != nil ||
		enrollment.Anchor.Version != SchemaVersion || enrollment.Anchor.Scope != expectedScope ||
		enrollment.Anchor.SignerID == uuid.Nil {
		return ManifestPayload{}, ErrInvalid
	}
	anchorKey, err := canonicalP256PublicKey(enrollment.Anchor.PublicSigningKeyX963)
	if err != nil || hex.EncodeToString(sha256Bytes(anchorKey)) !=
		enrollment.Anchor.SigningKeyFingerprint {
		return ManifestPayload{}, ErrInvalid
	}
	var manifest ManifestPayload
	if verifyCanonicalRecord(enrollment.Manifest.Payload, enrollment.Manifest.Signature,
		"Facets service authority manifest v1\x00", &manifest) != nil ||
		manifest.Validate(nil) != nil || manifest.Scope != expectedScope ||
		manifest.Revision != 1 || manifest.Transition != "initial_activation" ||
		manifest.PredecessorManifestDigest != nil ||
		manifest.IssuedAtMilliseconds < offer.IssuedAtMilliseconds ||
		manifest.IssuedAtMilliseconds >= offer.ExpiresAtMilliseconds ||
		manifest.ValidFromMilliseconds < manifest.IssuedAtMilliseconds ||
		(nowMilliseconds < manifest.ValidFromMilliseconds ||
			(manifest.ValidUntilMilliseconds != nil && nowMilliseconds >= *manifest.ValidUntilMilliseconds)) ||
		enrollment.Manifest.Signature.SignerID != enrollment.Anchor.SignerID ||
		enrollment.Manifest.Signature.PublicSigningKeyX963 != enrollment.Anchor.PublicSigningKeyX963 ||
		enrollment.Manifest.Signature.SigningKeyFingerprint != enrollment.Anchor.SigningKeyFingerprint ||
		!deploymentEqual(manifest.ActiveDeployment, offer.Deployment) ||
		!transportPolicyEqual(manifest.TransportPolicy, offer.TransportPolicy) {
		return ManifestPayload{}, ErrInvalid
	}
	return manifest, nil
}

type BootstrapProofRequest struct {
	Challenge             string       `json:"challenge"`
	DeploymentID          uuid.UUID    `json:"deploymentID"`
	DeploymentOfferDigest string       `json:"deploymentOfferDigest"`
	RouteID               uuid.UUID    `json:"routeID"`
	Scope                 Scope        `json:"scope"`
	TrafficClass          TrafficClass `json:"trafficClass"`
	Version               int          `json:"version"`
}

func (request BootstrapProofRequest) Validate(
	offer DeploymentOffer,
	expectedDeploymentID uuid.UUID,
) error {
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(request.Challenge)
	payload, offerErr := offer.VerifiedPayload(nil)
	digest, digestErr := offer.ReferenceDigest()
	if err != nil || len(challenge) != 32 ||
		base64.RawURLEncoding.EncodeToString(challenge) != request.Challenge ||
		offerErr != nil || digestErr != nil || request.Version != SchemaVersion ||
		request.Scope.Validate() != nil || request.DeploymentID != expectedDeploymentID ||
		request.DeploymentID != payload.Deployment.DeploymentID ||
		request.DeploymentOfferDigest != digest || request.RouteID == uuid.Nil ||
		!request.TrafficClass.Valid() ||
		!containsUUID(payload.TransportPolicy.routeIDs(request.TrafficClass), request.RouteID) ||
		!deploymentContainsRoute(payload.Deployment, request.RouteID) {
		return ErrInvalid
	}
	return nil
}

type BootstrapProofPayload struct {
	ExpiresAtMilliseconds int64                 `json:"expiresAtMilliseconds"`
	IssuedAtMilliseconds  int64                 `json:"issuedAtMilliseconds"`
	Request               BootstrapProofRequest `json:"request"`
	Version               int                   `json:"version"`
}

type BootstrapProof struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

func (signer *DeploymentSigner) SignBootstrapProof(
	request BootstrapProofRequest,
	offer DeploymentOffer,
	now time.Time,
) (BootstrapProof, error) {
	if signer == nil || request.Validate(offer, signer.deploymentID) != nil {
		return BootstrapProof{}, ErrInvalid
	}
	issued := now.UnixMilli()
	payload := BootstrapProofPayload{
		ExpiresAtMilliseconds: issued + MaximumProofLifetime.Milliseconds(),
		IssuedAtMilliseconds:  issued,
		Request:               request,
		Version:               SchemaVersion,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return BootstrapProof{}, err
	}
	signature, err := signer.signRecord(bootstrapProofSignatureDomain, encoded)
	if err != nil {
		return BootstrapProof{}, err
	}
	return BootstrapProof{Payload: encoded, Signature: signature}, nil
}

func (signer *DeploymentSigner) signRecord(domain string, payload []byte) (Signature, error) {
	digest := sha256.Sum256(append([]byte(domain), payload...))
	r, s, err := ecdsa.Sign(rand.Reader, signer.privateKey, digest[:])
	if err != nil {
		return Signature{}, err
	}
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)) > 0 {
		s.Sub(elliptic.P256().Params().N, s)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	return Signature{
		Algorithm:             "ES256",
		PublicSigningKeyX963:  signer.PublicSigningKeyX963(),
		Signature:             base64.RawURLEncoding.EncodeToString(raw),
		SignerID:              signer.deploymentID,
		SigningKeyFingerprint: signer.fingerprint,
	}, nil
}

func verifyCanonicalRecord(payload []byte, signature Signature, domain string, target any) error {
	if len(payload) == 0 || len(payload) > 262_144 {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrInvalid
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, payload) || signature.Algorithm != "ES256" ||
		signature.SignerID == uuid.Nil {
		return ErrInvalid
	}
	publicBytes, err := canonicalP256PublicKey(signature.PublicSigningKeyX963)
	if err != nil || hex.EncodeToString(sha256Bytes(publicBytes)) !=
		signature.SigningKeyFingerprint {
		return ErrInvalid
	}
	r, s, err := decodeCanonicalP256Signature(signature.Signature)
	if err != nil {
		return ErrInvalid
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicBytes)
	digest := sha256.Sum256(append([]byte(domain), payload...))
	if x == nil || y == nil || !ecdsa.Verify(
		&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
		digest[:], r, s,
	) {
		return ErrInvalid
	}
	return nil
}

// decodeCanonicalP256Signature admits exactly one raw ES256 representation.
// ECDSA verification alone also accepts (r, N-s), which is mathematically
// equivalent but would produce a different Facets reference digest.
func decodeCanonicalP256Signature(value string) (*big.Int, *big.Int, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != 64 ||
		base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, nil, ErrInvalid
	}
	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:])
	order := elliptic.P256().Params().N
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(order), 1)
	if r.Sign() <= 0 || r.Cmp(order) >= 0 || s.Sign() <= 0 || s.Cmp(halfOrder) > 0 {
		return nil, nil, ErrInvalid
	}
	return r, s, nil
}

func canonicalP256PublicKey(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalid
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), decoded)
	if x == nil || y == nil {
		return nil, ErrInvalid
	}
	return decoded, nil
}

func sha256Bytes(value []byte) []byte {
	digest := sha256.Sum256(value)
	return digest[:]
}

func uuidLess(left, right uuid.UUID) bool {
	return bytes.Compare(left[:], right[:]) < 0
}

func containsUUID(values []uuid.UUID, expected uuid.UUID) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func deploymentContainsRoute(deployment DeploymentDescriptor, routeID uuid.UUID) bool {
	for _, route := range deployment.Routes {
		if route.RouteID == routeID {
			return true
		}
	}
	return false
}

func transportPolicyEqual(left, right TransportPolicy) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func deploymentEqual(left, right DeploymentDescriptor) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

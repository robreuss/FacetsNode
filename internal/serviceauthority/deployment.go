package serviceauthority

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	SchemaVersion                               = 1
	MaximumProofLifetime                        = 5 * time.Minute
	deploymentProofSignatureDomain              = "Facets server deployment proof v1\x00"
	HeaderScopeKind                             = "X-Facets-Service-Scope-Kind"
	HeaderScopeID                               = "X-Facets-Service-Scope-ID"
	HeaderAuthorityRevision                     = "X-Facets-Authority-Revision"
	HeaderAuthorityDigest                       = "X-Facets-Authority-Digest"
	HeaderDeploymentID                          = "X-Facets-Deployment-ID"
	HeaderRouteID                               = "X-Facets-Route-ID"
	HeaderTrafficClass                          = "X-Facets-Traffic-Class"
	TrafficControl                 TrafficClass = "control"
	TrafficMessage                 TrafficClass = "message"
	TrafficBulk                    TrafficClass = "bulk"
	ScopeDeviceSync                ScopeKind    = "device_sync"
	ScopeSharedSpace               ScopeKind    = "shared_space"
	ScopeComputePool               ScopeKind    = "compute_pool"
)

var ErrInvalid = errors.New("invalid Facets service authority value")

type ScopeKind string

func (kind ScopeKind) Valid() bool {
	return kind == ScopeDeviceSync || kind == ScopeSharedSpace || kind == ScopeComputePool
}

type TrafficClass string

func (class TrafficClass) Valid() bool {
	return class == TrafficControl || class == TrafficMessage || class == TrafficBulk
}

type Scope struct {
	Kind    ScopeKind `json:"kind"`
	ScopeID uuid.UUID `json:"scopeID"`
}

func (scope Scope) Validate() error {
	if !scope.Kind.Valid() || scope.ScopeID == uuid.Nil {
		return ErrInvalid
	}
	return nil
}

// ProofRequest field order is canonical sorted-key JSON and must remain in
// lockstep with Swift's sorted-key encoder.
type ProofRequest struct {
	AuthorityManifestDigest string       `json:"authorityManifestDigest"`
	AuthorityRevision       uint64       `json:"authorityRevision"`
	Challenge               string       `json:"challenge"`
	DeploymentID            uuid.UUID    `json:"deploymentID"`
	RouteID                 uuid.UUID    `json:"routeID"`
	Scope                   Scope        `json:"scope"`
	TrafficClass            TrafficClass `json:"trafficClass"`
	Version                 int          `json:"version"`
}

func (request ProofRequest) Validate(expectedDeploymentID uuid.UUID) error {
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(request.Challenge)
	if err != nil || len(challenge) != 32 ||
		base64.RawURLEncoding.EncodeToString(challenge) != request.Challenge ||
		request.Version != SchemaVersion || request.AuthorityRevision == 0 ||
		!validDigest(request.AuthorityManifestDigest) ||
		request.DeploymentID == uuid.Nil || request.DeploymentID != expectedDeploymentID ||
		request.RouteID == uuid.Nil || !request.TrafficClass.Valid() ||
		request.Scope.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

// ProofPayload field order is canonical sorted-key JSON.
type ProofPayload struct {
	ExpiresAtMilliseconds int64        `json:"expiresAtMilliseconds"`
	IssuedAtMilliseconds  int64        `json:"issuedAtMilliseconds"`
	Request               ProofRequest `json:"request"`
	Version               int          `json:"version"`
}

type Signature struct {
	Algorithm             string    `json:"algorithm"`
	PublicSigningKeyX963  string    `json:"publicSigningKeyX963"`
	Signature             string    `json:"signature"`
	SignerID              uuid.UUID `json:"signerID"`
	SigningKeyFingerprint string    `json:"signingKeyFingerprint"`
}

type DeploymentProof struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

type DeploymentSigner struct {
	deploymentID uuid.UUID
	privateKey   *ecdsa.PrivateKey
	publicX963   []byte
	fingerprint  string
}

func NewDeploymentSigner(deploymentID uuid.UUID, privateScalar []byte) (*DeploymentSigner, error) {
	curve := elliptic.P256()
	d := new(big.Int).SetBytes(privateScalar)
	if deploymentID == uuid.Nil || len(privateScalar) != 32 || d.Sign() <= 0 ||
		d.Cmp(curve.Params().N) >= 0 {
		return nil, ErrInvalid
	}
	x, y := curve.ScalarBaseMult(privateScalar)
	key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}
	publicX963 := elliptic.Marshal(curve, x, y)
	fingerprint := sha256.Sum256(publicX963)
	return &DeploymentSigner{
		deploymentID: deploymentID,
		privateKey:   key,
		publicX963:   publicX963,
		fingerprint:  hex.EncodeToString(fingerprint[:]),
	}, nil
}

func LoadDeploymentSigner(
	deploymentID uuid.UUID,
	path string,
) (*DeploymentSigner, error) {
	encoded, err := readProtectedRegularFile(path, 128, 0o077)
	if err != nil || len(encoded) == 0 {
		return nil, ErrInvalid
	}
	text := strings.TrimSuffix(string(encoded), "\n")
	if strings.ContainsAny(text, "\r\n\t ") {
		return nil, ErrInvalid
	}
	seed, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || base64.RawURLEncoding.EncodeToString(seed) != text {
		return nil, ErrInvalid
	}
	return NewDeploymentSigner(deploymentID, seed)
}

func (signer *DeploymentSigner) DeploymentID() uuid.UUID { return signer.deploymentID }

func (signer *DeploymentSigner) PublicSigningKeyX963() string {
	return base64.RawURLEncoding.EncodeToString(signer.publicX963)
}

func (signer *DeploymentSigner) SigningKeyFingerprint() string { return signer.fingerprint }

func (signer *DeploymentSigner) SignProof(
	request ProofRequest,
	now time.Time,
) (DeploymentProof, error) {
	if signer == nil || request.Validate(signer.deploymentID) != nil {
		return DeploymentProof{}, ErrInvalid
	}
	issued := now.UnixMilli()
	payload := ProofPayload{
		ExpiresAtMilliseconds: issued + MaximumProofLifetime.Milliseconds(),
		IssuedAtMilliseconds:  issued,
		Request:               request,
		Version:               SchemaVersion,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return DeploymentProof{}, fmt.Errorf("encode deployment proof: %w", err)
	}
	digest := sha256.Sum256(append([]byte(deploymentProofSignatureDomain), encoded...))
	r, s, err := ecdsa.Sign(rand.Reader, signer.privateKey, digest[:])
	if err != nil {
		return DeploymentProof{}, fmt.Errorf("sign deployment proof: %w", err)
	}
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)) > 0 {
		s.Sub(elliptic.P256().Params().N, s)
	}
	rawSignature := make([]byte, 64)
	r.FillBytes(rawSignature[:32])
	s.FillBytes(rawSignature[32:])
	return DeploymentProof{
		Payload: encoded,
		Signature: Signature{
			Algorithm:             "ES256",
			PublicSigningKeyX963:  signer.PublicSigningKeyX963(),
			Signature:             base64.RawURLEncoding.EncodeToString(rawSignature),
			SignerID:              signer.deploymentID,
			SigningKeyFingerprint: signer.fingerprint,
		},
	}, nil
}

type RequestBinding struct {
	Scope             Scope
	AuthorityRevision uint64
	AuthorityDigest   string
	DeploymentID      uuid.UUID
	RouteID           uuid.UUID
	TrafficClass      TrafficClass
}

func ParseRequestBinding(
	header http.Header,
	expectedDeploymentID uuid.UUID,
	expectedTrafficClass TrafficClass,
) (RequestBinding, error) {
	revision, err := strconv.ParseUint(header.Get(HeaderAuthorityRevision), 10, 64)
	scopeID, scopeErr := uuid.Parse(header.Get(HeaderScopeID))
	deploymentID, deploymentErr := uuid.Parse(header.Get(HeaderDeploymentID))
	routeID, routeErr := uuid.Parse(header.Get(HeaderRouteID))
	binding := RequestBinding{
		Scope: Scope{
			Kind:    ScopeKind(header.Get(HeaderScopeKind)),
			ScopeID: scopeID,
		},
		AuthorityRevision: revision,
		AuthorityDigest:   header.Get(HeaderAuthorityDigest),
		DeploymentID:      deploymentID,
		RouteID:           routeID,
		TrafficClass:      TrafficClass(header.Get(HeaderTrafficClass)),
	}
	if err != nil || scopeErr != nil || deploymentErr != nil || routeErr != nil ||
		binding.Scope.Validate() != nil || revision == 0 ||
		!validDigest(binding.AuthorityDigest) || deploymentID != expectedDeploymentID ||
		routeID == uuid.Nil || binding.TrafficClass != expectedTrafficClass ||
		!expectedTrafficClass.Valid() {
		return RequestBinding{}, ErrInvalid
	}
	return binding, nil
}

type CurrentBinding struct {
	Revision     uint64
	Digest       string
	DeploymentID uuid.UUID
}

type BindingRegistry struct {
	mu       sync.RWMutex
	bindings map[Scope]CurrentBinding
}

type BindingFile struct {
	Bindings []BindingFileEntry `json:"bindings"`
	Version  int                `json:"version"`
}

type BindingFileEntry struct {
	DeploymentID uuid.UUID `json:"deploymentID"`
	Digest       string    `json:"digest"`
	Revision     uint64    `json:"revision"`
	Scope        Scope     `json:"scope"`
}

func NewBindingRegistry() *BindingRegistry {
	return &BindingRegistry{bindings: make(map[Scope]CurrentBinding)}
}

func LoadBindingRegistry(
	path string,
	expectedDeploymentID uuid.UUID,
) (*BindingRegistry, error) {
	if strings.TrimSpace(path) == "" || expectedDeploymentID == uuid.Nil {
		return nil, ErrInvalid
	}
	// Bindings are not secret, but only the service owner may modify them.
	data, err := readProtectedRegularFile(path, 1024*1024, 0o022)
	if err != nil {
		return nil, fmt.Errorf("read service authority bindings: %w", err)
	}
	if len(data) == 0 {
		return nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var file BindingFile
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("decode service authority bindings: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrInvalid
	}
	if file.Version != SchemaVersion ||
		len(file.Bindings) == 0 {
		return nil, ErrInvalid
	}
	registry := NewBindingRegistry()
	seen := make(map[Scope]struct{}, len(file.Bindings))
	for _, entry := range file.Bindings {
		if entry.DeploymentID != expectedDeploymentID {
			return nil, ErrInvalid
		}
		if _, exists := seen[entry.Scope]; exists {
			return nil, ErrInvalid
		}
		seen[entry.Scope] = struct{}{}
		if err := registry.Activate(entry.Scope, CurrentBinding{
			Revision:     entry.Revision,
			Digest:       entry.Digest,
			DeploymentID: entry.DeploymentID,
		}); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

// Activate is intentionally not exposed over HTTP. A caller must first
// authenticate the Facets authority chain before installing this non-secret
// active binding in the deployment runtime.
func (registry *BindingRegistry) Activate(scope Scope, binding CurrentBinding) error {
	if registry == nil || scope.Validate() != nil || binding.Revision == 0 ||
		!validDigest(binding.Digest) || binding.DeploymentID == uuid.Nil {
		return ErrInvalid
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if current, exists := registry.bindings[scope]; exists {
		if binding.Revision < current.Revision ||
			(binding.Revision == current.Revision &&
				(subtle.ConstantTimeCompare([]byte(binding.Digest), []byte(current.Digest)) != 1 ||
					binding.DeploymentID != current.DeploymentID)) {
			return ErrInvalid
		}
		if binding.Revision > current.Revision && binding.Revision != current.Revision+1 {
			return ErrInvalid
		}
	}
	registry.bindings[scope] = binding
	return nil
}

func (registry *BindingRegistry) Authorize(binding RequestBinding) error {
	if registry == nil {
		return ErrInvalid
	}
	registry.mu.RLock()
	current, exists := registry.bindings[binding.Scope]
	registry.mu.RUnlock()
	if !exists || current.Revision != binding.AuthorityRevision ||
		current.DeploymentID != binding.DeploymentID ||
		subtle.ConstantTimeCompare([]byte(current.Digest), []byte(binding.AuthorityDigest)) != 1 {
		return ErrInvalid
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func readProtectedRegularFile(
	path string,
	maximumByteCount int64,
	disallowedPermissions os.FileMode,
) ([]byte, error) {
	if strings.TrimSpace(path) == "" || maximumByteCount <= 0 {
		return nil, ErrInvalid
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() ||
		pathInfo.Mode().Perm()&disallowedPermissions != 0 {
		return nil, ErrInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalid
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() ||
		openedInfo.Mode().Perm()&disallowedPermissions != 0 ||
		!os.SameFile(pathInfo, openedInfo) {
		return nil, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumByteCount+1))
	if err != nil || int64(len(data)) > maximumByteCount {
		return nil, ErrInvalid
	}
	return data, nil
}

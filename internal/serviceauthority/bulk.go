package serviceauthority

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	bulkGrantSignatureDomain                      = "Facets bulk transfer grant v1\x00"
	HeaderBulkTransferGrant                       = "X-Facets-Bulk-Transfer-Grant"
	HeaderBulkResourceID                          = "X-Facets-Bulk-Resource-ID"
	HeaderBulkDirection                           = "X-Facets-Bulk-Direction"
	BulkUpload                      BulkDirection = "upload"
	BulkDownload                    BulkDirection = "download"
	maximumBulkGrantHeaderByteCount               = 16 * 1024
)

type BulkDirection string

func (direction BulkDirection) Valid() bool {
	return direction == BulkUpload || direction == BulkDownload
}

// BulkGrantPayload field order is canonical sorted-key JSON and must remain in
// lockstep with Swift's sorted-key encoder.
type BulkGrantPayload struct {
	AuthorityManifestDigest string        `json:"authorityManifestDigest"`
	DeploymentID            uuid.UUID     `json:"deploymentID"`
	Direction               BulkDirection `json:"direction"`
	ExpiresAtMilliseconds   int64         `json:"expiresAtMilliseconds"`
	GrantID                 uuid.UUID     `json:"grantID"`
	MaximumByteCount        int64         `json:"maximumByteCount"`
	NotBeforeMilliseconds   int64         `json:"notBeforeMilliseconds"`
	ResourceID              string        `json:"resourceID"`
	RouteID                 uuid.UUID     `json:"routeID"`
	Scope                   Scope         `json:"scope"`
	Version                 int           `json:"version"`
}

func (payload BulkGrantPayload) Validate() error {
	if payload.Version != SchemaVersion || payload.GrantID == uuid.Nil ||
		payload.Scope.Validate() != nil || !validDigest(payload.AuthorityManifestDigest) ||
		payload.DeploymentID == uuid.Nil || payload.RouteID == uuid.Nil ||
		!validBulkResourceID(payload.ResourceID) || !payload.Direction.Valid() ||
		payload.MaximumByteCount <= 0 || payload.NotBeforeMilliseconds < 0 ||
		payload.ExpiresAtMilliseconds <= payload.NotBeforeMilliseconds {
		return ErrInvalid
	}
	return nil
}

type BulkTransferGrant struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

func ParseBulkTransferGrantHeader(value string) (BulkTransferGrant, BulkGrantPayload, error) {
	if value == "" || len(value) > maximumBulkGrantHeaderByteCount {
		return BulkTransferGrant{}, BulkGrantPayload{}, ErrInvalid
	}
	encoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(encoded) != value {
		return BulkTransferGrant{}, BulkGrantPayload{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var grant BulkTransferGrant
	if err := decoder.Decode(&grant); err != nil {
		return BulkTransferGrant{}, BulkGrantPayload{}, ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return BulkTransferGrant{}, BulkGrantPayload{}, ErrInvalid
	}
	canonicalGrant, err := json.Marshal(grant)
	if err != nil || !bytes.Equal(canonicalGrant, encoded) {
		return BulkTransferGrant{}, BulkGrantPayload{}, ErrInvalid
	}

	payloadDecoder := json.NewDecoder(bytes.NewReader(grant.Payload))
	payloadDecoder.DisallowUnknownFields()
	var payload BulkGrantPayload
	if err := payloadDecoder.Decode(&payload); err != nil {
		return BulkTransferGrant{}, BulkGrantPayload{}, ErrInvalid
	}
	if err := payloadDecoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return BulkTransferGrant{}, BulkGrantPayload{}, ErrInvalid
	}
	canonicalPayload, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(canonicalPayload, grant.Payload) || payload.Validate() != nil {
		return BulkTransferGrant{}, BulkGrantPayload{}, ErrInvalid
	}
	return grant, payload, nil
}

func verifyBulkTransferGrant(
	grant BulkTransferGrant,
	payload BulkGrantPayload,
	authority CurrentBinding,
) error {
	if grant.Signature.Algorithm != "ES256" ||
		grant.Signature.SignerID != authority.AuthoritySignerID ||
		grant.Signature.PublicSigningKeyX963 != authority.AuthorityPublicSigningKeyX963 ||
		grant.Signature.SigningKeyFingerprint != authority.AuthoritySigningKeyFingerprint {
		return ErrInvalid
	}
	_, publicKey, fingerprint, err := decodeP256PublicKey(
		grant.Signature.PublicSigningKeyX963,
	)
	if err != nil || fingerprint != grant.Signature.SigningKeyFingerprint {
		return ErrInvalid
	}
	rawSignature, err := base64.RawURLEncoding.Strict().DecodeString(
		grant.Signature.Signature,
	)
	if err != nil || len(rawSignature) != 64 ||
		base64.RawURLEncoding.EncodeToString(rawSignature) != grant.Signature.Signature {
		return ErrInvalid
	}
	r := new(big.Int).SetBytes(rawSignature[:32])
	s := new(big.Int).SetBytes(rawSignature[32:])
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(elliptic.P256().Params().N) >= 0 ||
		s.Cmp(elliptic.P256().Params().N) >= 0 {
		return ErrInvalid
	}
	digest := sha256.Sum256(append([]byte(bulkGrantSignatureDomain), grant.Payload...))
	if !ecdsa.Verify(publicKey, digest[:], r, s) || payload.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

func (registry *BindingRegistry) AuthorizeBulkTransfer(
	binding RequestBinding,
	header http.Header,
	now time.Time,
) (BulkGrantPayload, error) {
	if registry == nil || binding.TrafficClass != TrafficBulk ||
		registry.Authorize(binding) != nil {
		return BulkGrantPayload{}, ErrInvalid
	}
	resourceID, resourceErr := singleHeaderValue(header, HeaderBulkResourceID)
	directionValue, directionErr := singleHeaderValue(header, HeaderBulkDirection)
	grantValue, grantErr := singleHeaderValue(header, HeaderBulkTransferGrant)
	direction := BulkDirection(directionValue)
	if resourceErr != nil || directionErr != nil || grantErr != nil ||
		!validBulkResourceID(resourceID) || !direction.Valid() {
		return BulkGrantPayload{}, ErrInvalid
	}
	grant, payload, err := ParseBulkTransferGrantHeader(grantValue)
	if err != nil {
		return BulkGrantPayload{}, ErrInvalid
	}
	registry.mu.RLock()
	current, exists := registry.bindings[binding.Scope]
	registry.mu.RUnlock()
	if !exists || verifyBulkTransferGrant(grant, payload, current) != nil ||
		payload.Scope != binding.Scope || payload.AuthorityManifestDigest != binding.AuthorityDigest ||
		payload.DeploymentID != binding.DeploymentID || payload.RouteID != binding.RouteID ||
		payload.ResourceID != resourceID || payload.Direction != direction ||
		now.UnixMilli() < payload.NotBeforeMilliseconds ||
		now.UnixMilli() >= payload.ExpiresAtMilliseconds {
		return BulkGrantPayload{}, ErrInvalid
	}
	return payload, nil
}

func validBulkResourceID(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len([]byte(value)) <= 512
}

func decodeP256PublicKey(value string) ([]byte, *ecdsa.PublicKey, string, error) {
	publicBytes, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(publicBytes) != value {
		return nil, nil, "", ErrInvalid
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicBytes)
	if x == nil || y == nil {
		return nil, nil, "", ErrInvalid
	}
	fingerprint := sha256.Sum256(publicBytes)
	return publicBytes, &ecdsa.PublicKey{
		Curve: elliptic.P256(), X: x, Y: y,
	}, hex.EncodeToString(fingerprint[:]), nil
}

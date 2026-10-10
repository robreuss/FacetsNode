package serviceauthority

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

const capacityPeerSignatureDomain = "Facets storage capacity peer request v1\x00"
const MaximumCapacityPeerPayloadBytes = 16 * 1024
const MaximumCapacityPeerBodyBytes = 64 * 1024
const CapacityPeerProofLifetime = time.Minute

type CapacityPeerOperation string

const (
	CapacityReserve   CapacityPeerOperation = "reserve"
	CapacityRecheck   CapacityPeerOperation = "recheck"
	CapacityDecide    CapacityPeerOperation = "decide"
	CapacityRead      CapacityPeerOperation = "read_reservation"
	CapacityReadiness CapacityPeerOperation = "read_readiness"
)

func (operation CapacityPeerOperation) valid() bool {
	switch operation {
	case CapacityReserve, CapacityRecheck, CapacityDecide, CapacityRead, CapacityReadiness:
		return true
	default:
		return false
	}
}

// CapacityPeerIdentity is owner-provisioned trust for one service deployment.
// The deployment UUID is also the content-blind capacity service instance ID.
// Account, Space, Job, object, path, and participant identities are forbidden.
type CapacityPeerIdentity struct {
	Service               storagecapacity.ServiceBinding `json:"service"`
	PublicSigningKeyX963  string                         `json:"publicSigningKeyX963"`
	SigningKeyFingerprint string                         `json:"signingKeyFingerprint"`
	Version               int                            `json:"version"`
}

func (identity CapacityPeerIdentity) Validate() error {
	public, err := canonicalP256PublicKey(identity.PublicSigningKeyX963)
	if identity.Version != SchemaVersion || identity.Service.Validate() != nil ||
		err != nil || len(identity.SigningKeyFingerprint) != sha256.Size*2 ||
		hex.EncodeToString(sha256Bytes(public)) != identity.SigningKeyFingerprint {
		return ErrInvalid
	}
	return nil
}

// CapacityPeerRequest commits to one exact, bounded private API body. PoolID
// prevents a proof provisioned for one physical authority from being replayed
// against another. OperationID is the ledger idempotency identity for writes
// and a fresh correlation identity for observational calls.
type CapacityPeerRequest struct {
	BodyByteCount int64                 `json:"bodyByteCount"`
	BodySHA256    string                `json:"bodySHA256"`
	Operation     CapacityPeerOperation `json:"operation"`
	OperationID   uuid.UUID             `json:"operationID"`
	PoolID        uuid.UUID             `json:"poolID"`
	Version       int                   `json:"version"`
}

func NewCapacityPeerRequest(
	operation CapacityPeerOperation,
	operationID, poolID uuid.UUID,
	body []byte,
) (CapacityPeerRequest, error) {
	digest := sha256.Sum256(body)
	request := CapacityPeerRequest{
		BodyByteCount: int64(len(body)), BodySHA256: hex.EncodeToString(digest[:]),
		Operation: operation, OperationID: operationID, PoolID: poolID,
		Version: SchemaVersion,
	}
	if request.Validate() != nil {
		return CapacityPeerRequest{}, ErrInvalid
	}
	return request, nil
}

func (request CapacityPeerRequest) Validate() error {
	if request.Version != SchemaVersion || !request.Operation.valid() ||
		request.OperationID == uuid.Nil || request.PoolID == uuid.Nil ||
		request.BodyByteCount < 0 || request.BodyByteCount > MaximumCapacityPeerBodyBytes ||
		!validDigest(request.BodySHA256) {
		return ErrInvalid
	}
	return nil
}

func (request CapacityPeerRequest) MatchesBody(body []byte) bool {
	if request.Validate() != nil || int64(len(body)) != request.BodyByteCount {
		return false
	}
	digest := sha256.Sum256(body)
	return bytes.Equal([]byte(request.BodySHA256), []byte(hex.EncodeToString(digest[:])))
}

type CapacityPeerPayload struct {
	ExpiresAtMilliseconds int64                          `json:"expiresAtMilliseconds"`
	IssuedAtMilliseconds  int64                          `json:"issuedAtMilliseconds"`
	Request               CapacityPeerRequest            `json:"request"`
	Service               storagecapacity.ServiceBinding `json:"service"`
	Version               int                            `json:"version"`
}

type CapacityPeerProof struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

// VerifiedCapacityPeerRequest is deliberately non-serializable: it conveys a
// verified deployment identity only within the receiving process and is not a
// bearer credential. The receiver still applies ledger idempotency and token
// checks to the committed body.
type VerifiedCapacityPeerRequest struct{ payload CapacityPeerPayload }

func (verified VerifiedCapacityPeerRequest) Service() storagecapacity.ServiceBinding {
	return verified.payload.Service
}

func (verified VerifiedCapacityPeerRequest) Request() CapacityPeerRequest {
	return verified.payload.Request
}

func (VerifiedCapacityPeerRequest) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (VerifiedCapacityPeerRequest) String() string {
	return "verified-storage-capacity-peer-request"
}
func (verified VerifiedCapacityPeerRequest) GoString() string { return verified.String() }

func (signer *DeploymentSigner) SignCapacityPeerRequestAt(
	service storagecapacity.ServiceBinding,
	request CapacityPeerRequest,
	body []byte,
	now time.Time,
) (CapacityPeerProof, error) {
	issued := now.UnixMilli()
	if signer == nil || service.Validate() != nil || service.InstanceID != signer.DeploymentID() ||
		!request.MatchesBody(body) || issued <= 0 ||
		issued > math.MaxInt64-CapacityPeerProofLifetime.Milliseconds() {
		return CapacityPeerProof{}, ErrInvalid
	}
	payload := CapacityPeerPayload{
		ExpiresAtMilliseconds: issued + CapacityPeerProofLifetime.Milliseconds(),
		IssuedAtMilliseconds:  issued, Request: request, Service: service,
		Version: SchemaVersion,
	}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > MaximumCapacityPeerPayloadBytes {
		return CapacityPeerProof{}, ErrInvalid
	}
	signature, err := signer.signRecord(capacityPeerSignatureDomain, encoded)
	if err != nil {
		return CapacityPeerProof{}, err
	}
	return CapacityPeerProof{Payload: encoded, Signature: signature}, nil
}

// VerifyCapacityPeerRequestAt trusts only the independently provisioned
// identity supplied by the capacity authority. The service identity embedded
// in the proof is never itself a trust anchor.
func VerifyCapacityPeerRequestAt(
	identity CapacityPeerIdentity,
	proof CapacityPeerProof,
	expected CapacityPeerRequest,
	body []byte,
	now time.Time,
) (VerifiedCapacityPeerRequest, error) {
	if identity.Validate() != nil || !expected.MatchesBody(body) ||
		len(proof.Payload) == 0 || len(proof.Payload) > MaximumCapacityPeerPayloadBytes {
		return VerifiedCapacityPeerRequest{}, ErrInvalid
	}
	var payload CapacityPeerPayload
	if verifyCanonicalRecord(proof.Payload, proof.Signature, capacityPeerSignatureDomain, &payload) != nil ||
		payload.Version != SchemaVersion || payload.Request != expected ||
		payload.Request.Validate() != nil || payload.Service != identity.Service ||
		payload.IssuedAtMilliseconds <= 0 ||
		payload.ExpiresAtMilliseconds <= payload.IssuedAtMilliseconds ||
		payload.ExpiresAtMilliseconds-payload.IssuedAtMilliseconds != CapacityPeerProofLifetime.Milliseconds() ||
		now.UnixMilli() < payload.IssuedAtMilliseconds || now.UnixMilli() >= payload.ExpiresAtMilliseconds ||
		proof.Signature.SignerID != identity.Service.InstanceID ||
		proof.Signature.PublicSigningKeyX963 != identity.PublicSigningKeyX963 ||
		proof.Signature.SigningKeyFingerprint != identity.SigningKeyFingerprint {
		return VerifiedCapacityPeerRequest{}, ErrInvalid
	}
	return VerifiedCapacityPeerRequest{payload: payload}, nil
}

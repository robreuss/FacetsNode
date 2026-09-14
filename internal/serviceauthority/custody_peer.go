package serviceauthority

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/objectcustodywire"
)

const custodyPeerSignatureDomain = "Facets immutable custody peer request v1\x00"
const MaximumCustodyPeerPayloadBytes = 16 * 1024
const MaximumCustodyPeerControlBodyBytes = 128 * 1024

type CustodyPeerOperation string

const (
	CustodyReserveObject      CustodyPeerOperation = "reserve_object"
	CustodyPutObject          CustodyPeerOperation = "put_object"
	CustodyReadObject         CustodyPeerOperation = "read_object"
	CustodyBeginPublication   CustodyPeerOperation = "begin_publication"
	CustodyAddPins            CustodyPeerOperation = "add_pins"
	CustodyPreparePublication CustodyPeerOperation = "prepare_publication"
	CustodyConfirmPublication CustodyPeerOperation = "confirm_publication"
	CustodyAcquireLease       CustodyPeerOperation = "acquire_restore_lease"
	CustodyRenewLease         CustodyPeerOperation = "renew_restore_lease"
	CustodyCloseLease         CustodyPeerOperation = "close_restore_lease"
	CustodyRetirePublication  CustodyPeerOperation = "retire_publication"
)

func (operation CustodyPeerOperation) valid() bool {
	switch operation {
	case CustodyReserveObject, CustodyPutObject, CustodyReadObject, CustodyBeginPublication,
		CustodyAddPins, CustodyPreparePublication, CustodyConfirmPublication, CustodyAcquireLease,
		CustodyRenewLease, CustodyCloseLease, CustodyRetirePublication:
		return true
	default:
		return false
	}
}

func (operation CustodyPeerOperation) access() RequestAccess {
	if operation == CustodyReadObject {
		return RequestRead
	}
	return RequestMutation
}

func (operation CustodyPeerOperation) trafficClass() TrafficClass {
	if operation == CustodyPutObject || operation == CustodyReadObject {
		return TrafficBulk
	}
	return TrafficControl
}

// Canonical sorted-key JSON structs; these contain opaque operation/byte
// commitments only. Body keys and plaintext are never part of the proof.
type CustodyPeerTarget struct {
	BindingID      uuid.UUID `json:"bindingID"`
	ContentEpoch   uint64    `json:"contentEpoch"`
	ContentScopeID uuid.UUID `json:"contentScopeID"`
	LedgerID       uuid.UUID `json:"ledgerID"`
	PoolID         uuid.UUID `json:"poolID"`
}

type CustodyPeerRequest struct {
	BodyByteCount int64                `json:"bodyByteCount"`
	BodySHA256    string               `json:"bodySHA256"`
	Challenge     string               `json:"challenge"`
	Operation     CustodyPeerOperation `json:"operation"`
	OperationID   uuid.UUID            `json:"operationID"`
	Target        CustodyPeerTarget    `json:"target"`
	Version       int                  `json:"version"`
}

func (request CustodyPeerRequest) Validate() error {
	if len(request.Challenge) != 43 || len(request.BodySHA256) != 64 {
		return ErrInvalid
	}
	limit := int64(MaximumCustodyPeerControlBodyBytes)
	if request.Operation == CustodyPutObject {
		limit = objectcustodywire.MaximumPlaintextBytes + objectcustodywire.WireOverhead
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(request.Challenge)
	if request.Version != SchemaVersion || !request.Operation.valid() || request.OperationID == uuid.Nil ||
		request.BodyByteCount < 0 || request.BodyByteCount > limit || !validDigest(request.BodySHA256) ||
		err != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != request.Challenge ||
		request.Target.BindingID == uuid.Nil || request.Target.ContentScopeID == uuid.Nil || request.Target.ContentEpoch == 0 ||
		request.Target.LedgerID == uuid.Nil || request.Target.PoolID == uuid.Nil {
		return ErrInvalid
	}
	return nil
}

func (request CustodyPeerRequest) MatchesBody(body []byte) bool {
	if request.Validate() != nil || int64(len(body)) != request.BodyByteCount {
		return false
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]) == request.BodySHA256
}

type CustodyPeerSource struct {
	AuthorityManifestDigest string       `json:"authorityManifestDigest"`
	AuthorityRevision       uint64       `json:"authorityRevision"`
	DeploymentID            uuid.UUID    `json:"deploymentID"`
	RouteID                 uuid.UUID    `json:"routeID"`
	Scope                   Scope        `json:"scope"`
	TrafficClass            TrafficClass `json:"trafficClass"`
}

func custodyPeerSource(binding RequestBinding) CustodyPeerSource {
	return CustodyPeerSource{AuthorityManifestDigest: binding.AuthorityDigest, AuthorityRevision: binding.AuthorityRevision,
		DeploymentID: binding.DeploymentID, RouteID: binding.RouteID, Scope: binding.Scope, TrafficClass: binding.TrafficClass}
}

func (source CustodyPeerSource) binding() RequestBinding {
	return RequestBinding{Scope: source.Scope, AuthorityRevision: source.AuthorityRevision, AuthorityDigest: source.AuthorityManifestDigest,
		DeploymentID: source.DeploymentID, RouteID: source.RouteID, TrafficClass: source.TrafficClass}
}

type CustodyPeerPayload struct {
	Request CustodyPeerRequest `json:"request"`
	Source  CustodyPeerSource  `json:"source"`
	Version int                `json:"version"`
}

type CustodyPeerProof struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

// VerifiedCustodyPeerRequest proves only an exact deployment-bound request.
// It is NOT an end-user/scope-link grant, a consumed fresh challenge, or a
// ledger mutation permit. Production must enforce those separate boundaries.
type VerifiedCustodyPeerRequest struct{ payload CustodyPeerPayload }

func (proof VerifiedCustodyPeerRequest) Source() RequestBinding {
	return proof.payload.Source.binding()
}
func (proof VerifiedCustodyPeerRequest) Request() CustodyPeerRequest  { return proof.payload.Request }
func (proof VerifiedCustodyPeerRequest) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (proof VerifiedCustodyPeerRequest) String() string {
	return "verified-custody-peer-request(bound-deployment-only)"
}
func (proof VerifiedCustodyPeerRequest) GoString() string { return proof.String() }

// SignCustodyPeerRequestAt reuses the existing deployment signer and current
// service registry. A real signed, persistent deployment-scoped binding is
// mandatory. The caller must already hold its scope mutation lease through its
// durable service-authority fence/effect, and authenticate the client intent.
func (registry *BindingRegistry) SignCustodyPeerRequestAt(signer *DeploymentSigner, binding RequestBinding, request CustodyPeerRequest, body []byte, now time.Time) (CustodyPeerProof, error) {
	if signer == nil || !request.MatchesBody(body) {
		return CustodyPeerProof{}, ErrInvalid
	}
	descriptor, err := registry.custodyPeerDeployment(binding, request.Operation, now)
	if err != nil || descriptor.DeploymentID != signer.DeploymentID() || descriptor.PublicSigningKeyX963 != signer.PublicSigningKeyX963() || descriptor.SigningKeyFingerprint != signer.SigningKeyFingerprint() {
		return CustodyPeerProof{}, ErrInvalid
	}
	payload := CustodyPeerPayload{Request: request, Source: custodyPeerSource(binding), Version: SchemaVersion}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > MaximumCustodyPeerPayloadBytes {
		return CustodyPeerProof{}, ErrInvalid
	}
	signature, err := signer.signRecord(custodyPeerSignatureDomain, encoded)
	if err != nil {
		return CustodyPeerProof{}, err
	}
	if _, err = registry.custodyPeerDeployment(binding, request.Operation, now); err != nil {
		return CustodyPeerProof{}, err
	}
	return CustodyPeerProof{Payload: encoded, Signature: signature}, nil
}

// VerifyCustodyPeerRequestAt requires an independently pinned/current peer
// registry and the receiver's OWN live challenge/operation context as expected.
// Never populate either from the untrusted request. This primitive checks nonce
// equality; it does not issue, expire or consume receiver challenges. The
// adapter must atomically enforce challenge and linked-scope permission before
// any trusted ledger effect, retaining its existing scope mutation lease.
func (registry *BindingRegistry) VerifyCustodyPeerRequestAt(proof CustodyPeerProof, expected CustodyPeerRequest, body []byte, now time.Time) (VerifiedCustodyPeerRequest, error) {
	if !expected.MatchesBody(body) || len(proof.Payload) > MaximumCustodyPeerPayloadBytes ||
		proof.Signature.Algorithm != "ES256" || len(proof.Signature.PublicSigningKeyX963) != 87 ||
		len(proof.Signature.Signature) != 86 || len(proof.Signature.SigningKeyFingerprint) != 64 {
		return VerifiedCustodyPeerRequest{}, ErrInvalid
	}
	var payload CustodyPeerPayload
	if verifyCanonicalRecord(proof.Payload, proof.Signature, custodyPeerSignatureDomain, &payload) != nil ||
		payload.Version != SchemaVersion || payload.Request != expected {
		return VerifiedCustodyPeerRequest{}, ErrInvalid
	}
	descriptor, err := registry.custodyPeerDeployment(payload.Source.binding(), payload.Request.Operation, now)
	if err != nil || proof.Signature.SignerID != descriptor.DeploymentID ||
		proof.Signature.PublicSigningKeyX963 != descriptor.PublicSigningKeyX963 ||
		proof.Signature.SigningKeyFingerprint != descriptor.SigningKeyFingerprint {
		return VerifiedCustodyPeerRequest{}, ErrInvalid
	}
	return VerifiedCustodyPeerRequest{payload: payload}, nil
}

func (registry *BindingRegistry) custodyPeerDeployment(binding RequestBinding, operation CustodyPeerOperation, now time.Time) (DeploymentDescriptor, error) {
	if registry == nil || !operation.valid() || now.UnixMilli() < 0 ||
		(binding.Scope.Kind != ScopeDeviceSync && binding.Scope.Kind != ScopeBackupCustody) ||
		binding.TrafficClass != operation.trafficClass() || registry.AuthorizeRequestAt(binding, operation.access(), now) != nil {
		return DeploymentDescriptor{}, ErrInvalid
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	current, exists := registry.bindings[binding.Scope]
	if registry.poisoned || !exists || registry.persistencePath == "" || registry.expectedDeploymentID != binding.DeploymentID || current.Manifest == nil ||
		current.Revision != binding.AuthorityRevision || current.Digest != binding.AuthorityDigest || current.DeploymentID != binding.DeploymentID ||
		validateCurrentBinding(binding.Scope, current, registry.expectedDeploymentID) != nil ||
		(operation.access() == RequestMutation && current.WriteFence != nil) ||
		!bindingManifestAuthorizes(current, now.UnixMilli(), binding.RouteID, binding.TrafficClass) {
		return DeploymentDescriptor{}, ErrInvalid
	}
	payload, err := current.Manifest.VerifiedPayload()
	if err != nil {
		return DeploymentDescriptor{}, ErrInvalid
	}
	return payload.ActiveDeployment, nil
}

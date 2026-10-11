package jobcustody

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computequeue"
)

const (
	AdmissionPermitVersion                  = 1
	MaximumAdmissionPermitBytes             = 64 * 1024
	MaximumAdmissionPermitLifetimeMillisecs = int64(15 * 60 * 1000)
	admissionPermitSignatureDomain          = "Facets Job Custody route permit v1\x00"
	admissionPermitEnvelopeDigestDomain     = "facets.job-custody.route-permit.envelope.v1"
)

var ErrAdmissionPermitAuthentication = errors.New("job custody route permit authentication failed")

// AdmissionPermitPayload is a short-lived, content-blind assertion made by
// the Box control plane after it has authenticated the submitting participant
// device and checked an active grant for the exact shared Worker capability
// revision. Job Custody learns only opaque authority/grant commitments and the
// exact route needed to hold the already-protected capsule.
//
// Field declaration order is canonical sorted-key JSON and must stay aligned
// with the portable client contract introduced with the issuing route.
type AdmissionPermitPayload struct {
	AdmissionEnvelopeDigest      computequeue.Digest               `json:"admissionEnvelopeDigest"`
	AdmissionSigner              computequeue.ReceiptSignerBinding `json:"admissionSigner"`
	AuthorityID                  uuid.UUID                         `json:"authorityID"`
	ExpiresAt                    computequeue.Timestamp            `json:"expiresAt"`
	IssuedAt                     computequeue.Timestamp            `json:"issuedAt"`
	PermitID                     uuid.UUID                         `json:"permitID"`
	RequesterAuthorityDigest     computequeue.Digest               `json:"requesterAuthorityDigest"`
	RouteRecipientKeyFingerprint computequeue.Digest               `json:"routeRecipientKeyFingerprint"`
	RouteRecipientWorkerID       computequeue.WorkerID             `json:"routeRecipientWorkerID"`
	Version                      int                               `json:"version"`
	WorkerAccessGrantDigest      computequeue.Digest               `json:"workerAccessGrantDigest"`
	WorkerCapabilitiesDigest     computequeue.Digest               `json:"workerCapabilitiesDigest"`
}

func (value AdmissionPermitPayload) Validate() error {
	if value.Version != AdmissionPermitVersion || value.AuthorityID == uuid.Nil ||
		value.PermitID == uuid.Nil || value.AdmissionEnvelopeDigest.Validate() != nil ||
		value.AdmissionSigner.Validate() != nil || value.RequesterAuthorityDigest.Validate() != nil ||
		value.RouteRecipientKeyFingerprint.Validate() != nil ||
		value.RouteRecipientWorkerID.Validate() != nil ||
		value.WorkerAccessGrantDigest.Validate() != nil ||
		value.WorkerCapabilitiesDigest.Validate() != nil ||
		value.IssuedAt.Validate() != nil || value.ExpiresAt.Validate() != nil ||
		value.IssuedAt >= value.ExpiresAt ||
		int64(value.ExpiresAt-value.IssuedAt) > MaximumAdmissionPermitLifetimeMillisecs {
		return ErrAdmissionPermitAuthentication
	}
	return nil
}

type SignedAdmissionPermit struct {
	Payload   []byte                      `json:"payload"`
	Signature computequeue.SignatureValue `json:"signature"`
}

// AdmissionPermitSigner is held only by the Box control plane. Constructing a
// valid payload does not itself prove participant or Worker authority; the
// issuing controller must complete those checks before calling Sign.
type AdmissionPermitSigner struct {
	authorityID uuid.UUID
	privateKey  ed25519.PrivateKey
}

func NewAdmissionPermitSigner(
	authorityID uuid.UUID,
	privateKey ed25519.PrivateKey,
) (*AdmissionPermitSigner, error) {
	if authorityID == uuid.Nil || len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrAdmissionPermitAuthentication
	}
	return &AdmissionPermitSigner{
		authorityID: authorityID,
		privateKey:  bytes.Clone(privateKey),
	}, nil
}

func NewAdmissionPermitPayload(
	authorityID uuid.UUID,
	permitID uuid.UUID,
	requesterAuthorityDigest computequeue.Digest,
	workerAccessGrantDigest computequeue.Digest,
	workerCapabilitiesDigest computequeue.Digest,
	admissionSigner computequeue.ReceiptSignerBinding,
	envelopeBytes []byte,
	issuedAt computequeue.Timestamp,
	expiresAt computequeue.Timestamp,
) (AdmissionPermitPayload, error) {
	envelope, err := computequeue.DecodeJobCustodyAdmissionCanonical(envelopeBytes)
	if err != nil {
		return AdmissionPermitPayload{}, ErrAdmissionPermitAuthentication
	}
	envelopeDigest, err := admissionPermitEnvelopeDigest(envelopeBytes)
	if err != nil {
		return AdmissionPermitPayload{}, err
	}
	value := AdmissionPermitPayload{
		AdmissionEnvelopeDigest:      envelopeDigest,
		AdmissionSigner:              admissionSigner,
		AuthorityID:                  authorityID,
		ExpiresAt:                    expiresAt,
		IssuedAt:                     issuedAt,
		PermitID:                     permitID,
		RequesterAuthorityDigest:     requesterAuthorityDigest,
		RouteRecipientKeyFingerprint: envelope.Header.RouteRecipientKeyFingerprint,
		RouteRecipientWorkerID:       envelope.Header.RouteRecipientWorkerID,
		Version:                      AdmissionPermitVersion,
		WorkerAccessGrantDigest:      workerAccessGrantDigest,
		WorkerCapabilitiesDigest:     workerCapabilitiesDigest,
	}
	if value.Validate() != nil || value.AdmissionSigner.SignatureProfileID != envelope.SignatureProfileID ||
		issuedAt < envelope.Header.NotBeforeAt || expiresAt > envelope.Header.RetentionUntil {
		return AdmissionPermitPayload{}, ErrAdmissionPermitAuthentication
	}
	return value, nil
}

func (signer *AdmissionPermitSigner) Sign(
	payload AdmissionPermitPayload,
) (SignedAdmissionPermit, error) {
	if signer == nil || signer.authorityID == uuid.Nil ||
		len(signer.privateKey) != ed25519.PrivateKeySize || payload.Validate() != nil ||
		payload.AuthorityID != signer.authorityID {
		return SignedAdmissionPermit{}, ErrAdmissionPermitAuthentication
	}
	encoded, err := computequeue.EncodeCanonical(payload)
	if err != nil || len(encoded) > MaximumAdmissionPermitBytes {
		return SignedAdmissionPermit{}, ErrAdmissionPermitAuthentication
	}
	signature := ed25519.Sign(signer.privateKey, admissionPermitSigningBytes(encoded))
	return SignedAdmissionPermit{
		Payload:   encoded,
		Signature: computequeue.SignatureValue(base64.RawURLEncoding.EncodeToString(signature)),
	}, nil
}

type AdmissionPermitVerificationKey struct {
	authorityID uuid.UUID
	publicKey   ed25519.PublicKey
}

func NewAdmissionPermitVerificationKey(
	authorityID uuid.UUID,
	publicKey ed25519.PublicKey,
) (AdmissionPermitVerificationKey, error) {
	if authorityID == uuid.Nil || len(publicKey) != ed25519.PublicKeySize {
		return AdmissionPermitVerificationKey{}, ErrAdmissionPermitAuthentication
	}
	return AdmissionPermitVerificationKey{
		authorityID: authorityID,
		publicKey:   bytes.Clone(publicKey),
	}, nil
}

// AdmissionPermitVerifier contains only owner-pinned Box control-plane keys.
// The signed payload may select among those configured authorities, but it can
// neither introduce a key nor alias one key under multiple authority IDs.
type AdmissionPermitVerifier struct {
	keys map[uuid.UUID]ed25519.PublicKey
}

func NewAdmissionPermitVerifier(
	trustedKeys []AdmissionPermitVerificationKey,
) (*AdmissionPermitVerifier, error) {
	if len(trustedKeys) == 0 {
		return nil, ErrAdmissionPermitAuthentication
	}
	keys := make(map[uuid.UUID]ed25519.PublicKey, len(trustedKeys))
	seen := make(map[[sha256.Size]byte]struct{}, len(trustedKeys))
	for _, key := range trustedKeys {
		fingerprint := sha256.Sum256(key.publicKey)
		if key.authorityID == uuid.Nil || len(key.publicKey) != ed25519.PublicKeySize {
			return nil, ErrAdmissionPermitAuthentication
		}
		if _, exists := keys[key.authorityID]; exists {
			return nil, ErrAdmissionPermitAuthentication
		}
		if _, exists := seen[fingerprint]; exists {
			return nil, ErrAdmissionPermitAuthentication
		}
		keys[key.authorityID] = bytes.Clone(key.publicKey)
		seen[fingerprint] = struct{}{}
	}
	return &AdmissionPermitVerifier{keys: keys}, nil
}

// AdmissionAuthorization is verified runtime evidence, never a wire or
// persistence contract. Its private fields prevent a decoded request from
// becoming trusted route state without first crossing Verify.
type AdmissionAuthorization struct {
	header                   computequeue.JobCustodyAdmissionHeader
	expectedSigner           computequeue.ReceiptSignerBinding
	permitDigest             computequeue.Digest
	authorityID              uuid.UUID
	requesterAuthorityDigest computequeue.Digest
	workerCapabilitiesDigest computequeue.Digest
}

func (value AdmissionAuthorization) Header() computequeue.JobCustodyAdmissionHeader {
	return value.header
}

func (value AdmissionAuthorization) ExpectedSigner() computequeue.ReceiptSignerBinding {
	return value.expectedSigner
}

func (value AdmissionAuthorization) PermitDigest() computequeue.Digest {
	return value.permitDigest
}

func (value AdmissionAuthorization) AuthorityID() uuid.UUID {
	return value.authorityID
}

func (value AdmissionAuthorization) RequesterAuthorityDigest() computequeue.Digest {
	return value.requesterAuthorityDigest
}

func (value AdmissionAuthorization) WorkerCapabilitiesDigest() computequeue.Digest {
	return value.workerCapabilitiesDigest
}

func (value AdmissionAuthorization) MarshalJSON() ([]byte, error) {
	return nil, ErrAdmissionPermitAuthentication
}

func (value AdmissionAuthorization) String() string {
	return "verified-job-custody-admission-authorization(redacted)"
}

func (value AdmissionAuthorization) GoString() string { return value.String() }

func (verifier *AdmissionPermitVerifier) Verify(
	permit SignedAdmissionPermit,
	envelopeBytes []byte,
	now computequeue.Timestamp,
) (AdmissionAuthorization, error) {
	if verifier == nil || len(permit.Payload) == 0 ||
		len(permit.Payload) > MaximumAdmissionPermitBytes || now.Validate() != nil {
		return AdmissionAuthorization{}, ErrAdmissionPermitAuthentication
	}
	payload, err := computequeue.DecodeCanonical[AdmissionPermitPayload](permit.Payload)
	if err != nil {
		return AdmissionAuthorization{}, ErrAdmissionPermitAuthentication
	}
	publicKey, trusted := verifier.keys[payload.AuthorityID]
	rawSignature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(string(permit.Signature))
	if !trusted || signatureErr != nil || len(rawSignature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(rawSignature) != string(permit.Signature) ||
		!ed25519.Verify(publicKey, admissionPermitSigningBytes(permit.Payload), rawSignature) ||
		now < payload.IssuedAt || now >= payload.ExpiresAt {
		return AdmissionAuthorization{}, ErrAdmissionPermitAuthentication
	}
	envelopeDigest, err := admissionPermitEnvelopeDigest(envelopeBytes)
	if err != nil || envelopeDigest != payload.AdmissionEnvelopeDigest {
		return AdmissionAuthorization{}, ErrAdmissionPermitAuthentication
	}
	envelope, err := computequeue.DecodeJobCustodyAdmissionCanonical(envelopeBytes)
	if err != nil || envelope.SignatureProfileID != payload.AdmissionSigner.SignatureProfileID ||
		envelope.Header.RouteRecipientWorkerID != payload.RouteRecipientWorkerID ||
		envelope.Header.RouteRecipientKeyFingerprint != payload.RouteRecipientKeyFingerprint ||
		payload.IssuedAt < envelope.Header.NotBeforeAt || payload.ExpiresAt > envelope.Header.RetentionUntil {
		return AdmissionAuthorization{}, ErrAdmissionPermitAuthentication
	}
	permitDigest, err := computequeue.ExactBytesDigest(
		"facets.job-custody.route-permit.v1",
		append(bytes.Clone(permit.Payload), rawSignature...),
		MaximumAdmissionPermitBytes+ed25519.SignatureSize,
	)
	if err != nil {
		return AdmissionAuthorization{}, ErrAdmissionPermitAuthentication
	}
	return AdmissionAuthorization{
		header:                   envelope.Header,
		expectedSigner:           payload.AdmissionSigner,
		permitDigest:             permitDigest,
		authorityID:              payload.AuthorityID,
		requesterAuthorityDigest: payload.RequesterAuthorityDigest,
		workerCapabilitiesDigest: payload.WorkerCapabilitiesDigest,
	}, nil
}

func admissionPermitEnvelopeDigest(envelopeBytes []byte) (computequeue.Digest, error) {
	digest, err := computequeue.ExactBytesDigest(
		admissionPermitEnvelopeDigestDomain,
		envelopeBytes,
		computequeue.MaximumDocumentBytes,
	)
	if err != nil {
		return "", ErrAdmissionPermitAuthentication
	}
	return digest, nil
}

// AdmissionEnvelopeDigest exposes the exact content-blind envelope commitment
// used by route permits so a durable custody receipt can bind the same bytes
// without learning encrypted Job semantics.
func AdmissionEnvelopeDigest(envelopeBytes []byte) (computequeue.Digest, error) {
	return admissionPermitEnvelopeDigest(envelopeBytes)
}

func admissionPermitSigningBytes(payload []byte) []byte {
	result := make([]byte, 0, len(admissionPermitSignatureDomain)+len(payload))
	result = append(result, admissionPermitSignatureDomain...)
	return append(result, payload...)
}

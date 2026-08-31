package serviceauthority

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/google/uuid"
)

const (
	BackupCustodyReceiptVersion                 = 1
	MaximumBackupCustodyReceiptPayloadByteCount = 32 * 1024
	MaximumBackupCustodyReceiptRecordByteCount  = 40 * 1024
	BackupCustodyReceiptSignatureDomain         = "Facets backup custody committed receipt v1\x00"
	BackupRetentionReceiptSignatureDomain       = "Facets backup retention confirmed receipt v1\x00"
	BackupCustodyReceiptReferenceDomain         = "Facets backup custody committed receipt reference v1\x00"
	BackupRetentionReceiptReferenceDomain       = "Facets backup retention confirmed receipt reference v1\x00"
	BackupCustodyGenerationReferenceDomain      = "Facets backup custody generation reference v1\x00"
	BackupCustodyCommittedKind                  = "custody_committed"
	BackupRetentionConfirmedKind                = "retention_confirmed"
)

type BackupCustodyAuthorityContext struct {
	AuthorityManifestDigest string    `json:"authorityManifestDigest"`
	AuthorityRevision       uint64    `json:"authorityRevision"`
	DeploymentID            uuid.UUID `json:"deploymentID"`
	Scope                   Scope     `json:"scope"`
}

func (context BackupCustodyAuthorityContext) Validate() error {
	if context.Scope.Validate() != nil || context.Scope.Kind != ScopeBackupCustody ||
		context.AuthorityRevision == 0 || !validDigest(context.AuthorityManifestDigest) ||
		context.DeploymentID == uuid.Nil {
		return ErrInvalid
	}
	return nil
}

type BackupCustodyGenerationRecord struct {
	AccountID                  uuid.UUID `json:"accountID"`
	BackupSetID                uuid.UUID `json:"backupSetID"`
	Generation                 uint64    `json:"generation"`
	OuterByteCount             uint64    `json:"outerByteCount"`
	OuterDigest                string    `json:"outerDigest"`
	PredecessorReferenceDigest *string   `json:"predecessorReferenceDigest,omitempty"`
	TargetID                   uuid.UUID `json:"targetID"`
	UploadID                   uuid.UUID `json:"uploadID"`
	Version                    int       `json:"version"`
}

func (record BackupCustodyGenerationRecord) Validate() error {
	if record.Version != BackupCustodyReceiptVersion || record.AccountID == uuid.Nil || record.TargetID == uuid.Nil ||
		record.BackupSetID == uuid.Nil || record.Generation == 0 || record.UploadID == uuid.Nil ||
		record.OuterByteCount == 0 || !validBase64URLDigest(record.OuterDigest) {
		return ErrInvalid
	}
	if record.Generation == 1 {
		if record.PredecessorReferenceDigest != nil {
			return ErrInvalid
		}
	} else if record.PredecessorReferenceDigest == nil ||
		!validDigest(*record.PredecessorReferenceDigest) {
		return ErrInvalid
	}
	return nil
}

func (record BackupCustodyGenerationRecord) ReferenceDigest() (string, error) {
	if record.Validate() != nil {
		return "", ErrInvalid
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(append([]byte(BackupCustodyGenerationReferenceDomain), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func (record BackupCustodyGenerationRecord) ValidateSuccessor(
	predecessor BackupCustodyGenerationRecord,
) error {
	digest, err := predecessor.ReferenceDigest()
	if err != nil || record.Validate() != nil || predecessor.Generation == ^uint64(0) ||
		record.AccountID != predecessor.AccountID || record.TargetID != predecessor.TargetID ||
		record.BackupSetID != predecessor.BackupSetID ||
		record.Generation != predecessor.Generation+1 || record.PredecessorReferenceDigest == nil ||
		*record.PredecessorReferenceDigest != digest {
		return ErrInvalid
	}
	return nil
}

type BackupCustodyReceiptPayload struct {
	Authority                     BackupCustodyAuthorityContext `json:"authority"`
	CredentialID                  uuid.UUID                     `json:"credentialID"`
	CustodyReceiptReferenceDigest *string                       `json:"custodyReceiptReferenceDigest,omitempty"`
	Generation                    BackupCustodyGenerationRecord `json:"generation"`
	IssuedAtMilliseconds          int64                         `json:"issuedAtMilliseconds"`
	Kind                          string                        `json:"kind"`
	ReceiptID                     uuid.UUID                     `json:"receiptID"`
	RequestID                     uuid.UUID                     `json:"requestID"`
	RetainedThroughMilliseconds   *int64                        `json:"retainedThroughMilliseconds,omitempty"`
	Version                       int                           `json:"version"`
}

func (payload BackupCustodyReceiptPayload) Validate() error {
	if payload.Version != BackupCustodyReceiptVersion || payload.ReceiptID == uuid.Nil ||
		payload.RequestID == uuid.Nil || payload.CredentialID == uuid.Nil ||
		payload.IssuedAtMilliseconds < 0 || payload.Authority.Validate() != nil ||
		payload.Generation.Validate() != nil || payload.Authority.Scope.ScopeID != payload.Generation.AccountID {
		return ErrInvalid
	}
	switch payload.Kind {
	case BackupCustodyCommittedKind:
		if payload.CustodyReceiptReferenceDigest != nil || payload.RetainedThroughMilliseconds != nil {
			return ErrInvalid
		}
	case BackupRetentionConfirmedKind:
		if payload.CustodyReceiptReferenceDigest == nil ||
			!validDigest(*payload.CustodyReceiptReferenceDigest) ||
			payload.RetainedThroughMilliseconds == nil ||
			*payload.RetainedThroughMilliseconds != payload.IssuedAtMilliseconds {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type BackupCustodyReceipt struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

func (signer *DeploymentSigner) SignBackupCustodyReceipt(
	payload BackupCustodyReceiptPayload,
) (BackupCustodyReceipt, error) {
	if signer == nil || payload.Validate() != nil ||
		payload.Authority.DeploymentID != signer.deploymentID {
		return BackupCustodyReceipt{}, ErrInvalid
	}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > MaximumBackupCustodyReceiptPayloadByteCount {
		return BackupCustodyReceipt{}, ErrInvalid
	}
	signature, err := signer.signRecord(backupCustodyReceiptSignatureDomain(payload.Kind), encoded)
	if err != nil {
		return BackupCustodyReceipt{}, err
	}
	receipt := BackupCustodyReceipt{Payload: encoded, Signature: signature}
	if _, err := receipt.VerifiedPayload(); err != nil {
		return BackupCustodyReceipt{}, err
	}
	return receipt, nil
}

func (receipt BackupCustodyReceipt) VerifiedPayload() (BackupCustodyReceiptPayload, error) {
	var payload BackupCustodyReceiptPayload
	if len(receipt.Payload) == 0 || len(receipt.Payload) > MaximumBackupCustodyReceiptPayloadByteCount ||
		decodeCanonicalBackupCustody(receipt.Payload, &payload) != nil || payload.Validate() != nil ||
		verifyCanonicalRecord(receipt.Payload, receipt.Signature,
			backupCustodyReceiptSignatureDomain(payload.Kind), &payload) != nil ||
		receipt.Signature.SignerID != payload.Authority.DeploymentID {
		return BackupCustodyReceiptPayload{}, ErrInvalid
	}
	return payload, nil
}

func (receipt BackupCustodyReceipt) ReferenceDigest() (string, error) {
	payload, err := receipt.VerifiedPayload()
	if err != nil {
		return "", ErrInvalid
	}
	encodedSignature, err := json.Marshal(receipt.Signature)
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(append(append(
		[]byte(backupCustodyReceiptReferenceDomain(payload.Kind)), receipt.Payload...), encodedSignature...))
	return hex.EncodeToString(digest[:]), nil
}

func (receipt BackupCustodyReceipt) Authorize(
	anchor TrustAnchor,
	manifest Manifest,
) (BackupCustodyReceiptPayload, error) {
	payload, err := receipt.VerifiedPayload()
	if err != nil || anchor.Scope != payload.Authority.Scope {
		return BackupCustodyReceiptPayload{}, ErrInvalid
	}
	manifestDigest, digestErr := manifest.ReferenceDigest()
	authorized, authorizeErr := manifest.Authorize(anchor, payload.IssuedAtMilliseconds)
	if digestErr != nil || authorizeErr != nil ||
		manifestDigest != payload.Authority.AuthorityManifestDigest ||
		authorized.Revision != payload.Authority.AuthorityRevision ||
		authorized.ActiveDeployment.DeploymentID != payload.Authority.DeploymentID ||
		receipt.Signature.SignerID != authorized.ActiveDeployment.DeploymentID ||
		receipt.Signature.PublicSigningKeyX963 != authorized.ActiveDeployment.PublicSigningKeyX963 ||
		receipt.Signature.SigningKeyFingerprint != authorized.ActiveDeployment.SigningKeyFingerprint {
		return BackupCustodyReceiptPayload{}, ErrInvalid
	}
	return payload, nil
}

func DecodeBackupCustodyReceipt(input []byte) (BackupCustodyReceipt, error) {
	if len(input) == 0 || len(input) > MaximumBackupCustodyReceiptRecordByteCount {
		return BackupCustodyReceipt{}, ErrInvalid
	}
	var receipt BackupCustodyReceipt
	if decodeCanonicalBackupCustody(input, &receipt) != nil {
		return BackupCustodyReceipt{}, ErrInvalid
	}
	if _, err := receipt.VerifiedPayload(); err != nil {
		return BackupCustodyReceipt{}, err
	}
	return receipt, nil
}

func (receipt BackupCustodyReceipt) CanonicalJSON() ([]byte, error) {
	if _, err := receipt.VerifiedPayload(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) > MaximumBackupCustodyReceiptRecordByteCount {
		return nil, ErrInvalid
	}
	return encoded, nil
}

func NewBackupRetentionReceiptPayload(
	receiptID uuid.UUID,
	authority BackupCustodyAuthorityContext,
	requestID uuid.UUID,
	credentialID uuid.UUID,
	custodyReceipt BackupCustodyReceipt,
	custodyAnchor TrustAnchor,
	custodyManifest Manifest,
	retainedThroughMilliseconds int64,
	issuedAtMilliseconds int64,
) (BackupCustodyReceiptPayload, error) {
	custody, err := custodyReceipt.Authorize(custodyAnchor, custodyManifest)
	ref, refErr := custodyReceipt.ReferenceDigest()
	if err != nil || refErr != nil || custody.Kind != BackupCustodyCommittedKind ||
		custody.Authority.Scope != authority.Scope {
		return BackupCustodyReceiptPayload{}, ErrInvalid
	}
	payload := BackupCustodyReceiptPayload{
		Authority: authority, CredentialID: credentialID,
		CustodyReceiptReferenceDigest: &ref, Generation: custody.Generation,
		IssuedAtMilliseconds: issuedAtMilliseconds, Kind: BackupRetentionConfirmedKind,
		ReceiptID: receiptID, RequestID: requestID,
		RetainedThroughMilliseconds: &retainedThroughMilliseconds,
		Version:                     BackupCustodyReceiptVersion,
	}
	if payload.Validate() != nil {
		return BackupCustodyReceiptPayload{}, ErrInvalid
	}
	return payload, nil
}

func backupCustodyReceiptSignatureDomain(kind string) string {
	if kind == BackupRetentionConfirmedKind {
		return BackupRetentionReceiptSignatureDomain
	}
	return BackupCustodyReceiptSignatureDomain
}

func backupCustodyReceiptReferenceDomain(kind string) string {
	if kind == BackupRetentionConfirmedKind {
		return BackupRetentionReceiptReferenceDomain
	}
	return BackupCustodyReceiptReferenceDomain
}

func decodeCanonicalBackupCustody(input []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	encoded, err := json.Marshal(target)
	if err != nil || !bytes.Equal(encoded, input) {
		return ErrInvalid
	}
	return nil
}

func validBase64URLDigest(value string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == sha256.Size &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}

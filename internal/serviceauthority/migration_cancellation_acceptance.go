package serviceauthority

import (
	"encoding/json"

	"github.com/google/uuid"
)

const migrationCancellationAcceptanceSignatureDomain = "Facets Device Sync migration cancellation acceptance v1\x00"

// MigrationCancellationAcceptancePayload is deployment-signed local evidence
// that one exact Facets-authorized cancellation was fully validated while
// live. It is an operational restart journal, never a replacement for Facets
// authority or for the complete cancellation evidence it identifies.
type MigrationCancellationAcceptancePayload struct {
	AcceptedAtMilliseconds     int64     `json:"acceptedAtMilliseconds"`
	CancellationEvidenceDigest string    `json:"cancellationEvidenceDigest"`
	LocalDeploymentID          uuid.UUID `json:"localDeploymentID"`
	MigrationID                uuid.UUID `json:"migrationID"`
	Scope                      Scope     `json:"scope"`
	Version                    int       `json:"version"`
}

func (payload MigrationCancellationAcceptancePayload) Validate() error {
	if payload.Version != SchemaVersion || payload.AcceptedAtMilliseconds < 0 ||
		payload.LocalDeploymentID == uuid.Nil || payload.MigrationID == uuid.Nil ||
		payload.Scope.Kind != ScopeDeviceSync || payload.Scope.Validate() != nil ||
		!validDigest(payload.CancellationEvidenceDigest) {
		return ErrInvalid
	}
	return nil
}

type MigrationCancellationAcceptance struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

func (signer *DeploymentSigner) SignMigrationCancellationAcceptance(
	payload MigrationCancellationAcceptancePayload,
) (MigrationCancellationAcceptance, error) {
	if signer == nil || payload.Validate() != nil ||
		payload.LocalDeploymentID != signer.DeploymentID() {
		return MigrationCancellationAcceptance{}, ErrInvalid
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return MigrationCancellationAcceptance{}, err
	}
	signature, err := signer.signRecord(
		migrationCancellationAcceptanceSignatureDomain,
		encoded,
	)
	if err != nil {
		return MigrationCancellationAcceptance{}, err
	}
	return MigrationCancellationAcceptance{Payload: encoded, Signature: signature}, nil
}

func (acceptance MigrationCancellationAcceptance) VerifiedPayload() (
	MigrationCancellationAcceptancePayload,
	error,
) {
	var payload MigrationCancellationAcceptancePayload
	if verifyCanonicalRecord(
		acceptance.Payload,
		acceptance.Signature,
		migrationCancellationAcceptanceSignatureDomain,
		&payload,
	) != nil || payload.Validate() != nil ||
		acceptance.Signature.SignerID != payload.LocalDeploymentID {
		return MigrationCancellationAcceptancePayload{}, ErrInvalid
	}
	return payload, nil
}

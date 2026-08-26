package serviceauthority

import (
	"encoding/json"

	"github.com/google/uuid"
)

const migrationActivationAcceptanceSignatureDomain = "Facets Device Sync migration activation acceptance v1\x00"

// MigrationActivationAcceptancePayload is deployment-signed local evidence
// that one exact Facets-authorized activation was fully validated while live.
// It is an operational restart journal, never a substitute for Facets
// authority or for the complete activation evidence it identifies.
type MigrationActivationAcceptancePayload struct {
	AcceptedAtMilliseconds   int64     `json:"acceptedAtMilliseconds"`
	ActivationEvidenceDigest string    `json:"activationEvidenceDigest"`
	LocalDeploymentID        uuid.UUID `json:"localDeploymentID"`
	MigrationID              uuid.UUID `json:"migrationID"`
	Scope                    Scope     `json:"scope"`
	SnapshotReferenceDigest  string    `json:"snapshotReferenceDigest"`
	Version                  int       `json:"version"`
}

func (payload MigrationActivationAcceptancePayload) Validate() error {
	if payload.Version != SchemaVersion || payload.AcceptedAtMilliseconds < 0 ||
		payload.LocalDeploymentID == uuid.Nil || payload.MigrationID == uuid.Nil ||
		payload.Scope.Kind != ScopeDeviceSync || payload.Scope.Validate() != nil ||
		!validDigest(payload.ActivationEvidenceDigest) ||
		!validDigest(payload.SnapshotReferenceDigest) {
		return ErrInvalid
	}
	return nil
}

type MigrationActivationAcceptance struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

func (signer *DeploymentSigner) SignMigrationActivationAcceptance(
	payload MigrationActivationAcceptancePayload,
) (MigrationActivationAcceptance, error) {
	if signer == nil || payload.Validate() != nil ||
		payload.LocalDeploymentID != signer.DeploymentID() {
		return MigrationActivationAcceptance{}, ErrInvalid
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return MigrationActivationAcceptance{}, err
	}
	signature, err := signer.signRecord(
		migrationActivationAcceptanceSignatureDomain,
		encoded,
	)
	if err != nil {
		return MigrationActivationAcceptance{}, err
	}
	return MigrationActivationAcceptance{Payload: encoded, Signature: signature}, nil
}

func (acceptance MigrationActivationAcceptance) VerifiedPayload() (
	MigrationActivationAcceptancePayload,
	error,
) {
	var payload MigrationActivationAcceptancePayload
	if verifyCanonicalRecord(
		acceptance.Payload,
		acceptance.Signature,
		migrationActivationAcceptanceSignatureDomain,
		&payload,
	) != nil || payload.Validate() != nil ||
		acceptance.Signature.SignerID != payload.LocalDeploymentID {
		return MigrationActivationAcceptancePayload{}, ErrInvalid
	}
	return payload, nil
}

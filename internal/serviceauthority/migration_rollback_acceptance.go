package serviceauthority

import (
	"encoding/json"

	"github.com/google/uuid"
)

const migrationRollbackAcceptanceSignatureDomain = "Facets Device Sync migration rollback acceptance v1\x00"

// MigrationRollbackAcceptancePayload is deployment-signed restart evidence
// that one exact Facets-authorized rollback was accepted while live. It never
// substitutes for the authority-signed rollback Manifest or its prerequisites.
type MigrationRollbackAcceptancePayload struct {
	AcceptedAtMilliseconds int64     `json:"acceptedAtMilliseconds"`
	LocalDeploymentID      uuid.UUID `json:"localDeploymentID"`
	MigrationID            uuid.UUID `json:"migrationID"`
	RollbackEvidenceDigest string    `json:"rollbackEvidenceDigest"`
	Scope                  Scope     `json:"scope"`
	Version                int       `json:"version"`
}

func (payload MigrationRollbackAcceptancePayload) Validate() error {
	if payload.Version != SchemaVersion || payload.AcceptedAtMilliseconds < 0 ||
		payload.LocalDeploymentID == uuid.Nil || payload.MigrationID == uuid.Nil ||
		payload.Scope.Kind != ScopeDeviceSync || payload.Scope.Validate() != nil ||
		!validDigest(payload.RollbackEvidenceDigest) {
		return ErrInvalid
	}
	return nil
}

type MigrationRollbackAcceptance struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

func (signer *DeploymentSigner) SignMigrationRollbackAcceptance(
	payload MigrationRollbackAcceptancePayload,
) (MigrationRollbackAcceptance, error) {
	if signer == nil || payload.Validate() != nil ||
		payload.LocalDeploymentID != signer.DeploymentID() {
		return MigrationRollbackAcceptance{}, ErrInvalid
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return MigrationRollbackAcceptance{}, err
	}
	signature, err := signer.signRecord(
		migrationRollbackAcceptanceSignatureDomain, encoded,
	)
	if err != nil {
		return MigrationRollbackAcceptance{}, err
	}
	return MigrationRollbackAcceptance{Payload: encoded, Signature: signature}, nil
}

func (acceptance MigrationRollbackAcceptance) VerifiedPayload() (
	MigrationRollbackAcceptancePayload,
	error,
) {
	var payload MigrationRollbackAcceptancePayload
	if verifyCanonicalRecord(
		acceptance.Payload,
		acceptance.Signature,
		migrationRollbackAcceptanceSignatureDomain,
		&payload,
	) != nil || payload.Validate() != nil ||
		acceptance.Signature.SignerID != payload.LocalDeploymentID {
		return MigrationRollbackAcceptancePayload{}, ErrInvalid
	}
	return payload, nil
}

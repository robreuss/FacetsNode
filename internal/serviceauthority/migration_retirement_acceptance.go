package serviceauthority

import (
	"encoding/json"

	"github.com/google/uuid"
)

const migrationRetirementAcceptanceSignatureDomain = "Facets Device Sync migration retirement acceptance v1\x00"

// MigrationRetirementAcceptancePayload is deployment-signed local evidence
// that one exact Facets-authorized retirement was validated while live. It is
// restart evidence only and cannot replace Facets authority or the complete
// retirement evidence it identifies.
type MigrationRetirementAcceptancePayload struct {
	AcceptedAtMilliseconds   int64     `json:"acceptedAtMilliseconds"`
	LocalDeploymentID        uuid.UUID `json:"localDeploymentID"`
	MigrationID              uuid.UUID `json:"migrationID"`
	RetirementEvidenceDigest string    `json:"retirementEvidenceDigest"`
	Scope                    Scope     `json:"scope"`
	Version                  int       `json:"version"`
}

func (payload MigrationRetirementAcceptancePayload) Validate() error {
	if payload.Version != SchemaVersion || payload.AcceptedAtMilliseconds < 0 ||
		payload.LocalDeploymentID == uuid.Nil || payload.MigrationID == uuid.Nil ||
		payload.Scope.Kind != ScopeDeviceSync || payload.Scope.Validate() != nil ||
		!validDigest(payload.RetirementEvidenceDigest) {
		return ErrInvalid
	}
	return nil
}

type MigrationRetirementAcceptance struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

func (signer *DeploymentSigner) SignMigrationRetirementAcceptance(
	payload MigrationRetirementAcceptancePayload,
) (MigrationRetirementAcceptance, error) {
	if signer == nil || payload.Validate() != nil ||
		payload.LocalDeploymentID != signer.DeploymentID() {
		return MigrationRetirementAcceptance{}, ErrInvalid
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return MigrationRetirementAcceptance{}, err
	}
	signature, err := signer.signRecord(
		migrationRetirementAcceptanceSignatureDomain, encoded,
	)
	if err != nil {
		return MigrationRetirementAcceptance{}, err
	}
	return MigrationRetirementAcceptance{Payload: encoded, Signature: signature}, nil
}

func (acceptance MigrationRetirementAcceptance) VerifiedPayload() (
	MigrationRetirementAcceptancePayload,
	error,
) {
	var payload MigrationRetirementAcceptancePayload
	if verifyCanonicalRecord(
		acceptance.Payload, acceptance.Signature,
		migrationRetirementAcceptanceSignatureDomain, &payload,
	) != nil || payload.Validate() != nil ||
		acceptance.Signature.SignerID != payload.LocalDeploymentID {
		return MigrationRetirementAcceptancePayload{}, ErrInvalid
	}
	return payload, nil
}

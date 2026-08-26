package serviceauthority

import (
	"encoding/json"

	"github.com/google/uuid"
)

const (
	migrationRollbackSourceAcceptanceSignatureDomain = "Facets Device Sync rollback source preparation acceptance v1\x00"
	migrationRollbackSourceAcceptanceReferenceDomain = "Facets Device Sync rollback source preparation acceptance reference v1\x00"
	migrationRollbackSourcePreparedSignatureDomain   = "Facets Device Sync rollback source prepared v1\x00"
)

// MigrationRollbackSourceAcceptancePayload is deployment-signed local
// evidence that the active replacement accepted one exact reverse-export
// operation while the activation remained live. It is an operational journal,
// not Facets authority and not a substitute for the activation evidence.
type MigrationRollbackSourceAcceptancePayload struct {
	AcceptedAtMilliseconds   int64     `json:"acceptedAtMilliseconds"`
	ActivationEvidenceDigest string    `json:"activationEvidenceDigest"`
	BlobInventoryArtifactID  uuid.UUID `json:"blobInventoryArtifactID"`
	ExportWriteFenceID       uuid.UUID `json:"exportWriteFenceID"`
	LocalDeploymentID        uuid.UUID `json:"localDeploymentID"`
	MigrationID              uuid.UUID `json:"migrationID"`
	Scope                    Scope     `json:"scope"`
	ServiceStateArtifactID   uuid.UUID `json:"serviceStateArtifactID"`
	SnapshotID               uuid.UUID `json:"snapshotID"`
	Version                  int       `json:"version"`
}

func (payload MigrationRollbackSourceAcceptancePayload) Validate() error {
	if payload.Version != SchemaVersion || payload.AcceptedAtMilliseconds < 0 ||
		payload.LocalDeploymentID == uuid.Nil || payload.MigrationID == uuid.Nil ||
		payload.ExportWriteFenceID == uuid.Nil || payload.SnapshotID == uuid.Nil ||
		payload.ServiceStateArtifactID == uuid.Nil ||
		payload.BlobInventoryArtifactID == uuid.Nil ||
		payload.ServiceStateArtifactID == payload.BlobInventoryArtifactID ||
		payload.Scope.Kind != ScopeDeviceSync || payload.Scope.Validate() != nil ||
		!validDigest(payload.ActivationEvidenceDigest) {
		return ErrInvalid
	}
	identities := map[uuid.UUID]struct{}{}
	for _, identity := range []uuid.UUID{
		payload.ExportWriteFenceID, payload.SnapshotID,
		payload.ServiceStateArtifactID, payload.BlobInventoryArtifactID,
	} {
		if _, duplicate := identities[identity]; duplicate {
			return ErrInvalid
		}
		identities[identity] = struct{}{}
	}
	return nil
}

type MigrationRollbackSourceAcceptance struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

func (acceptance MigrationRollbackSourceAcceptance) ReferenceDigest() (string, error) {
	if _, err := acceptance.VerifiedPayload(); err != nil {
		return "", err
	}
	return migrationEvidenceDigest(
		migrationRollbackSourceAcceptanceReferenceDomain, acceptance,
	)
}

func (signer *DeploymentSigner) SignMigrationRollbackSourceAcceptance(
	payload MigrationRollbackSourceAcceptancePayload,
) (MigrationRollbackSourceAcceptance, error) {
	if signer == nil || payload.Validate() != nil ||
		payload.LocalDeploymentID != signer.DeploymentID() {
		return MigrationRollbackSourceAcceptance{}, ErrInvalid
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return MigrationRollbackSourceAcceptance{}, err
	}
	signature, err := signer.signRecord(
		migrationRollbackSourceAcceptanceSignatureDomain, encoded,
	)
	if err != nil {
		return MigrationRollbackSourceAcceptance{}, err
	}
	return MigrationRollbackSourceAcceptance{
		Payload: encoded, Signature: signature,
	}, nil
}

func (acceptance MigrationRollbackSourceAcceptance) VerifiedPayload() (
	MigrationRollbackSourceAcceptancePayload,
	error,
) {
	var payload MigrationRollbackSourceAcceptancePayload
	if verifyCanonicalRecord(
		acceptance.Payload,
		acceptance.Signature,
		migrationRollbackSourceAcceptanceSignatureDomain,
		&payload,
	) != nil || payload.Validate() != nil ||
		acceptance.Signature.SignerID != payload.LocalDeploymentID {
		return MigrationRollbackSourceAcceptancePayload{}, ErrInvalid
	}
	return payload, nil
}

// MigrationRollbackSourcePreparedPayload is deployment-signed local evidence
// that the exact accepted reverse-export operation reached signed artifact
// custody. It does not make the transfer current or authorize rollback.
type MigrationRollbackSourcePreparedPayload struct {
	AcceptanceReferenceDigest string    `json:"acceptanceReferenceDigest"`
	LocalDeploymentID         uuid.UUID `json:"localDeploymentID"`
	MigrationID               uuid.UUID `json:"migrationID"`
	Scope                     Scope     `json:"scope"`
	SnapshotID                uuid.UUID `json:"snapshotID"`
	SnapshotReferenceDigest   string    `json:"snapshotReferenceDigest"`
	StateCommitmentDigest     string    `json:"stateCommitmentDigest"`
	Version                   int       `json:"version"`
}

func (payload MigrationRollbackSourcePreparedPayload) Validate() error {
	if payload.Version != SchemaVersion || payload.LocalDeploymentID == uuid.Nil ||
		payload.MigrationID == uuid.Nil || payload.SnapshotID == uuid.Nil ||
		payload.Scope.Kind != ScopeDeviceSync || payload.Scope.Validate() != nil ||
		!validDigest(payload.AcceptanceReferenceDigest) ||
		!validDigest(payload.SnapshotReferenceDigest) ||
		!validDigest(payload.StateCommitmentDigest) {
		return ErrInvalid
	}
	return nil
}

type MigrationRollbackSourcePrepared struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

func (signer *DeploymentSigner) SignMigrationRollbackSourcePrepared(
	payload MigrationRollbackSourcePreparedPayload,
) (MigrationRollbackSourcePrepared, error) {
	if signer == nil || payload.Validate() != nil ||
		payload.LocalDeploymentID != signer.DeploymentID() {
		return MigrationRollbackSourcePrepared{}, ErrInvalid
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return MigrationRollbackSourcePrepared{}, err
	}
	signature, err := signer.signRecord(
		migrationRollbackSourcePreparedSignatureDomain, encoded,
	)
	if err != nil {
		return MigrationRollbackSourcePrepared{}, err
	}
	return MigrationRollbackSourcePrepared{
		Payload: encoded, Signature: signature,
	}, nil
}

func (prepared MigrationRollbackSourcePrepared) VerifiedPayload() (
	MigrationRollbackSourcePreparedPayload,
	error,
) {
	var payload MigrationRollbackSourcePreparedPayload
	if verifyCanonicalRecord(
		prepared.Payload,
		prepared.Signature,
		migrationRollbackSourcePreparedSignatureDomain,
		&payload,
	) != nil || payload.Validate() != nil ||
		prepared.Signature.SignerID != payload.LocalDeploymentID {
		return MigrationRollbackSourcePreparedPayload{}, ErrInvalid
	}
	return payload, nil
}

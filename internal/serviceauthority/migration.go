package serviceauthority

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

const (
	TransitionInitialActivation     = "initial_activation"
	TransitionRouteRotation         = "route_rotation"
	TransitionPolicyUpdate          = "policy_update"
	TransitionMigrationPreparation  = "migration_preparation"
	TransitionMigrationCancellation = "migration_cancellation"
	TransitionMigrationActivation   = "migration_activation"
	TransitionMigrationRetirement   = "migration_retirement"
	TransitionMigrationRollback     = "migration_rollback"
	TransitionRecovery              = "recovery"

	MaximumMigrationTargetOfferLifetime = 7 * 24 * time.Hour
	MaximumMigrationSnapshotLifetime    = 24 * time.Hour
	MaximumMigrationReadinessLifetime   = time.Hour
	MaximumMigrationCustodyPlaintext    = 64 * 1024
	maximumMigrationEvidenceByteCount   = 8 * 1024 * 1024

	migrationTargetOfferSignatureDomain     = "Facets service migration target offer v1\x00"
	migrationTargetOfferReferenceDomain     = "Facets service migration target offer reference v1\x00"
	migrationCustodyEnvelopeReferenceDomain = "Facets service migration custody envelope reference v1\x00"
	migrationCustodyKeyDomain               = "Facets service migration custody key v1\x00"
	migrationSnapshotSignatureDomain        = "Facets service migration snapshot v1\x00"
	migrationSnapshotReferenceDomain        = "Facets service migration snapshot reference v1\x00"
	migrationReadinessSignatureDomain       = "Facets service migration readiness v1\x00"
)

type MigrationAuthority struct {
	MigrationID                uuid.UUID `json:"migrationID"`
	RollbackUntilMilliseconds  *int64    `json:"rollbackUntilMilliseconds,omitempty"`
	SourceDeploymentID         uuid.UUID `json:"sourceDeploymentID"`
	TargetDeploymentID         uuid.UUID `json:"targetDeploymentID"`
	TargetMigrationOfferDigest string    `json:"targetMigrationOfferDigest"`
	Version                    int       `json:"version"`
}

func (migration MigrationAuthority) Validate() error {
	if migration.Version != SchemaVersion || migration.MigrationID == uuid.Nil ||
		migration.SourceDeploymentID == uuid.Nil || migration.TargetDeploymentID == uuid.Nil ||
		migration.SourceDeploymentID == migration.TargetDeploymentID ||
		!validDigest(migration.TargetMigrationOfferDigest) ||
		(migration.RollbackUntilMilliseconds != nil && *migration.RollbackUntilMilliseconds <= 0) {
		return ErrInvalid
	}
	return nil
}

func (anchor TrustAnchor) Validate() error {
	publicKey, err := canonicalP256PublicKey(anchor.PublicSigningKeyX963)
	if err != nil || anchor.Version != SchemaVersion || anchor.Scope.Validate() != nil ||
		anchor.SignerID == uuid.Nil ||
		hex.EncodeToString(sha256Bytes(publicKey)) != anchor.SigningKeyFingerprint {
		return ErrInvalid
	}
	return nil
}

func (payload ManifestPayload) Validate(nowMilliseconds *int64) error {
	if payload.Version != SchemaVersion || payload.Scope.Validate() != nil || payload.Revision == 0 ||
		payload.PreparedDeployments == nil ||
		payload.IssuedAtMilliseconds < 0 ||
		payload.ValidFromMilliseconds < payload.IssuedAtMilliseconds ||
		(payload.ValidUntilMilliseconds != nil && *payload.ValidUntilMilliseconds <= payload.ValidFromMilliseconds) ||
		payload.ActiveDeployment.Validate() != nil ||
		payload.TransportPolicy.Validate(payload.ActiveDeployment) != nil {
		return ErrInvalid
	}
	switch payload.Transition {
	case TransitionInitialActivation, TransitionRouteRotation, TransitionPolicyUpdate,
		TransitionMigrationPreparation, TransitionMigrationCancellation, TransitionMigrationActivation,
		TransitionMigrationRetirement, TransitionMigrationRollback, TransitionRecovery:
	default:
		return ErrInvalid
	}
	if payload.Revision == 1 {
		if payload.Transition != TransitionInitialActivation || payload.PredecessorManifestDigest != nil {
			return ErrInvalid
		}
	} else if payload.Transition == TransitionInitialActivation ||
		payload.PredecessorManifestDigest == nil || !validDigest(*payload.PredecessorManifestDigest) {
		return ErrInvalid
	}
	seen := make(map[uuid.UUID]struct{}, len(payload.PreparedDeployments))
	for index, deployment := range payload.PreparedDeployments {
		if deployment.Validate() != nil || deployment.DeploymentID == payload.ActiveDeployment.DeploymentID {
			return ErrInvalid
		}
		if _, exists := seen[deployment.DeploymentID]; exists {
			return ErrInvalid
		}
		seen[deployment.DeploymentID] = struct{}{}
		if index > 0 && !uuidLess(payload.PreparedDeployments[index-1].DeploymentID, deployment.DeploymentID) {
			return ErrInvalid
		}
	}
	migrationTransition := payload.Transition == TransitionMigrationPreparation ||
		payload.Transition == TransitionMigrationCancellation ||
		payload.Transition == TransitionMigrationActivation ||
		payload.Transition == TransitionMigrationRetirement ||
		payload.Transition == TransitionMigrationRollback
	if migrationTransition != (payload.Migration != nil) {
		return ErrInvalid
	}
	if payload.Migration == nil {
		if len(payload.PreparedDeployments) != 0 {
			return ErrInvalid
		}
	} else {
		migration := *payload.Migration
		if migration.Validate() != nil ||
			(payload.ActiveDeployment.DeploymentID != migration.SourceDeploymentID &&
				payload.ActiveDeployment.DeploymentID != migration.TargetDeploymentID) {
			return ErrInvalid
		}
		for _, deployment := range payload.PreparedDeployments {
			if deployment.DeploymentID != migration.SourceDeploymentID &&
				deployment.DeploymentID != migration.TargetDeploymentID {
				return ErrInvalid
			}
		}
		if payload.Transition != TransitionMigrationCancellation &&
			payload.Transition != TransitionMigrationRetirement &&
			migration.RollbackUntilMilliseconds != nil &&
			*migration.RollbackUntilMilliseconds <= payload.ValidFromMilliseconds {
			return ErrInvalid
		}
		if payload.Transition == TransitionMigrationActivation &&
			migration.RollbackUntilMilliseconds != nil &&
			payload.ValidUntilMilliseconds != nil &&
			*payload.ValidUntilMilliseconds < *migration.RollbackUntilMilliseconds {
			return ErrInvalid
		}
		if payload.Transition == TransitionMigrationRetirement &&
			migration.RollbackUntilMilliseconds != nil &&
			payload.ValidFromMilliseconds < *migration.RollbackUntilMilliseconds {
			return ErrInvalid
		}
		if payload.Transition == TransitionMigrationRollback &&
			(migration.RollbackUntilMilliseconds == nil || payload.ValidUntilMilliseconds == nil ||
				*payload.ValidUntilMilliseconds != *migration.RollbackUntilMilliseconds) {
			return ErrInvalid
		}
	}
	if nowMilliseconds != nil && (*nowMilliseconds < payload.ValidFromMilliseconds ||
		(payload.ValidUntilMilliseconds != nil && *nowMilliseconds >= *payload.ValidUntilMilliseconds)) {
		return ErrInvalid
	}
	return nil
}

func (manifest Manifest) VerifiedPayload() (ManifestPayload, error) {
	var payload ManifestPayload
	if verifyCanonicalRecord(manifest.Payload, manifest.Signature,
		"Facets service authority manifest v1\x00", &payload) != nil || payload.Validate(nil) != nil {
		return ManifestPayload{}, ErrInvalid
	}
	return payload, nil
}

func (manifest Manifest) Authorize(anchor TrustAnchor, nowMilliseconds int64) (ManifestPayload, error) {
	payload, err := manifest.VerifiedPayload()
	if err != nil || anchor.Validate() != nil || payload.Scope != anchor.Scope ||
		manifest.Signature.SignerID != anchor.SignerID ||
		manifest.Signature.PublicSigningKeyX963 != anchor.PublicSigningKeyX963 ||
		manifest.Signature.SigningKeyFingerprint != anchor.SigningKeyFingerprint ||
		payload.Validate(&nowMilliseconds) != nil {
		return ManifestPayload{}, ErrInvalid
	}
	return payload, nil
}

func (candidate Manifest) ValidateSuccessor(predecessor Manifest) (ManifestPayload, error) {
	next, err := candidate.VerifiedPayload()
	if err != nil {
		return ManifestPayload{}, err
	}
	current, err := predecessor.VerifiedPayload()
	if err != nil {
		return ManifestPayload{}, err
	}
	digest, err := predecessor.ReferenceDigest()
	if err != nil || next.Scope != current.Scope ||
		candidate.Signature.SignerID != predecessor.Signature.SignerID ||
		candidate.Signature.PublicSigningKeyX963 != predecessor.Signature.PublicSigningKeyX963 ||
		candidate.Signature.SigningKeyFingerprint != predecessor.Signature.SigningKeyFingerprint ||
		next.Revision != current.Revision+1 || next.PredecessorManifestDigest == nil ||
		*next.PredecessorManifestDigest != digest ||
		next.IssuedAtMilliseconds < current.IssuedAtMilliseconds ||
		validateManifestTransition(current, next) != nil {
		return ManifestPayload{}, ErrInvalid
	}
	return next, nil
}

func validateManifestTransition(current, next ManifestPayload) error {
	switch next.Transition {
	case TransitionInitialActivation, TransitionRecovery:
		return ErrInvalid
	case TransitionPolicyUpdate:
		if next.Migration != nil || len(next.PreparedDeployments) != 0 ||
			len(current.PreparedDeployments) != 0 ||
			(current.Migration != nil && current.Transition != TransitionMigrationCancellation &&
				current.Transition != TransitionMigrationRetirement &&
				current.Transition != TransitionMigrationRollback) ||
			!deploymentEqual(next.ActiveDeployment, current.ActiveDeployment) {
			return ErrInvalid
		}
	case TransitionRouteRotation:
		if next.Migration != nil || len(next.PreparedDeployments) != 0 ||
			len(current.PreparedDeployments) != 0 ||
			(current.Migration != nil && current.Transition != TransitionMigrationCancellation &&
				current.Transition != TransitionMigrationRetirement &&
				current.Transition != TransitionMigrationRollback) ||
			next.ActiveDeployment.DeploymentID != current.ActiveDeployment.DeploymentID ||
			next.ActiveDeployment.PublicSigningKeyX963 != current.ActiveDeployment.PublicSigningKeyX963 ||
			next.ActiveDeployment.SigningKeyFingerprint != current.ActiveDeployment.SigningKeyFingerprint ||
			next.ActiveDeployment.CreatedAtMilliseconds != current.ActiveDeployment.CreatedAtMilliseconds {
			return ErrInvalid
		}
	case TransitionMigrationPreparation:
		if current.Transition == TransitionMigrationPreparation || current.Transition == TransitionMigrationActivation ||
			len(current.PreparedDeployments) != 0 || next.Migration == nil ||
			!deploymentEqual(next.ActiveDeployment, current.ActiveDeployment) ||
			!transportPolicyEqual(next.TransportPolicy, current.TransportPolicy) ||
			next.Migration.SourceDeploymentID != current.ActiveDeployment.DeploymentID ||
			len(next.PreparedDeployments) != 1 ||
			next.PreparedDeployments[0].DeploymentID != next.Migration.TargetDeploymentID {
			return ErrInvalid
		}
	case TransitionMigrationCancellation:
		if current.Transition != TransitionMigrationPreparation || current.Migration == nil ||
			next.Migration == nil || !migrationEqual(next.Migration, current.Migration) ||
			!deploymentEqual(next.ActiveDeployment, current.ActiveDeployment) ||
			!transportPolicyEqual(next.TransportPolicy, current.TransportPolicy) ||
			len(next.PreparedDeployments) != 0 {
			return ErrInvalid
		}
	case TransitionMigrationActivation:
		if current.Transition != TransitionMigrationPreparation || next.Migration == nil ||
			!migrationEqual(next.Migration, current.Migration) || len(current.PreparedDeployments) != 1 ||
			!deploymentEqual(next.ActiveDeployment, current.PreparedDeployments[0]) ||
			next.ActiveDeployment.DeploymentID != next.Migration.TargetDeploymentID {
			return ErrInvalid
		}
		if next.Migration.RollbackUntilMilliseconds == nil {
			if len(next.PreparedDeployments) != 0 {
				return ErrInvalid
			}
		} else if len(next.PreparedDeployments) != 1 ||
			!deploymentEqual(next.PreparedDeployments[0], current.ActiveDeployment) {
			return ErrInvalid
		}
		if next.Migration.RollbackUntilMilliseconds != nil &&
			next.ValidUntilMilliseconds != nil &&
			*next.ValidUntilMilliseconds < *next.Migration.RollbackUntilMilliseconds {
			return ErrInvalid
		}
	case TransitionMigrationRetirement:
		if current.Transition != TransitionMigrationActivation || next.Migration == nil ||
			!migrationEqual(next.Migration, current.Migration) ||
			!deploymentEqual(next.ActiveDeployment, current.ActiveDeployment) ||
			!transportPolicyEqual(next.TransportPolicy, current.TransportPolicy) ||
			next.ActiveDeployment.DeploymentID != next.Migration.TargetDeploymentID ||
			len(next.PreparedDeployments) != 0 {
			return ErrInvalid
		}
		if next.Migration.RollbackUntilMilliseconds != nil &&
			next.ValidFromMilliseconds < *next.Migration.RollbackUntilMilliseconds {
			return ErrInvalid
		}
	case TransitionMigrationRollback:
		if current.Transition != TransitionMigrationActivation || next.Migration == nil ||
			!migrationEqual(next.Migration, current.Migration) || next.Migration.RollbackUntilMilliseconds == nil ||
			next.ValidFromMilliseconds >= *next.Migration.RollbackUntilMilliseconds ||
			len(current.PreparedDeployments) != 1 ||
			!deploymentEqual(next.ActiveDeployment, current.PreparedDeployments[0]) ||
			next.ActiveDeployment.DeploymentID != next.Migration.SourceDeploymentID ||
			len(next.PreparedDeployments) != 0 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type MigrationTargetOfferPayload struct {
	CustodyAgreementKeyFingerprint string          `json:"custodyAgreementKeyFingerprint"`
	CustodyAgreementPublicKeyX963  string          `json:"custodyAgreementPublicKeyX963"`
	DeploymentOffer                DeploymentOffer `json:"deploymentOffer"`
	ExpiresAtMilliseconds          int64           `json:"expiresAtMilliseconds"`
	IssuedAtMilliseconds           int64           `json:"issuedAtMilliseconds"`
	MigrationID                    uuid.UUID       `json:"migrationID"`
	Scope                          Scope           `json:"scope"`
	SourceManifestDigest           string          `json:"sourceManifestDigest"`
	Version                        int             `json:"version"`
}

func (payload MigrationTargetOfferPayload) Validate(nowMilliseconds *int64) error {
	offered, err := payload.DeploymentOffer.VerifiedPayload(nil)
	custodyKey, custodyErr := canonicalP256AgreementPublicKey(payload.CustodyAgreementPublicKeyX963)
	if err != nil || custodyErr != nil || payload.Version != SchemaVersion || payload.MigrationID == uuid.Nil ||
		payload.Scope.Validate() != nil || !validDigest(payload.SourceManifestDigest) ||
		hex.EncodeToString(sha256Bytes(custodyKey)) != payload.CustodyAgreementKeyFingerprint ||
		payload.CustodyAgreementKeyFingerprint == offered.Deployment.SigningKeyFingerprint ||
		payload.IssuedAtMilliseconds < offered.IssuedAtMilliseconds ||
		payload.IssuedAtMilliseconds >= offered.ExpiresAtMilliseconds ||
		payload.ExpiresAtMilliseconds <= payload.IssuedAtMilliseconds ||
		payload.ExpiresAtMilliseconds > offered.ExpiresAtMilliseconds ||
		payload.ExpiresAtMilliseconds-payload.IssuedAtMilliseconds > MaximumMigrationTargetOfferLifetime.Milliseconds() {
		return ErrInvalid
	}
	if nowMilliseconds != nil {
		if *nowMilliseconds < payload.IssuedAtMilliseconds || *nowMilliseconds >= payload.ExpiresAtMilliseconds {
			return ErrInvalid
		}
		if _, err := payload.DeploymentOffer.VerifiedPayload(nowMilliseconds); err != nil {
			return ErrInvalid
		}
	}
	return nil
}

type MigrationTargetOffer struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

func (signer *DeploymentSigner) SignMigrationTargetOffer(
	payload MigrationTargetOfferPayload,
) (MigrationTargetOffer, error) {
	if signer == nil || payload.Validate(nil) != nil {
		return MigrationTargetOffer{}, ErrInvalid
	}
	offered, err := payload.DeploymentOffer.VerifiedPayload(nil)
	if err != nil || offered.Deployment.DeploymentID != signer.DeploymentID() ||
		offered.Deployment.PublicSigningKeyX963 != signer.PublicSigningKeyX963() ||
		offered.Deployment.SigningKeyFingerprint != signer.SigningKeyFingerprint() {
		return MigrationTargetOffer{}, ErrInvalid
	}
	encoded, err := canonicalJSON(payload)
	if err != nil {
		return MigrationTargetOffer{}, ErrInvalid
	}
	signature, err := signer.signRecord(migrationTargetOfferSignatureDomain, encoded)
	if err != nil {
		return MigrationTargetOffer{}, ErrInvalid
	}
	offer := MigrationTargetOffer{Payload: encoded, Signature: signature}
	if _, err := offer.VerifiedPayload(nil); err != nil {
		return MigrationTargetOffer{}, ErrInvalid
	}
	return offer, nil
}

func (offer MigrationTargetOffer) VerifiedPayload(nowMilliseconds *int64) (MigrationTargetOfferPayload, error) {
	var payload MigrationTargetOfferPayload
	if verifyCanonicalRecord(offer.Payload, offer.Signature,
		migrationTargetOfferSignatureDomain, &payload) != nil || payload.Validate(nowMilliseconds) != nil {
		return MigrationTargetOfferPayload{}, ErrInvalid
	}
	offered, err := payload.DeploymentOffer.VerifiedPayload(nil)
	if err != nil || offer.Signature.SignerID != offered.Deployment.DeploymentID ||
		offer.Signature.PublicSigningKeyX963 != offered.Deployment.PublicSigningKeyX963 ||
		offer.Signature.SigningKeyFingerprint != offered.Deployment.SigningKeyFingerprint {
		return MigrationTargetOfferPayload{}, ErrInvalid
	}
	return payload, nil
}

func (offer MigrationTargetOffer) ReferenceDigest() (string, error) {
	if _, err := offer.VerifiedPayload(nil); err != nil {
		return "", err
	}
	return signedReferenceDigest(migrationTargetOfferReferenceDomain, offer.Payload, offer.Signature)
}

type MigrationPreparation struct {
	CurrentManifest     Manifest             `json:"currentManifest"`
	PreparationManifest Manifest             `json:"preparationManifest"`
	TargetOffer         MigrationTargetOffer `json:"targetOffer"`
}

func (preparation MigrationPreparation) Validate(
	anchor TrustAnchor,
	nowMilliseconds int64,
) (MigrationAuthority, MigrationTargetOfferPayload, error) {
	current, err := preparation.CurrentManifest.Authorize(anchor, nowMilliseconds)
	if err != nil {
		return MigrationAuthority{}, MigrationTargetOfferPayload{}, ErrInvalid
	}
	prepared, err := preparation.PreparationManifest.Authorize(anchor, nowMilliseconds)
	if err != nil {
		return MigrationAuthority{}, MigrationTargetOfferPayload{}, ErrInvalid
	}
	if _, err := preparation.PreparationManifest.ValidateSuccessor(preparation.CurrentManifest); err != nil {
		return MigrationAuthority{}, MigrationTargetOfferPayload{}, ErrInvalid
	}
	target, err := preparation.TargetOffer.VerifiedPayload(&nowMilliseconds)
	if err != nil {
		return MigrationAuthority{}, MigrationTargetOfferPayload{}, ErrInvalid
	}
	targetDeployment, err := target.DeploymentOffer.VerifiedPayload(nil)
	currentDigest, currentDigestErr := preparation.CurrentManifest.ReferenceDigest()
	targetDigest, targetDigestErr := preparation.TargetOffer.ReferenceDigest()
	if err != nil || currentDigestErr != nil || targetDigestErr != nil ||
		prepared.Transition != TransitionMigrationPreparation || prepared.Migration == nil ||
		current.Scope != target.Scope || target.SourceManifestDigest != currentDigest ||
		target.MigrationID != prepared.Migration.MigrationID ||
		targetDigest != prepared.Migration.TargetMigrationOfferDigest ||
		(prepared.Migration.RollbackUntilMilliseconds != nil &&
			*prepared.Migration.RollbackUntilMilliseconds > target.ExpiresAtMilliseconds) ||
		len(prepared.PreparedDeployments) != 1 ||
		!deploymentEqual(prepared.PreparedDeployments[0], targetDeployment.Deployment) {
		return MigrationAuthority{}, MigrationTargetOfferPayload{}, ErrInvalid
	}
	return *prepared.Migration, target, nil
}

func (preparation MigrationPreparation) validateHistorically(
	anchor TrustAnchor,
) (MigrationAuthority, MigrationTargetOfferPayload, error) {
	current, currentErr := preparation.CurrentManifest.VerifiedPayload()
	prepared, preparedErr := preparation.PreparationManifest.VerifiedPayload()
	target, targetErr := preparation.TargetOffer.VerifiedPayload(nil)
	deployment, deploymentErr := target.DeploymentOffer.VerifiedPayload(nil)
	if currentErr != nil || preparedErr != nil || targetErr != nil || deploymentErr != nil {
		return MigrationAuthority{}, MigrationTargetOfferPayload{}, ErrInvalid
	}
	validationTime := current.ValidFromMilliseconds
	for _, candidate := range []int64{
		prepared.ValidFromMilliseconds,
		target.IssuedAtMilliseconds,
		deployment.IssuedAtMilliseconds,
	} {
		if candidate > validationTime {
			validationTime = candidate
		}
	}
	return preparation.Validate(anchor, validationTime)
}

// validateForTransfer reconstructs the predecessor link at the interval where
// the complete preparation was valid, but requires the authority-bearing
// preparation manifest and target offer to remain live at transfer time. This
// permits an attended migration to finish after only the superseded
// predecessor manifest expires.
func (preparation MigrationPreparation) validateForTransfer(
	anchor TrustAnchor,
	nowMilliseconds int64,
) (MigrationAuthority, MigrationTargetOfferPayload, error) {
	migration, target, err := preparation.validateHistorically(anchor)
	if err != nil {
		return MigrationAuthority{}, MigrationTargetOfferPayload{}, ErrInvalid
	}
	if _, err := preparation.PreparationManifest.Authorize(anchor, nowMilliseconds); err != nil {
		return MigrationAuthority{}, MigrationTargetOfferPayload{}, ErrInvalid
	}
	if _, err := preparation.TargetOffer.VerifiedPayload(&nowMilliseconds); err != nil {
		return MigrationAuthority{}, MigrationTargetOfferPayload{}, ErrInvalid
	}
	return migration, target, nil
}

// MigrationCancellationEvidence proves that an exact, previously valid
// preparation was cancelled by its immediate authority successor. The target
// offer and preparation need not remain live forever, so the full preparation
// is reconstructed at its historical validity overlap. The cancellation itself
// must be authority-valid at acceptance time, while the registry independently
// requires this exact preparation to be its installed predecessor.
type MigrationCancellationEvidence struct {
	CancellationManifest Manifest             `json:"cancellationManifest"`
	Preparation          MigrationPreparation `json:"preparation"`
}

func (evidence MigrationCancellationEvidence) Validate(
	anchor TrustAnchor,
	nowMilliseconds int64,
) (ManifestPayload, error) {
	preparedHistorical, err := evidence.Preparation.PreparationManifest.VerifiedPayload()
	if err != nil || preparedHistorical.Transition != TransitionMigrationPreparation ||
		preparedHistorical.Migration == nil {
		return ManifestPayload{}, ErrInvalid
	}
	if _, _, err := evidence.Preparation.validateHistorically(anchor); err != nil {
		return ManifestPayload{}, ErrInvalid
	}
	cancelled, err := evidence.CancellationManifest.Authorize(anchor, nowMilliseconds)
	if err != nil {
		return ManifestPayload{}, ErrInvalid
	}
	if _, err := evidence.CancellationManifest.ValidateSuccessor(
		evidence.Preparation.PreparationManifest,
	); err != nil || cancelled.Transition != TransitionMigrationCancellation ||
		!migrationEqual(cancelled.Migration, preparedHistorical.Migration) ||
		!deploymentEqual(cancelled.ActiveDeployment, preparedHistorical.ActiveDeployment) ||
		!transportPolicyEqual(cancelled.TransportPolicy, preparedHistorical.TransportPolicy) ||
		len(cancelled.PreparedDeployments) != 0 {
		return ManifestPayload{}, ErrInvalid
	}
	return cancelled, nil
}

type MigrationArtifactKind string

const (
	ArtifactServiceStateSnapshot MigrationArtifactKind = "service_state_snapshot"
	ArtifactBlobInventory        MigrationArtifactKind = "blob_inventory"
	ArtifactOnionServiceState    MigrationArtifactKind = "onion_service_state"
	ArtifactTLSIdentity          MigrationArtifactKind = "tls_identity"
	ArtifactRouteConfiguration   MigrationArtifactKind = "route_configuration"
)

func (kind MigrationArtifactKind) valid() bool {
	return kind == ArtifactServiceStateSnapshot || kind == ArtifactBlobInventory ||
		kind == ArtifactOnionServiceState || kind == ArtifactTLSIdentity || kind == ArtifactRouteConfiguration
}

func (kind MigrationArtifactKind) permitsCustodyEnvelope() bool {
	return kind == ArtifactOnionServiceState || kind == ArtifactTLSIdentity || kind == ArtifactRouteConfiguration
}

type MigrationArtifactDescriptor struct {
	ArtifactID     uuid.UUID             `json:"artifactID"`
	ByteCount      int64                 `json:"byteCount"`
	Kind           MigrationArtifactKind `json:"kind"`
	TransferDigest string                `json:"transferDigest"`
}

func (artifact MigrationArtifactDescriptor) Validate() error {
	if artifact.ArtifactID == uuid.Nil || artifact.ByteCount < 0 || !artifact.Kind.valid() ||
		!validDigest(artifact.TransferDigest) {
		return ErrInvalid
	}
	return nil
}

type MigrationCustodyMetadata struct {
	ArtifactID              uuid.UUID             `json:"artifactID"`
	Kind                    MigrationArtifactKind `json:"kind"`
	MigrationID             uuid.UUID             `json:"migrationID"`
	PlaintextByteCount      int                   `json:"plaintextByteCount"`
	RecipientKeyFingerprint string                `json:"recipientKeyFingerprint"`
	TargetDeploymentID      uuid.UUID             `json:"targetDeploymentID"`
	Version                 int                   `json:"version"`
}

func (metadata MigrationCustodyMetadata) Validate() error {
	if metadata.Version != SchemaVersion || metadata.ArtifactID == uuid.Nil ||
		metadata.MigrationID == uuid.Nil || metadata.TargetDeploymentID == uuid.Nil ||
		!metadata.Kind.permitsCustodyEnvelope() || !validDigest(metadata.RecipientKeyFingerprint) ||
		metadata.PlaintextByteCount < 0 || metadata.PlaintextByteCount > MaximumMigrationCustodyPlaintext {
		return ErrInvalid
	}
	return nil
}

type MigrationCustodyEnvelope struct {
	EphemeralPublicKeyX963 string                   `json:"ephemeralPublicKeyX963"`
	Metadata               MigrationCustodyMetadata `json:"metadata"`
	SealedPayload          string                   `json:"sealedPayload"`
}

func (envelope MigrationCustodyEnvelope) Validate() error {
	if envelope.Metadata.Validate() != nil {
		return ErrInvalid
	}
	if _, err := canonicalP256AgreementPublicKey(envelope.EphemeralPublicKeyX963); err != nil {
		return ErrInvalid
	}
	sealed, err := canonicalBase64URL(envelope.SealedPayload)
	if err != nil || len(sealed) != envelope.Metadata.PlaintextByteCount+28 {
		return ErrInvalid
	}
	return nil
}

func (envelope MigrationCustodyEnvelope) Open(
	targetPrivateKeyRaw []byte,
	preparation MigrationPreparation,
	snapshot MigrationSnapshot,
	anchor TrustAnchor,
	nowMilliseconds int64,
) ([]byte, error) {
	if envelope.Validate() != nil {
		return nil, ErrInvalid
	}
	migration, target, err := preparation.validateForTransfer(anchor, nowMilliseconds)
	if err != nil {
		return nil, ErrInvalid
	}
	prepared, err := preparation.PreparationManifest.Authorize(anchor, nowMilliseconds)
	if err != nil {
		return nil, ErrInvalid
	}
	offered, err := target.DeploymentOffer.VerifiedPayload(nil)
	offerDigest, digestErr := preparation.TargetOffer.ReferenceDigest()
	snapshotPayload, snapshotErr := snapshot.validateTransfer(
		preparation.PreparationManifest,
		prepared,
		migration,
		prepared.ActiveDeployment,
		offered.Deployment,
		nowMilliseconds,
	)
	envelopeDigest, envelopeDigestErr := envelope.ReferenceDigest()
	canonicalEnvelope, canonicalEnvelopeErr := canonicalJSON(envelope)
	var matchingArtifact *MigrationArtifactDescriptor
	for index := range snapshotPayload.Artifacts {
		artifact := &snapshotPayload.Artifacts[index]
		if artifact.ArtifactID == envelope.Metadata.ArtifactID && artifact.Kind == envelope.Metadata.Kind {
			matchingArtifact = artifact
			break
		}
	}
	privateKey, keyErr := ecdh.P256().NewPrivateKey(targetPrivateKeyRaw)
	if err != nil || digestErr != nil || snapshotErr != nil || envelopeDigestErr != nil ||
		canonicalEnvelopeErr != nil || matchingArtifact == nil || keyErr != nil ||
		matchingArtifact.ByteCount != int64(len(canonicalEnvelope)) ||
		matchingArtifact.TransferDigest != envelopeDigest ||
		migration.MigrationID != envelope.Metadata.MigrationID ||
		migration.TargetDeploymentID != envelope.Metadata.TargetDeploymentID ||
		migration.TargetDeploymentID != offered.Deployment.DeploymentID ||
		migration.TargetMigrationOfferDigest != offerDigest ||
		target.CustodyAgreementPublicKeyX963 != base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()) ||
		target.CustodyAgreementKeyFingerprint != envelope.Metadata.RecipientKeyFingerprint {
		return nil, ErrInvalid
	}
	ephemeralBytes, err := canonicalBase64URL(envelope.EphemeralPublicKeyX963)
	if err != nil {
		return nil, ErrInvalid
	}
	ephemeral, err := ecdh.P256().NewPublicKey(ephemeralBytes)
	if err != nil {
		return nil, ErrInvalid
	}
	shared, err := privateKey.ECDH(ephemeral)
	metadata, metadataErr := canonicalJSON(envelope.Metadata)
	if err != nil || metadataErr != nil {
		return nil, ErrInvalid
	}
	key, err := hkdf.Key(sha256.New, shared, []byte(migrationCustodyKeyDomain), string(metadata), 32)
	if err != nil {
		return nil, ErrInvalid
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalid
	}
	gcm, err := cipher.NewGCM(block)
	sealed, sealedErr := canonicalBase64URL(envelope.SealedPayload)
	if err != nil || sealedErr != nil || len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return nil, ErrInvalid
	}
	plaintext, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], metadata)
	if err != nil || len(plaintext) != envelope.Metadata.PlaintextByteCount {
		return nil, ErrInvalid
	}
	return plaintext, nil
}

func (envelope MigrationCustodyEnvelope) ReferenceDigest() (string, error) {
	if envelope.Validate() != nil {
		return "", ErrInvalid
	}
	encoded, err := canonicalJSON(envelope)
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(append([]byte(migrationCustodyEnvelopeReferenceDomain), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

type MigrationSnapshotPayload struct {
	Artifacts               []MigrationArtifactDescriptor `json:"artifacts"`
	AuthorityManifestDigest string                        `json:"authorityManifestDigest"`
	CapturedAtMilliseconds  int64                         `json:"capturedAtMilliseconds"`
	ExpiresAtMilliseconds   int64                         `json:"expiresAtMilliseconds"`
	ExportWriteFenceID      uuid.UUID                     `json:"exportWriteFenceID"`
	ExportingDeploymentID   uuid.UUID                     `json:"exportingDeploymentID"`
	ImportingDeploymentID   uuid.UUID                     `json:"importingDeploymentID"`
	MigrationID             uuid.UUID                     `json:"migrationID"`
	Scope                   Scope                         `json:"scope"`
	SnapshotID              uuid.UUID                     `json:"snapshotID"`
	StateCommitmentDigest   string                        `json:"stateCommitmentDigest"`
	Version                 int                           `json:"version"`
}

func (payload MigrationSnapshotPayload) Validate(nowMilliseconds *int64) error {
	if payload.Version != SchemaVersion || payload.MigrationID == uuid.Nil || payload.Scope.Validate() != nil ||
		!validDigest(payload.AuthorityManifestDigest) || payload.ExportingDeploymentID == uuid.Nil ||
		payload.ImportingDeploymentID == uuid.Nil || payload.ExportingDeploymentID == payload.ImportingDeploymentID ||
		payload.ExportWriteFenceID == uuid.Nil || payload.SnapshotID == uuid.Nil ||
		!validDigest(payload.StateCommitmentDigest) || len(payload.Artifacts) == 0 ||
		payload.CapturedAtMilliseconds < 0 || payload.ExpiresAtMilliseconds <= payload.CapturedAtMilliseconds ||
		payload.ExpiresAtMilliseconds-payload.CapturedAtMilliseconds > MaximumMigrationSnapshotLifetime.Milliseconds() {
		return ErrInvalid
	}
	seen := make(map[uuid.UUID]struct{}, len(payload.Artifacts))
	seenKinds := make(map[MigrationArtifactKind]struct{}, len(payload.Artifacts))
	serviceStateSnapshots := 0
	for index, artifact := range payload.Artifacts {
		if artifact.Validate() != nil {
			return ErrInvalid
		}
		if _, exists := seen[artifact.ArtifactID]; exists {
			return ErrInvalid
		}
		seen[artifact.ArtifactID] = struct{}{}
		if _, exists := seenKinds[artifact.Kind]; exists {
			return ErrInvalid
		}
		seenKinds[artifact.Kind] = struct{}{}
		if artifact.Kind == ArtifactServiceStateSnapshot {
			serviceStateSnapshots++
		}
		if index > 0 && !uuidLess(payload.Artifacts[index-1].ArtifactID, artifact.ArtifactID) {
			return ErrInvalid
		}
	}
	if serviceStateSnapshots != 1 {
		return ErrInvalid
	}
	if nowMilliseconds != nil && (*nowMilliseconds < payload.CapturedAtMilliseconds ||
		*nowMilliseconds >= payload.ExpiresAtMilliseconds) {
		return ErrInvalid
	}
	return nil
}

type MigrationSnapshot struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

func (snapshot MigrationSnapshot) VerifiedPayload(nowMilliseconds *int64) (MigrationSnapshotPayload, error) {
	var payload MigrationSnapshotPayload
	if verifyCanonicalRecord(snapshot.Payload, snapshot.Signature,
		migrationSnapshotSignatureDomain, &payload) != nil || payload.Validate(nowMilliseconds) != nil ||
		snapshot.Signature.SignerID != payload.ExportingDeploymentID {
		return MigrationSnapshotPayload{}, ErrInvalid
	}
	return payload, nil
}

func (snapshot MigrationSnapshot) ReferenceDigest() (string, error) {
	if _, err := snapshot.VerifiedPayload(nil); err != nil {
		return "", err
	}
	return signedReferenceDigest(migrationSnapshotReferenceDomain, snapshot.Payload, snapshot.Signature)
}

func (snapshot MigrationSnapshot) validateTransfer(
	authorityManifest Manifest,
	authorityPayload ManifestPayload,
	migration MigrationAuthority,
	exporting, importing DeploymentDescriptor,
	nowMilliseconds int64,
) (MigrationSnapshotPayload, error) {
	payload, err := snapshot.VerifiedPayload(&nowMilliseconds)
	manifestDigest, digestErr := authorityManifest.ReferenceDigest()
	if err != nil || digestErr != nil || payload.MigrationID != migration.MigrationID ||
		payload.Scope != authorityPayload.Scope || payload.AuthorityManifestDigest != manifestDigest ||
		payload.CapturedAtMilliseconds < authorityPayload.ValidFromMilliseconds ||
		payload.ExportingDeploymentID != exporting.DeploymentID ||
		payload.ImportingDeploymentID != importing.DeploymentID ||
		snapshot.Signature.SignerID != exporting.DeploymentID ||
		snapshot.Signature.PublicSigningKeyX963 != exporting.PublicSigningKeyX963 ||
		snapshot.Signature.SigningKeyFingerprint != exporting.SigningKeyFingerprint {
		return MigrationSnapshotPayload{}, ErrInvalid
	}
	return payload, nil
}

type MigrationReadinessPayload struct {
	AppliedStateCommitmentDigest string    `json:"appliedStateCommitmentDigest"`
	AuthorityManifestDigest      string    `json:"authorityManifestDigest"`
	ExpiresAtMilliseconds        int64     `json:"expiresAtMilliseconds"`
	ImportingDeploymentID        uuid.UUID `json:"importingDeploymentID"`
	MigrationID                  uuid.UUID `json:"migrationID"`
	ReadyAtMilliseconds          int64     `json:"readyAtMilliseconds"`
	Scope                        Scope     `json:"scope"`
	SnapshotReferenceDigest      string    `json:"snapshotReferenceDigest"`
	Version                      int       `json:"version"`
}

func (payload MigrationReadinessPayload) Validate(nowMilliseconds *int64) error {
	if payload.Version != SchemaVersion || payload.MigrationID == uuid.Nil || payload.Scope.Validate() != nil ||
		!validDigest(payload.AuthorityManifestDigest) || payload.ImportingDeploymentID == uuid.Nil ||
		!validDigest(payload.SnapshotReferenceDigest) || !validDigest(payload.AppliedStateCommitmentDigest) ||
		payload.ReadyAtMilliseconds < 0 || payload.ExpiresAtMilliseconds <= payload.ReadyAtMilliseconds ||
		payload.ExpiresAtMilliseconds-payload.ReadyAtMilliseconds > MaximumMigrationReadinessLifetime.Milliseconds() {
		return ErrInvalid
	}
	if nowMilliseconds != nil && (*nowMilliseconds < payload.ReadyAtMilliseconds ||
		*nowMilliseconds >= payload.ExpiresAtMilliseconds) {
		return ErrInvalid
	}
	return nil
}

type MigrationReadiness struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

func (signer *DeploymentSigner) SignMigrationReadiness(
	payload MigrationReadinessPayload,
) (MigrationReadiness, error) {
	if signer == nil || payload.Validate(nil) != nil ||
		payload.ImportingDeploymentID != signer.DeploymentID() {
		return MigrationReadiness{}, ErrInvalid
	}
	encoded, err := canonicalJSON(payload)
	if err != nil {
		return MigrationReadiness{}, ErrInvalid
	}
	signature, err := signer.signRecord(migrationReadinessSignatureDomain, encoded)
	if err != nil {
		return MigrationReadiness{}, ErrInvalid
	}
	readiness := MigrationReadiness{Payload: encoded, Signature: signature}
	if _, err := readiness.VerifiedPayload(nil); err != nil {
		return MigrationReadiness{}, ErrInvalid
	}
	return readiness, nil
}

func (readiness MigrationReadiness) VerifiedPayload(nowMilliseconds *int64) (MigrationReadinessPayload, error) {
	var payload MigrationReadinessPayload
	if verifyCanonicalRecord(readiness.Payload, readiness.Signature,
		migrationReadinessSignatureDomain, &payload) != nil || payload.Validate(nowMilliseconds) != nil ||
		readiness.Signature.SignerID != payload.ImportingDeploymentID {
		return MigrationReadinessPayload{}, ErrInvalid
	}
	return payload, nil
}

func (readiness MigrationReadiness) validateTransfer(
	snapshot MigrationSnapshot,
	snapshotPayload MigrationSnapshotPayload,
	migration MigrationAuthority,
	importing DeploymentDescriptor,
	nowMilliseconds int64,
) (MigrationReadinessPayload, error) {
	payload, err := readiness.VerifiedPayload(&nowMilliseconds)
	snapshotDigest, digestErr := snapshot.ReferenceDigest()
	if err != nil || digestErr != nil || payload.MigrationID != migration.MigrationID ||
		payload.Scope != snapshotPayload.Scope ||
		payload.AuthorityManifestDigest != snapshotPayload.AuthorityManifestDigest ||
		payload.ImportingDeploymentID != importing.DeploymentID ||
		payload.SnapshotReferenceDigest != snapshotDigest ||
		payload.AppliedStateCommitmentDigest != snapshotPayload.StateCommitmentDigest ||
		readiness.Signature.SignerID != importing.DeploymentID ||
		readiness.Signature.PublicSigningKeyX963 != importing.PublicSigningKeyX963 ||
		readiness.Signature.SigningKeyFingerprint != importing.SigningKeyFingerprint ||
		payload.ReadyAtMilliseconds < snapshotPayload.CapturedAtMilliseconds {
		return MigrationReadinessPayload{}, ErrInvalid
	}
	return payload, nil
}

type MigrationActivationEvidence struct {
	ActivationManifest Manifest             `json:"activationManifest"`
	Preparation        MigrationPreparation `json:"preparation"`
	Readiness          MigrationReadiness   `json:"readiness"`
	Snapshot           MigrationSnapshot    `json:"snapshot"`
}

func (evidence MigrationActivationEvidence) Validate(
	anchor TrustAnchor,
	nowMilliseconds int64,
) (ManifestPayload, error) {
	migration, target, err := evidence.Preparation.validateForTransfer(anchor, nowMilliseconds)
	if err != nil {
		return ManifestPayload{}, ErrInvalid
	}
	prepared, err := evidence.Preparation.PreparationManifest.VerifiedPayload()
	if err != nil {
		return ManifestPayload{}, ErrInvalid
	}
	targetOffer, err := target.DeploymentOffer.VerifiedPayload(nil)
	if err != nil {
		return ManifestPayload{}, ErrInvalid
	}
	snapshot, err := evidence.Snapshot.validateTransfer(
		evidence.Preparation.PreparationManifest, prepared, migration,
		prepared.ActiveDeployment, targetOffer.Deployment, nowMilliseconds,
	)
	if err != nil {
		return ManifestPayload{}, ErrInvalid
	}
	ready, err := evidence.Readiness.validateTransfer(
		evidence.Snapshot, snapshot, migration, targetOffer.Deployment, nowMilliseconds,
	)
	if err != nil {
		return ManifestPayload{}, ErrInvalid
	}
	activated, err := evidence.ActivationManifest.Authorize(anchor, nowMilliseconds)
	if err != nil {
		return ManifestPayload{}, ErrInvalid
	}
	if _, err := evidence.ActivationManifest.ValidateSuccessor(evidence.Preparation.PreparationManifest); err != nil ||
		activated.Transition != TransitionMigrationActivation ||
		!migrationEqual(activated.Migration, &migration) ||
		!deploymentEqual(activated.ActiveDeployment, targetOffer.Deployment) ||
		!transportPolicyEqual(activated.TransportPolicy, targetOffer.TransportPolicy) ||
		activated.IssuedAtMilliseconds < ready.ReadyAtMilliseconds {
		return ManifestPayload{}, ErrInvalid
	}
	return activated, nil
}

type MigrationRollbackEvidence struct {
	ActivationEvidence MigrationActivationEvidence `json:"activationEvidence"`
	RollbackManifest   Manifest                    `json:"rollbackManifest"`
	SourceReadiness    MigrationReadiness          `json:"sourceReadiness"`
	TargetSnapshot     MigrationSnapshot           `json:"targetSnapshot"`
}

func (evidence MigrationRollbackEvidence) Validate(
	anchor TrustAnchor,
	nowMilliseconds int64,
) (ManifestPayload, error) {
	activationPayload, err := evidence.ActivationEvidence.ActivationManifest.VerifiedPayload()
	if err != nil {
		return ManifestPayload{}, ErrInvalid
	}
	if _, err := evidence.ActivationEvidence.Validate(anchor, activationPayload.ValidFromMilliseconds); err != nil {
		return ManifestPayload{}, ErrInvalid
	}
	current, err := evidence.ActivationEvidence.ActivationManifest.Authorize(anchor, nowMilliseconds)
	if err != nil || current.Transition != TransitionMigrationActivation || current.Migration == nil ||
		current.Migration.RollbackUntilMilliseconds == nil ||
		nowMilliseconds >= *current.Migration.RollbackUntilMilliseconds || len(current.PreparedDeployments) != 1 {
		return ManifestPayload{}, ErrInvalid
	}
	source := current.PreparedDeployments[0]
	snapshot, err := evidence.TargetSnapshot.validateTransfer(
		evidence.ActivationEvidence.ActivationManifest, current, *current.Migration,
		current.ActiveDeployment, source, nowMilliseconds,
	)
	if err != nil {
		return ManifestPayload{}, ErrInvalid
	}
	ready, err := evidence.SourceReadiness.validateTransfer(
		evidence.TargetSnapshot, snapshot, *current.Migration, source, nowMilliseconds,
	)
	if err != nil {
		return ManifestPayload{}, ErrInvalid
	}
	rolledBack, err := evidence.RollbackManifest.Authorize(anchor, nowMilliseconds)
	if err != nil {
		return ManifestPayload{}, ErrInvalid
	}
	if _, err := evidence.RollbackManifest.ValidateSuccessor(evidence.ActivationEvidence.ActivationManifest); err != nil {
		return ManifestPayload{}, ErrInvalid
	}
	preparationPayload, err := evidence.ActivationEvidence.Preparation.PreparationManifest.VerifiedPayload()
	if err != nil || rolledBack.Transition != TransitionMigrationRollback ||
		!migrationEqual(rolledBack.Migration, current.Migration) ||
		!deploymentEqual(rolledBack.ActiveDeployment, source) ||
		!transportPolicyEqual(rolledBack.TransportPolicy, preparationPayload.TransportPolicy) ||
		rolledBack.IssuedAtMilliseconds < ready.ReadyAtMilliseconds {
		return ManifestPayload{}, ErrInvalid
	}
	return rolledBack, nil
}

func canonicalP256AgreementPublicKey(value string) ([]byte, error) {
	decoded, err := canonicalBase64URL(value)
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err := ecdh.P256().NewPublicKey(decoded); err != nil {
		return nil, ErrInvalid
	}
	return decoded, nil
}

func canonicalBase64URL(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalid
	}
	return decoded, nil
}

func canonicalJSON(value any) ([]byte, error) {
	return canonicalJSONWithLimit(value, 262_144)
}

func canonicalJSONWithLimit(value any, maximumByteCount int) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil || maximumByteCount <= 0 || len(encoded) > maximumByteCount {
		return nil, ErrInvalid
	}
	return encoded, nil
}

func signedReferenceDigest(domain string, payload []byte, signature Signature) (string, error) {
	encodedSignature, err := canonicalJSON(signature)
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(domain))
	_, _ = digest.Write(payload)
	_, _ = digest.Write(encodedSignature)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func migrationEvidenceDigest(domain string, evidence any) (string, error) {
	encoded, err := canonicalJSONWithLimit(evidence, maximumMigrationEvidenceByteCount)
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(append([]byte(domain), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func migrationEqual(left, right *MigrationAuthority) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	leftJSON, leftErr := canonicalJSON(left)
	rightJSON, rightErr := canonicalJSON(right)
	return leftErr == nil && rightErr == nil &&
		subtle.ConstantTimeCompare(leftJSON, rightJSON) == 1
}

func canonicalEqual(left, right any) bool {
	leftJSON, leftErr := canonicalJSON(left)
	rightJSON, rightErr := canonicalJSON(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func decodeCanonical(input []byte, target any) error {
	if len(input) == 0 || len(input) > 262_144 {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrInvalid
	}
	encoded, err := canonicalJSON(target)
	if err != nil || !bytes.Equal(encoded, input) {
		return ErrInvalid
	}
	return nil
}

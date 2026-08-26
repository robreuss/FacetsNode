package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

// PrepareDeviceSyncMigrationRollbackStandby replaces the retired source's
// stale semantic rows with one exact activation-authorized reverse snapshot.
// It leaves the source non-writable and records immutable reverse-import
// evidence. Blob bytes must already have been copied and verified by the
// coordinator before this method returns readiness-worthy state.
func (s *RelayStore) PrepareDeviceSyncMigrationRollbackStandby(
	ctx context.Context,
	localDeploymentID uuid.UUID,
	activationEvidence serviceauthority.MigrationActivationEvidence,
	targetSnapshot serviceauthority.MigrationSnapshot,
	anchor serviceauthority.TrustAnchor,
	nowMilliseconds int64,
	staged DeviceSyncMigrationStagedArtifacts,
) (DeviceSyncMigrationRollbackImportRecord, error) {
	if ctx == nil || localDeploymentID == uuid.Nil || nowMilliseconds < 0 {
		return DeviceSyncMigrationRollbackImportRecord{}, serviceauthority.ErrInvalid
	}
	validated, err := targetSnapshot.ValidateRollbackTransfer(
		activationEvidence, anchor, nowMilliseconds,
	)
	if err != nil || validated.SourceDeployment.DeploymentID != localDeploymentID ||
		validated.Migration.SourceDeploymentID != localDeploymentID {
		return DeviceSyncMigrationRollbackImportRecord{}, serviceauthority.ErrInvalid
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return DeviceSyncMigrationRollbackImportRecord{}, fmt.Errorf(
			"begin Device Sync rollback import: %w", err,
		)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))
	`, validated.Snapshot.Scope.ScopeID); err != nil {
		return DeviceSyncMigrationRollbackImportRecord{}, fmt.Errorf(
			"lock Device Sync rollback import scope: %w", err,
		)
	}
	current, err := loadDeviceSyncScopeEnforcement(
		ctx, tx, validated.Snapshot.Scope.ScopeID, "FOR UPDATE",
	)
	if err != nil {
		return DeviceSyncMigrationRollbackImportRecord{}, err
	}
	candidate, err := buildDeviceSyncMigrationRollbackImportCandidate(
		current, localDeploymentID, activationEvidence, targetSnapshot,
		validated, nowMilliseconds,
	)
	if err != nil {
		return DeviceSyncMigrationRollbackImportRecord{}, err
	}
	existing, found, err := loadDeviceSyncMigrationRollbackImport(
		ctx, tx, candidate.PrincipalID, candidate.MigrationID,
		candidate.ImportingDeploymentID, "FOR SHARE",
	)
	if err != nil {
		return DeviceSyncMigrationRollbackImportRecord{}, err
	}
	if found {
		if current.State != DeviceSyncScopeRollbackStandby ||
			current.ActiveRollbackImportID == nil ||
			*current.ActiveRollbackImportID != candidate.MigrationID ||
			!sameDeviceSyncMigrationRollbackImportIdentity(existing, candidate) {
			return DeviceSyncMigrationRollbackImportRecord{}, ErrDeviceSyncMigrationImportConflict
		}
		return cloneDeviceSyncMigrationRollbackImportRecord(existing), nil
	}
	activationDigest, err := activationEvidence.ReferenceDigest()
	if err != nil || current.State != DeviceSyncScopeRetired ||
		current.LocalDeploymentID == nil || *current.LocalDeploymentID != localDeploymentID ||
		current.ActiveExportWriteFenceID != nil || current.ActiveMigrationImportID != nil ||
		current.ActiveRollbackImportID != nil ||
		!deviceSyncAuthorityMatchesExactManifest(
			current.Authority, activationEvidence.ActivationManifest, activationDigest,
		) {
		return DeviceSyncMigrationRollbackImportRecord{}, ErrDeviceSyncMigrationImportConflict
	}
	if err := MaterializeValidatedDeviceSyncMigrationRollbackState(
		ctx, deviceSyncStandbyImportTransaction{tx: tx}, validated, staged,
	); err != nil {
		return DeviceSyncMigrationRollbackImportRecord{}, fmt.Errorf(
			"materialize Device Sync rollback standby: %w", err,
		)
	}
	if err := insertDeviceSyncMigrationRollbackImport(ctx, tx, candidate); err != nil {
		return DeviceSyncMigrationRollbackImportRecord{}, err
	}
	result, err := tx.Exec(ctx, `
		UPDATE device_sync_scope_enforcement
		SET state='rollback_standby', active_rollback_import_id=$2,
			updated_at=now()
		WHERE principal_id=$1 AND tenant_id=$1 AND state='retired'
		  AND active_export_write_fence_id IS NULL
		  AND active_migration_import_id IS NULL
		  AND active_rollback_import_id IS NULL
	`, candidate.PrincipalID, candidate.MigrationID)
	if err != nil {
		return DeviceSyncMigrationRollbackImportRecord{}, fmt.Errorf(
			"install Device Sync rollback standby: %w", err,
		)
	}
	if result.RowsAffected() != 1 {
		return DeviceSyncMigrationRollbackImportRecord{}, errors.New(
			"Device Sync rollback standby affected an unexpected row count",
		)
	}
	stored, found, err := loadDeviceSyncMigrationRollbackImport(
		ctx, tx, candidate.PrincipalID, candidate.MigrationID,
		candidate.ImportingDeploymentID, "FOR SHARE",
	)
	if err != nil || !found ||
		!sameDeviceSyncMigrationRollbackImportIdentity(stored, candidate) {
		if err != nil {
			return DeviceSyncMigrationRollbackImportRecord{}, err
		}
		return DeviceSyncMigrationRollbackImportRecord{}, errors.New(
			"persisted Device Sync rollback import differs from authenticated evidence",
		)
	}
	standby, err := loadDeviceSyncScopeEnforcement(
		ctx, tx, candidate.PrincipalID, "FOR SHARE",
	)
	if err != nil || standby.State != DeviceSyncScopeRollbackStandby ||
		standby.ActiveRollbackImportID == nil ||
		*standby.ActiveRollbackImportID != candidate.MigrationID {
		if err != nil {
			return DeviceSyncMigrationRollbackImportRecord{}, err
		}
		return DeviceSyncMigrationRollbackImportRecord{}, errors.New(
			"persisted Device Sync rollback standby is inconsistent",
		)
	}
	if err := tx.Commit(ctx); err != nil {
		return DeviceSyncMigrationRollbackImportRecord{}, fmt.Errorf(
			"commit Device Sync rollback import: %w", err,
		)
	}
	return cloneDeviceSyncMigrationRollbackImportRecord(stored), nil
}

// ApplyDeviceSyncMigrationRollback atomically advances one local database side
// from activation to the exact rollback successor. The reverse-imported source
// becomes writable; the reverse-export-fenced target becomes retired.
func (s *RelayStore) ApplyDeviceSyncMigrationRollback(
	ctx context.Context,
	localDeploymentID uuid.UUID,
	evidence serviceauthority.MigrationRollbackEvidence,
	anchor serviceauthority.TrustAnchor,
	nowMilliseconds int64,
) error {
	if ctx == nil || localDeploymentID == uuid.Nil || nowMilliseconds < 0 {
		return serviceauthority.ErrInvalid
	}
	rollback, err := evidence.RollbackManifest.VerifiedPayload()
	if err != nil || rollback.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		rollback.Transition != serviceauthority.TransitionMigrationRollback ||
		rollback.Migration == nil ||
		(localDeploymentID != rollback.Migration.SourceDeploymentID &&
			localDeploymentID != rollback.Migration.TargetDeploymentID) {
		return serviceauthority.ErrInvalid
	}
	evidenceDigest, err := evidence.ReferenceDigest()
	if err != nil || !validDeviceSyncDigest(evidenceDigest) {
		return serviceauthority.ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin Device Sync migration rollback: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := loadDeviceSyncScopeEnforcement(
		ctx, tx, rollback.Scope.ScopeID, "FOR UPDATE",
	)
	if err != nil {
		return err
	}
	sourceSide := localDeploymentID == rollback.Migration.SourceDeploymentID
	terminalState := DeviceSyncScopeRetired
	if sourceSide {
		terminalState = DeviceSyncScopeWritable
	}
	if current.State == terminalState && current.LocalDeploymentID != nil &&
		*current.LocalDeploymentID == localDeploymentID &&
		deviceSyncAuthorityMatchesExactManifest(
			current.Authority, evidence.RollbackManifest, evidenceDigest,
		) && current.ActiveExportWriteFenceID == nil &&
		current.ActiveMigrationImportID == nil && current.ActiveRollbackImportID == nil {
		return nil
	}
	validatedRollback, err := evidence.ValidateHistoricalCatchUp(anchor, nowMilliseconds)
	if err != nil || validatedRollback.Scope != rollback.Scope ||
		validatedRollback.Revision != rollback.Revision ||
		validatedRollback.ActiveDeployment.DeploymentID !=
			rollback.Migration.SourceDeploymentID {
		return serviceauthority.ErrInvalid
	}
	nextAuthority, err := DeviceSyncScopeAuthorityFromManifest(
		evidence.RollbackManifest, &evidenceDigest, nowMilliseconds,
	)
	if err != nil {
		return err
	}
	activationDigest, err := evidence.ActivationEvidence.ReferenceDigest()
	if err != nil || current.Authority == nil || current.LocalDeploymentID == nil ||
		*current.LocalDeploymentID != localDeploymentID ||
		!deviceSyncAuthorityMatchesExactManifest(
			current.Authority,
			evidence.ActivationEvidence.ActivationManifest,
			activationDigest,
		) {
		return ErrDeviceSyncMigrationImportConflict
	}
	if sourceSide {
		if err := validateDeviceSyncRollbackSource(ctx, tx, current, evidence); err != nil {
			return err
		}
	} else if err := validateDeviceSyncRollbackTarget(ctx, tx, current, evidence); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `
		UPDATE device_sync_scope_enforcement
		SET state=$2, authority_validated_at_milliseconds=$3,
			authority_revision=$4, authority_manifest_digest=$5,
			authority_manifest_record=$6, active_deployment_id=$7,
			transition_evidence_digest=$8,
			active_export_write_fence_id=NULL,
			active_migration_import_id=NULL,
			active_rollback_import_id=NULL, updated_at=now()
		WHERE principal_id=$1 AND tenant_id=$1
	`, rollback.Scope.ScopeID, terminalState,
		nextAuthority.ValidatedAtMilliseconds, int64(nextAuthority.Revision),
		nextAuthority.ManifestDigest, nextAuthority.ManifestRecord,
		nextAuthority.ActiveDeploymentID,
		nextAuthority.TransitionEvidenceDigest)
	if err != nil {
		return fmt.Errorf("persist Device Sync migration rollback: %w", err)
	}
	if result.RowsAffected() != 1 {
		return errors.New("Device Sync migration rollback affected an unexpected row count")
	}
	stored, err := loadDeviceSyncScopeEnforcement(
		ctx, tx, rollback.Scope.ScopeID, "FOR SHARE",
	)
	if err != nil || stored.State != terminalState || stored.LocalDeploymentID == nil ||
		*stored.LocalDeploymentID != localDeploymentID ||
		!deviceSyncScopeAuthorityEqual(stored.Authority, &nextAuthority) ||
		stored.ActiveExportWriteFenceID != nil || stored.ActiveMigrationImportID != nil ||
		stored.ActiveRollbackImportID != nil {
		if err != nil {
			return err
		}
		return errors.New("persisted Device Sync migration rollback is inconsistent")
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit Device Sync migration rollback: %w", err)
	}
	return nil
}

func validateDeviceSyncRollbackSource(
	ctx context.Context,
	tx pgx.Tx,
	current DeviceSyncScopeEnforcement,
	evidence serviceauthority.MigrationRollbackEvidence,
) error {
	activation, err := evidence.ActivationEvidence.ActivationManifest.VerifiedPayload()
	if err != nil || activation.Migration == nil ||
		current.State != DeviceSyncScopeRollbackStandby ||
		current.ActiveExportWriteFenceID != nil || current.ActiveMigrationImportID != nil ||
		current.ActiveRollbackImportID == nil ||
		*current.ActiveRollbackImportID != activation.Migration.MigrationID {
		return ErrDeviceSyncMigrationImportConflict
	}
	imported, found, err := loadDeviceSyncMigrationRollbackImport(
		ctx, tx, current.PrincipalID, activation.Migration.MigrationID,
		activation.Migration.SourceDeploymentID, "FOR SHARE",
	)
	if err != nil {
		return err
	}
	if !found || !deviceSyncRollbackSourceRecordMatches(current, imported, evidence) {
		return ErrDeviceSyncMigrationImportConflict
	}
	return nil
}

func deviceSyncRollbackSourceRecordMatches(
	current DeviceSyncScopeEnforcement,
	imported DeviceSyncMigrationRollbackImportRecord,
	evidence serviceauthority.MigrationRollbackEvidence,
) bool {
	activation, activationErr :=
		evidence.ActivationEvidence.ActivationManifest.VerifiedPayload()
	canonicalActivation, encodingErr := json.Marshal(evidence.ActivationEvidence)
	canonicalSnapshot, snapshotEncodingErr := json.Marshal(evidence.TargetSnapshot)
	return activationErr == nil && activation.Migration != nil && encodingErr == nil &&
		snapshotEncodingErr == nil && current.State == DeviceSyncScopeRollbackStandby &&
		current.ActiveRollbackImportID != nil &&
		*current.ActiveRollbackImportID == activation.Migration.MigrationID &&
		imported.PrincipalID == current.PrincipalID && imported.TenantID == current.TenantID &&
		imported.MigrationID == activation.Migration.MigrationID &&
		imported.ExportingDeploymentID == activation.Migration.TargetDeploymentID &&
		imported.ImportingDeploymentID == activation.Migration.SourceDeploymentID &&
		bytes.Equal(imported.CanonicalActivationEvidenceRecord, canonicalActivation) &&
		bytes.Equal(imported.CanonicalSnapshotRecord, canonicalSnapshot)
}

func validateDeviceSyncRollbackTarget(
	ctx context.Context,
	tx pgx.Tx,
	current DeviceSyncScopeEnforcement,
	evidence serviceauthority.MigrationRollbackEvidence,
) error {
	snapshot, err := evidence.TargetSnapshot.VerifiedPayload(nil)
	if err != nil || current.State != DeviceSyncScopeExportFenced ||
		current.ActiveMigrationImportID != nil || current.ActiveRollbackImportID != nil ||
		current.ActiveExportWriteFenceID == nil ||
		*current.ActiveExportWriteFenceID != snapshot.ExportWriteFenceID {
		return ErrDeviceSyncMigrationImportConflict
	}
	exported, found, err := loadDeviceSyncMigrationExport(
		ctx, tx, current.PrincipalID, snapshot.ExportWriteFenceID, "FOR SHARE",
	)
	if err != nil {
		return err
	}
	if !found || exported.MigrationID != snapshot.MigrationID ||
		exported.SnapshotID != snapshot.SnapshotID ||
		exported.ExportingDeploymentID != snapshot.ExportingDeploymentID ||
		exported.ImportingDeploymentID != snapshot.ImportingDeploymentID ||
		!bytes.Equal(exported.CanonicalSnapshotPayload, evidence.TargetSnapshot.Payload) ||
		exported.StateCommitmentDigest != snapshot.StateCommitmentDigest {
		return ErrDeviceSyncMigrationImportConflict
	}
	return nil
}

func buildDeviceSyncMigrationRollbackImportCandidate(
	current DeviceSyncScopeEnforcement,
	localDeploymentID uuid.UUID,
	activationEvidence serviceauthority.MigrationActivationEvidence,
	targetSnapshot serviceauthority.MigrationSnapshot,
	validated serviceauthority.ValidatedMigrationRollbackTransfer,
	nowMilliseconds int64,
) (DeviceSyncMigrationRollbackImportRecord, error) {
	if current.Authority == nil || current.LocalDeploymentID == nil ||
		*current.LocalDeploymentID != localDeploymentID ||
		validated.Snapshot.ImportingDeploymentID != localDeploymentID ||
		validated.ActivationManifest.Revision == 0 ||
		validated.ActivationManifest.Revision > math.MaxInt64 {
		return DeviceSyncMigrationRollbackImportRecord{}, serviceauthority.ErrInvalid
	}
	activationManifestDigest, err := activationEvidence.ActivationManifest.ReferenceDigest()
	activationEvidenceDigest, activationDigestErr := activationEvidence.ReferenceDigest()
	snapshotReferenceDigest, snapshotDigestErr := targetSnapshot.ReferenceDigest()
	if err != nil || activationDigestErr != nil || snapshotDigestErr != nil ||
		validated.Snapshot.AuthorityManifestDigest != activationManifestDigest {
		return DeviceSyncMigrationRollbackImportRecord{}, serviceauthority.ErrInvalid
	}
	canonicalActivation, activationRecordSHA256, err :=
		encodeCanonicalDeviceSyncEvidenceRecord(
			activationEvidence, maximumDeviceSyncMigrationEvidenceRecordByteCount,
		)
	if err != nil {
		return DeviceSyncMigrationRollbackImportRecord{}, err
	}
	canonicalSnapshot, snapshotRecordSHA256, err :=
		encodeCanonicalDeviceSyncEvidenceRecord(
			targetSnapshot, maximumDeviceSyncMigrationEvidenceRecordByteCount,
		)
	if err != nil {
		return DeviceSyncMigrationRollbackImportRecord{}, err
	}
	canonicalArtifacts, artifactDescriptorsSHA256, err :=
		encodeCanonicalDeviceSyncEvidenceRecord(
			validated.Snapshot.Artifacts, maximumDeviceSyncSnapshotPayloadByteCount,
		)
	if err != nil {
		return DeviceSyncMigrationRollbackImportRecord{}, err
	}
	var serviceStateArtifact *serviceauthority.MigrationArtifactDescriptor
	for index := range validated.Snapshot.Artifacts {
		if validated.Snapshot.Artifacts[index].Kind == serviceauthority.ArtifactServiceStateSnapshot {
			candidate := validated.Snapshot.Artifacts[index]
			serviceStateArtifact = &candidate
			break
		}
	}
	if serviceStateArtifact == nil {
		return DeviceSyncMigrationRollbackImportRecord{}, serviceauthority.ErrInvalid
	}
	if current.InitialDeploymentID == nil ||
		current.InitialAuthorityValidatedAtMilliseconds == nil ||
		current.InitialAuthorityManifestDigest == nil ||
		len(current.InitialAuthorityManifestRecord) == 0 {
		return DeviceSyncMigrationRollbackImportRecord{}, serviceauthority.ErrInvalid
	}
	initialManifest, err := decodeCanonicalDeviceSyncAuthorityManifest(
		current.InitialAuthorityManifestRecord,
	)
	if err != nil || *current.InitialDeploymentID == uuid.Nil {
		return DeviceSyncMigrationRollbackImportRecord{}, serviceauthority.ErrInvalid
	}
	initialDigest, err := initialManifest.ReferenceDigest()
	if err != nil || initialDigest != *current.InitialAuthorityManifestDigest {
		return DeviceSyncMigrationRollbackImportRecord{}, serviceauthority.ErrInvalid
	}
	snapshotPayloadDigest := sha256.Sum256(targetSnapshot.Payload)
	return DeviceSyncMigrationRollbackImportRecord{
		PrincipalID: current.PrincipalID, TenantID: current.TenantID,
		MigrationID:                             validated.Migration.MigrationID,
		SnapshotID:                              validated.Snapshot.SnapshotID,
		ExportWriteFenceID:                      validated.Snapshot.ExportWriteFenceID,
		AuthorityRevision:                       validated.ActivationManifest.Revision,
		AuthorityManifestDigest:                 activationManifestDigest,
		ActivationEvidenceDigest:                activationEvidenceDigest,
		ExportingDeploymentID:                   validated.Snapshot.ExportingDeploymentID,
		ImportingDeploymentID:                   validated.Snapshot.ImportingDeploymentID,
		CanonicalActivationEvidenceRecord:       canonicalActivation,
		ActivationEvidenceRecordSHA256:          activationRecordSHA256,
		CanonicalSnapshotRecord:                 canonicalSnapshot,
		SnapshotRecordSHA256:                    snapshotRecordSHA256,
		SnapshotReferenceDigest:                 snapshotReferenceDigest,
		SnapshotPayloadSHA256:                   hex.EncodeToString(snapshotPayloadDigest[:]),
		StateCommitmentDigest:                   validated.Snapshot.StateCommitmentDigest,
		CanonicalArtifactDescriptors:            canonicalArtifacts,
		ArtifactDescriptorsSHA256:               artifactDescriptorsSHA256,
		ArtifactCount:                           len(validated.Snapshot.Artifacts),
		ServiceStateArtifactID:                  serviceStateArtifact.ArtifactID,
		ServiceStateArtifactByteCount:           serviceStateArtifact.ByteCount,
		ServiceStateArtifactTransferDigest:      serviceStateArtifact.TransferDigest,
		CapturedAtMilliseconds:                  validated.Snapshot.CapturedAtMilliseconds,
		ExpiresAtMilliseconds:                   validated.Snapshot.ExpiresAtMilliseconds,
		ImportedAtMilliseconds:                  nowMilliseconds,
		InitialDeploymentID:                     *current.InitialDeploymentID,
		InitialAuthorityValidatedAtMilliseconds: *current.InitialAuthorityValidatedAtMilliseconds,
		InitialAuthorityManifestDigest:          initialDigest,
		InitialAuthorityManifestRecord: append(
			[]byte(nil), current.InitialAuthorityManifestRecord...,
		),
	}, nil
}

func insertDeviceSyncMigrationRollbackImport(
	ctx context.Context,
	tx pgx.Tx,
	record DeviceSyncMigrationRollbackImportRecord,
) error {
	result, err := tx.Exec(ctx, `
		INSERT INTO device_sync_migration_rollback_imports (
			principal_id,tenant_id,migration_id,snapshot_id,
			export_write_fence_id,authority_revision,
			authority_manifest_digest,activation_evidence_digest,
			exporting_deployment_id,importing_deployment_id,
			canonical_activation_evidence_record,
			activation_evidence_record_sha256,canonical_snapshot_record,
			snapshot_record_sha256,snapshot_reference_digest,
			snapshot_payload_sha256,state_commitment_digest,
			canonical_artifact_descriptors,artifact_descriptors_sha256,
			artifact_count,service_state_artifact_id,
			service_state_artifact_byte_count,
			service_state_artifact_transfer_digest,captured_at_milliseconds,
			expires_at_milliseconds,imported_at_milliseconds,
			initial_deployment_id,
			initial_authority_validated_at_milliseconds,
			initial_authority_manifest_digest,initial_authority_manifest_record
		) VALUES (
			$1,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
			$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29
		)
	`, record.PrincipalID, record.MigrationID, record.SnapshotID,
		record.ExportWriteFenceID, int64(record.AuthorityRevision),
		record.AuthorityManifestDigest, record.ActivationEvidenceDigest,
		record.ExportingDeploymentID, record.ImportingDeploymentID,
		record.CanonicalActivationEvidenceRecord, record.ActivationEvidenceRecordSHA256,
		record.CanonicalSnapshotRecord, record.SnapshotRecordSHA256,
		record.SnapshotReferenceDigest, record.SnapshotPayloadSHA256,
		record.StateCommitmentDigest, record.CanonicalArtifactDescriptors,
		record.ArtifactDescriptorsSHA256, record.ArtifactCount,
		record.ServiceStateArtifactID, record.ServiceStateArtifactByteCount,
		record.ServiceStateArtifactTransferDigest, record.CapturedAtMilliseconds,
		record.ExpiresAtMilliseconds, record.ImportedAtMilliseconds,
		record.InitialDeploymentID, record.InitialAuthorityValidatedAtMilliseconds,
		record.InitialAuthorityManifestDigest, record.InitialAuthorityManifestRecord)
	if err != nil {
		return fmt.Errorf("insert Device Sync rollback import evidence: %w", err)
	}
	if result.RowsAffected() != 1 {
		return errors.New("Device Sync rollback import insert affected an unexpected row count")
	}
	return nil
}

func loadDeviceSyncMigrationRollbackImport(
	ctx context.Context,
	querier relayQuerier,
	principalID uuid.UUID,
	migrationID uuid.UUID,
	importingDeploymentID uuid.UUID,
	lockClause string,
) (DeviceSyncMigrationRollbackImportRecord, bool, error) {
	query := `
		SELECT snapshot_id,export_write_fence_id,authority_revision,
			authority_manifest_digest,activation_evidence_digest,
			exporting_deployment_id,canonical_activation_evidence_record,
			activation_evidence_record_sha256,canonical_snapshot_record,
			snapshot_record_sha256,snapshot_reference_digest,
			snapshot_payload_sha256,state_commitment_digest,
			canonical_artifact_descriptors,artifact_descriptors_sha256,
			artifact_count,service_state_artifact_id,
			service_state_artifact_byte_count,
			service_state_artifact_transfer_digest,
			captured_at_milliseconds,expires_at_milliseconds,
			imported_at_milliseconds,initial_deployment_id,
			initial_authority_validated_at_milliseconds,
			initial_authority_manifest_digest,initial_authority_manifest_record
		FROM device_sync_migration_rollback_imports
		WHERE principal_id=$1 AND tenant_id=$1 AND migration_id=$2
		  AND importing_deployment_id=$3
	`
	if lockClause != "" {
		query += " " + lockClause
	}
	stored := DeviceSyncMigrationRollbackImportRecord{
		PrincipalID: principalID, TenantID: principalID,
		MigrationID: migrationID, ImportingDeploymentID: importingDeploymentID,
	}
	var authorityRevision int64
	err := querier.QueryRow(ctx, query, principalID, migrationID, importingDeploymentID).Scan(
		&stored.SnapshotID, &stored.ExportWriteFenceID, &authorityRevision,
		&stored.AuthorityManifestDigest, &stored.ActivationEvidenceDigest,
		&stored.ExportingDeploymentID, &stored.CanonicalActivationEvidenceRecord,
		&stored.ActivationEvidenceRecordSHA256, &stored.CanonicalSnapshotRecord,
		&stored.SnapshotRecordSHA256, &stored.SnapshotReferenceDigest,
		&stored.SnapshotPayloadSHA256, &stored.StateCommitmentDigest,
		&stored.CanonicalArtifactDescriptors, &stored.ArtifactDescriptorsSHA256,
		&stored.ArtifactCount, &stored.ServiceStateArtifactID,
		&stored.ServiceStateArtifactByteCount,
		&stored.ServiceStateArtifactTransferDigest,
		&stored.CapturedAtMilliseconds, &stored.ExpiresAtMilliseconds,
		&stored.ImportedAtMilliseconds, &stored.InitialDeploymentID,
		&stored.InitialAuthorityValidatedAtMilliseconds,
		&stored.InitialAuthorityManifestDigest,
		&stored.InitialAuthorityManifestRecord,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeviceSyncMigrationRollbackImportRecord{}, false, nil
	}
	if err != nil {
		return DeviceSyncMigrationRollbackImportRecord{}, false, fmt.Errorf(
			"load Device Sync rollback import: %w", err,
		)
	}
	stored.AuthorityRevision = uint64(authorityRevision)
	if err := validateStoredDeviceSyncMigrationRollbackImport(stored); err != nil {
		return DeviceSyncMigrationRollbackImportRecord{}, false, err
	}
	return cloneDeviceSyncMigrationRollbackImportRecord(stored), true, nil
}

func validateStoredDeviceSyncMigrationRollbackImport(
	stored DeviceSyncMigrationRollbackImportRecord,
) error {
	if stored.AuthorityRevision == 0 || stored.AuthorityRevision > math.MaxInt64 ||
		!validDeviceSyncDigest(stored.AuthorityManifestDigest) ||
		!validDeviceSyncDigest(stored.ActivationEvidenceDigest) ||
		!validDeviceSyncDigest(stored.ActivationEvidenceRecordSHA256) ||
		!validDeviceSyncDigest(stored.SnapshotRecordSHA256) ||
		!validDeviceSyncDigest(stored.SnapshotReferenceDigest) ||
		!validDeviceSyncDigest(stored.SnapshotPayloadSHA256) ||
		!validDeviceSyncDigest(stored.StateCommitmentDigest) ||
		!validDeviceSyncDigest(stored.ArtifactDescriptorsSHA256) ||
		!validDeviceSyncDigest(stored.ServiceStateArtifactTransferDigest) ||
		stored.ExportingDeploymentID == uuid.Nil || stored.ImportingDeploymentID == uuid.Nil ||
		stored.ExportingDeploymentID == stored.ImportingDeploymentID ||
		stored.SnapshotID == uuid.Nil || stored.ExportWriteFenceID == uuid.Nil ||
		stored.ArtifactCount <= 0 || stored.ServiceStateArtifactID == uuid.Nil ||
		stored.ServiceStateArtifactByteCount < 0 || stored.CapturedAtMilliseconds < 0 ||
		stored.ExpiresAtMilliseconds <= stored.CapturedAtMilliseconds ||
		stored.ImportedAtMilliseconds < stored.CapturedAtMilliseconds ||
		stored.ImportedAtMilliseconds >= stored.ExpiresAtMilliseconds {
		return errors.New("stored Device Sync rollback import has invalid scalar evidence")
	}
	var activation serviceauthority.MigrationActivationEvidence
	if err := decodeCanonicalDeviceSyncEvidenceRecord(
		stored.CanonicalActivationEvidenceRecord,
		maximumDeviceSyncMigrationEvidenceRecordByteCount,
		&activation,
	); err != nil {
		return err
	}
	activationRecordDigest := sha256.Sum256(stored.CanonicalActivationEvidenceRecord)
	activationReferenceDigest, referenceErr := activation.ReferenceDigest()
	activationPayload, activationErr := activation.ActivationManifest.VerifiedPayload()
	activationManifestDigest, manifestDigestErr := activation.ActivationManifest.ReferenceDigest()
	if referenceErr != nil || activationErr != nil || manifestDigestErr != nil ||
		activationPayload.Migration == nil ||
		hex.EncodeToString(activationRecordDigest[:]) != stored.ActivationEvidenceRecordSHA256 ||
		activationReferenceDigest != stored.ActivationEvidenceDigest ||
		activationManifestDigest != stored.AuthorityManifestDigest ||
		activationPayload.Revision != stored.AuthorityRevision ||
		activationPayload.Migration.MigrationID != stored.MigrationID ||
		activationPayload.Migration.TargetDeploymentID != stored.ExportingDeploymentID ||
		activationPayload.Migration.SourceDeploymentID != stored.ImportingDeploymentID {
		return errors.New("stored Device Sync rollback activation evidence is inconsistent")
	}
	currentPayload, err := activation.Preparation.CurrentManifest.VerifiedPayload()
	if err != nil {
		return err
	}
	anchor := serviceauthority.TrustAnchor{
		PublicSigningKeyX963:  activation.Preparation.CurrentManifest.Signature.PublicSigningKeyX963,
		Scope:                 currentPayload.Scope,
		SignerID:              activation.Preparation.CurrentManifest.Signature.SignerID,
		SigningKeyFingerprint: activation.Preparation.CurrentManifest.Signature.SigningKeyFingerprint,
		Version:               serviceauthority.SchemaVersion,
	}
	var snapshot serviceauthority.MigrationSnapshot
	if err := decodeCanonicalDeviceSyncEvidenceRecord(
		stored.CanonicalSnapshotRecord,
		maximumDeviceSyncMigrationEvidenceRecordByteCount,
		&snapshot,
	); err != nil {
		return err
	}
	validated, err := snapshot.ValidateRollbackTransfer(
		activation, anchor, stored.ImportedAtMilliseconds,
	)
	snapshotRecordDigest := sha256.Sum256(stored.CanonicalSnapshotRecord)
	snapshotPayloadDigest := sha256.Sum256(snapshot.Payload)
	snapshotReferenceDigest, snapshotDigestErr := snapshot.ReferenceDigest()
	if err != nil || snapshotDigestErr != nil ||
		hex.EncodeToString(snapshotRecordDigest[:]) != stored.SnapshotRecordSHA256 ||
		hex.EncodeToString(snapshotPayloadDigest[:]) != stored.SnapshotPayloadSHA256 ||
		snapshotReferenceDigest != stored.SnapshotReferenceDigest ||
		validated.Snapshot.SnapshotID != stored.SnapshotID ||
		validated.Snapshot.ExportWriteFenceID != stored.ExportWriteFenceID ||
		validated.Snapshot.StateCommitmentDigest != stored.StateCommitmentDigest ||
		validated.Snapshot.CapturedAtMilliseconds != stored.CapturedAtMilliseconds ||
		validated.Snapshot.ExpiresAtMilliseconds != stored.ExpiresAtMilliseconds {
		return errors.New("stored Device Sync rollback snapshot evidence is inconsistent")
	}
	canonicalArtifacts, artifactDigest, err := encodeCanonicalDeviceSyncEvidenceRecord(
		validated.Snapshot.Artifacts, maximumDeviceSyncSnapshotPayloadByteCount,
	)
	if err != nil || !bytes.Equal(canonicalArtifacts, stored.CanonicalArtifactDescriptors) ||
		artifactDigest != stored.ArtifactDescriptorsSHA256 ||
		len(validated.Snapshot.Artifacts) != stored.ArtifactCount {
		return errors.New("stored Device Sync rollback artifact evidence is inconsistent")
	}
	serviceStateMatches := false
	for _, artifact := range validated.Snapshot.Artifacts {
		if artifact.Kind == serviceauthority.ArtifactServiceStateSnapshot {
			serviceStateMatches = artifact.ArtifactID == stored.ServiceStateArtifactID &&
				artifact.ByteCount == stored.ServiceStateArtifactByteCount &&
				artifact.TransferDigest == stored.ServiceStateArtifactTransferDigest
			break
		}
	}
	if !serviceStateMatches {
		return errors.New("stored Device Sync rollback service-state artifact is inconsistent")
	}
	initialManifest, err := decodeCanonicalDeviceSyncAuthorityManifest(
		stored.InitialAuthorityManifestRecord,
	)
	initialDigest, initialDigestErr := initialManifest.ReferenceDigest()
	initialPayload, initialErr := initialManifest.Authorize(
		anchor, stored.InitialAuthorityValidatedAtMilliseconds,
	)
	if err != nil || initialDigestErr != nil || initialErr != nil ||
		initialPayload.Revision != 1 ||
		initialPayload.Transition != serviceauthority.TransitionInitialActivation ||
		initialPayload.ActiveDeployment.DeploymentID != stored.InitialDeploymentID ||
		initialDigest != stored.InitialAuthorityManifestDigest {
		return errors.New("stored Device Sync rollback initial authority is inconsistent")
	}
	return nil
}

func sameDeviceSyncMigrationRollbackImportIdentity(
	left DeviceSyncMigrationRollbackImportRecord,
	right DeviceSyncMigrationRollbackImportRecord,
) bool {
	left.ImportedAtMilliseconds = 0
	right.ImportedAtMilliseconds = 0
	return reflect.DeepEqual(left, right)
}

func cloneDeviceSyncMigrationRollbackImportRecord(
	record DeviceSyncMigrationRollbackImportRecord,
) DeviceSyncMigrationRollbackImportRecord {
	record.CanonicalActivationEvidenceRecord = append(
		[]byte(nil), record.CanonicalActivationEvidenceRecord...,
	)
	record.CanonicalSnapshotRecord = append([]byte(nil), record.CanonicalSnapshotRecord...)
	record.CanonicalArtifactDescriptors = append(
		[]byte(nil), record.CanonicalArtifactDescriptors...,
	)
	record.InitialAuthorityManifestRecord = append(
		[]byte(nil), record.InitialAuthorityManifestRecord...,
	)
	return record
}

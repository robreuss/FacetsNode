package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/backupcustody"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type BackupCustodyStore struct {
	pool                                  *pgxpool.Pool
	localDeploymentID                     uuid.UUID
	maximumActiveUploads                  int
	maximumTargets                        int
	maximumGenerations                    int
	maximumRequests                       int
	maximumRetentionProofs                int
	maximumControlRecords                 int
	maximumCredentialLifetimeMilliseconds int64
	maximumChunksPerUpload                int
	maximumChunkBytes                     int64
	maximumStagingBytes                   int64
	maximumCommittedBytes                 int64
}

type BackupCustodyStoreLimits struct {
	MaximumActiveUploads                  int
	MaximumTargets                        int
	MaximumGenerations                    int
	MaximumRequests                       int
	MaximumRetentionProofs                int
	MaximumControlRecords                 int
	MaximumCredentialLifetimeMilliseconds int64
	MaximumChunksPerUpload                int
	MaximumChunkBytes                     int64
	MaximumStagingBytes                   int64
	MaximumCommittedBytes                 int64
}

type backupCustodyQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func NewBackupCustodyStore(pool *pgxpool.Pool, deploymentID uuid.UUID, limits BackupCustodyStoreLimits) (*BackupCustodyStore, error) {
	if pool == nil || deploymentID == uuid.Nil || limits.MaximumActiveUploads <= 0 || limits.MaximumTargets <= 0 ||
		limits.MaximumGenerations <= 0 || limits.MaximumRequests <= 0 || limits.MaximumRetentionProofs <= 0 ||
		limits.MaximumControlRecords <= 0 || limits.MaximumCredentialLifetimeMilliseconds <= 0 ||
		limits.MaximumChunksPerUpload <= 0 ||
		limits.MaximumChunkBytes <= 0 || limits.MaximumStagingBytes <= 0 || limits.MaximumCommittedBytes <= 0 ||
		limits.MaximumChunkBytes > limits.MaximumStagingBytes || limits.MaximumStagingBytes > limits.MaximumCommittedBytes {
		return nil, serviceauthority.ErrInvalid
	}
	return &BackupCustodyStore{pool: pool, localDeploymentID: deploymentID,
		maximumActiveUploads: limits.MaximumActiveUploads, maximumTargets: limits.MaximumTargets,
		maximumGenerations: limits.MaximumGenerations, maximumRequests: limits.MaximumRequests,
		maximumRetentionProofs: limits.MaximumRetentionProofs, maximumChunkBytes: limits.MaximumChunkBytes,
		maximumControlRecords:                 limits.MaximumControlRecords,
		maximumCredentialLifetimeMilliseconds: limits.MaximumCredentialLifetimeMilliseconds,
		maximumChunksPerUpload:                limits.MaximumChunksPerUpload,
		maximumStagingBytes:                   limits.MaximumStagingBytes, maximumCommittedBytes: limits.MaximumCommittedBytes}, nil
}

func (store *BackupCustodyStore) LoadAccountClaim(ctx context.Context, accountID, claimID, admissionID uuid.UUID) (backupcustody.AccountRecord, string, error) {
	if accountID == uuid.Nil || claimID == uuid.Nil || admissionID == uuid.Nil {
		return backupcustody.AccountRecord{}, "", serviceauthority.ErrInvalid
	}
	return loadAccountClaim(ctx, store.pool, accountID, claimID, admissionID)
}

func (store *BackupCustodyStore) PrepareAccount(ctx context.Context, record backupcustody.AccountRecord) error {
	admissionBytes, err := json.Marshal(record.Admission)
	controlAnchorBytes, controlAnchorErr := record.InitialControlAnchor.CanonicalJSON()
	controlAnchorReference, controlReferenceErr := record.InitialControlAnchor.ReferenceDigest()
	var enrollment serviceauthority.InitialEnrollment
	expectedScope := serviceauthority.Scope{Kind: serviceauthority.ScopeBackupCustody, ScopeID: record.AccountID}
	var payload serviceauthority.ManifestPayload
	enrollmentErr := decodeCanonical(record.InitialEnrollmentRecord, &enrollment)
	if enrollmentErr == nil {
		payload, enrollmentErr = enrollment.ValidateForAdmissionClaim(expectedScope)
	}
	anchorBytes, anchorErr := json.Marshal(enrollment.Anchor)
	manifestBytes, manifestErr := json.Marshal(enrollment.Manifest)
	if err != nil || controlAnchorErr != nil || controlReferenceErr != nil ||
		record.AccountID == uuid.Nil || record.ClaimID == uuid.Nil || record.Admission.AccountID != record.AccountID || record.Admission.Validate() != nil ||
		record.InitialControlAnchor.Unsigned.AccountID != record.AccountID ||
		record.InitialControlAnchor.Unsigned.ControlGeneration != 1 ||
		record.AuthorityRevision == 0 || record.AuthorityRevision > math.MaxInt64 || record.DeploymentID != store.localDeploymentID ||
		record.CreatedAtMilliseconds < 0 || enrollmentErr != nil || anchorErr != nil || manifestErr != nil ||
		record.InitialBinding == nil || record.InitialBinding.Validate() != nil || record.InitialBinding.Scope() != expectedScope ||
		record.InitialBinding.Revision() != record.AuthorityRevision || record.InitialBinding.ManifestDigest() != record.AuthorityManifestDigest ||
		record.InitialBinding.LocalDeploymentID() != record.DeploymentID || payload.Revision != record.AuthorityRevision ||
		payload.ActiveDeployment.DeploymentID != record.DeploymentID || !bytes.Equal(anchorBytes, record.InitialAnchorRecord) ||
		!bytes.Equal(manifestBytes, record.InitialManifestRecord) || !bytes.Equal(record.InitialBinding.ManifestRecord(), record.InitialManifestRecord) ||
		!canonicalHexDigest(record.AdmissionAuthorizationDigest) || !canonicalHexDigest(record.AuthorityManifestDigest) {
		return serviceauthority.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var existing backupcustody.AccountRecord
	var existingAdmission []byte
	var state string
	var matchingAccounts int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM backup_custody_accounts WHERE account_id=$1 OR claim_id=$2 OR admission_id=$3`, record.AccountID, record.ClaimID, record.Admission.AdmissionID).Scan(&matchingAccounts); err != nil {
		return err
	}
	if matchingAccounts > 1 {
		return backupcustody.ErrConflict
	}
	err = tx.QueryRow(ctx, `SELECT account_id,claim_id,admission_id,admission_record,admission_authorization_digest,authority_revision,authority_manifest_digest,deployment_id,initial_anchor_record,initial_manifest_record,initial_enrollment_record,created_at_milliseconds,state FROM backup_custody_accounts WHERE account_id=$1 OR claim_id=$2 OR admission_id=$3 FOR UPDATE`, record.AccountID, record.ClaimID, record.Admission.AdmissionID).Scan(
		&existing.AccountID, &existing.ClaimID, &existing.Admission.AdmissionID, &existingAdmission, &existing.AdmissionAuthorizationDigest,
		&existing.AuthorityRevision, &existing.AuthorityManifestDigest, &existing.DeploymentID,
		&existing.InitialAnchorRecord, &existing.InitialManifestRecord, &existing.InitialEnrollmentRecord, &existing.CreatedAtMilliseconds, &state)
	if err == nil {
		if decodeCanonical(existingAdmission, &existing.Admission) != nil || existing.ClaimID != record.ClaimID || existing.Admission != record.Admission ||
			existing.AccountID != record.AccountID || existing.AdmissionAuthorizationDigest != record.AdmissionAuthorizationDigest ||
			existing.AuthorityRevision != record.AuthorityRevision || existing.AuthorityManifestDigest != record.AuthorityManifestDigest ||
			existing.DeploymentID != record.DeploymentID || !bytes.Equal(existing.InitialAnchorRecord, record.InitialAnchorRecord) ||
			!bytes.Equal(existing.InitialManifestRecord, record.InitialManifestRecord) ||
			!bytes.Equal(existing.InitialEnrollmentRecord, record.InitialEnrollmentRecord) || existing.CreatedAtMilliseconds != record.CreatedAtMilliseconds {
			return backupcustody.ErrConflict
		}
		var historyCount, totalHistoryCount, requestCount int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM backup_custody_authority_history WHERE account_id=$1 AND authority_revision=$2 AND authority_manifest_digest=$3 AND deployment_id=$4 AND anchor_record=$5 AND manifest_record=$6 AND accepted_at_milliseconds=$7`, record.AccountID, int64(record.AuthorityRevision), record.AuthorityManifestDigest, record.DeploymentID, record.InitialAnchorRecord, record.InitialManifestRecord, record.CreatedAtMilliseconds).Scan(&historyCount); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM backup_custody_authority_history WHERE account_id=$1`, record.AccountID).Scan(&totalHistoryCount); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM backup_custody_requests WHERE request_id=$1 AND account_id=$2 AND operation='account_claim' AND request_record=$3`, record.ClaimID, record.AccountID, canonicalAccountClaim(record)).Scan(&requestCount); err != nil {
			return err
		}
		if historyCount != 1 || totalHistoryCount != 1 || requestCount != 1 {
			return backupcustody.ErrConflict
		}
		var storedInitial, storedCurrent []byte
		var initialReference, currentReference, headReference string
		var headSequence, controlGeneration int64
		var controlKeyID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT initial_anchor_record,initial_anchor_reference_digest,current_anchor_record,current_anchor_reference_digest,head_sequence,head_reference_digest,control_generation,control_key_id FROM backup_custody_account_control WHERE account_id=$1`, record.AccountID).Scan(&storedInitial, &initialReference, &storedCurrent, &currentReference, &headSequence, &headReference, &controlGeneration, &controlKeyID); err != nil ||
			!bytes.Equal(storedInitial, controlAnchorBytes) || !bytes.Equal(storedCurrent, controlAnchorBytes) ||
			initialReference != controlAnchorReference || currentReference != controlAnchorReference || headSequence != 0 ||
			headReference != controlAnchorReference || controlGeneration != 1 || controlKeyID != record.InitialControlAnchor.Unsigned.ControlKeyID {
			return backupcustody.ErrConflict
		}
		return tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO backup_custody_accounts(account_id,claim_id,admission_id,admission_record,admission_authorization_digest,authority_revision,authority_manifest_digest,deployment_id,initial_anchor_record,initial_manifest_record,initial_enrollment_record,server_time_high_water_milliseconds,state,created_at_milliseconds) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'standby',$12)`, record.AccountID, record.ClaimID, record.Admission.AdmissionID, admissionBytes, record.AdmissionAuthorizationDigest, int64(record.AuthorityRevision), record.AuthorityManifestDigest, record.DeploymentID, record.InitialAnchorRecord, record.InitialManifestRecord, record.InitialEnrollmentRecord, record.CreatedAtMilliseconds)
	if err != nil {
		return err
	}
	if err := insertRequest(ctx, tx, record.ClaimID, record.AccountID, "account_claim", canonicalAccountClaim(record)); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO backup_custody_authority_history(account_id,authority_revision,authority_manifest_digest,deployment_id,anchor_record,manifest_record,accepted_at_milliseconds) VALUES($1,$2,$3,$4,$5,$6,$7)`, record.AccountID, int64(record.AuthorityRevision), record.AuthorityManifestDigest, record.DeploymentID, record.InitialAnchorRecord, record.InitialManifestRecord, record.CreatedAtMilliseconds)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO backup_custody_account_control(account_id,initial_anchor_record,initial_anchor_reference_digest,current_anchor_record,current_anchor_reference_digest,head_sequence,head_reference_digest,control_generation,control_key_id) VALUES($1,$2,$3,$2,$3,0,$3,1,$4)`, record.AccountID, controlAnchorBytes, controlAnchorReference, record.InitialControlAnchor.Unsigned.ControlKeyID)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (store *BackupCustodyStore) ActivateAccount(ctx context.Context, accountID uuid.UUID, revision uint64, digest string, deploymentID uuid.UUID, now int64) error {
	if accountID == uuid.Nil || revision != 1 || deploymentID != store.localDeploymentID || now < 0 || !canonicalHexDigest(digest) {
		return serviceauthority.ErrInvalid
	}
	tag, err := store.pool.Exec(ctx, `UPDATE backup_custody_accounts SET state='writable',server_time_high_water_milliseconds=GREATEST(server_time_high_water_milliseconds,$5),stored_at=now() WHERE account_id=$1 AND authority_revision=$2 AND authority_manifest_digest=$3 AND deployment_id=$4 AND state IN ('standby','writable')`, accountID, int64(revision), digest, deploymentID, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return backupcustody.ErrConflict
	}
	return nil
}

func (store *BackupCustodyStore) ApplyControlCommand(ctx context.Context, record backupcustody.SignedControlCommand, authorization serviceauthority.MutationAuthorization) (backupcustody.ControlCommandAcceptance, error) {
	payload, err := record.DecodedPayload()
	recordBytes, recordErr := record.CanonicalJSON()
	reference, referenceErr := record.ReferenceDigest()
	if err != nil || recordErr != nil || referenceErr != nil ||
		authorization.ValidateFor(serviceauthority.ScopeBackupCustody, store.localDeploymentID) != nil ||
		authorization.Scope().ScopeID != payload.AccountID {
		return backupcustody.ControlCommandAcceptance{}, serviceauthority.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return backupcustody.ControlCommandAcceptance{}, err
	}
	defer tx.Rollback(ctx)
	if err := store.lockAccount(ctx, tx, authorization); err != nil {
		return backupcustody.ControlCommandAcceptance{}, err
	}
	// Historical exact replay is resolved before current-head validation.
	var existingRecord, existingAcceptance []byte
	if err := tx.QueryRow(ctx, `SELECT command_record,acceptance_record FROM backup_custody_control_commands WHERE account_id=$1 AND command_id=$2`, payload.AccountID, payload.CommandID).Scan(&existingRecord, &existingAcceptance); err == nil {
		var acceptance backupcustody.ControlCommandAcceptance
		if !bytes.Equal(existingRecord, recordBytes) || decodeCanonical(existingAcceptance, &acceptance) != nil || acceptance.Validate() != nil ||
			acceptance.CommandReferenceDigest != reference {
			return backupcustody.ControlCommandAcceptance{}, backupcustody.ErrConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return backupcustody.ControlCommandAcceptance{}, err
		}
		return acceptance, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return backupcustody.ControlCommandAcceptance{}, err
	}
	state, err := loadCredentialAuthorityState(ctx, tx, payload.AccountID, true)
	if err != nil {
		return backupcustody.ControlCommandAcceptance{}, err
	}
	if payload.Effect.Grant != nil {
		expires := payload.Effect.Grant.Credential.ExpiresAtMilliseconds
		now := authorization.AuthorizedAtMilliseconds()
		if expires <= now || now > math.MaxInt64-store.maximumCredentialLifetimeMilliseconds ||
			expires > now+store.maximumCredentialLifetimeMilliseconds {
			return backupcustody.ControlCommandAcceptance{}, backupcustody.ErrUnauthorized
		}
	}
	var commandCount int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM backup_custody_control_commands WHERE account_id=$1`, payload.AccountID).Scan(&commandCount); err != nil {
		return backupcustody.ControlCommandAcceptance{}, err
	}
	if commandCount >= store.maximumControlRecords || state.Apply(record) != nil {
		return backupcustody.ControlCommandAcceptance{}, backupcustody.ErrConflict
	}
	var grantReference *string
	if payload.Effect.Grant != nil {
		value, err := payload.Effect.Grant.ReferenceDigest()
		if err != nil {
			return backupcustody.ControlCommandAcceptance{}, serviceauthority.ErrInvalid
		}
		grantReference = &value
	}
	acceptance := backupcustody.ControlCommandAcceptance{Version: backupcustody.CredentialAuthorityVersion,
		AccountID: payload.AccountID, CommandID: payload.CommandID, Sequence: payload.Sequence,
		CommandReferenceDigest: reference, ControlHeadReferenceDigest: reference,
		ControlGeneration: state.Head.ControlGeneration, ControlKeyID: state.Head.ControlKeyID,
		CredentialGrantReferenceDigest: grantReference}
	acceptanceBytes, err := json.Marshal(acceptance)
	if err != nil || acceptance.Validate() != nil {
		return backupcustody.ControlCommandAcceptance{}, serviceauthority.ErrInvalid
	}
	_, err = tx.Exec(ctx, `INSERT INTO backup_custody_control_commands(account_id,sequence,command_id,predecessor_reference_digest,command_reference_digest,command_record,acceptance_record,effect_kind,accepted_at_milliseconds) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, payload.AccountID, int64(payload.Sequence), payload.CommandID, payload.PredecessorReferenceDigest, reference, recordBytes, acceptanceBytes, string(payload.Effect.Kind), authorization.AuthorizedAtMilliseconds())
	if err != nil {
		return backupcustody.ControlCommandAcceptance{}, err
	}
	switch payload.Effect.Kind {
	case backupcustody.CreateTargetWithInitialGrant:
		var targetCount int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM backup_custody_targets WHERE account_id=$1`, payload.AccountID).Scan(&targetCount); err != nil || targetCount >= store.maximumTargets {
			if err != nil {
				return backupcustody.ControlCommandAcceptance{}, err
			}
			return backupcustody.ControlCommandAcceptance{}, backupcustody.ErrConflict
		}
		_, err = tx.Exec(ctx, `INSERT INTO backup_custody_targets(account_id,target_id,backup_set_id,create_control_command_reference_digest,created_at_milliseconds) VALUES($1,$2,$3,$4,$5)`, payload.AccountID, *payload.Effect.TargetID, *payload.Effect.BackupSetID, reference, authorization.AuthorizedAtMilliseconds())
		if err == nil {
			err = insertCredentialGrant(ctx, tx, payload.AccountID, *payload.Effect.Grant, reference)
		}
	case backupcustody.GrantCredential:
		err = insertCredentialGrant(ctx, tx, payload.AccountID, *payload.Effect.Grant, reference)
	case backupcustody.SupersedeCredential:
		err = insertCredentialGrant(ctx, tx, payload.AccountID, *payload.Effect.Grant, reference)
		if err == nil {
			err = insertCredentialTransition(ctx, tx, payload.AccountID, *payload.Effect.PriorGrantReferenceDigest, "supersede", grantReference, reference)
		}
	case backupcustody.RevokeCredential:
		err = insertCredentialTransition(ctx, tx, payload.AccountID, *payload.Effect.PriorGrantReferenceDigest, "revoke", nil, reference)
	case backupcustody.RotateControlKey:
	default:
		err = serviceauthority.ErrInvalid
	}
	if err != nil {
		return backupcustody.ControlCommandAcceptance{}, err
	}
	currentBytes, err := state.CurrentAnchor.CanonicalJSON()
	currentReference, referenceErr := state.CurrentAnchor.ReferenceDigest()
	if err != nil || referenceErr != nil {
		return backupcustody.ControlCommandAcceptance{}, serviceauthority.ErrInvalid
	}
	tag, err := tx.Exec(ctx, `UPDATE backup_custody_account_control SET current_anchor_record=$4,current_anchor_reference_digest=$5,head_sequence=$6,head_reference_digest=$7,control_generation=$8,control_key_id=$9,stored_at=now() WHERE account_id=$1 AND head_sequence=$2 AND head_reference_digest=$3`, payload.AccountID, int64(payload.Sequence-1), payload.PredecessorReferenceDigest, currentBytes, currentReference, int64(payload.Sequence), reference, int64(state.Head.ControlGeneration), state.Head.ControlKeyID)
	if err != nil {
		return backupcustody.ControlCommandAcceptance{}, err
	}
	if tag.RowsAffected() != 1 {
		return backupcustody.ControlCommandAcceptance{}, backupcustody.ErrConflict
	}
	if _, err := loadCredentialAuthorityState(ctx, tx, payload.AccountID, true); err != nil {
		return backupcustody.ControlCommandAcceptance{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return backupcustody.ControlCommandAcceptance{}, err
	}
	return acceptance, nil
}

func (store *BackupCustodyStore) LoadTarget(ctx context.Context, accountID, targetID uuid.UUID) (backupcustody.TargetRecord, error) {
	return loadTarget(ctx, store.pool, accountID, targetID, false)
}

func (store *BackupCustodyStore) ValidateControlLedger(ctx context.Context, accountID uuid.UUID) error {
	if accountID == uuid.Nil {
		return serviceauthority.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var commandCount int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM backup_custody_control_commands WHERE account_id=$1`, accountID).Scan(&commandCount); err != nil {
		return err
	}
	if commandCount > store.maximumControlRecords {
		return serviceauthority.ErrInvalid
	}
	if _, err := loadCredentialAuthorityState(ctx, tx, accountID, false); err != nil {
		return err
	}
	generationRows, err := tx.Query(ctx, `SELECT generation_reference_digest FROM backup_custody_generations WHERE account_id=$1 ORDER BY target_id,generation`, accountID)
	if err != nil {
		return err
	}
	var generationReferences []string
	for generationRows.Next() {
		var reference string
		if generationRows.Scan(&reference) != nil {
			generationRows.Close()
			return serviceauthority.ErrInvalid
		}
		generationReferences = append(generationReferences, reference)
	}
	if err := generationRows.Err(); err != nil {
		generationRows.Close()
		return err
	}
	generationRows.Close()
	for _, reference := range generationReferences {
		if _, err := loadGeneration(ctx, tx, accountID, reference); err != nil {
			return err
		}
	}
	retentionRows, err := tx.Query(ctx, `SELECT request_id FROM backup_custody_retention_receipts WHERE account_id=$1 ORDER BY issued_at_milliseconds,request_id`, accountID)
	if err != nil {
		return err
	}
	var retentionRequestIDs []uuid.UUID
	for retentionRows.Next() {
		var requestID uuid.UUID
		if retentionRows.Scan(&requestID) != nil {
			retentionRows.Close()
			return serviceauthority.ErrInvalid
		}
		retentionRequestIDs = append(retentionRequestIDs, requestID)
	}
	if err := retentionRows.Err(); err != nil {
		retentionRows.Close()
		return err
	}
	retentionRows.Close()
	for _, requestID := range retentionRequestIDs {
		if _, err := loadRetentionTx(ctx, tx, accountID, requestID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func insertCredentialGrant(ctx context.Context, tx pgx.Tx, accountID uuid.UUID, grant backupcustody.CredentialGrant, commandReference string) error {
	reference, err := grant.ReferenceDigest()
	encoded, encodeErr := json.Marshal(grant)
	if err != nil || encodeErr != nil || grant.Credential.AccountID != accountID {
		return serviceauthority.ErrInvalid
	}
	_, err = tx.Exec(ctx, `INSERT INTO backup_custody_credential_grants(account_id,credential_id,target_id,backup_set_id,grant_reference_digest,grant_record,authorization_digest,accepted_control_command_reference_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, accountID, grant.Credential.CredentialID, grant.Credential.TargetID, grant.Credential.BackupSetID, reference, encoded, grant.AuthorizationDigest, commandReference)
	return err
}

func insertCredentialTransition(ctx context.Context, tx pgx.Tx, accountID uuid.UUID, prior, kind string, replacement *string, commandReference string) error {
	_, err := tx.Exec(ctx, `INSERT INTO backup_custody_credential_grant_transitions(account_id,prior_grant_reference_digest,transition_kind,replacement_grant_reference_digest,accepted_control_command_reference_digest) VALUES($1,$2,$3,$4,$5)`, accountID, prior, kind, replacement, commandReference)
	return err
}

func loadCredentialAuthorityState(ctx context.Context, tx backupCustodyQuerier, accountID uuid.UUID, lock bool) (backupcustody.CredentialAuthorityState, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	var initialBytes, currentBytes []byte
	var initialReference, currentReference, headReference string
	var headSequence, controlGeneration int64
	var controlKeyID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT initial_anchor_record,initial_anchor_reference_digest,current_anchor_record,current_anchor_reference_digest,head_sequence,head_reference_digest,control_generation,control_key_id FROM backup_custody_account_control WHERE account_id=$1`+suffix, accountID).Scan(&initialBytes, &initialReference, &currentBytes, &currentReference, &headSequence, &headReference, &controlGeneration, &controlKeyID); err != nil {
		return backupcustody.CredentialAuthorityState{}, err
	}
	initial, err := backupcustody.DecodeControlPossessionAnchor(initialBytes)
	current, currentErr := backupcustody.DecodeControlPossessionAnchor(currentBytes)
	initialRef, initialRefErr := initial.ReferenceDigest()
	currentRef, currentRefErr := current.ReferenceDigest()
	if err != nil || currentErr != nil || initialRefErr != nil || currentRefErr != nil || initial.Unsigned.AccountID != accountID ||
		initialRef != initialReference || currentRef != currentReference || headSequence < 0 || controlGeneration <= 0 ||
		uint64(controlGeneration) != current.Unsigned.ControlGeneration || controlKeyID != current.Unsigned.ControlKeyID {
		return backupcustody.CredentialAuthorityState{}, serviceauthority.ErrInvalid
	}
	state, err := backupcustody.NewCredentialAuthorityState(initial)
	if err != nil {
		return state, err
	}
	type acceptedCommand struct {
		payload                backupcustody.ControlCommandPayload
		acceptedAtMilliseconds int64
	}
	commandsByReference := make(map[string]acceptedCommand)
	rows, err := tx.Query(ctx, `SELECT sequence,command_id,predecessor_reference_digest,command_reference_digest,command_record,acceptance_record,effect_kind,accepted_at_milliseconds FROM backup_custody_control_commands WHERE account_id=$1 ORDER BY sequence`, accountID)
	if err != nil {
		return state, err
	}
	defer rows.Close()
	for rows.Next() {
		var sequence, acceptedAtMilliseconds int64
		var commandID uuid.UUID
		var predecessor, reference, effectKind string
		var encoded, acceptanceBytes []byte
		if rows.Scan(&sequence, &commandID, &predecessor, &reference, &encoded, &acceptanceBytes, &effectKind, &acceptedAtMilliseconds) != nil || sequence <= 0 || acceptedAtMilliseconds < 0 {
			return state, serviceauthority.ErrInvalid
		}
		record, decodeErr := backupcustody.DecodeSignedControlCommand(encoded)
		payload, payloadErr := record.DecodedPayload()
		recomputedReference, referenceErr := record.ReferenceDigest()
		var acceptance backupcustody.ControlCommandAcceptance
		if decodeErr != nil || payloadErr != nil || referenceErr != nil || payload.Sequence != uint64(sequence) ||
			payload.CommandID != commandID || payload.PredecessorReferenceDigest != predecessor || recomputedReference != reference ||
			string(payload.Effect.Kind) != effectKind || decodeCanonical(acceptanceBytes, &acceptance) != nil || acceptance.Validate() != nil ||
			acceptance.AccountID != accountID || acceptance.CommandID != commandID || acceptance.Sequence != uint64(sequence) ||
			acceptance.CommandReferenceDigest != reference || state.Apply(record) != nil {
			return state, serviceauthority.ErrInvalid
		}
		var expectedGrantReference *string
		if payload.Effect.Grant != nil {
			value, err := payload.Effect.Grant.ReferenceDigest()
			if err != nil {
				return state, serviceauthority.ErrInvalid
			}
			expectedGrantReference = &value
		}
		if acceptance.ControlGeneration != state.Head.ControlGeneration || acceptance.ControlKeyID != state.Head.ControlKeyID ||
			acceptance.ControlHeadReferenceDigest != state.Head.ReferenceDigest ||
			!optionalStringsEqual(acceptance.CredentialGrantReferenceDigest, expectedGrantReference) {
			return state, serviceauthority.ErrInvalid
		}
		if _, duplicate := commandsByReference[reference]; duplicate {
			return state, serviceauthority.ErrInvalid
		}
		commandsByReference[reference] = acceptedCommand{payload: payload, acceptedAtMilliseconds: acceptedAtMilliseconds}
	}
	if rows.Err() != nil {
		return state, rows.Err()
	}
	if state.Head.Sequence != uint64(headSequence) || state.Head.ReferenceDigest != headReference ||
		state.Head.ControlGeneration != uint64(controlGeneration) || state.Head.ControlKeyID != controlKeyID || state.CurrentAnchor != current {
		return state, serviceauthority.ErrInvalid
	}
	targetRows, err := tx.Query(ctx, `SELECT target_id,backup_set_id,create_control_command_reference_digest,created_at_milliseconds FROM backup_custody_targets WHERE account_id=$1`, accountID)
	if err != nil {
		return state, err
	}
	validatedTargets := make(map[uuid.UUID]uuid.UUID)
	for targetRows.Next() {
		var targetID, backupSetID uuid.UUID
		var commandReference string
		var createdAtMilliseconds int64
		if targetRows.Scan(&targetID, &backupSetID, &commandReference, &createdAtMilliseconds) != nil {
			targetRows.Close()
			return state, serviceauthority.ErrInvalid
		}
		command, exists := commandsByReference[commandReference]
		projectedSetID, projected := state.Targets[targetID]
		if !exists || !projected || projectedSetID != backupSetID ||
			command.payload.Effect.Kind != backupcustody.CreateTargetWithInitialGrant ||
			command.payload.Effect.TargetID == nil || *command.payload.Effect.TargetID != targetID ||
			command.payload.Effect.BackupSetID == nil || *command.payload.Effect.BackupSetID != backupSetID ||
			command.payload.Effect.Grant == nil || command.acceptedAtMilliseconds != createdAtMilliseconds {
			targetRows.Close()
			return state, serviceauthority.ErrInvalid
		}
		if _, duplicate := validatedTargets[targetID]; duplicate {
			targetRows.Close()
			return state, serviceauthority.ErrInvalid
		}
		validatedTargets[targetID] = backupSetID
	}
	if err := targetRows.Err(); err != nil {
		targetRows.Close()
		return state, err
	}
	targetRows.Close()
	if len(validatedTargets) != len(state.Targets) {
		return state, serviceauthority.ErrInvalid
	}

	grantRows, err := tx.Query(ctx, `SELECT credential_id,target_id,backup_set_id,grant_reference_digest,grant_record,authorization_digest,accepted_control_command_reference_digest FROM backup_custody_credential_grants WHERE account_id=$1`, accountID)
	if err != nil {
		return state, err
	}
	validatedGrants := make(map[string]struct{})
	for grantRows.Next() {
		var credentialID, targetID, backupSetID uuid.UUID
		var reference, authorizationDigest, commandReference string
		var encoded []byte
		if grantRows.Scan(&credentialID, &targetID, &backupSetID, &reference, &encoded, &authorizationDigest, &commandReference) != nil {
			grantRows.Close()
			return state, serviceauthority.ErrInvalid
		}
		accepted, projected := state.Grants[reference]
		command, exists := commandsByReference[commandReference]
		expected, _ := json.Marshal(accepted.Grant)
		commandGrantReference := ""
		if exists && command.payload.Effect.Grant != nil {
			commandGrantReference, _ = command.payload.Effect.Grant.ReferenceDigest()
		}
		if !projected || !exists || commandGrantReference != reference || !bytes.Equal(encoded, expected) ||
			accepted.Grant.Credential.CredentialID != credentialID || accepted.Grant.Credential.TargetID != targetID ||
			accepted.Grant.Credential.BackupSetID != backupSetID || accepted.Grant.AuthorizationDigest != authorizationDigest {
			grantRows.Close()
			return state, serviceauthority.ErrInvalid
		}
		if _, duplicate := validatedGrants[reference]; duplicate {
			grantRows.Close()
			return state, serviceauthority.ErrInvalid
		}
		validatedGrants[reference] = struct{}{}
	}
	if err := grantRows.Err(); err != nil {
		grantRows.Close()
		return state, err
	}
	grantRows.Close()
	if len(validatedGrants) != len(state.Grants) {
		return state, serviceauthority.ErrInvalid
	}

	transitionRows, err := tx.Query(ctx, `SELECT prior_grant_reference_digest,transition_kind,replacement_grant_reference_digest,accepted_control_command_reference_digest FROM backup_custody_credential_grant_transitions WHERE account_id=$1`, accountID)
	if err != nil {
		return state, err
	}
	validatedTransitions := 0
	for transitionRows.Next() {
		var priorReference, transitionKind, commandReference string
		var replacementReference *string
		if transitionRows.Scan(&priorReference, &transitionKind, &replacementReference, &commandReference) != nil {
			transitionRows.Close()
			return state, serviceauthority.ErrInvalid
		}
		accepted, projected := state.Grants[priorReference]
		command, exists := commandsByReference[commandReference]
		expectedKind := backupcustody.RevokeCredential
		if accepted.Status == backupcustody.GrantSuperseded {
			expectedKind = backupcustody.SupersedeCredential
		}
		if !projected || accepted.Status == backupcustody.GrantActive || !exists || command.payload.Effect.Kind != expectedKind ||
			command.payload.Effect.PriorGrantReferenceDigest == nil || *command.payload.Effect.PriorGrantReferenceDigest != priorReference ||
			transitionKind != string(expectedKind) || !optionalStringsEqual(replacementReference, accepted.ReplacementReferenceDigest) {
			transitionRows.Close()
			return state, serviceauthority.ErrInvalid
		}
		if expectedKind == backupcustody.SupersedeCredential {
			if command.payload.Effect.Grant == nil || replacementReference == nil {
				transitionRows.Close()
				return state, serviceauthority.ErrInvalid
			}
			commandReplacement, _ := command.payload.Effect.Grant.ReferenceDigest()
			if commandReplacement != *replacementReference {
				transitionRows.Close()
				return state, serviceauthority.ErrInvalid
			}
		}
		validatedTransitions++
	}
	if err := transitionRows.Err(); err != nil {
		transitionRows.Close()
		return state, err
	}
	transitionRows.Close()
	expectedTransitionCount := 0
	for _, accepted := range state.Grants {
		if accepted.Status != backupcustody.GrantActive {
			expectedTransitionCount++
		}
	}
	if validatedTransitions != expectedTransitionCount {
		return state, serviceauthority.ErrInvalid
	}
	return state, nil
}

func optionalStringsEqual(left, right *string) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}

func loadAcceptedCredentialAuthority(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, use backupcustody.CredentialUse, requireActive bool) (backupcustody.AcceptedCredentialAuthority, error) {
	if use.Reference.Validate() != nil || !canonicalHexDigest(use.AuthorizationDigest) {
		return backupcustody.AcceptedCredentialAuthority{}, serviceauthority.ErrInvalid
	}
	var grantBytes []byte
	var grantReference, authorizationDigest string
	if err := q.QueryRow(ctx, `SELECT grant_reference_digest,grant_record,authorization_digest FROM backup_custody_credential_grants WHERE account_id=$1 AND credential_id=$2`, use.Reference.AccountID, use.Reference.CredentialID).Scan(&grantReference, &grantBytes, &authorizationDigest); err != nil {
		return backupcustody.AcceptedCredentialAuthority{}, err
	}
	var grant backupcustody.CredentialGrant
	recomputedReference := ""
	if decodeCanonical(grantBytes, &grant) == nil {
		recomputedReference, _ = grant.ReferenceDigest()
	}
	if grant.Validate() != nil || !reflect.DeepEqual(grant.Credential, use.Reference) || recomputedReference != grantReference ||
		authorizationDigest != grant.AuthorizationDigest || authorizationDigest != use.AuthorizationDigest {
		return backupcustody.AcceptedCredentialAuthority{}, backupcustody.ErrUnauthorized
	}
	if requireActive {
		var transitioned bool
		if err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM backup_custody_credential_grant_transitions WHERE account_id=$1 AND prior_grant_reference_digest=$2)`, use.Reference.AccountID, grantReference).Scan(&transitioned); err != nil {
			return backupcustody.AcceptedCredentialAuthority{}, err
		}
		if transitioned {
			return backupcustody.AcceptedCredentialAuthority{}, backupcustody.ErrUnauthorized
		}
	}
	var sequence, generation int64
	var headReference string
	var keyID uuid.UUID
	if err := q.QueryRow(ctx, `SELECT head_sequence,head_reference_digest,control_generation,control_key_id FROM backup_custody_account_control WHERE account_id=$1`, use.Reference.AccountID).Scan(&sequence, &headReference, &generation, &keyID); err != nil {
		return backupcustody.AcceptedCredentialAuthority{}, err
	}
	value := backupcustody.AcceptedCredentialAuthority{Grant: grant, GrantReferenceDigest: grantReference,
		ControlHead: backupcustody.AcceptedControlHead{AccountID: use.Reference.AccountID, Sequence: uint64(sequence),
			ControlGeneration: uint64(generation), ControlKeyID: keyID, ReferenceDigest: headReference}}
	if value.Validate() != nil {
		return value, serviceauthority.ErrInvalid
	}
	return value, nil
}

// validateHistoricalCredentialProjection proves that one exact durable grant
// was already accepted at the referenced control head and had not yet been
// superseded or revoked there. The raw bearer is intentionally optional: only
// the live historical-replay entry point has it, while stored receipts retain
// the grant's canonical authorization digest instead of the bearer itself.
func validateHistoricalCredentialProjection(
	ctx context.Context,
	q backupCustodyQuerier,
	accountID, credentialID uuid.UUID,
	grantReference, headReference string,
	use *backupcustody.CredentialUse,
	required backupcustody.Capability,
	issuedAtMilliseconds int64,
) error {
	if accountID == uuid.Nil || credentialID == uuid.Nil || !canonicalHexDigest(grantReference) ||
		!canonicalHexDigest(headReference) || issuedAtMilliseconds < 0 ||
		(required != backupcustody.Publish && required != backupcustody.Read && required != backupcustody.RetentionProof) {
		return serviceauthority.ErrInvalid
	}
	// This validates every signed command, acceptance, target, grant and
	// transition projection before any historical relationship is trusted.
	if _, err := loadCredentialAuthorityState(ctx, q, accountID, false); err != nil {
		return err
	}

	var headSequence int64
	var headCommandBytes, headAcceptanceBytes []byte
	if err := q.QueryRow(ctx, `SELECT sequence,command_record,acceptance_record FROM backup_custody_control_commands WHERE account_id=$1 AND command_reference_digest=$2`, accountID, headReference).Scan(&headSequence, &headCommandBytes, &headAcceptanceBytes); err != nil {
		return err
	}
	headCommand, err := backupcustody.DecodeSignedControlCommand(headCommandBytes)
	headPayload, payloadErr := headCommand.DecodedPayload()
	recomputedHeadReference, referenceErr := headCommand.ReferenceDigest()
	var headAcceptance backupcustody.ControlCommandAcceptance
	if err != nil || payloadErr != nil || referenceErr != nil || headSequence <= 0 ||
		headPayload.AccountID != accountID || headPayload.Sequence != uint64(headSequence) ||
		recomputedHeadReference != headReference || decodeCanonical(headAcceptanceBytes, &headAcceptance) != nil ||
		headAcceptance.Validate() != nil || headAcceptance.AccountID != accountID ||
		headAcceptance.CommandID != headPayload.CommandID || headAcceptance.Sequence != uint64(headSequence) ||
		headAcceptance.CommandReferenceDigest != headReference || headAcceptance.ControlHeadReferenceDigest != headReference {
		return serviceauthority.ErrInvalid
	}

	var storedCredentialID, targetID, backupSetID uuid.UUID
	var grantBytes []byte
	var authorizationDigest, acceptedCommandReference string
	if err := q.QueryRow(ctx, `SELECT credential_id,target_id,backup_set_id,grant_record,authorization_digest,accepted_control_command_reference_digest FROM backup_custody_credential_grants WHERE account_id=$1 AND grant_reference_digest=$2`, accountID, grantReference).Scan(&storedCredentialID, &targetID, &backupSetID, &grantBytes, &authorizationDigest, &acceptedCommandReference); err != nil {
		return err
	}
	var grant backupcustody.CredentialGrant
	recomputedGrantReference := ""
	if decodeCanonical(grantBytes, &grant) == nil {
		recomputedGrantReference, _ = grant.ReferenceDigest()
	}
	if grant.Validate() != nil || recomputedGrantReference != grantReference || grant.AuthorizationDigest != authorizationDigest ||
		grant.Credential.AccountID != accountID || grant.Credential.CredentialID != credentialID ||
		grant.Credential.CredentialID != storedCredentialID || grant.Credential.TargetID != targetID ||
		grant.Credential.BackupSetID != backupSetID || !grant.Credential.Admits(required, issuedAtMilliseconds) {
		return serviceauthority.ErrInvalid
	}
	if use != nil && (!reflect.DeepEqual(use.Reference, grant.Credential) || use.AuthorizationDigest != authorizationDigest) {
		return backupcustody.ErrUnauthorized
	}

	var grantSequence int64
	if err := q.QueryRow(ctx, `SELECT sequence FROM backup_custody_control_commands WHERE account_id=$1 AND command_reference_digest=$2`, accountID, acceptedCommandReference).Scan(&grantSequence); err != nil {
		return err
	}
	if grantSequence <= 0 || grantSequence > headSequence {
		return serviceauthority.ErrInvalid
	}
	var transitionSequence int64
	if err := q.QueryRow(ctx, `SELECT command.sequence FROM backup_custody_credential_grant_transitions transition JOIN backup_custody_control_commands command ON command.account_id=transition.account_id AND command.command_reference_digest=transition.accepted_control_command_reference_digest WHERE transition.account_id=$1 AND transition.prior_grant_reference_digest=$2`, accountID, grantReference).Scan(&transitionSequence); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	} else if transitionSequence <= 0 || transitionSequence <= headSequence {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func (store *BackupCustodyStore) AuthorizeHistoricalCredential(ctx context.Context, use backupcustody.CredentialUse, grantReference, headReference string, required backupcustody.Capability, issuedAtMilliseconds int64) error {
	if !canonicalHexDigest(grantReference) || !canonicalHexDigest(headReference) || use.Reference.Validate() != nil {
		return serviceauthority.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := validateHistoricalCredentialProjection(ctx, tx, use.Reference.AccountID, use.Reference.CredentialID,
		grantReference, headReference, &use, required, issuedAtMilliseconds); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (store *BackupCustodyStore) ReserveUpload(ctx context.Context, proposed backupcustody.UploadRecord, use backupcustody.CredentialUse, clock backupcustody.Clock, authorization serviceauthority.MutationAuthorization) (backupcustody.UploadRecord, bool, error) {
	if clock == nil || proposed.AccountID == uuid.Nil || proposed.TargetID == uuid.Nil || proposed.BackupSetID == uuid.Nil || proposed.UploadID == uuid.Nil ||
		proposed.Request.Validate() != nil || proposed.Request.Generation > math.MaxInt64 || proposed.Request.Credential.AccountID != proposed.AccountID ||
		proposed.Request.Credential.TargetID != proposed.TargetID || proposed.Request.Credential.BackupSetID != proposed.BackupSetID ||
		proposed.CommittedBytes != 0 || proposed.Committed || proposed.MaximumChunkCount != 0 || proposed.CreatedAtMilliseconds < 0 ||
		decodeExactPublishRequest(proposed.RequestBytes, proposed.Request) != nil {
		return backupcustody.UploadRecord{}, false, serviceauthority.ErrInvalid
	}
	if err := authorization.ValidateFor(serviceauthority.ScopeBackupCustody, store.localDeploymentID); err != nil {
		return backupcustody.UploadRecord{}, false, err
	}
	if authorization.Scope().ScopeID != proposed.AccountID {
		return backupcustody.UploadRecord{}, false, serviceauthority.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return backupcustody.UploadRecord{}, false, err
	}
	defer tx.Rollback(ctx)
	if err := store.lockAccount(ctx, tx, authorization); err != nil {
		return backupcustody.UploadRecord{}, false, err
	}
	grant, err := loadAcceptedCredentialAuthority(ctx, tx, use, true)
	if err != nil || grant.Grant.Credential.TargetID != proposed.TargetID ||
		!grant.Grant.Credential.Admits(backupcustody.Publish, clock.Now().UnixMilli()) ||
		!reflect.DeepEqual(grant.Grant.Credential, proposed.Request.Credential) {
		if err != nil {
			return backupcustody.UploadRecord{}, false, err
		}
		return backupcustody.UploadRecord{}, false, backupcustody.ErrUnauthorized
	}
	target, err := loadTarget(ctx, tx, proposed.AccountID, proposed.TargetID, true)
	if err != nil || target.BackupSetID != proposed.BackupSetID {
		if err != nil {
			return backupcustody.UploadRecord{}, false, err
		}
		return backupcustody.UploadRecord{}, false, backupcustody.ErrConflict
	}
	var existingAccount, existingUpload uuid.UUID
	var operation string
	var requestBytes []byte
	err = tx.QueryRow(ctx, `SELECT account_id,operation,request_record FROM backup_custody_requests WHERE request_id=$1 FOR UPDATE`, proposed.Request.RequestID).Scan(&existingAccount, &operation, &requestBytes)
	if err == nil {
		if existingAccount != proposed.AccountID || operation != "begin_upload" || !bytes.Equal(requestBytes, proposed.RequestBytes) {
			return backupcustody.UploadRecord{}, false, backupcustody.ErrConflict
		}
		if err := tx.QueryRow(ctx, `SELECT upload_id FROM backup_custody_uploads WHERE publish_request_id=$1`, proposed.Request.RequestID).Scan(&existingUpload); err != nil {
			return backupcustody.UploadRecord{}, false, err
		}
		existing, err := loadUpload(ctx, tx, proposed.AccountID, existingUpload, false)
		if err != nil {
			return backupcustody.UploadRecord{}, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return backupcustody.UploadRecord{}, false, err
		}
		return existing, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return backupcustody.UploadRecord{}, false, err
	}
	var active, requestCount, generationCount int
	var staging int64
	var committed int64
	if err := tx.QueryRow(ctx, `SELECT count(*),COALESCE(sum(committed_bytes),0) FROM backup_custody_uploads WHERE account_id=$1 AND state='uploading'`, proposed.AccountID).Scan(&active, &staging); err != nil {
		return backupcustody.UploadRecord{}, false, err
	}
	if err := tx.QueryRow(ctx, `SELECT COALESCE(sum(outer_byte_count),0) FROM backup_custody_generations WHERE account_id=$1`, proposed.AccountID).Scan(&committed); err != nil {
		return backupcustody.UploadRecord{}, false, err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM backup_custody_generations WHERE account_id=$1`, proposed.AccountID).Scan(&generationCount); err != nil {
		return backupcustody.UploadRecord{}, false, err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM backup_custody_requests WHERE account_id=$1`, proposed.AccountID).Scan(&requestCount); err != nil {
		return backupcustody.UploadRecord{}, false, err
	}
	worstTail, overflow := multiplyWithinInt64(int64(active+1), store.maximumChunkBytes)
	if overflow || active >= store.maximumActiveUploads || generationCount >= store.maximumGenerations || requestCount >= store.maximumRequests ||
		staging < 0 || committed < 0 || staging > store.maximumStagingBytes-worstTail ||
		committed > store.maximumCommittedBytes-staging || worstTail > store.maximumCommittedBytes-committed-staging {
		return backupcustody.UploadRecord{}, false, backupcustody.ErrConflict
	}
	if err := insertRequest(ctx, tx, proposed.Request.RequestID, proposed.AccountID, "begin_upload", proposed.RequestBytes); err != nil {
		return backupcustody.UploadRecord{}, false, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO backup_custody_uploads(account_id,upload_id,target_id,backup_set_id,publish_request_id,request_record,committed_bytes,maximum_chunk_count,state,created_at_milliseconds) VALUES($1,$2,$3,$4,$5,$6,0,$7,'uploading',$8)`, proposed.AccountID, proposed.UploadID, proposed.TargetID, proposed.BackupSetID, proposed.Request.RequestID, proposed.RequestBytes, store.maximumChunksPerUpload, proposed.CreatedAtMilliseconds)
	if err != nil {
		return backupcustody.UploadRecord{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return backupcustody.UploadRecord{}, false, err
	}
	proposed.MaximumChunkCount = store.maximumChunksPerUpload
	return proposed, true, nil
}

func (store *BackupCustodyStore) LoadUpload(ctx context.Context, accountID, uploadID uuid.UUID) (backupcustody.UploadRecord, error) {
	return loadUpload(ctx, store.pool, accountID, uploadID, false)
}

type backupUploadAppend struct {
	tx           pgx.Tx
	upload       backupcustody.UploadRecord
	existingNext *uint64
	digest       string
	length       uint64
}

func (lease *backupUploadAppend) Upload() backupcustody.UploadRecord { return lease.upload }
func (lease *backupUploadAppend) ExistingNextOffset() *uint64 {
	if lease.existingNext == nil {
		return nil
	}
	v := *lease.existingNext
	return &v
}
func (lease *backupUploadAppend) Abort(ctx context.Context) error {
	err := lease.tx.Rollback(ctx)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}
func (lease *backupUploadAppend) Commit(ctx context.Context, next uint64) error {
	if lease.length == 0 || lease.upload.CommittedBytes > math.MaxInt64-lease.length ||
		next != lease.upload.CommittedBytes+lease.length || next > math.MaxInt64 {
		return serviceauthority.ErrInvalid
	}
	_, err := lease.tx.Exec(ctx, `INSERT INTO backup_custody_upload_chunks(account_id,upload_id,chunk_offset,chunk_byte_count,chunk_sha256,next_offset) VALUES($1,$2,$3,$4,$5,$6)`, lease.upload.AccountID, lease.upload.UploadID, int64(lease.upload.CommittedBytes), int64(next-lease.upload.CommittedBytes), lease.digest, int64(next))
	if err != nil {
		return err
	}
	tag, err := lease.tx.Exec(ctx, `UPDATE backup_custody_uploads SET committed_bytes=$3,stored_at=now() WHERE account_id=$1 AND upload_id=$2 AND committed_bytes=$4 AND state='uploading'`, lease.upload.AccountID, lease.upload.UploadID, int64(next), int64(lease.upload.CommittedBytes))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return backupcustody.ErrConflict
	}
	return lease.tx.Commit(ctx)
}
func (store *BackupCustodyStore) BeginUploadAppend(ctx context.Context, accountID, uploadID uuid.UUID, offset uint64, digest string, length uint64, use backupcustody.CredentialUse, clock backupcustody.Clock, authorization serviceauthority.MutationAuthorization) (backupcustody.UploadAppend, error) {
	if clock == nil || accountID == uuid.Nil || uploadID == uuid.Nil || offset > math.MaxInt64 || length == 0 || length > uint64(store.maximumChunkBytes) ||
		length > math.MaxInt64 || offset > math.MaxInt64-length || !canonicalHexDigest(digest) {
		return nil, serviceauthority.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (backupcustody.UploadAppend, error) { _ = tx.Rollback(ctx); return nil, e }
	if err := store.lockAccount(ctx, tx, authorization); err != nil {
		return fail(err)
	}
	upload, err := loadUpload(ctx, tx, accountID, uploadID, true)
	if err != nil {
		return fail(err)
	}
	grant, err := loadAcceptedCredentialAuthority(ctx, tx, use, true)
	if err != nil || !reflect.DeepEqual(grant.Grant.Credential, upload.Request.Credential) ||
		!grant.Grant.Credential.Admits(backupcustody.Publish, clock.Now().UnixMilli()) {
		if err != nil {
			return fail(err)
		}
		return fail(backupcustody.ErrUnauthorized)
	}
	lease := &backupUploadAppend{tx: tx, upload: upload, digest: digest, length: length}
	if offset < upload.CommittedBytes {
		var storedDigest string
		var storedLength, next uint64
		err := tx.QueryRow(ctx, `SELECT chunk_sha256,chunk_byte_count,next_offset FROM backup_custody_upload_chunks WHERE account_id=$1 AND upload_id=$2 AND chunk_offset=$3`, accountID, uploadID, int64(offset)).Scan(&storedDigest, &storedLength, &next)
		if err != nil || storedDigest != digest || storedLength != length || next != offset+length || next > upload.CommittedBytes {
			return fail(backupcustody.ErrConflict)
		}
		lease.existingNext = &next
		return lease, nil
	}
	if offset != upload.CommittedBytes {
		return fail(backupcustody.ErrConflict)
	}
	var chunkCount int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM backup_custody_upload_chunks WHERE account_id=$1 AND upload_id=$2`, accountID, uploadID).Scan(&chunkCount); err != nil {
		return fail(err)
	}
	if upload.MaximumChunkCount <= 0 || chunkCount >= upload.MaximumChunkCount {
		return fail(backupcustody.ErrConflict)
	}
	var active int64
	var staging, committed int64
	if err := tx.QueryRow(ctx, `SELECT count(*),COALESCE(sum(committed_bytes),0) FROM backup_custody_uploads WHERE account_id=$1 AND state='uploading'`, accountID).Scan(&active, &staging); err != nil {
		return fail(err)
	}
	if err := tx.QueryRow(ctx, `SELECT COALESCE(sum(outer_byte_count),0) FROM backup_custody_generations WHERE account_id=$1`, accountID).Scan(&committed); err != nil {
		return fail(err)
	}
	worstTail, overflow := multiplyWithinInt64(active, store.maximumChunkBytes)
	if overflow || staging < 0 || committed < 0 || int64(length) > store.maximumStagingBytes-staging ||
		worstTail > store.maximumStagingBytes-staging-int64(length) || committed > store.maximumCommittedBytes-staging ||
		int64(length) > store.maximumCommittedBytes-committed-staging ||
		worstTail > store.maximumCommittedBytes-committed-staging-int64(length) {
		return fail(backupcustody.ErrConflict)
	}
	return lease, nil
}

type backupFinalization struct {
	store               *BackupCustodyStore
	tx                  pgx.Tx
	authorization       serviceauthority.MutationAuthorization
	upload              backupcustody.UploadRecord
	target              backupcustody.TargetRecord
	credentialAuthority backupcustody.AcceptedCredentialAuthority
	existing            *backupcustody.GenerationRecord
}

func (lease *backupFinalization) Upload() backupcustody.UploadRecord        { return lease.upload }
func (lease *backupFinalization) Target() backupcustody.TargetRecord        { return lease.target }
func (lease *backupFinalization) Existing() *backupcustody.GenerationRecord { return lease.existing }
func (lease *backupFinalization) CredentialAuthority() backupcustody.AcceptedCredentialAuthority {
	return lease.credentialAuthority
}
func (lease *backupFinalization) Abort(ctx context.Context) error {
	err := lease.tx.Rollback(ctx)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}
func (lease *backupFinalization) Revalidate(ctx context.Context, a serviceauthority.MutationAuthorization) error {
	if err := lease.store.lockAccount(ctx, lease.tx, a); err != nil {
		return err
	}
	lease.authorization = a
	return nil
}
func (lease *backupFinalization) Commit(ctx context.Context, record backupcustody.GenerationRecord) error {
	if record.ValidateStored() != nil || lease.authorization.ValidateFor(serviceauthority.ScopeBackupCustody, lease.store.localDeploymentID) != nil ||
		record.Generation.AccountID != lease.upload.AccountID || record.Generation.TargetID != lease.upload.TargetID ||
		record.Generation.BackupSetID != lease.upload.BackupSetID || record.Generation.UploadID != lease.upload.UploadID ||
		record.Generation.Generation != lease.upload.Request.Generation || record.Generation.OuterByteCount > math.MaxInt64 {
		return serviceauthority.ErrInvalid
	}
	encoded, err := json.Marshal(record.Generation)
	if err != nil {
		return err
	}
	payload, err := record.CustodyReceipt.VerifiedPayload()
	if err != nil {
		return err
	}
	authority := serviceauthority.BackupCustodyAuthorityContext{Scope: lease.authorization.Scope(),
		AuthorityRevision: lease.authorization.AuthorityRevision(), AuthorityManifestDigest: lease.authorization.AuthorityManifestDigest(),
		DeploymentID: lease.authorization.DeploymentID()}
	if payload.RequestID != lease.upload.Request.RequestID || payload.CredentialID != lease.credentialAuthority.Grant.Credential.CredentialID ||
		payload.CredentialGrantReferenceDigest != lease.credentialAuthority.GrantReferenceDigest ||
		payload.ControlHeadReferenceDigest != lease.credentialAuthority.ControlHead.ReferenceDigest ||
		payload.Authority != authority || payload.IssuedAtMilliseconds != lease.authorization.AuthorizedAtMilliseconds() ||
		lease.upload.Committed || lease.upload.CommittedBytes != record.Generation.OuterByteCount {
		return serviceauthority.ErrInvalid
	}
	anchor, manifest, err := loadAuthority(ctx, lease.tx, payload.Authority)
	if err != nil {
		return err
	}
	if authorized, err := record.CustodyReceipt.Authorize(anchor, manifest); err != nil ||
		!reflect.DeepEqual(authorized.Generation, record.Generation) {
		return serviceauthority.ErrInvalid
	}
	var generationCount int
	if err := lease.tx.QueryRow(ctx, `SELECT count(*) FROM backup_custody_generations WHERE account_id=$1`, record.Generation.AccountID).Scan(&generationCount); err != nil {
		return err
	}
	if generationCount >= lease.store.maximumGenerations {
		return backupcustody.ErrConflict
	}
	_, err = lease.tx.Exec(ctx, `INSERT INTO backup_custody_generations(account_id,target_id,backup_set_id,generation,upload_id,generation_record,generation_reference_digest,object_path,custody_receipt_record,custody_receipt_reference_digest,credential_grant_reference_digest,control_head_reference_digest,outer_byte_count,outer_digest,committed_at_milliseconds) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, record.Generation.AccountID, record.Generation.TargetID, record.Generation.BackupSetID, int64(record.Generation.Generation), record.Generation.UploadID, encoded, record.GenerationReferenceDigest, record.ObjectPath, record.CustodyReceiptBytes, record.CustodyReceiptReferenceDigest, payload.CredentialGrantReferenceDigest, payload.ControlHeadReferenceDigest, int64(record.Generation.OuterByteCount), record.Generation.OuterDigest, payload.IssuedAtMilliseconds)
	if err != nil {
		return err
	}
	var tag pgconn.CommandTag
	if record.Generation.Generation == 1 {
		tag, err = lease.tx.Exec(ctx, `UPDATE backup_custody_targets SET head_generation=$3,head_generation_reference_digest=$4,stored_at=now() WHERE account_id=$1 AND target_id=$2 AND backup_set_id=$5 AND head_generation IS NULL AND head_generation_reference_digest IS NULL`, record.Generation.AccountID, record.Generation.TargetID, int64(record.Generation.Generation), record.GenerationReferenceDigest, record.Generation.BackupSetID)
	} else if record.Generation.PredecessorReferenceDigest != nil {
		tag, err = lease.tx.Exec(ctx, `UPDATE backup_custody_targets SET head_generation=$3,head_generation_reference_digest=$4,stored_at=now() WHERE account_id=$1 AND target_id=$2 AND backup_set_id=$5 AND head_generation=$6 AND head_generation_reference_digest=$7`, record.Generation.AccountID, record.Generation.TargetID, int64(record.Generation.Generation), record.GenerationReferenceDigest, record.Generation.BackupSetID, int64(record.Generation.Generation-1), *record.Generation.PredecessorReferenceDigest)
	} else {
		return serviceauthority.ErrInvalid
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return backupcustody.ErrConflict
	}
	tag, err = lease.tx.Exec(ctx, `UPDATE backup_custody_uploads SET state='committed',stored_at=now() WHERE account_id=$1 AND upload_id=$2 AND target_id=$3 AND backup_set_id=$4 AND committed_bytes=$5 AND state='uploading'`, record.Generation.AccountID, record.Generation.UploadID, record.Generation.TargetID, record.Generation.BackupSetID, int64(record.Generation.OuterByteCount))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return backupcustody.ErrConflict
	}
	return lease.tx.Commit(ctx)
}

func (store *BackupCustodyStore) BeginFinalization(ctx context.Context, accountID, uploadID uuid.UUID, use backupcustody.CredentialUse, a serviceauthority.MutationAuthorization) (backupcustody.Finalization, error) {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (backupcustody.Finalization, error) { _ = tx.Rollback(ctx); return nil, e }
	if err := store.lockAccount(ctx, tx, a); err != nil {
		return fail(err)
	}
	upload, err := loadUpload(ctx, tx, accountID, uploadID, true)
	if err != nil {
		return fail(err)
	}
	credentialAuthority, err := loadAcceptedCredentialAuthority(ctx, tx, use, true)
	if err != nil || !reflect.DeepEqual(credentialAuthority.Grant.Credential, upload.Request.Credential) {
		if err != nil {
			return fail(err)
		}
		return fail(backupcustody.ErrUnauthorized)
	}
	target, err := loadTarget(ctx, tx, accountID, upload.TargetID, true)
	if err != nil {
		return fail(err)
	}
	lease := &backupFinalization{store: store, tx: tx, authorization: a, upload: upload, target: target, credentialAuthority: credentialAuthority}
	if existing, err := loadGenerationByUpload(ctx, tx, accountID, uploadID); err == nil {
		lease.existing = &existing
	} else if !errors.Is(err, backupcustody.ErrNotFound) {
		return fail(err)
	}
	if upload.Committed != (lease.existing != nil) {
		return fail(serviceauthority.ErrInvalid)
	}
	return lease, nil
}

func (store *BackupCustodyStore) LoadGenerationByUpload(ctx context.Context, accountID, uploadID uuid.UUID) (backupcustody.GenerationRecord, error) {
	return loadGenerationByUpload(ctx, store.pool, accountID, uploadID)
}
func (store *BackupCustodyStore) LoadGeneration(ctx context.Context, accountID uuid.UUID, reference string) (backupcustody.GenerationRecord, error) {
	return loadGeneration(ctx, store.pool, accountID, reference)
}

type backupRetention struct {
	store               *BackupCustodyStore
	tx                  pgx.Tx
	authorization       serviceauthority.MutationAuthorization
	target              backupcustody.TargetRecord
	generation          backupcustody.GenerationRecord
	existing            *backupcustody.RetentionRecord
	credentialAuthority backupcustody.AcceptedCredentialAuthority
	highWater           int64
}

func (l *backupRetention) Target() backupcustody.TargetRecord         { return l.target }
func (l *backupRetention) Generation() backupcustody.GenerationRecord { return l.generation }
func (l *backupRetention) Existing() *backupcustody.RetentionRecord   { return l.existing }
func (l *backupRetention) CredentialAuthority() backupcustody.AcceptedCredentialAuthority {
	return l.credentialAuthority
}
func (l *backupRetention) ServerTimeHighWaterMilliseconds() int64 { return l.highWater }
func (l *backupRetention) Abort(ctx context.Context) error {
	e := l.tx.Rollback(ctx)
	if errors.Is(e, pgx.ErrTxClosed) {
		return nil
	}
	return e
}
func (l *backupRetention) Revalidate(ctx context.Context, a serviceauthority.MutationAuthorization) error {
	if err := l.store.lockAccount(ctx, l.tx, a); err != nil {
		return err
	}
	l.authorization = a
	return nil
}
func (l *backupRetention) Commit(ctx context.Context, r backupcustody.RetentionRecord, high int64) error {
	if r.ValidateStored() != nil || l.authorization.ValidateFor(serviceauthority.ScopeBackupCustody, l.store.localDeploymentID) != nil ||
		r.AccountID != l.target.AccountID || r.Request.Credential.TargetID != l.target.TargetID ||
		r.Request.Credential.BackupSetID != l.target.BackupSetID ||
		r.Request.GenerationReferenceDigest != l.generation.GenerationReferenceDigest ||
		r.Request.CustodyReceiptReferenceDigest != l.generation.CustodyReceiptReferenceDigest {
		return serviceauthority.ErrInvalid
	}
	payload, err := r.Receipt.VerifiedPayload()
	if err != nil {
		return err
	}
	authority := serviceauthority.BackupCustodyAuthorityContext{Scope: l.authorization.Scope(),
		AuthorityRevision: l.authorization.AuthorityRevision(), AuthorityManifestDigest: l.authorization.AuthorityManifestDigest(),
		DeploymentID: l.authorization.DeploymentID()}
	if payload.Authority != authority || payload.IssuedAtMilliseconds != high || high != l.authorization.AuthorizedAtMilliseconds() ||
		payload.CredentialGrantReferenceDigest != l.credentialAuthority.GrantReferenceDigest ||
		payload.ControlHeadReferenceDigest != l.credentialAuthority.ControlHead.ReferenceDigest ||
		!reflect.DeepEqual(payload.Generation, l.generation.Generation) {
		return serviceauthority.ErrInvalid
	}
	anchor, manifest, err := loadAuthority(ctx, l.tx, payload.Authority)
	if err != nil {
		return err
	}
	if authorized, err := r.Receipt.Authorize(anchor, manifest); err != nil ||
		!reflect.DeepEqual(authorized.Generation, l.generation.Generation) {
		return serviceauthority.ErrInvalid
	}
	var requestCount, receiptCount int
	if err := l.tx.QueryRow(ctx, `SELECT count(*) FROM backup_custody_requests WHERE account_id=$1`, r.AccountID).Scan(&requestCount); err != nil {
		return err
	}
	if err := l.tx.QueryRow(ctx, `SELECT count(*) FROM backup_custody_retention_receipts WHERE account_id=$1`, r.AccountID).Scan(&receiptCount); err != nil {
		return err
	}
	if requestCount >= l.store.maximumRequests || receiptCount >= l.store.maximumRetentionProofs {
		return backupcustody.ErrConflict
	}
	if err := insertRequest(ctx, l.tx, r.Request.RequestID, r.AccountID, "retention", r.RequestBytes); err != nil {
		return err
	}
	_, err = l.tx.Exec(ctx, `INSERT INTO backup_custody_retention_receipts(account_id,request_id,request_record,receipt_record,receipt_reference_digest,credential_grant_reference_digest,control_head_reference_digest,issued_at_milliseconds)VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, r.AccountID, r.Request.RequestID, r.RequestBytes, r.ReceiptBytes, r.ReceiptReferenceDigest, payload.CredentialGrantReferenceDigest, payload.ControlHeadReferenceDigest, payload.IssuedAtMilliseconds)
	if err != nil {
		return err
	}
	tag, err := l.tx.Exec(ctx, `UPDATE backup_custody_accounts SET server_time_high_water_milliseconds=$2 WHERE account_id=$1 AND server_time_high_water_milliseconds<=$2`, r.AccountID, high)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return backupcustody.ErrClockRollback
	}
	return l.tx.Commit(ctx)
}

func (store *BackupCustodyStore) BeginRetention(ctx context.Context, request backupcustody.RetentionProofRequest, requestBytes []byte, use backupcustody.CredentialUse, a serviceauthority.MutationAuthorization) (backupcustody.RetentionConfirmation, error) {
	if request.Validate() != nil || decodeExactRetentionRequest(requestBytes, request) != nil ||
		a.ValidateFor(serviceauthority.ScopeBackupCustody, store.localDeploymentID) != nil || a.Scope().ScopeID != request.Credential.AccountID {
		return nil, serviceauthority.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (backupcustody.RetentionConfirmation, error) { _ = tx.Rollback(ctx); return nil, e }
	high, err := store.lockAccountHighWater(ctx, tx, a)
	if err != nil {
		return fail(err)
	}
	credentialAuthority, err := loadAcceptedCredentialAuthority(ctx, tx, use, true)
	if err != nil || !reflect.DeepEqual(credentialAuthority.Grant.Credential, request.Credential) {
		if err != nil {
			return fail(err)
		}
		return fail(backupcustody.ErrUnauthorized)
	}
	var existingOperation string
	var existingRequest []byte
	err = tx.QueryRow(ctx, `SELECT operation,request_record FROM backup_custody_requests WHERE request_id=$1`, request.RequestID).Scan(&existingOperation, &existingRequest)
	if err == nil {
		if existingOperation != "retention" || !bytes.Equal(existingRequest, requestBytes) {
			return fail(backupcustody.ErrConflict)
		}
		existing, loadErr := loadRetentionTx(ctx, tx, request.Credential.AccountID, request.RequestID)
		if loadErr != nil {
			return fail(loadErr)
		}
		target, loadErr := loadTarget(ctx, tx, request.Credential.AccountID, request.Credential.TargetID, true)
		if loadErr != nil {
			return fail(loadErr)
		}
		generation, loadErr := loadGeneration(ctx, tx, request.Credential.AccountID, request.GenerationReferenceDigest)
		if loadErr != nil {
			return fail(loadErr)
		}
		if err := validateRetentionInputs(request, target, generation); err != nil {
			return fail(err)
		}
		return &backupRetention{store: store, tx: tx, authorization: a, target: target, generation: generation, existing: &existing, highWater: high, credentialAuthority: credentialAuthority}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fail(err)
	}
	target, err := loadTarget(ctx, tx, request.Credential.AccountID, request.Credential.TargetID, true)
	if err != nil {
		return fail(err)
	}
	generation, err := loadGeneration(ctx, tx, request.Credential.AccountID, request.GenerationReferenceDigest)
	if err != nil {
		return fail(err)
	}
	if err := validateRetentionInputs(request, target, generation); err != nil {
		return fail(err)
	}
	return &backupRetention{store: store, tx: tx, authorization: a, target: target, generation: generation, highWater: high, credentialAuthority: credentialAuthority}, nil
}

func (store *BackupCustodyStore) LoadRetentionByRequest(ctx context.Context, accountID, requestID uuid.UUID) (backupcustody.RetentionRecord, error) {
	return loadRetentionTx(ctx, store.pool, accountID, requestID)
}

func (store *BackupCustodyStore) ReadSnapshot(ctx context.Context, authorization backupcustody.ReadAuthorization, use backupcustody.CredentialUse, clock backupcustody.Clock, targetID uuid.UUID, requestedReference *string) (backupcustody.TargetRecord, backupcustody.GenerationRecord, error) {
	if clock == nil || authorization.Validate() != nil || authorization.DeploymentID() != store.localDeploymentID || targetID == uuid.Nil ||
		(requestedReference != nil && !canonicalHexDigest(*requestedReference)) {
		return backupcustody.TargetRecord{}, backupcustody.GenerationRecord{}, serviceauthority.ErrInvalid
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return backupcustody.TargetRecord{}, backupcustody.GenerationRecord{}, err
	}
	defer tx.Rollback(ctx)
	if err := store.lockReadAccount(ctx, tx, authorization); err != nil {
		return backupcustody.TargetRecord{}, backupcustody.GenerationRecord{}, err
	}
	credentialAuthority, err := loadAcceptedCredentialAuthority(ctx, tx, use, true)
	if err != nil || credentialAuthority.Grant.Credential.TargetID != targetID ||
		!credentialAuthority.Grant.Credential.Admits(backupcustody.Read, clock.Now().UnixMilli()) {
		if err != nil {
			return backupcustody.TargetRecord{}, backupcustody.GenerationRecord{}, err
		}
		return backupcustody.TargetRecord{}, backupcustody.GenerationRecord{}, backupcustody.ErrUnauthorized
	}
	target, err := loadTarget(ctx, tx, authorization.Scope().ScopeID, targetID, true)
	if err != nil {
		return backupcustody.TargetRecord{}, backupcustody.GenerationRecord{}, err
	}
	reference := requestedReference
	if reference == nil {
		reference = target.HeadReferenceDigest
	}
	if reference == nil {
		return backupcustody.TargetRecord{}, backupcustody.GenerationRecord{}, backupcustody.ErrNotFound
	}
	generation, err := loadGeneration(ctx, tx, target.AccountID, *reference)
	if err != nil || generation.Generation.TargetID != target.TargetID || generation.Generation.BackupSetID != target.BackupSetID {
		if err != nil {
			return backupcustody.TargetRecord{}, backupcustody.GenerationRecord{}, err
		}
		return backupcustody.TargetRecord{}, backupcustody.GenerationRecord{}, serviceauthority.ErrInvalid
	}
	if err := tx.Commit(ctx); err != nil {
		return backupcustody.TargetRecord{}, backupcustody.GenerationRecord{}, err
	}
	return target, generation, nil
}

func loadRetentionTx(ctx context.Context, q backupCustodyQuerier, accountID, requestID uuid.UUID) (backupcustody.RetentionRecord, error) {
	var r backupcustody.RetentionRecord
	var requestBytes, receiptBytes []byte
	var reference, credentialGrantReference, controlHeadReference string
	var issuedAt int64
	err := q.QueryRow(ctx, `SELECT request_record,receipt_record,receipt_reference_digest,credential_grant_reference_digest,control_head_reference_digest,issued_at_milliseconds FROM backup_custody_retention_receipts WHERE account_id=$1 AND request_id=$2`, accountID, requestID).Scan(&requestBytes, &receiptBytes, &reference, &credentialGrantReference, &controlHeadReference, &issuedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, backupcustody.ErrNotFound
	}
	if err != nil {
		return r, err
	}
	if decodeCanonical(requestBytes, &r.Request) != nil {
		return r, serviceauthority.ErrInvalid
	}
	receipt, err := serviceauthority.DecodeBackupCustodyReceipt(receiptBytes)
	if err != nil {
		return r, err
	}
	r.AccountID = accountID
	r.RequestBytes = requestBytes
	r.Receipt = receipt
	r.ReceiptBytes = receiptBytes
	r.ReceiptReferenceDigest = reference
	if r.ValidateStored() != nil {
		return r, serviceauthority.ErrInvalid
	}
	payload, payloadErr := r.Receipt.VerifiedPayload()
	if r.AccountID != accountID || r.Request.RequestID != requestID || payloadErr != nil || payload.IssuedAtMilliseconds != issuedAt ||
		payload.CredentialGrantReferenceDigest != credentialGrantReference || payload.ControlHeadReferenceDigest != controlHeadReference {
		return r, serviceauthority.ErrInvalid
	}
	if err := validateHistoricalCredentialProjection(ctx, q, accountID, payload.CredentialID,
		payload.CredentialGrantReferenceDigest, payload.ControlHeadReferenceDigest, nil,
		backupcustody.RetentionProof, payload.IssuedAtMilliseconds); err != nil {
		return r, err
	}
	var operation string
	var ledgerBytes []byte
	if err := q.QueryRow(ctx, `SELECT operation,request_record FROM backup_custody_requests WHERE account_id=$1 AND request_id=$2`, accountID, requestID).Scan(&operation, &ledgerBytes); err != nil ||
		operation != "retention" || !bytes.Equal(ledgerBytes, requestBytes) {
		return r, serviceauthority.ErrInvalid
	}
	anchor, manifest, err := loadAuthority(ctx, q, payload.Authority)
	if err != nil {
		return r, err
	}
	if authorized, err := r.Receipt.Authorize(anchor, manifest); err != nil ||
		!reflect.DeepEqual(authorized.Generation, payload.Generation) {
		return r, serviceauthority.ErrInvalid
	}
	custody, err := loadGeneration(ctx, q, accountID, r.Request.GenerationReferenceDigest)
	if err != nil || custody.CustodyReceiptReferenceDigest != r.Request.CustodyReceiptReferenceDigest ||
		!reflect.DeepEqual(custody.Generation, payload.Generation) {
		if err != nil {
			return r, err
		}
		return r, serviceauthority.ErrInvalid
	}
	return r, nil
}

func (store *BackupCustodyStore) ResolveBackupCustodyAuthority(ctx context.Context, authority serviceauthority.BackupCustodyAuthorityContext) (serviceauthority.TrustAnchor, serviceauthority.Manifest, error) {
	return loadAuthority(ctx, store.pool, authority)
}

func (store *BackupCustodyStore) lockAccount(ctx context.Context, tx pgx.Tx, a serviceauthority.MutationAuthorization) error {
	_, err := store.lockAccountHighWater(ctx, tx, a)
	return err
}
func (store *BackupCustodyStore) lockAccountHighWater(ctx context.Context, tx pgx.Tx, a serviceauthority.MutationAuthorization) (int64, error) {
	if err := a.ValidateFor(serviceauthority.ScopeBackupCustody, store.localDeploymentID); err != nil {
		return 0, err
	}
	var rev int64
	var digest, state string
	var deployment uuid.UUID
	var high int64
	err := tx.QueryRow(ctx, `SELECT authority_revision,authority_manifest_digest,deployment_id,state,server_time_high_water_milliseconds FROM backup_custody_accounts WHERE account_id=$1 FOR UPDATE`, a.Scope().ScopeID).Scan(&rev, &digest, &deployment, &state, &high)
	if err != nil {
		return 0, err
	}
	if a.AuthorizedAtMilliseconds() < high {
		return high, backupcustody.ErrClockRollback
	}
	// Checkpoint 1 intentionally has no authority-successor acceptance seam.
	// Any registry migration makes the durable account fence fail closed until
	// a later reviewed history-reconciliation checkpoint updates both stores.
	if state != "writable" || rev <= 0 || uint64(rev) != a.AuthorityRevision() || digest != a.AuthorityManifestDigest() || deployment != a.DeploymentID() {
		return high, backupcustody.ErrUnauthorized
	}
	tag, err := tx.Exec(ctx, `UPDATE backup_custody_accounts SET server_time_high_water_milliseconds=$2 WHERE account_id=$1 AND server_time_high_water_milliseconds<=$2`, a.Scope().ScopeID, a.AuthorizedAtMilliseconds())
	if err != nil {
		return high, err
	}
	if tag.RowsAffected() != 1 {
		return high, backupcustody.ErrClockRollback
	}
	return high, nil
}

func (store *BackupCustodyStore) lockReadAccount(ctx context.Context, tx pgx.Tx, authorization backupcustody.ReadAuthorization) error {
	if authorization.Validate() != nil || authorization.DeploymentID() != store.localDeploymentID {
		return serviceauthority.ErrInvalid
	}
	var revision int64
	var digest, state string
	var deploymentID uuid.UUID
	var highWater int64
	if err := tx.QueryRow(ctx, `SELECT authority_revision,authority_manifest_digest,deployment_id,state,server_time_high_water_milliseconds FROM backup_custody_accounts WHERE account_id=$1 FOR UPDATE`, authorization.Scope().ScopeID).Scan(&revision, &digest, &deploymentID, &state, &highWater); err != nil {
		return err
	}
	if authorization.AuthorizedAtMilliseconds() < highWater {
		return backupcustody.ErrClockRollback
	}
	if state != backupcustody.AccountStateWritable || revision <= 0 || uint64(revision) != authorization.AuthorityRevision() ||
		digest != authorization.AuthorityManifestDigest() || deploymentID != authorization.DeploymentID() {
		return backupcustody.ErrUnauthorized
	}
	tag, err := tx.Exec(ctx, `UPDATE backup_custody_accounts SET server_time_high_water_milliseconds=$2 WHERE account_id=$1 AND server_time_high_water_milliseconds<=$2`, authorization.Scope().ScopeID, authorization.AuthorizedAtMilliseconds())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return backupcustody.ErrClockRollback
	}
	return nil
}

func canonicalAccountClaim(record backupcustody.AccountRecord) []byte {
	encoded, _ := json.Marshal(struct {
		AccountID                    uuid.UUID                               `json:"accountID"`
		ClaimID                      uuid.UUID                               `json:"claimID"`
		Admission                    backupcustody.AccountAdmissionReference `json:"admission"`
		AdmissionAuthorizationDigest string                                  `json:"admissionAuthorizationDigest"`
		AuthorityManifestDigest      string                                  `json:"authorityManifestDigest"`
		AuthorityRevision            uint64                                  `json:"authorityRevision"`
		DeploymentID                 uuid.UUID                               `json:"deploymentID"`
		InitialControlAnchor         backupcustody.ControlPossessionAnchor   `json:"initialControlAnchor"`
		InitialEnrollmentRecord      []byte                                  `json:"initialEnrollmentRecord"`
		CreatedAtMilliseconds        int64                                   `json:"createdAtMilliseconds"`
	}{record.AccountID, record.ClaimID, record.Admission, record.AdmissionAuthorizationDigest,
		record.AuthorityManifestDigest, record.AuthorityRevision, record.DeploymentID,
		record.InitialControlAnchor, record.InitialEnrollmentRecord, record.CreatedAtMilliseconds})
	return encoded
}

func insertRequest(ctx context.Context, tx pgx.Tx, id, account uuid.UUID, operation string, record []byte) error {
	tag, err := tx.Exec(ctx, `INSERT INTO backup_custody_requests(request_id,account_id,operation,request_record)VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, id, account, operation, record)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var existingAccount uuid.UUID
	var existingOperation string
	var existing []byte
	if err := tx.QueryRow(ctx, `SELECT account_id,operation,request_record FROM backup_custody_requests WHERE request_id=$1`, id).Scan(&existingAccount, &existingOperation, &existing); err != nil {
		return err
	}
	if existingAccount != account || existingOperation != operation || !bytes.Equal(existing, record) {
		return backupcustody.ErrConflict
	}
	return nil
}

func loadAccountClaim(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, accountID, claimID, admissionID uuid.UUID) (backupcustody.AccountRecord, string, error) {
	var record backupcustody.AccountRecord
	var admissionBytes []byte
	var storedAdmissionID uuid.UUID
	var state string
	err := q.QueryRow(ctx, `SELECT account_id,claim_id,admission_id,admission_record,admission_authorization_digest,authority_revision,authority_manifest_digest,deployment_id,initial_anchor_record,initial_manifest_record,initial_enrollment_record,created_at_milliseconds,state FROM backup_custody_accounts WHERE account_id=$1 AND claim_id=$2 AND admission_id=$3`, accountID, claimID, admissionID).Scan(
		&record.AccountID, &record.ClaimID, &storedAdmissionID, &admissionBytes, &record.AdmissionAuthorizationDigest,
		&record.AuthorityRevision, &record.AuthorityManifestDigest, &record.DeploymentID, &record.InitialAnchorRecord,
		&record.InitialManifestRecord, &record.InitialEnrollmentRecord, &record.CreatedAtMilliseconds, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return record, "", backupcustody.ErrNotFound
	}
	if err != nil {
		return record, "", err
	}
	var enrollment serviceauthority.InitialEnrollment
	if decodeCanonical(admissionBytes, &record.Admission) != nil || record.Admission.Validate() != nil ||
		decodeCanonical(record.InitialEnrollmentRecord, &enrollment) != nil || record.AccountID != accountID ||
		record.ClaimID != claimID || storedAdmissionID != admissionID || record.Admission.AdmissionID != admissionID ||
		record.Admission.AccountID != accountID || record.AuthorityRevision != 1 || record.DeploymentID == uuid.Nil ||
		record.CreatedAtMilliseconds < 0 || !canonicalHexDigest(record.AdmissionAuthorizationDigest) ||
		!canonicalHexDigest(record.AuthorityManifestDigest) ||
		(state != backupcustody.AccountStateStandby && state != backupcustody.AccountStateWritable) {
		return record, "", serviceauthority.ErrInvalid
	}
	expectedScope := serviceauthority.Scope{Kind: serviceauthority.ScopeBackupCustody, ScopeID: accountID}
	payload, enrollmentErr := enrollment.ValidateForAdmissionClaim(expectedScope)
	anchorBytes, anchorErr := json.Marshal(enrollment.Anchor)
	manifestBytes, manifestErr := json.Marshal(enrollment.Manifest)
	digest, digestErr := enrollment.Manifest.ReferenceDigest()
	if enrollmentErr != nil || anchorErr != nil || manifestErr != nil || digestErr != nil ||
		payload.Revision != record.AuthorityRevision || payload.ActiveDeployment.DeploymentID != record.DeploymentID ||
		digest != record.AuthorityManifestDigest || !bytes.Equal(anchorBytes, record.InitialAnchorRecord) ||
		!bytes.Equal(manifestBytes, record.InitialManifestRecord) {
		return record, "", serviceauthority.ErrInvalid
	}
	var controlAnchorBytes []byte
	var controlAnchorReference string
	var headSequence, controlGeneration int64
	var headReference string
	var controlKeyID uuid.UUID
	if err := q.QueryRow(ctx, `SELECT initial_anchor_record,initial_anchor_reference_digest,head_sequence,head_reference_digest,control_generation,control_key_id FROM backup_custody_account_control WHERE account_id=$1`, accountID).Scan(
		&controlAnchorBytes, &controlAnchorReference, &headSequence, &headReference, &controlGeneration, &controlKeyID); err != nil ||
		decodeCanonical(controlAnchorBytes, &record.InitialControlAnchor) != nil || record.InitialControlAnchor.VerifyPossession() != nil ||
		record.InitialControlAnchor.Unsigned.AccountID != accountID || record.InitialControlAnchor.Unsigned.ControlGeneration != 1 ||
		controlGeneration < 1 || controlKeyID == uuid.Nil || headSequence < 0 || !canonicalHexDigest(headReference) {
		return record, "", serviceauthority.ErrInvalid
	}
	computedControlReference, err := record.InitialControlAnchor.ReferenceDigest()
	if err != nil || computedControlReference != controlAnchorReference {
		return record, "", serviceauthority.ErrInvalid
	}
	var historyCount, requestCount int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM backup_custody_authority_history WHERE account_id=$1 AND authority_revision=$2 AND authority_manifest_digest=$3 AND deployment_id=$4 AND anchor_record=$5 AND manifest_record=$6 AND accepted_at_milliseconds=$7`, accountID, int64(record.AuthorityRevision), record.AuthorityManifestDigest, record.DeploymentID, record.InitialAnchorRecord, record.InitialManifestRecord, record.CreatedAtMilliseconds).Scan(&historyCount); err != nil {
		return record, "", err
	}
	if err := q.QueryRow(ctx, `SELECT count(*) FROM backup_custody_requests WHERE request_id=$1 AND account_id=$2 AND operation='account_claim' AND request_record=$3`, claimID, accountID, canonicalAccountClaim(record)).Scan(&requestCount); err != nil {
		return record, "", err
	}
	if historyCount != 1 || requestCount != 1 {
		return record, "", serviceauthority.ErrInvalid
	}
	return record, state, nil
}

func loadTarget(ctx context.Context, q backupCustodyQuerier, accountID, targetID uuid.UUID, lock bool) (backupcustody.TargetRecord, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	var r backupcustody.TargetRecord
	var headGen *int64
	err := q.QueryRow(ctx, `SELECT account_id,target_id,backup_set_id,create_control_command_reference_digest,created_at_milliseconds,head_generation,head_generation_reference_digest FROM backup_custody_targets WHERE account_id=$1 AND target_id=$2`+suffix, accountID, targetID).Scan(&r.AccountID, &r.TargetID, &r.BackupSetID, &r.CreateControlCommandReferenceDigest, &r.CreatedAtMilliseconds, &headGen, &r.HeadReferenceDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, backupcustody.ErrNotFound
	}
	if err != nil {
		return r, err
	}
	if r.AccountID != accountID || r.TargetID != targetID || r.CreatedAtMilliseconds < 0 ||
		!canonicalHexDigest(r.CreateControlCommandReferenceDigest) || (headGen == nil) != (r.HeadReferenceDigest == nil) {
		return r, serviceauthority.ErrInvalid
	}
	var effectKind string
	if err := q.QueryRow(ctx, `SELECT effect_kind FROM backup_custody_control_commands WHERE account_id=$1 AND command_reference_digest=$2`, accountID, r.CreateControlCommandReferenceDigest).Scan(&effectKind); err != nil ||
		effectKind != string(backupcustody.CreateTargetWithInitialGrant) {
		return r, serviceauthority.ErrInvalid
	}
	if headGen != nil {
		if *headGen <= 0 {
			return r, serviceauthority.ErrInvalid
		}
		generation, err := loadGenerationByNumber(ctx, q, accountID, targetID, *headGen)
		if err != nil {
			return r, err
		}
		if r.HeadReferenceDigest == nil || generation.GenerationReferenceDigest != *r.HeadReferenceDigest ||
			generation.Generation.BackupSetID != r.BackupSetID {
			return r, serviceauthority.ErrInvalid
		}
		r.Head = &generation.Generation
	}
	return r, nil
}
func targetEqual(a, b backupcustody.TargetRecord) bool {
	return a.AccountID == b.AccountID && a.TargetID == b.TargetID && a.BackupSetID == b.BackupSetID &&
		a.CreateControlCommandReferenceDigest == b.CreateControlCommandReferenceDigest &&
		a.CreatedAtMilliseconds == b.CreatedAtMilliseconds
}
func loadUpload(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, accountID, uploadID uuid.UUID, lock bool) (backupcustody.UploadRecord, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	var r backupcustody.UploadRecord
	var committed int64
	var maximumChunkCount int
	var state string
	var publishRequestID uuid.UUID
	err := q.QueryRow(ctx, `SELECT account_id,target_id,backup_set_id,upload_id,publish_request_id,request_record,committed_bytes,maximum_chunk_count,created_at_milliseconds,state FROM backup_custody_uploads WHERE account_id=$1 AND upload_id=$2`+suffix, accountID, uploadID).Scan(&r.AccountID, &r.TargetID, &r.BackupSetID, &r.UploadID, &publishRequestID, &r.RequestBytes, &committed, &maximumChunkCount, &r.CreatedAtMilliseconds, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, backupcustody.ErrNotFound
	}
	if err != nil {
		return r, err
	}
	if committed < 0 || decodeCanonical(r.RequestBytes, &r.Request) != nil || r.Request.Validate() != nil ||
		r.Request.Generation > math.MaxInt64 || r.AccountID != accountID || r.UploadID != uploadID ||
		publishRequestID != r.Request.RequestID ||
		r.Request.Credential.AccountID != r.AccountID || r.Request.Credential.TargetID != r.TargetID ||
		r.Request.Credential.BackupSetID != r.BackupSetID || r.CreatedAtMilliseconds < 0 ||
		maximumChunkCount <= 0 || (state != "uploading" && state != "committed") {
		return r, serviceauthority.ErrInvalid
	}
	r.CommittedBytes = uint64(committed)
	r.Committed = state == "committed"
	r.MaximumChunkCount = maximumChunkCount
	var chunkCount int
	var minimumOffset, maximumNext, totalBytes int64
	var exactArithmetic, contiguous bool
	if err := q.QueryRow(ctx, `
		SELECT count(*),
		       COALESCE(min(chunk_offset),0),
		       COALESCE(max(next_offset),0),
		       COALESCE(sum(chunk_byte_count),0),
		       COALESCE(bool_and(next_offset=chunk_offset+chunk_byte_count),true),
		       COALESCE(bool_and(
		           (previous_next IS NULL AND chunk_offset=0) OR
		           (previous_next IS NOT NULL AND chunk_offset=previous_next)
		       ),true)
		FROM (
			SELECT chunk_offset,chunk_byte_count,next_offset,
			       lag(next_offset) OVER (ORDER BY chunk_offset) AS previous_next
			FROM backup_custody_upload_chunks
			WHERE account_id=$1 AND upload_id=$2
		) ordered_chunks`, accountID, uploadID).Scan(&chunkCount, &minimumOffset, &maximumNext, &totalBytes, &exactArithmetic, &contiguous); err != nil ||
		chunkCount < 0 || chunkCount > maximumChunkCount || minimumOffset != 0 || totalBytes != committed || maximumNext != committed || !exactArithmetic || !contiguous ||
		(committed == 0) != (chunkCount == 0) {
		return r, serviceauthority.ErrInvalid
	}
	var operation string
	var ledgerBytes []byte
	if err := q.QueryRow(ctx, `SELECT operation,request_record FROM backup_custody_requests WHERE account_id=$1 AND request_id=$2`, accountID, publishRequestID).Scan(&operation, &ledgerBytes); err != nil ||
		operation != "begin_upload" || !bytes.Equal(ledgerBytes, r.RequestBytes) {
		return r, serviceauthority.ErrInvalid
	}
	return r, nil
}
func loadGenerationByUpload(ctx context.Context, q backupCustodyQuerier, accountID, uploadID uuid.UUID) (backupcustody.GenerationRecord, error) {
	record, err := scanGeneration(q.QueryRow(ctx, `SELECT account_id,target_id,backup_set_id,generation,upload_id,outer_byte_count,outer_digest,generation_record,generation_reference_digest,object_path,custody_receipt_record,custody_receipt_reference_digest,credential_grant_reference_digest,control_head_reference_digest FROM backup_custody_generations WHERE account_id=$1 AND upload_id=$2`, accountID, uploadID))
	if err == nil && (record.Generation.AccountID != accountID || record.Generation.UploadID != uploadID) {
		return record, serviceauthority.ErrInvalid
	}
	if err == nil {
		err = validateGenerationLinks(ctx, q, record)
	}
	return record, err
}
func loadGeneration(ctx context.Context, q backupCustodyQuerier, accountID uuid.UUID, reference string) (backupcustody.GenerationRecord, error) {
	record, err := scanGeneration(q.QueryRow(ctx, `SELECT account_id,target_id,backup_set_id,generation,upload_id,outer_byte_count,outer_digest,generation_record,generation_reference_digest,object_path,custody_receipt_record,custody_receipt_reference_digest,credential_grant_reference_digest,control_head_reference_digest FROM backup_custody_generations WHERE account_id=$1 AND generation_reference_digest=$2`, accountID, reference))
	if err == nil && (record.Generation.AccountID != accountID || record.GenerationReferenceDigest != reference) {
		return record, serviceauthority.ErrInvalid
	}
	if err == nil {
		err = validateGenerationLinks(ctx, q, record)
	}
	return record, err
}
func loadGenerationByNumber(ctx context.Context, q backupCustodyQuerier, accountID, targetID uuid.UUID, generation int64) (backupcustody.GenerationRecord, error) {
	record, err := scanGeneration(q.QueryRow(ctx, `SELECT account_id,target_id,backup_set_id,generation,upload_id,outer_byte_count,outer_digest,generation_record,generation_reference_digest,object_path,custody_receipt_record,custody_receipt_reference_digest,credential_grant_reference_digest,control_head_reference_digest FROM backup_custody_generations WHERE account_id=$1 AND target_id=$2 AND generation=$3`, accountID, targetID, generation))
	if err == nil && (record.Generation.AccountID != accountID || record.Generation.TargetID != targetID ||
		record.Generation.Generation > math.MaxInt64 || int64(record.Generation.Generation) != generation) {
		return record, serviceauthority.ErrInvalid
	}
	if err == nil {
		err = validateGenerationLinks(ctx, q, record)
	}
	return record, err
}
func scanGeneration(row pgx.Row) (backupcustody.GenerationRecord, error) {
	var r backupcustody.GenerationRecord
	var genBytes, receiptBytes []byte
	var accountID, targetID, backupSetID, uploadID uuid.UUID
	var generation, outerByteCount int64
	var outerDigest string
	var grantReference, headReference string
	err := row.Scan(&accountID, &targetID, &backupSetID, &generation, &uploadID, &outerByteCount, &outerDigest,
		&genBytes, &r.GenerationReferenceDigest, &r.ObjectPath, &receiptBytes, &r.CustodyReceiptReferenceDigest,
		&grantReference, &headReference)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, backupcustody.ErrNotFound
	}
	if err != nil {
		return r, err
	}
	if generation <= 0 || outerByteCount <= 0 || decodeCanonical(genBytes, &r.Generation) != nil ||
		r.Generation.AccountID != accountID || r.Generation.TargetID != targetID || r.Generation.BackupSetID != backupSetID ||
		r.Generation.UploadID != uploadID || r.Generation.Generation > math.MaxInt64 || int64(r.Generation.Generation) != generation ||
		r.Generation.OuterByteCount > math.MaxInt64 || int64(r.Generation.OuterByteCount) != outerByteCount || r.Generation.OuterDigest != outerDigest {
		return r, serviceauthority.ErrInvalid
	}
	receipt, err := serviceauthority.DecodeBackupCustodyReceipt(receiptBytes)
	if err != nil {
		return r, err
	}
	r.CustodyReceipt = receipt
	r.CustodyReceiptBytes = receiptBytes
	payload, payloadErr := receipt.VerifiedPayload()
	if payloadErr != nil || payload.CredentialGrantReferenceDigest != grantReference ||
		payload.ControlHeadReferenceDigest != headReference || r.ValidateStored() != nil {
		return r, serviceauthority.ErrInvalid
	}
	return r, nil
}

func validateGenerationLinks(ctx context.Context, q backupCustodyQuerier, record backupcustody.GenerationRecord) error {
	upload, err := loadUpload(ctx, q, record.Generation.AccountID, record.Generation.UploadID, false)
	if err != nil || !upload.Committed || upload.TargetID != record.Generation.TargetID ||
		upload.BackupSetID != record.Generation.BackupSetID || upload.Request.Generation != record.Generation.Generation ||
		upload.CommittedBytes != record.Generation.OuterByteCount {
		return serviceauthority.ErrInvalid
	}
	payload, err := record.CustodyReceipt.VerifiedPayload()
	if err != nil || payload.RequestID != upload.Request.RequestID ||
		payload.CredentialID != upload.Request.Credential.CredentialID ||
		payload.Authority.Scope.ScopeID != record.Generation.AccountID {
		return serviceauthority.ErrInvalid
	}
	anchor, manifest, err := loadAuthority(ctx, q, payload.Authority)
	if err != nil {
		return err
	}
	if authorized, err := record.CustodyReceipt.Authorize(anchor, manifest); err != nil ||
		!reflect.DeepEqual(authorized.Generation, record.Generation) {
		return serviceauthority.ErrInvalid
	}
	var backupSetID uuid.UUID
	if err := q.QueryRow(ctx, `SELECT backup_set_id FROM backup_custody_targets WHERE account_id=$1 AND target_id=$2`, record.Generation.AccountID, record.Generation.TargetID).Scan(&backupSetID); err != nil ||
		backupSetID != record.Generation.BackupSetID {
		return serviceauthority.ErrInvalid
	}
	if err := validateHistoricalCredentialProjection(ctx, q, record.Generation.AccountID, payload.CredentialID,
		payload.CredentialGrantReferenceDigest, payload.ControlHeadReferenceDigest, nil,
		backupcustody.Publish, payload.IssuedAtMilliseconds); err != nil {
		return err
	}
	return nil
}

func loadAuthority(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, authority serviceauthority.BackupCustodyAuthorityContext) (serviceauthority.TrustAnchor, serviceauthority.Manifest, error) {
	if authority.Validate() != nil || authority.Scope.Kind != serviceauthority.ScopeBackupCustody || authority.AuthorityRevision > math.MaxInt64 {
		return serviceauthority.TrustAnchor{}, serviceauthority.Manifest{}, serviceauthority.ErrInvalid
	}
	var anchorBytes, manifestBytes []byte
	err := q.QueryRow(ctx, `SELECT anchor_record,manifest_record FROM backup_custody_authority_history WHERE account_id=$1 AND authority_revision=$2 AND authority_manifest_digest=$3 AND deployment_id=$4`, authority.Scope.ScopeID, int64(authority.AuthorityRevision), authority.AuthorityManifestDigest, authority.DeploymentID).Scan(&anchorBytes, &manifestBytes)
	if err != nil {
		return serviceauthority.TrustAnchor{}, serviceauthority.Manifest{}, err
	}
	var anchor serviceauthority.TrustAnchor
	var manifest serviceauthority.Manifest
	if decodeCanonical(anchorBytes, &anchor) != nil || decodeCanonical(manifestBytes, &manifest) != nil {
		return anchor, manifest, serviceauthority.ErrInvalid
	}
	payload, payloadErr := manifest.VerifiedPayload()
	digest, digestErr := manifest.ReferenceDigest()
	if payloadErr != nil || digestErr != nil || anchor.Validate() != nil || anchor.Scope != authority.Scope ||
		payload.Scope != authority.Scope || payload.Revision != authority.AuthorityRevision ||
		payload.ActiveDeployment.DeploymentID != authority.DeploymentID || digest != authority.AuthorityManifestDigest ||
		manifest.Signature.SignerID != anchor.SignerID || manifest.Signature.PublicSigningKeyX963 != anchor.PublicSigningKeyX963 ||
		manifest.Signature.SigningKeyFingerprint != anchor.SigningKeyFingerprint {
		return anchor, manifest, serviceauthority.ErrInvalid
	}
	return anchor, manifest, nil
}
func decodeCanonical(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return serviceauthority.ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return serviceauthority.ErrInvalid
	}
	encoded, err := json.Marshal(target)
	if err != nil || !bytes.Equal(encoded, data) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func canonicalHexDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func multiplyWithinInt64(left, right int64) (int64, bool) {
	if left < 0 || right < 0 || (left != 0 && right > math.MaxInt64/left) {
		return 0, true
	}
	return left * right, false
}

func decodeExactPublishRequest(encoded []byte, expected backupcustody.PublishRequest) error {
	var decoded backupcustody.PublishRequest
	if decodeCanonical(encoded, &decoded) != nil || !reflect.DeepEqual(decoded, expected) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func decodeExactRetentionRequest(encoded []byte, expected backupcustody.RetentionProofRequest) error {
	var decoded backupcustody.RetentionProofRequest
	if decodeCanonical(encoded, &decoded) != nil || !reflect.DeepEqual(decoded, expected) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func validateRetentionInputs(request backupcustody.RetentionProofRequest, target backupcustody.TargetRecord, generation backupcustody.GenerationRecord) error {
	if target.AccountID != request.Credential.AccountID || target.TargetID != request.Credential.TargetID ||
		target.BackupSetID != request.Credential.BackupSetID ||
		generation.ValidateStored() != nil || generation.Generation.AccountID != target.AccountID ||
		generation.Generation.TargetID != target.TargetID || generation.Generation.BackupSetID != target.BackupSetID ||
		generation.GenerationReferenceDigest != request.GenerationReferenceDigest ||
		generation.CustodyReceiptReferenceDigest != request.CustodyReceiptReferenceDigest {
		return serviceauthority.ErrInvalid
	}
	return nil
}

var _ backupcustody.Store = (*BackupCustodyStore)(nil)
var _ backupcustody.AuthorityHistory = (*BackupCustodyStore)(nil)

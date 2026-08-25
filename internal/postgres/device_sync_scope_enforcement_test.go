package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type deviceSyncEnforcementMigrationFixture struct {
	AuthorityAnchor           serviceauthority.TrustAnchor `json:"authorityAnchor"`
	PreparationEvidenceDigest string                       `json:"preparationEvidenceDigest"`
	RollbackEvidenceDigest    string                       `json:"rollbackEvidenceDigest"`
	RollbackEvidence          struct {
		ActivationEvidence struct {
			Preparation serviceauthority.MigrationPreparation `json:"preparation"`
			Snapshot    serviceauthority.MigrationSnapshot    `json:"snapshot"`
		} `json:"activationEvidence"`
		RollbackManifest serviceauthority.Manifest `json:"rollbackManifest"`
	} `json:"rollbackEvidence"`
}

func TestDeviceSyncScopeAuthorityRequiresExactCanonicalEvidence(t *testing.T) {
	fixture := loadDeviceSyncEnforcementMigrationFixture(t)
	current := fixture.RollbackEvidence.ActivationEvidence.Preparation.CurrentManifest
	preparation := fixture.RollbackEvidence.ActivationEvidence.Preparation.PreparationManifest

	currentVerified, err := current.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	currentPayload, err := current.Authorize(
		fixture.AuthorityAnchor, currentVerified.ValidFromMilliseconds,
	)
	currentAuthority, authorityErr := DeviceSyncScopeAuthorityFromManifest(
		current, nil, currentVerified.ValidFromMilliseconds,
	)
	if err != nil || authorityErr != nil || currentPayload.Revision != 1 ||
		currentAuthority.Revision != 1 ||
		currentAuthority.TransitionEvidenceDigest != nil {
		t.Fatalf("fresh authority payload=%+v authority=%+v err=%v/%v", currentPayload, currentAuthority, err, authorityErr)
	}
	if _, err := preparation.Authorize(
		fixture.AuthorityAnchor, currentVerified.ValidFromMilliseconds,
	); !errors.Is(err, serviceauthority.ErrInvalid) {
		t.Fatalf("migration preparation accepted as fresh activation: %v", err)
	}

	preparationAuthority, err := DeviceSyncScopeAuthorityFromManifest(
		preparation, &fixture.PreparationEvidenceDigest, 2_000,
	)
	if err != nil || preparationAuthority.Revision != 2 ||
		preparationAuthority.TransitionEvidenceDigest == nil ||
		*preparationAuthority.TransitionEvidenceDigest != fixture.PreparationEvidenceDigest {
		t.Fatalf("preparation authority=%+v err=%v", preparationAuthority, err)
	}
	if _, err := DeviceSyncScopeAuthorityFromManifest(
		preparation, nil, 2_000,
	); !errors.Is(err, serviceauthority.ErrInvalid) {
		t.Fatalf("missing preparation evidence digest error=%v", err)
	}
	unexpectedEvidence := fixture.PreparationEvidenceDigest
	if _, err := DeviceSyncScopeAuthorityFromManifest(
		current, &unexpectedEvidence, currentVerified.ValidFromMilliseconds,
	); !errors.Is(err, serviceauthority.ErrInvalid) {
		t.Fatalf("unexpected initial evidence digest error=%v", err)
	}
	upperEvidence := strings.ToUpper(fixture.PreparationEvidenceDigest)
	if _, err := DeviceSyncScopeAuthorityFromManifest(
		preparation, &upperEvidence, 2_000,
	); !errors.Is(err, serviceauthority.ErrInvalid) {
		t.Fatalf("uppercase evidence digest error=%v", err)
	}
	if _, err := decodeCanonicalDeviceSyncAuthorityManifest(
		append(append([]byte(nil), preparationAuthority.ManifestRecord...), '\n'),
	); !errors.Is(err, serviceauthority.ErrInvalid) {
		t.Fatalf("non-canonical Manifest record error=%v", err)
	}
}

func TestDeviceSyncSnapshotPayloadRequiresSignableCanonicalBytes(t *testing.T) {
	fixture := loadDeviceSyncEnforcementMigrationFixture(t)
	snapshotPayload := fixture.RollbackEvidence.ActivationEvidence.Snapshot.Payload
	parsed, digest, err := decodeCanonicalDeviceSyncSnapshotPayload(snapshotPayload, nil)
	expectedDigest := sha256.Sum256(snapshotPayload)
	if err != nil || parsed.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		digest != hex.EncodeToString(expectedDigest[:]) {
		t.Fatalf("snapshot payload=%+v digest=%s err=%v", parsed, digest, err)
	}

	nonCanonical := append(append([]byte(nil), snapshotPayload...), '\n')
	if _, _, err := decodeCanonicalDeviceSyncSnapshotPayload(
		nonCanonical, nil,
	); !errors.Is(err, serviceauthority.ErrInvalid) {
		t.Fatalf("non-canonical snapshot error=%v", err)
	}
	if _, _, err := decodeCanonicalDeviceSyncSnapshotPayload(
		make([]byte, maximumDeviceSyncSnapshotPayloadByteCount+1), nil,
	); !errors.Is(err, serviceauthority.ErrInvalid) {
		t.Fatalf("oversized snapshot error=%v", err)
	}

	var withUnknown map[string]any
	if err := json.Unmarshal(snapshotPayload, &withUnknown); err != nil {
		t.Fatal(err)
	}
	withUnknown["unknown"] = true
	unknownPayload, err := json.Marshal(withUnknown)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeCanonicalDeviceSyncSnapshotPayload(
		unknownPayload, nil,
	); !errors.Is(err, serviceauthority.ErrInvalid) {
		t.Fatalf("unknown snapshot field error=%v", err)
	}

	now := parsed.ExpiresAtMilliseconds
	if _, _, err := decodeCanonicalDeviceSyncSnapshotPayload(
		snapshotPayload, &now,
	); !errors.Is(err, serviceauthority.ErrInvalid) {
		t.Fatalf("expired snapshot error=%v", err)
	}
}

func TestDeviceSyncMutationExpectationBindsDeploymentRevisionDigestAndTime(t *testing.T) {
	fixture := loadDeviceSyncEnforcementMigrationFixture(t)
	manifest := fixture.RollbackEvidence.ActivationEvidence.Preparation.CurrentManifest
	payload, err := manifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := DeviceSyncScopeAuthorityFromManifest(
		manifest, nil, payload.ValidFromMilliseconds,
	)
	if err != nil {
		t.Fatal(err)
	}
	localDeploymentID := authority.ActiveDeploymentID
	current := DeviceSyncScopeEnforcement{
		PrincipalID:       payload.Scope.ScopeID,
		TenantID:          payload.Scope.ScopeID,
		State:             DeviceSyncScopeWritable,
		LocalDeploymentID: &localDeploymentID,
		Authority:         &authority,
	}
	if err := validateDeviceSyncMutationExpectation(
		current, localDeploymentID, authority.Revision,
		authority.ManifestDigest, payload.ValidFromMilliseconds,
	); err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name       string
		deployment uuid.UUID
		revision   uint64
		digest     string
		now        int64
	}{
		{"nil deployment", uuid.Nil, authority.Revision, authority.ManifestDigest, payload.ValidFromMilliseconds},
		{"wrong deployment", uuid.New(), authority.Revision, authority.ManifestDigest, payload.ValidFromMilliseconds},
		{"zero revision", localDeploymentID, 0, authority.ManifestDigest, payload.ValidFromMilliseconds},
		{"wrong revision", localDeploymentID, authority.Revision + 1, authority.ManifestDigest, payload.ValidFromMilliseconds},
		{"wrong digest", localDeploymentID, authority.Revision, strings.Repeat("0", 64), payload.ValidFromMilliseconds},
		{"future authority", localDeploymentID, authority.Revision, authority.ManifestDigest, payload.ValidFromMilliseconds - 1},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := validateDeviceSyncMutationExpectation(
				current, check.deployment, check.revision, check.digest, check.now,
			); err == nil {
				t.Fatal("mismatched mutation expectation was accepted")
			}
		})
	}

	wrongScope := current
	wrongScope.PrincipalID = uuid.New()
	if err := validateDeviceSyncMutationExpectation(
		wrongScope, localDeploymentID, authority.Revision,
		authority.ManifestDigest, payload.ValidFromMilliseconds,
	); err == nil {
		t.Fatal("authority Manifest for another scope was accepted")
	}
	fenced := current
	fenced.State = DeviceSyncScopeExportFenced
	if err := validateDeviceSyncMutationExpectation(
		fenced, localDeploymentID, authority.Revision,
		authority.ManifestDigest, payload.ValidFromMilliseconds,
	); !errors.Is(err, devicesync.ErrScopeWriteFenced) {
		t.Fatalf("fenced mutation error=%v", err)
	}

	rollback := fixture.RollbackEvidence.RollbackManifest
	rollbackPayload, err := rollback.VerifiedPayload()
	if err != nil || rollbackPayload.ValidUntilMilliseconds == nil {
		t.Fatalf("rollback payload=%+v err=%v", rollbackPayload, err)
	}
	rollbackAuthority, err := DeviceSyncScopeAuthorityFromManifest(
		rollback, &fixture.RollbackEvidenceDigest,
		rollbackPayload.ValidFromMilliseconds,
	)
	if err != nil {
		t.Fatal(err)
	}
	rollbackLocal := rollbackAuthority.ActiveDeploymentID
	stale := DeviceSyncScopeEnforcement{
		PrincipalID: rollbackPayload.Scope.ScopeID, TenantID: rollbackPayload.Scope.ScopeID,
		State: DeviceSyncScopeWritable, LocalDeploymentID: &rollbackLocal,
		Authority: &rollbackAuthority,
	}
	if err := validateDeviceSyncMutationExpectation(
		stale, rollbackLocal, rollbackAuthority.Revision,
		rollbackAuthority.ManifestDigest, *rollbackPayload.ValidUntilMilliseconds,
	); err == nil {
		t.Fatal("expired authority was accepted")
	}
}

func TestDeviceSyncScopeWriteFenceErrorHasStableSentinel(t *testing.T) {
	err := &deviceSyncScopeWriteFenceError{state: DeviceSyncScopeExportFenced}
	if !errors.Is(err, devicesync.ErrScopeWriteFenced) ||
		!strings.Contains(err.Error(), string(DeviceSyncScopeExportFenced)) {
		t.Fatalf("write-fence error=%v", err)
	}
}

func TestDeviceSyncMigrationImportCandidateAuthenticatesHistoricalEvidence(
	t *testing.T,
) {
	fixture := loadDeviceSyncEnforcementMigrationFixture(t)
	preparation := fixture.RollbackEvidence.ActivationEvidence.Preparation
	snapshot := fixture.RollbackEvidence.ActivationEvidence.Snapshot
	prepared, err := preparation.PreparationManifest.VerifiedPayload()
	if err != nil || len(prepared.PreparedDeployments) != 1 {
		t.Fatalf("prepared payload=%+v err=%v", prepared, err)
	}
	initial := DeviceSyncInitialAuthorityEvidence{
		Manifest:                preparation.CurrentManifest,
		ValidatedAtMilliseconds: 1_100,
	}
	candidate, _, err := buildDeviceSyncMigrationImportCandidate(
		prepared.PreparedDeployments[0].DeploymentID,
		preparation, snapshot, fixture.AuthorityAnchor, initial, 20_001,
	)
	if err != nil || candidate.MigrationID == uuid.Nil ||
		candidate.ImportedAtMilliseconds != 20_001 ||
		candidate.ServiceStateArtifactID == uuid.Nil ||
		candidate.PreparationManifestRecord == nil {
		t.Fatalf("candidate=%+v err=%v", candidate, err)
	}
	wrongAnchor := fixture.AuthorityAnchor
	wrongAnchor.SigningKeyFingerprint = strings.Repeat("0", 64)
	if _, _, err := buildDeviceSyncMigrationImportCandidate(
		prepared.PreparedDeployments[0].DeploymentID,
		preparation, snapshot, wrongAnchor, initial, 20_001,
	); !errors.Is(err, serviceauthority.ErrInvalid) {
		t.Fatalf("wrong authority anchor error=%v", err)
	}
	tampered := snapshot
	tampered.Payload = append(append([]byte(nil), snapshot.Payload...), '\n')
	if _, _, err := buildDeviceSyncMigrationImportCandidate(
		prepared.PreparedDeployments[0].DeploymentID,
		preparation, tampered, fixture.AuthorityAnchor, initial, 20_001,
	); !errors.Is(err, serviceauthority.ErrInvalid) {
		t.Fatalf("tampered signed snapshot error=%v", err)
	}
}

func TestDeviceSyncScopeEnforcementMigrationContainsHardConstraints(t *testing.T) {
	contents, err := migrationFiles.ReadFile(
		"migrations/041_device_sync_scope_enforcement.sql",
	)
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	required := []string{
		"state IN ('standby', 'writable', 'export_fenced', 'retired')",
		"local_deployment_id uuid",
		"active_migration_import_id uuid",
		"initial_claim_transaction_id xid8 NOT NULL",
		"device_sync_initial_claim_transaction_is_bound",
		"initial_authority_validated_at_milliseconds bigint",
		"authority_validated_at_milliseconds bigint",
		"CHECK (principal_id = tenant_id)",
		"canonical_snapshot_payload bytea NOT NULL",
		"octet_length(canonical_snapshot_payload) <= 262144",
		"UNIQUE (principal_id, migration_id, exporting_deployment_id)",
		"device_sync_scope_enforcement_active_fence_fk",
		"CREATE TABLE device_sync_migration_imports",
		"canonical_preparation_record bytea NOT NULL",
		"canonical_snapshot_record bytea NOT NULL",
		"canonical_artifact_descriptors bytea NOT NULL",
		"preparation_reference_digest",
		"device_sync_scope_enforcement_active_import_fk",
		"device_sync_migration_import_is_immutable",
		"'device_sync_migration_imports'",
		"device_sync_principal_requires_enforcement",
		"device_sync_principal_enforcement_is_permanent",
		"scope enforcement row cannot be deleted",
		"device_sync_initial_authority_is_immutable",
		"OLD.initial_authority_manifest_record IS DISTINCT FROM",
		"device_sync_migration_export_is_immutable",
		"device_sync_principal_is_permanent",
		"Device Sync principal % cannot be deleted",
		"preexisting Device Sync principals require an unreleased database reset",
		"require_device_sync_scope_writable(scope_id uuid)",
		"enforce_device_sync_scope_writable_mutation",
		"stored_initial_claim_transaction_id = current_transaction_id",
		"ds_writable_device_sync_account_admissions",
		"DEFERRABLE INITIALLY DEFERRED",
	}
	for _, fragment := range required {
		if !bytes.Contains(contents, []byte(fragment)) {
			t.Errorf("migration is missing %q", fragment)
		}
	}
	if strings.Contains(text, "INSERT INTO device_sync_scope_enforcement SELECT") {
		t.Fatal("migration unexpectedly backfills legacy Device Sync principals")
	}
	if strings.Contains(text, "xmin") {
		t.Fatal("standby exception unexpectedly depends on mutable tuple xmin")
	}
}

func loadDeviceSyncEnforcementMigrationFixture(
	t *testing.T,
) deviceSyncEnforcementMigrationFixture {
	t.Helper()
	contents, err := os.ReadFile("../serviceauthority/testdata/service-migration-portable-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture deviceSyncEnforcementMigrationFixture
	if err := json.Unmarshal(contents, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

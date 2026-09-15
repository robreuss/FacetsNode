package postgres_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/robreuss/FacetsNode/internal/backupcustody"
	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestPostgresBackupObjectScopeConsent(t *testing.T) {
	databaseURL := os.Getenv("FACETS_BACKUP_CONSENT_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_BACKUP_CONSENT_TEST_DATABASE_URL is not set")
	}
	parsed, err := url.Parse(databaseURL)
	if err != nil || parsed.Path != "/facets_backup_consent_tests" {
		t.Fatal("requires dedicated disposable consent database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	lockDisposablePostgres(t, ctx, databaseURL)
	pool := openPool(t, ctx, databaseURL)
	defer pool.Close()
	otherPool := openPool(t, ctx, databaseURL)
	defer otherPool.Close()
	resetBackupCustodySchema(t, ctx, pool)
	deployment, account := uuid.New(), uuid.New()
	limits := postgresstore.BackupCustodyStoreLimits{MaximumActiveUploads: 2, MaximumTargets: 2,
		MaximumGenerations: 4, MaximumRequests: 40, MaximumRetentionProofs: 4, MaximumControlRecords: 40,
		MaximumCredentialLifetimeMilliseconds: 10_000, MaximumChunksPerUpload: 4,
		MaximumChunkBytes: 1024, MaximumStagingBytes: 8192, MaximumCommittedBytes: 16384}
	openStore := func(p *pgxpool.Pool) *postgresstore.BackupCustodyStore {
		s, e := postgresstore.NewBackupCustodyStore(p, deployment, limits)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	store := openStore(pool)
	enrollment, deploymentSigner := backupPostgresEnrollment(t, account, deployment)
	manifest, _ := enrollment.Manifest.VerifiedPayload()
	digest, _ := enrollment.Manifest.ReferenceDigest()
	clock := &backupIntegrationClock{now: time.UnixMilli(1100)}
	registry := serviceauthority.NewBindingRegistry()
	parent := t.TempDir()
	if os.Chmod(parent, 0700) != nil {
		t.Fatal("private fixture directory")
	}
	journal, err := backupcustody.OpenPreparedAccountJournal(filepath.Join(parent, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	admission, err := backupcustody.NewAccountAdmissionCredential(backupcustody.AccountAdmissionReference{
		Version: 1, AccountID: account, AdmissionID: uuid.New(), ExpiresAtMilliseconds: 10_000,
		RequestNonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	owner := newBackupControlSigner(account, 1, 63)
	anchor := owner.anchor(t)
	provisioning := backupcustody.ProvisioningCustody{Store: store, Journal: journal, Registry: registry,
		Signer: deploymentSigner, Clock: clock}
	if err := provisioning.ProvisionAccount(ctx, admission, uuid.New(), enrollment, anchor); err != nil {
		t.Fatal(err)
	}
	binding := serviceauthority.RequestBinding{Scope: serviceauthority.Scope{Kind: serviceauthority.ScopeBackupCustody, ScopeID: account},
		AuthorityRevision: 1, AuthorityDigest: digest, DeploymentID: deployment,
		RouteID: manifest.ActiveDeployment.Routes[0].RouteID, TrafficClass: serviceauthority.TrafficControl}
	control := backupcustody.ControlCustody{Store: store, Registry: registry, Clock: clock}
	credential := backupIntegrationTarget(t, account, uuid.New(), uuid.New())
	create := backupCreateTargetCommand(t, owner, anchor, credential, uuid.New(), 1)
	created, err := control.Submit(ctx, create, binding)
	if err != nil {
		t.Fatal(err)
	}
	consent := backupcustody.ObjectScopeConsent{Version: 1, AccountID: account, TargetID: credential.Reference.TargetID,
		BackupSetID: credential.Reference.BackupSetID, BindingID: uuid.New(), ContentEpoch: 1, ContentScopeID: uuid.New(),
		LedgerID: uuid.New(), LinkID: uuid.New(), LinkIntentDigest: strings.Repeat("a", 64), PoolID: uuid.New()}
	command := func(effect backupcustody.ControlEffect, sequence uint64, prior string) backupcustody.SignedControlCommand {
		return backupSignedControlCommand(t, owner, nil, backupcustody.ControlCommandPayload{Version: 1,
			AccountID: account, CommandID: uuid.New(), ControlGeneration: owner.generation, ControlKeyID: owner.keyID,
			Sequence: sequence, PredecessorReferenceDigest: prior, Effect: effect})
	}
	consentCommand := command(backupcustody.ControlEffect{Kind: backupcustody.ConsentObjectScope, ObjectScopeConsent: &consent}, 2, created.CommandReferenceDigest)
	consentRef, _ := consent.ReferenceDigest()
	accepted, err := control.Submit(ctx, consentCommand, binding)
	if err != nil || accepted.CredentialGrantReferenceDigest != nil {
		t.Fatalf("consent acceptance: %v", err)
	}
	replay, err := control.Submit(ctx, consentCommand, binding)
	if err != nil || replay != accepted {
		t.Fatalf("lost response replay: %v", err)
	}

	// Reopen through an independent pool and independently activated registry:
	// no shared Go mutex can serialize the competing control commands below.
	otherRegistry := serviceauthority.NewBindingRegistry()
	if err := otherRegistry.Activate(binding.Scope, serviceauthority.CurrentBinding{Revision: 1, Digest: digest,
		DeploymentID: deployment, Manifest: &enrollment.Manifest}); err != nil {
		t.Fatal(err)
	}
	otherControl := backupcustody.ControlCustody{Store: openStore(otherPool), Registry: otherRegistry, Clock: clock}
	if err := otherControl.Store.ValidateControlLedger(ctx, account); err != nil {
		t.Fatal(err)
	}
	revokeA := command(backupcustody.ControlEffect{Kind: backupcustody.RevokeObjectScopeConsent, PriorObjectScopeConsentDigest: &consentRef}, 3, accepted.CommandReferenceDigest)
	revokeB := command(backupcustody.ControlEffect{Kind: backupcustody.RevokeObjectScopeConsent, PriorObjectScopeConsentDigest: &consentRef}, 3, accepted.CommandReferenceDigest)
	start := make(chan struct{})
	type outcome struct {
		acceptance backupcustody.ControlCommandAcceptance
		err        error
	}
	results := make(chan outcome, 2)
	var group sync.WaitGroup
	for _, job := range []struct {
		control backupcustody.ControlCustody
		command backupcustody.SignedControlCommand
	}{{control, revokeA}, {otherControl, revokeB}} {
		group.Add(1)
		go func(c backupcustody.ControlCustody, r backupcustody.SignedControlCommand) {
			defer group.Done()
			<-start
			a, e := c.Submit(ctx, r, binding)
			results <- outcome{a, e}
		}(job.control, job.command)
	}
	close(start)
	group.Wait()
	close(results)
	var winner backupcustody.ControlCommandAcceptance
	won, lost := 0, 0
	for r := range results {
		if r.err == nil {
			won++
			winner = r.acceptance
		} else if errors.Is(r.err, backupcustody.ErrConflict) {
			lost++
		} else {
			t.Fatal(r.err)
		}
	}
	if won != 1 || lost != 1 {
		t.Fatalf("competing revocations won=%d lost=%d", won, lost)
	}
	if err := otherControl.Store.ValidateControlLedger(ctx, account); err != nil {
		t.Fatal(err)
	}
	replay, err = otherControl.Submit(ctx, consentCommand, binding)
	if err != nil || replay != accepted {
		t.Fatalf("historical acceptance retry: %v", err)
	}
	state := readConsentProjection(t, ctx, otherPool, account, anchor)
	if state.Head.ReferenceDigest != winner.CommandReferenceDigest || !state.ObjectScopeConsents[consentRef].Revoked {
		t.Fatal("historical acceptance reactivated withdrawn consent")
	}
	if _, ok := state.ActiveGrant(credential.Reference.CredentialID); !ok {
		t.Fatal("consent changed target credential")
	}
	duplicate := command(backupcustody.ControlEffect{Kind: backupcustody.ConsentObjectScope, ObjectScopeConsent: &consent}, 4, winner.CommandReferenceDigest)
	if _, err := control.Submit(ctx, duplicate, binding); !errors.Is(err, backupcustody.ErrConflict) {
		t.Fatalf("binding resurrection: %v", err)
	}

	// The connection dies after command insertion but before the control-head
	// update/commit. A separate connection must see neither partial consent nor
	// an advanced head; the exact signed command remains retryable.
	next := consent
	next.BindingID, next.LinkID, next.LinkIntentDigest = uuid.New(), uuid.New(), strings.Repeat("b", 64)
	nextCommand := command(backupcustody.ControlEffect{Kind: backupcustody.ConsentObjectScope, ObjectScopeConsent: &next}, 4, winner.CommandReferenceDigest)
	if _, err := pool.Exec(ctx, `CREATE FUNCTION consent_test_disconnect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_terminate_backend(pg_backend_pid()); RETURN NEW; END $$;
		CREATE TRIGGER consent_test_disconnect BEFORE UPDATE ON backup_custody_account_control FOR EACH ROW EXECUTE FUNCTION consent_test_disconnect()`); err != nil {
		t.Fatal(err)
	}
	if _, err := control.Submit(ctx, nextCommand, binding); err == nil {
		t.Fatal("terminated write succeeded")
	}
	if _, err := otherPool.Exec(ctx, `DROP TRIGGER consent_test_disconnect ON backup_custody_account_control; DROP FUNCTION consent_test_disconnect()`); err != nil {
		t.Fatal(err)
	}
	state = readConsentProjection(t, ctx, otherPool, account, anchor)
	if state.Head.Sequence != 3 || len(state.ObjectScopeConsents) != 1 {
		t.Fatal("partial transaction escaped rollback")
	}
	if _, err := otherControl.Submit(ctx, nextCommand, binding); err != nil {
		t.Fatalf("retry after connection death: %v", err)
	}
	if err := otherControl.Store.ValidateControlLedger(ctx, account); err != nil {
		t.Fatal(err)
	}
	state = readConsentProjection(t, ctx, otherPool, account, anchor)
	if state.Head.Sequence != 4 || len(state.ObjectScopeConsents) != 2 {
		t.Fatal("retry did not persist exactly once")
	}

	// No custody data, uploads, target keys, or unsigned consent authority table.
	var effects int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM backup_custody_generations)+(SELECT count(*) FROM backup_custody_uploads)`).Scan(&effects); err != nil || effects != 0 {
		t.Fatalf("unexpected content effect: %d %v", effects, err)
	}
	wrongRoute := binding
	wrongRoute.AuthorityDigest = strings.Repeat("c", 64)
	if _, err := control.Submit(ctx, consentCommand, wrongRoute); err == nil {
		t.Fatal("stale authority replay accepted")
	}
	// Corrupt the durable signed record, not just a caller's input. A reopen
	// must fail instead of rebuilding a guessed consent projection.
	if _, err := pool.Exec(ctx, `UPDATE backup_custody_control_commands SET command_record=decode('00','hex') WHERE account_id=$1 AND sequence=2`, account); err != nil {
		t.Fatal(err)
	}
	if err := openStore(otherPool).ValidateControlLedger(ctx, account); err == nil {
		t.Fatal("corrupted signed consent accepted")
	}
}

func readConsentProjection(t *testing.T, ctx context.Context, pool *pgxpool.Pool, account uuid.UUID, anchor backupcustody.ControlPossessionAnchor) backupcustody.CredentialAuthorityState {
	t.Helper()
	state, err := backupcustody.NewCredentialAuthorityState(anchor)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := pool.Query(ctx, `SELECT command_record FROM backup_custody_control_commands WHERE account_id=$1 ORDER BY sequence`, account)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var encoded []byte
		if rows.Scan(&encoded) != nil {
			t.Fatal("read command")
		}
		command, err := backupcustody.DecodeSignedControlCommand(encoded)
		if err != nil || state.Apply(command) != nil {
			t.Fatalf("rebuild signed consent: %v", err)
		}
	}
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
	return state
}

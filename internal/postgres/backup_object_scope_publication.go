package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/robreuss/FacetsNode/internal/backupcustody"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

// These locks are source-service locks, not a cross-database effect commit.
type backupObjectScopePublication struct {
	tx      pgx.Tx
	store   *BackupCustodyStore
	use     backupcustody.CredentialUse
	request backupcustody.ObjectScopePublicationRequest
	initial serviceauthority.MutationAuthorization
	checked bool
}

func (store *BackupCustodyStore) BeginObjectScopePublication(ctx context.Context, use backupcustody.CredentialUse,
	r backupcustody.ObjectScopePublicationRequest, a serviceauthority.MutationAuthorization) (backupcustody.ObjectScopePublicationTransaction, error) {
	if r.Validate() != nil || use.Reference.Validate() != nil || !canonicalHexDigest(use.AuthorizationDigest) ||
		use.Reference.AccountID != r.Consent.AccountID || use.Reference.TargetID != r.Consent.TargetID ||
		use.Reference.BackupSetID != r.Consent.BackupSetID || a.Scope().ScopeID != r.Consent.AccountID {
		return nil, serviceauthority.ErrInvalid
	}
	use.Reference.Capabilities = append([]backupcustody.Capability(nil), use.Reference.Capabilities...)
	// First persist an authenticated clock floor. A killed connection during
	// the later held transaction must not erase this admission observation.
	// Recheck everything after reacquiring locks: revocation can win the gap.
	for pass := 0; pass < 2; pass++ {
		tx, err := store.pool.Begin(ctx)
		if err != nil {
			return nil, err
		}
		// Backstop the Go deadline if its process/connection becomes unreachable.
		// Local settings disappear with the transaction; no global DB tuning.
		if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout='30s'; SET LOCAL lock_timeout='30s'; SET LOCAL idle_in_transaction_session_timeout='35s'`); err != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = tx.Rollback(cleanup)
			cancel()
			return nil, err
		}
		lease := &backupObjectScopePublication{tx: tx, store: store, use: use, request: r, initial: a}
		if err := lease.Revalidate(ctx, a); err != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = tx.Rollback(cleanup)
			cancel()
			return nil, err
		}
		if pass == 1 {
			return lease, nil
		}
		if err := lease.Close(ctx); err != nil {
			return nil, err
		}
	}
	return nil, serviceauthority.ErrInvalid
}

func (l *backupObjectScopePublication) Revalidate(ctx context.Context, a serviceauthority.MutationAuthorization) error {
	if a.Scope() != l.initial.Scope() || a.AuthorityRevision() != l.initial.AuthorityRevision() ||
		a.AuthorityManifestDigest() != l.initial.AuthorityManifestDigest() || a.DeploymentID() != l.initial.DeploymentID() {
		return backupcustody.ErrUnauthorized
	}
	if err := l.store.lockAccount(ctx, l.tx, a); err != nil {
		return err
	}
	if !l.use.Reference.Admits(backupcustody.Publish, a.AuthorizedAtMilliseconds()) {
		return backupcustody.ErrUnauthorized
	}
	// The account/control/target locks have not been released. Signed control
	// commands cannot change this projection while the transaction is held.
	// Still probe the durable account fence/transaction and time on every call.
	if l.checked {
		return nil
	}
	var commandCount int
	if err := l.tx.QueryRow(ctx, `SELECT count(*) FROM backup_custody_control_commands WHERE account_id=$1`, l.request.Consent.AccountID).Scan(&commandCount); err != nil {
		return err
	}
	if commandCount > l.store.maximumControlRecords {
		return serviceauthority.ErrInvalid
	}
	// Every projection is checked against the ordered owner-signed log. An old
	// exact command acceptance is deliberately never an authorization shortcut.
	state, err := loadCredentialAuthorityState(ctx, l.tx, l.request.Consent.AccountID, true)
	if err != nil {
		return err
	}
	reference, _ := l.request.Consent.ReferenceDigest()
	consent, exists := state.ObjectScopeConsents[reference]
	if !exists || consent.Revoked || consent.Consent != l.request.Consent || consent.ReferenceDigest != reference {
		return backupcustody.ErrUnauthorized
	}
	accepted, err := loadAcceptedCredentialAuthority(ctx, l.tx, l.use, true)
	if err != nil {
		return err
	}
	if accepted.ControlHead != state.Head || !l.use.Reference.Admits(backupcustody.Publish, a.AuthorizedAtMilliseconds()) {
		return backupcustody.ErrUnauthorized
	}
	target, err := loadTarget(ctx, l.tx, l.request.Consent.AccountID, l.request.Consent.TargetID, true)
	if err != nil {
		return err
	}
	if target.BackupSetID != l.request.Consent.BackupSetID {
		return backupcustody.ErrUnauthorized
	}
	l.checked = true
	return nil
}

func (l *backupObjectScopePublication) Close(ctx context.Context) error {
	// Only the account's clock high-water can have changed in this transaction.
	// A failed commit is not successful authorization or successful custody.
	err := l.tx.Commit(ctx)
	if err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = l.tx.Rollback(cleanup)
		cancel()
	}
	if errors.Is(err, pgx.ErrTxClosed) {
		return backupcustody.ErrUnauthorized
	}
	return err
}

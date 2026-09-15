package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

var _ devicesync.ObjectScopeConsentStore = (*RelayStore)(nil)

type syncObjectConsentTransaction struct {
	tx         pgx.Tx
	store      *RelayStore
	credential devicesync.SpaceSponsorCredential
	mutation   devicesync.ObjectScopeConsentMutation
	initial    serviceauthority.MutationAuthorization
	control    relay.SubscriptionMemberRegistration
	member     relay.SubscriptionMemberRegistration
	closed     bool // owned by the sequential custody call, never shared
}

func (r *syncObjectConsentTransaction) MarshalJSON() ([]byte, error) {
	return nil, serviceauthority.ErrInvalid
}
func (r *syncObjectConsentTransaction) String() string {
	return "sync-object-scope-consent-transaction(redacted)"
}
func (r *syncObjectConsentTransaction) GoString() string { return r.String() }

func (r *syncObjectConsentTransaction) checkParticipant(now int64) error {
	// Revocation is terminal even if a later wall clock is earlier than its
	// recorded timestamp. Do not resurrect a revoked member on clock rollback.
	if !devicesync.CurrentSpaceSponsorMember(r.control.MemberRegistration, now) ||
		!devicesync.CurrentSpaceSponsorMember(r.member.MemberRegistration, now) {
		return devicesync.NewProtocolError(devicesync.CodeUnauthorized, "current Space participant required")
	}
	return devicesync.AuthenticateSpaceSponsor(r.credential, r.control, r.member, now)
}

func (s *RelayStore) BeginObjectScopeConsentMutation(ctx context.Context, credential devicesync.SpaceSponsorCredential,
	m devicesync.ObjectScopeConsentMutation, a serviceauthority.MutationAuthorization) (devicesync.ObjectScopeConsentTransaction, error) {
	return s.beginSyncObjectConsentTransaction(ctx, credential, m, a)
}

func (s *RelayStore) beginSyncObjectConsentTransaction(ctx context.Context, credential devicesync.SpaceSponsorCredential,
	m devicesync.ObjectScopeConsentMutation, a serviceauthority.MutationAuthorization) (*syncObjectConsentTransaction, error) {
	if ctx == nil || s == nil || s.pool == nil || m.Validate(credential) != nil ||
		a.ValidateFor(serviceauthority.ScopeDeviceSync, s.deviceSyncLocalDeploymentID) != nil || a.Scope().ScopeID != m.Consent.PrincipalID {
		return nil, serviceauthority.ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	r := &syncObjectConsentTransaction{tx: tx, store: s, credential: credential, mutation: m, initial: a}
	ok := false
	defer func() {
		if !ok {
			r.cleanup(ctx)
		}
	}()
	if _, err = tx.Exec(ctx, `SET LOCAL statement_timeout='30s'; SET LOCAL lock_timeout='30s'; SET LOCAL idle_in_transaction_session_timeout='35s'`); err != nil {
		return nil, err
	}
	// This fence is in the SAME transaction as the consent decision. No second
	// pooled connection or outer fence is required for this narrow store seam.
	if err = r.checkFence(ctx, a); err != nil {
		return nil, err
	}
	c := m.Consent
	if _, err = loadRelayTenant(ctx, tx, c.PrincipalID, "FOR UPDATE"); err != nil {
		return nil, err
	}
	if _, err = loadDeviceSyncPrincipalAuthority(ctx, tx, c.PrincipalID, "FOR UPDATE"); err != nil {
		return nil, err
	}
	space, err := loadDeviceSyncSpaceAuthority(ctx, tx, c.PrincipalID, c.SpaceID, "FOR UPDATE")
	if err != nil {
		return nil, err
	}
	if space.domainID != c.DomainID {
		return nil, serviceauthority.ErrInvalid
	}
	domain, _, _, _, _, _, err := loadRelayDomain(ctx, tx, c.PrincipalID, space.domainID, "FOR UPDATE")
	if err != nil {
		return nil, err
	}
	if err = domain.Authorize(credential.Administration); err != nil {
		return nil, err
	}
	r.control, r.member, _, err = loadDeviceSyncSponsorMembers(ctx, tx, c.PrincipalID, c.SpaceID, m.ParticipantDeviceID, m.ParticipantDeviceID)
	if err != nil {
		return nil, err
	}
	if err = r.checkParticipant(a.AuthorizedAtMilliseconds()); err != nil {
		return nil, err
	}
	ok = true
	return r, nil
}

func (r *syncObjectConsentTransaction) checkFence(ctx context.Context, a serviceauthority.MutationAuthorization) error {
	if a.ValidateFor(serviceauthority.ScopeDeviceSync, r.store.deviceSyncLocalDeploymentID) != nil ||
		a.Scope() != r.initial.Scope() || a.AuthorityRevision() != r.initial.AuthorityRevision() ||
		a.AuthorityManifestDigest() != r.initial.AuthorityManifestDigest() ||
		a.AuthorizedAtMilliseconds() < r.initial.AuthorizedAtMilliseconds() {
		return serviceauthority.ErrInvalid
	}
	_, err := lockDeviceSyncScopeForMutation(ctx, r.tx, a.Scope().ScopeID, a.DeploymentID(),
		a.AuthorityRevision(), a.AuthorityManifestDigest(), a.AuthorizedAtMilliseconds())
	return err
}

func (r *syncObjectConsentTransaction) Commit(ctx context.Context, a serviceauthority.MutationAuthorization) (result devicesync.ObjectScopeConsentStatus, err error) {
	if r.closed || ctx == nil {
		return result, serviceauthority.ErrInvalid
	}
	// A failed commit/revalidation is terminal; the caller cannot later revive
	// this transaction with an earlier clock or different authority.
	defer func() {
		if err != nil {
			r.cleanup(ctx)
		}
	}()
	if err = r.checkFence(ctx, a); err != nil {
		return result, err
	}
	now := a.AuthorizedAtMilliseconds()
	if err = r.checkParticipant(now); err != nil {
		return result, err
	}
	m, c := r.mutation, r.mutation.Consent
	// Principal lock serializes this floor with every consent operation, even
	// across different Spaces. Only authenticated committed observations persist.
	var floor int64
	err = r.tx.QueryRow(ctx, `SELECT observed_at_ms FROM device_sync_object_scope_clocks WHERE principal_id=$1`, c.PrincipalID).Scan(&floor)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if now < floor {
		return result, serviceauthority.ErrInvalid
	}
	if _, err = r.tx.Exec(ctx, `INSERT INTO device_sync_object_scope_clocks VALUES ($1,$2)
	 ON CONFLICT (principal_id) DO UPDATE SET observed_at_ms=EXCLUDED.observed_at_ms`, c.PrincipalID, now); err != nil {
		return result, err
	}
	ref, _ := c.ReferenceDigest()
	body, _ := json.Marshal(m)
	var prior []byte
	var priorRef string
	err = r.tx.QueryRow(ctx, `SELECT reference_digest,canonical_mutation FROM device_sync_object_scope_mutations WHERE principal_id=$1 AND retry_id=$2`, c.PrincipalID, m.RetryID).Scan(&priorRef, &prior)
	retry := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if retry && (priorRef != ref || !bytes.Equal(prior, body)) {
		return result, devicesync.ErrObjectScopeConflict
	}
	result, err = loadSyncObjectConsent(ctx, r.tx, c)
	exists := err == nil
	if err != nil && !errors.Is(err, devicesync.ErrObjectScopeNotFound) {
		return result, err
	}
	if retry && !exists {
		return result, serviceauthority.ErrInvalid
	}
	if !retry {
		if !m.Withdraw {
			if exists {
				return result, devicesync.ErrObjectScopeConflict
			}
			var reused bool
			if err = r.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM device_sync_object_scope_consents
			 WHERE principal_id=$1 AND (binding_id=$2 OR link_id=$3 OR link_intent_digest=$4))`, c.PrincipalID, c.BindingID, c.LinkID, c.LinkIntentDigest).Scan(&reused); err != nil {
				return result, err
			}
			if reused {
				return result, devicesync.ErrObjectScopeConflict
			}
			encoded, _ := json.Marshal(c)
			if _, err = r.tx.Exec(ctx, `INSERT INTO device_sync_object_scope_consents
			 (principal_id,space_id,reference_digest,binding_id,link_id,link_intent_digest,canonical_consent,accepted_at_ms)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, c.PrincipalID, c.SpaceID, ref, c.BindingID, c.LinkID, c.LinkIntentDigest, encoded, now); err != nil {
				return result, err
			}
			result = devicesync.ObjectScopeConsentStatus{ReferenceDigest: ref, AcceptedAtMilliseconds: now}
		} else {
			if !exists {
				return result, devicesync.ErrObjectScopeNotFound
			}
			if _, err = r.tx.Exec(ctx, `UPDATE device_sync_object_scope_consents SET withdrawn_at_ms=COALESCE(withdrawn_at_ms,$3)
			 WHERE principal_id=$1 AND reference_digest=$2`, c.PrincipalID, ref, now); err != nil {
				return result, err
			}
			result.Withdrawn = true
		}
		if _, err = r.tx.Exec(ctx, `INSERT INTO device_sync_object_scope_mutations
		 (principal_id,retry_id,reference_digest,canonical_mutation,participant_device_id,control_subscription_id,space_subscription_id,applied_at_ms)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, c.PrincipalID, m.RetryID, ref, body, m.ParticipantDeviceID, r.control.SubscriptionID, r.member.SubscriptionID, now); err != nil {
			return result, err
		}
	}
	err = r.tx.Commit(ctx)
	r.closed = true
	r.credential = devicesync.SpaceSponsorCredential{}
	return result, err
}

func (r *syncObjectConsentTransaction) Close(ctx context.Context) error {
	if r.closed {
		return nil
	}
	r.closed = true
	r.credential = devicesync.SpaceSponsorCredential{}
	err := r.tx.Rollback(ctx)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}

func (r *syncObjectConsentTransaction) cleanup(ctx context.Context) {
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = r.Close(bounded)
}

func loadSyncObjectConsent(ctx context.Context, tx pgx.Tx, expected devicesync.ObjectScopeConsent) (devicesync.ObjectScopeConsentStatus, error) {
	ref, err := expected.ReferenceDigest()
	if err != nil {
		return devicesync.ObjectScopeConsentStatus{}, err
	}
	result := devicesync.ObjectScopeConsentStatus{ReferenceDigest: ref}
	var encoded []byte
	var space, binding, link uuid.UUID
	var intent string
	var withdrawn *int64
	err = tx.QueryRow(ctx, `SELECT space_id,binding_id,link_id,link_intent_digest,canonical_consent,accepted_at_ms,withdrawn_at_ms
	 FROM device_sync_object_scope_consents WHERE principal_id=$1 AND reference_digest=$2`, expected.PrincipalID, ref).
		Scan(&space, &binding, &link, &intent, &encoded, &result.AcceptedAtMilliseconds, &withdrawn)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, devicesync.ErrObjectScopeNotFound
	}
	if err != nil {
		return result, err
	}
	canonical, _ := json.Marshal(expected)
	if !bytes.Equal(canonical, encoded) || space != expected.SpaceID || binding != expected.BindingID || link != expected.LinkID ||
		intent != expected.LinkIntentDigest || result.AcceptedAtMilliseconds < 0 || (withdrawn != nil && *withdrawn < result.AcceptedAtMilliseconds) {
		return result, serviceauthority.ErrInvalid
	}
	result.Withdrawn = withdrawn != nil
	return result, nil
}

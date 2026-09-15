package postgres

import (
	"context"
	"time"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

var _ devicesync.ObjectScopePublicationStore = (*RelayStore)(nil)

type syncObjectPublicationTransaction struct{ base *syncObjectConsentTransaction }

func (r *syncObjectPublicationTransaction) MarshalJSON() ([]byte, error) {
	return nil, serviceauthority.ErrInvalid
}
func (r *syncObjectPublicationTransaction) String() string {
	return "sync-object-publication-transaction(redacted)"
}
func (r *syncObjectPublicationTransaction) GoString() string { return r.String() }

func (s *RelayStore) BeginSyncObjectScopePublication(ctx context.Context, credential devicesync.SpaceSponsorCredential,
	r devicesync.ObjectScopePublicationRequest, a serviceauthority.MutationAuthorization) (devicesync.ObjectScopePublicationTransaction, error) {
	if r.Validate() != nil {
		return nil, serviceauthority.ErrInvalid
	}
	// The private helper only ACQUIRES current participant/resource locks. Its
	// consent Commit method is never called; publication cannot create consent.
	m := devicesync.ObjectScopeConsentMutation{Consent: r.Consent, ParticipantDeviceID: credential.Control.MemberID, RetryID: r.Request.OperationID}
	// Commit an authenticated admission clock before reacquiring. Revocation
	// in this gap wins: the second transaction checks every authority again.
	for phase := 0; phase < 2; phase++ {
		base, err := s.beginSyncObjectConsentTransaction(ctx, credential, m, a)
		if err != nil {
			return nil, err
		}
		row := &syncObjectPublicationTransaction{base: base}
		if err := row.Revalidate(ctx, a); err != nil {
			base.cleanup(ctx)
			return nil, err
		}
		if phase == 1 {
			return row, nil
		}
		if err := row.Close(ctx); err != nil {
			return nil, err
		}
	}
	return nil, serviceauthority.ErrInvalid
}

func (r *syncObjectPublicationTransaction) Revalidate(ctx context.Context, a serviceauthority.MutationAuthorization) (err error) {
	if r == nil {
		return serviceauthority.ErrInvalid
	}
	b := r.base
	if b == nil || b.closed || ctx == nil {
		return serviceauthority.ErrInvalid
	}
	// A failed raw-store handle is terminal too. Persist only earlier valid
	// observations; a failed authority check never advances the clock.
	defer func() {
		if err != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_ = r.Close(cleanup)
		}
	}()
	if err := b.checkFence(ctx, a); err != nil {
		return err
	}
	if err := b.checkParticipant(a.AuthorizedAtMilliseconds()); err != nil {
		return err
	}
	c := b.mutation.Consent
	status, err := loadSyncObjectConsent(ctx, b.tx, c)
	if err != nil {
		return err
	}
	if status.Withdrawn {
		return devicesync.ErrObjectScopeConflict
	}
	var floor int64
	if err := b.tx.QueryRow(ctx, `SELECT observed_at_ms FROM device_sync_object_scope_clocks WHERE principal_id=$1`, c.PrincipalID).Scan(&floor); err != nil {
		return err
	}
	if floor > a.AuthorizedAtMilliseconds() || status.AcceptedAtMilliseconds > floor {
		return serviceauthority.ErrInvalid
	}
	_, err = b.tx.Exec(ctx, `UPDATE device_sync_object_scope_clocks SET observed_at_ms=$2 WHERE principal_id=$1`, c.PrincipalID, a.AuthorizedAtMilliseconds())
	return err
}

// No publication/object/receipt is written here. Commit only authenticated
// clock observations, including when the caller's preparation was cancelled.
func (r *syncObjectPublicationTransaction) Close(ctx context.Context) error {
	if r == nil || ctx == nil {
		return serviceauthority.ErrInvalid
	}
	b := r.base
	if b == nil || b.closed {
		return nil
	}
	err := b.tx.Commit(ctx)
	b.closed = true
	b.credential = devicesync.SpaceSponsorCredential{}
	return err
}

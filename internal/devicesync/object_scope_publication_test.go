package devicesync

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestSyncObjectPublicationExactOperationAndIntent(t *testing.T) {
	r, _, _ := syncPublicationUnitRequest(t)
	for _, op := range []serviceauthority.CustodyPeerOperation{serviceauthority.CustodyReserveObject,
		serviceauthority.CustodyPutObject, serviceauthority.CustodyBeginPublication,
		serviceauthority.CustodyAddPins, serviceauthority.CustodyPreparePublication} {
		r.Request.Operation = op
		if err := r.Validate(); err != nil {
			t.Fatal(op, err)
		}
	}
	for _, op := range []serviceauthority.CustodyPeerOperation{serviceauthority.CustodyReadObject,
		serviceauthority.CustodyAcquireLease, serviceauthority.CustodyRenewLease, serviceauthority.CustodyCloseLease,
		serviceauthority.CustodyConfirmPublication, serviceauthority.CustodyRetirePublication, "unknown"} {
		r.Request.Operation = op
		if r.Validate() == nil {
			t.Fatal("preparation authority admitted", op)
		}
	}
	r.Request.Operation = serviceauthority.CustodyReserveObject
	for _, change := range []func(*ObjectScopePublicationRequest){
		func(r *ObjectScopePublicationRequest) { r.Intent.BackupAccountID = uuid.New() },
		func(r *ObjectScopePublicationRequest) { r.Intent.BackupBindingID = uuid.New() },
		func(r *ObjectScopePublicationRequest) { r.Intent.BackupSetID = uuid.New() },
		func(r *ObjectScopePublicationRequest) { r.Intent.BackupTargetID = uuid.New() },
		func(r *ObjectScopePublicationRequest) { r.Intent.SyncSpaceID = uuid.New() },
		func(r *ObjectScopePublicationRequest) { r.Consent.LinkIntentDigest = strings.Repeat("b", 64) },
		func(r *ObjectScopePublicationRequest) { r.Request.Target.BindingID = uuid.New() },
		func(r *ObjectScopePublicationRequest) { r.Request.Target.ContentEpoch-- },
		func(r *ObjectScopePublicationRequest) { r.Request.Target.ContentScopeID = uuid.New() },
		func(r *ObjectScopePublicationRequest) { r.Request.Target.LedgerID = uuid.New() },
		func(r *ObjectScopePublicationRequest) { r.Request.Target.PoolID = uuid.New() },
		func(r *ObjectScopePublicationRequest) { r.Request.OperationID = uuid.Nil },
		func(r *ObjectScopePublicationRequest) { r.Request.Challenge = "bad" },
		func(r *ObjectScopePublicationRequest) { r.Request.BodySHA256 = "bad" },
		func(r *ObjectScopePublicationRequest) { r.Request.BodyByteCount = 0 },
		func(r *ObjectScopePublicationRequest) {
			r.Request.BodyByteCount = serviceauthority.MaximumCustodyPeerControlBodyBytes + 1
		},
	} {
		changed := r
		change(&changed)
		if changed.Validate() == nil {
			t.Fatal("invalid operation accepted")
		}
	}
}

func TestSyncObjectPublicationLeaseLifecycle(t *testing.T) {
	r, credential, binding := syncPublicationUnitRequest(t)
	registry := syncPublicationUnitRegistry(t, binding)
	row := &syncPublicationUnitRow{}
	now := int64(1000)
	store := &syncPublicationUnitStore{row: row, during: func() { now = 2000 }}
	c := ObjectScopePublicationCustody{Store: store, Registry: registry, Now: func() time.Time { return time.UnixMilli(now) }}
	l, err := c.Begin(context.Background(), credential, r, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if store.request != r || store.credential != credential || row.observed.Load() != 2000 {
		t.Fatal("lost exact inputs or reused pre-wait authorization")
	}
	if store.remaining <= 0 || store.remaining > MaximumObjectScopeConsentDuration {
		t.Fatal("unbounded operation")
	}
	if _, err := json.Marshal(l); err == nil {
		t.Fatal("source handle serialized")
	}
	if strings.Contains(l.String(), credential.Space.Token) {
		t.Fatal("bearer in formatting")
	}
	blocked, stop := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer stop()
	if drain, err := registry.AcquireMigrationDrain(blocked, binding.Scope); err == nil {
		drain.Release()
		t.Fatal("migration escaped held source lease")
	}
	row.fail.Store(true)
	if l.Revalidate() == nil {
		t.Fatal("failed currentness accepted")
	}
	row.fail.Store(false)
	if l.Revalidate() == nil {
		t.Fatal("failed handle revived")
	}
	if err := l.Close(); err != nil || row.closed.Load() != 1 {
		t.Fatal("non-idempotent close", err)
	}
	ready, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	drain, err := registry.AcquireMigrationDrain(ready, binding.Scope)
	if err != nil {
		t.Fatal(err)
	}
	drain.Release()
}

func TestSyncObjectPublicationCancellationAndConcurrency(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		r, credential, binding := syncPublicationUnitRequest(t)
		registry := syncPublicationUnitRegistry(t, binding)
		row := &syncPublicationUnitRow{}
		c := ObjectScopePublicationCustody{Store: &syncPublicationUnitStore{row: row}, Registry: registry,
			Now: func() time.Time { return time.UnixMilli(1000) }}
		ctx, cancel := context.WithCancel(context.Background())
		if expiry {
			cancel()
			ctx, cancel = context.WithTimeout(context.Background(), 30*time.Millisecond)
		}
		l, err := c.Begin(ctx, credential, r, binding)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if !expiry {
			cancel()
		}
		wait, stop := context.WithTimeout(context.Background(), time.Second)
		drain, err := registry.AcquireMigrationDrain(wait, binding.Scope)
		stop()
		cancel()
		if err != nil {
			t.Fatal("cancellation did not release source lease", err)
		}
		drain.Release()
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); _ = l.Revalidate(); _ = l.Close() }()
		}
		wg.Wait()
		if row.closed.Load() != 1 {
			t.Fatal("duplicate close")
		}
	}
}

func TestSyncObjectPublicationRejectsBeforeStoreAndCleansBeginFailure(t *testing.T) {
	for _, mode := range []string{"scope", "traffic", "put-control", "store-failure", "cancel-during-begin"} {
		t.Run(mode, func(t *testing.T) {
			r, credential, binding := syncPublicationUnitRequest(t)
			registry := syncPublicationUnitRegistry(t, binding)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			row := &syncPublicationUnitRow{}
			store := &syncPublicationUnitStore{row: row}
			c := ObjectScopePublicationCustody{Store: store, Registry: registry, Now: func() time.Time { return time.UnixMilli(1000) }}
			bad := binding
			switch mode {
			case "scope":
				bad.Scope.ScopeID = uuid.New()
			case "traffic":
				bad.TrafficClass = serviceauthority.TrafficBulk
			case "put-control":
				r.Request.Operation = serviceauthority.CustodyPutObject
			case "store-failure":
				store.fail = true
			case "cancel-during-begin":
				store.during = cancel
			}
			if l, err := c.Begin(ctx, credential, r, bad); err == nil || l != nil {
				t.Fatal("invalid begin admitted")
			}
			if mode != "store-failure" && mode != "cancel-during-begin" && store.calls != 0 {
				t.Fatal("invalid scope reached store")
			}
			wait, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			drain, err := registry.AcquireMigrationDrain(wait, binding.Scope)
			if err != nil {
				t.Fatal("failed begin leaked lease", err)
			}
			drain.Release()
		})
	}
}

type syncPublicationUnitStore struct {
	row        *syncPublicationUnitRow
	request    ObjectScopePublicationRequest
	credential SpaceSponsorCredential
	remaining  time.Duration
	calls      int
	fail       bool
	during     func()
}

func (s *syncPublicationUnitStore) BeginSyncObjectScopePublication(ctx context.Context, c SpaceSponsorCredential, r ObjectScopePublicationRequest, _ serviceauthority.MutationAuthorization) (ObjectScopePublicationTransaction, error) {
	s.calls++
	s.request, s.credential = r, c
	deadline, _ := ctx.Deadline()
	s.remaining = time.Until(deadline)
	if s.during != nil {
		s.during()
	}
	if s.fail {
		return nil, serviceauthority.ErrInvalid
	}
	return s.row, nil
}

type syncPublicationUnitRow struct {
	closed, observed atomic.Int64
	fail             atomic.Bool
}

func (r *syncPublicationUnitRow) Revalidate(ctx context.Context, a serviceauthority.MutationAuthorization) error {
	if r.closed.Load() != 0 || r.fail.Load() {
		return serviceauthority.ErrInvalid
	}
	r.observed.Store(a.AuthorizedAtMilliseconds())
	return ctx.Err()
}
func (r *syncPublicationUnitRow) Close(ctx context.Context) error { r.closed.Add(1); return ctx.Err() }

func syncPublicationUnitRequest(t *testing.T) (ObjectScopePublicationRequest, SpaceSponsorCredential, serviceauthority.RequestBinding) {
	t.Helper()
	m, credential := objectConsentFixture()
	credential.Space.Token = "synthetic-token-never-in-handle"
	i := serviceauthority.CustodyLinkIntent{Version: 1, BackupAccountID: uuid.New(), BackupBindingID: uuid.New(), BackupSetID: uuid.New(), BackupTargetID: uuid.New(),
		ContentEpoch: m.Consent.ContentEpoch, ContentScopeID: m.Consent.ContentScopeID, LedgerID: m.Consent.LedgerID, LinkID: m.Consent.LinkID, PoolID: m.Consent.PoolID,
		SyncBindingID: m.Consent.BindingID, SyncDomainID: m.Consent.DomainID, SyncPrincipalID: m.Consent.PrincipalID, SyncSpaceID: m.Consent.SpaceID}
	consent, err := NewObjectScopeConsent(i)
	if err != nil {
		t.Fatal(err)
	}
	r := ObjectScopePublicationRequest{Intent: i, Consent: consent, Request: serviceauthority.CustodyPeerRequest{Version: 1,
		OperationID: uuid.New(), Operation: serviceauthority.CustodyReserveObject, BodyByteCount: 1, BodySHA256: strings.Repeat("c", 64),
		Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Target: serviceauthority.CustodyPeerTarget{
			BindingID: consent.BindingID, ContentEpoch: consent.ContentEpoch, ContentScopeID: consent.ContentScopeID, LedgerID: consent.LedgerID, PoolID: consent.PoolID}}}
	b := serviceauthority.RequestBinding{Scope: serviceauthority.Scope{Kind: serviceauthority.ScopeDeviceSync, ScopeID: consent.PrincipalID},
		AuthorityRevision: 1, AuthorityDigest: strings.Repeat("a", 64), DeploymentID: uuid.New(), RouteID: uuid.New(), TrafficClass: serviceauthority.TrafficControl}
	return r, credential, b
}
func syncPublicationUnitRegistry(t *testing.T, b serviceauthority.RequestBinding) *serviceauthority.BindingRegistry {
	t.Helper()
	r := serviceauthority.NewBindingRegistry()
	if err := r.Activate(b.Scope, serviceauthority.CurrentBinding{Revision: b.AuthorityRevision, Digest: b.AuthorityDigest, DeploymentID: b.DeploymentID}); err != nil {
		t.Fatal(err)
	}
	return r
}

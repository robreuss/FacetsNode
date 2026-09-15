package backupcustody

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestObjectScopePublicationOperationBounds(t *testing.T) {
	r, _, _ := publicationUnitRequest(t)
	for _, operation := range []serviceauthority.CustodyPeerOperation{serviceauthority.CustodyReserveObject,
		serviceauthority.CustodyPutObject, serviceauthority.CustodyBeginPublication,
		serviceauthority.CustodyAddPins, serviceauthority.CustodyPreparePublication} {
		r.Request.Operation = operation
		if err := r.Validate(); err != nil {
			t.Fatal(operation, err)
		}
	}
	for _, operation := range []serviceauthority.CustodyPeerOperation{serviceauthority.CustodyReadObject,
		serviceauthority.CustodyAcquireLease, serviceauthority.CustodyRenewLease, serviceauthority.CustodyCloseLease,
		serviceauthority.CustodyConfirmPublication, serviceauthority.CustodyRetirePublication, "unknown"} {
		r.Request.Operation = operation
		if err := r.Validate(); err == nil {
			t.Fatal("publication credential admitted", operation)
		}
	}
	r.Request.Operation = serviceauthority.CustodyReserveObject
	for _, change := range []func(*ObjectScopePublicationRequest){
		func(v *ObjectScopePublicationRequest) { v.Request.BodyByteCount = 0 },
		func(v *ObjectScopePublicationRequest) {
			v.Request.BodyByteCount = serviceauthority.MaximumCustodyPeerControlBodyBytes + 1
		},
		func(v *ObjectScopePublicationRequest) { v.Request.Target.BindingID = uuid.New() },
		func(v *ObjectScopePublicationRequest) { v.Request.Target.ContentScopeID = uuid.New() },
		func(v *ObjectScopePublicationRequest) { v.Request.Target.ContentEpoch++ },
		func(v *ObjectScopePublicationRequest) { v.Request.Target.LedgerID = uuid.New() },
		func(v *ObjectScopePublicationRequest) { v.Request.Target.PoolID = uuid.New() },
		func(v *ObjectScopePublicationRequest) { v.Request.OperationID = uuid.Nil },
		func(v *ObjectScopePublicationRequest) { v.Request.Challenge = "not-a-challenge" },
		func(v *ObjectScopePublicationRequest) { v.Consent.LinkID = uuid.Nil },
	} {
		changed := r
		change(&changed)
		if changed.Validate() == nil {
			t.Fatal("invalid request admitted")
		}
	}
}

func TestObjectScopePublicationCurrentnessLifecycle(t *testing.T) {
	r, credential, binding := publicationUnitRequest(t)
	registry := publicationUnitRegistry(t, binding)
	row := &publicationUnitTransaction{}
	store := &publicationUnitStore{row: row}
	c := ObjectScopePublicationCustody{Store: store, Registry: registry, Clock: fixedBackupClock{time.UnixMilli(1100)}}
	l, err := c.Begin(context.Background(), credential, r, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if store.use.Reference.Capabilities[0] != Publish || row.revalidated.Load() != 1 {
		t.Fatal("did not recheck after store wait")
	}
	if store.request != r {
		t.Fatal("operation commitment changed")
	}
	credential.Reference.Capabilities[0] = Read
	r.Request.OperationID = uuid.New()
	if store.use.Reference.Capabilities[0] != Publish || store.request.Request.OperationID == r.Request.OperationID {
		t.Fatal("caller mutated retained authorization inputs")
	}
	if _, err := json.Marshal(l); err == nil {
		t.Fatal("source handle serialized")
	}
	if strings.Contains(l.String(), credential.TransportBearer()) {
		t.Fatal("credential formatting leaked bearer")
	}
	if store.remaining <= 0 || store.remaining > MaximumObjectScopePublicationDuration {
		t.Fatal("missing machine operation deadline", store.remaining)
	}
	blocked, stop := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer stop()
	if drain, err := registry.AcquireMigrationDrain(blocked, binding.Scope); err == nil {
		drain.Release()
		t.Fatal("source migration escaped held lease")
	}
	row.fail.Store(true)
	if err := l.Revalidate(); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("failed revalidation", err)
	}
	row.fail.Store(false)
	if err := l.Revalidate(); err == nil {
		t.Fatal("failed handle revived")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if row.closed.Load() != 1 {
		t.Fatal("transaction closed more than once")
	}
	ready, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	drain, err := registry.AcquireMigrationDrain(ready, binding.Scope)
	if err != nil {
		t.Fatal(err)
	}
	drain.Release()
}

func TestObjectScopePublicationCleanupAndConcurrentCalls(t *testing.T) {
	for _, earlyDeadline := range []bool{false, true} {
		r, credential, binding := publicationUnitRequest(t)
		registry := publicationUnitRegistry(t, binding)
		row := &publicationUnitTransaction{}
		c := ObjectScopePublicationCustody{Store: &publicationUnitStore{row: row}, Registry: registry, Clock: fixedBackupClock{time.UnixMilli(1100)}}
		ctx, cancel := context.WithCancel(context.Background())
		if earlyDeadline {
			cancel()
			ctx, cancel = context.WithTimeout(context.Background(), 30*time.Millisecond)
		}
		l, err := c.Begin(ctx, credential, r, binding)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if !earlyDeadline {
			cancel()
		}
		wait, stop := context.WithTimeout(context.Background(), time.Second)
		drain, err := registry.AcquireMigrationDrain(wait, binding.Scope)
		stop()
		cancel()
		if err != nil {
			t.Fatal("automatic cleanup did not release registry", err)
		}
		drain.Release()
		var group sync.WaitGroup
		for i := 0; i < 32; i++ {
			group.Add(1)
			go func() { defer group.Done(); _ = l.Revalidate(); _ = l.Close() }()
		}
		group.Wait()
		if row.closed.Load() != 1 {
			t.Fatal("cleanup count", row.closed.Load())
		}
	}
}

func TestObjectScopePublicationRejectsBeforeStoreAndReleasesOnError(t *testing.T) {
	r, credential, binding := publicationUnitRequest(t)
	registry := publicationUnitRegistry(t, binding)
	store := &publicationUnitStore{row: &publicationUnitTransaction{}}
	c := ObjectScopePublicationCustody{Store: store, Registry: registry, Clock: fixedBackupClock{time.UnixMilli(1100)}}
	bad := binding
	bad.TrafficClass = serviceauthority.TrafficBulk
	if l, err := c.Begin(context.Background(), credential, r, bad); err == nil || l != nil {
		t.Fatal("wrong traffic admitted")
	}
	bad = binding
	bad.Scope.ScopeID = uuid.New()
	if l, err := c.Begin(context.Background(), credential, r, bad); err == nil || l != nil {
		t.Fatal("foreign account admitted")
	}
	if store.calls != 0 {
		t.Fatal("invalid operation reached store")
	}
	store.fail = true
	if l, err := c.Begin(context.Background(), credential, r, binding); err == nil || l != nil {
		t.Fatal("store failure admitted")
	}
	ready, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	drain, err := registry.AcquireMigrationDrain(ready, binding.Scope)
	if err != nil {
		t.Fatal(err)
	}
	drain.Release()
}

type publicationUnitStore struct {
	row       *publicationUnitTransaction
	fail      bool
	calls     int
	use       CredentialUse
	request   ObjectScopePublicationRequest
	remaining time.Duration
}

func (s *publicationUnitStore) BeginObjectScopePublication(ctx context.Context, use CredentialUse, r ObjectScopePublicationRequest, a serviceauthority.MutationAuthorization) (ObjectScopePublicationTransaction, error) {
	s.calls++
	s.use, s.request = use, r
	deadline, _ := ctx.Deadline()
	s.remaining = time.Until(deadline)
	if s.fail {
		return nil, ErrUnauthorized
	}
	return s.row, nil
}

type publicationUnitTransaction struct {
	closed, revalidated atomic.Int64
	fail                atomic.Bool
}

func (r *publicationUnitTransaction) Revalidate(ctx context.Context, a serviceauthority.MutationAuthorization) error {
	r.revalidated.Add(1)
	if r.closed.Load() != 0 || r.fail.Load() {
		return ErrUnauthorized
	}
	return ctx.Err()
}
func (r *publicationUnitTransaction) Close(ctx context.Context) error {
	r.closed.Add(1)
	return ctx.Err()
}

func publicationUnitRequest(t *testing.T) (ObjectScopePublicationRequest, TargetCredential, serviceauthority.RequestBinding) {
	t.Helper()
	consent := ObjectScopeConsent{Version: 1, AccountID: uuid.New(), TargetID: uuid.New(), BackupSetID: uuid.New(),
		ContentEpoch: 1, ContentScopeID: uuid.New(), BindingID: uuid.New(), LedgerID: uuid.New(), PoolID: uuid.New(),
		LinkID: uuid.New(), LinkIntentDigest: strings.Repeat("a", 64)}
	r := ObjectScopePublicationRequest{Consent: consent, Request: serviceauthority.CustodyPeerRequest{Version: 1,
		OperationID: uuid.New(), Operation: serviceauthority.CustodyReserveObject, BodyByteCount: 1, BodySHA256: strings.Repeat("c", 64),
		Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Target: serviceauthority.CustodyPeerTarget{BindingID: consent.BindingID,
			ContentEpoch: consent.ContentEpoch, ContentScopeID: consent.ContentScopeID, LedgerID: consent.LedgerID, PoolID: consent.PoolID}}}
	credential, err := NewTargetCredential(TargetCredentialReference{Version: 1, AccountID: consent.AccountID,
		TargetID: consent.TargetID, BackupSetID: consent.BackupSetID, CredentialID: uuid.New(), Capabilities: []Capability{Publish},
		ExpiresAtMilliseconds: 10000, RequestNonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	binding := serviceauthority.RequestBinding{Scope: serviceauthority.Scope{Kind: serviceauthority.ScopeBackupCustody, ScopeID: consent.AccountID},
		AuthorityRevision: 1, AuthorityDigest: strings.Repeat("a", 64), DeploymentID: uuid.New(), RouteID: uuid.New(), TrafficClass: serviceauthority.TrafficControl}
	return r, credential, binding
}
func publicationUnitRegistry(t *testing.T, b serviceauthority.RequestBinding) *serviceauthority.BindingRegistry {
	t.Helper()
	registry := serviceauthority.NewBindingRegistry()
	if err := registry.Activate(b.Scope, serviceauthority.CurrentBinding{Revision: b.AuthorityRevision, Digest: b.AuthorityDigest, DeploymentID: b.DeploymentID}); err != nil {
		t.Fatal(err)
	}
	return registry
}

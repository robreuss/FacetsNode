package devicesync

import (
	"context"
	"sync"
	"time"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type ObjectScopePublicationRequest struct {
	Intent  serviceauthority.CustodyLinkIntent
	Consent ObjectScopeConsent
	Request serviceauthority.CustodyPeerRequest
}

func (r ObjectScopePublicationRequest) Validate() error {
	if r.Consent.ValidateIntent(r.Intent) != nil || r.Request.Validate() != nil || r.Request.BodyByteCount == 0 ||
		r.Request.Target != (serviceauthority.CustodyPeerTarget{BindingID: r.Consent.BindingID, ContentEpoch: r.Consent.ContentEpoch,
			ContentScopeID: r.Consent.ContentScopeID, LedgerID: r.Consent.LedgerID, PoolID: r.Consent.PoolID}) {
		return serviceauthority.ErrInvalid
	}
	switch r.Request.Operation {
	case serviceauthority.CustodyReserveObject, serviceauthority.CustodyPutObject, serviceauthority.CustodyBeginPublication,
		serviceauthority.CustodyAddPins, serviceauthority.CustodyPreparePublication:
		return nil
	default:
		return serviceauthority.ErrInvalid
	}
}

type ObjectScopePublicationTransaction interface {
	Revalidate(context.Context, serviceauthority.MutationAuthorization) error
	Close(context.Context) error
}

type ObjectScopePublicationStore interface {
	BeginSyncObjectScopePublication(context.Context, SpaceSponsorCredential, ObjectScopePublicationRequest,
		serviceauthority.MutationAuthorization) (ObjectScopePublicationTransaction, error)
}

type ObjectScopePublicationCustody struct {
	Store    ObjectScopePublicationStore
	Registry *serviceauthority.BindingRegistry
	Now      func() time.Time
}

// Held SOURCE transaction only, not a portable effect permit. No endpoint or
// ledger consumes this value. A receiver still needs live bilateral authority,
// its own effect-time fence, exact body validation and genuine root outcomes.
type ObjectScopePublicationLease struct {
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	stop     func() bool
	closed   bool
	closeErr error
	row      ObjectScopePublicationTransaction
	scope    *serviceauthority.ScopeLease
	registry *serviceauthority.BindingRegistry
	now      func() time.Time
	binding  serviceauthority.RequestBinding
}

func (l *ObjectScopePublicationLease) MarshalJSON() ([]byte, error) {
	return nil, serviceauthority.ErrInvalid
}
func (l *ObjectScopePublicationLease) String() string {
	return "sync-object-scope-transaction(not-an-effect-permit)"
}
func (l *ObjectScopePublicationLease) GoString() string { return l.String() }

func (c *ObjectScopePublicationCustody) Begin(ctx context.Context, credential SpaceSponsorCredential, r ObjectScopePublicationRequest, binding serviceauthority.RequestBinding) (*ObjectScopePublicationLease, error) {
	if c == nil || c.Store == nil || c.Registry == nil || c.Now == nil || ctx == nil || r.Validate() != nil ||
		binding.Scope != (serviceauthority.Scope{Kind: serviceauthority.ScopeDeviceSync, ScopeID: r.Consent.PrincipalID}) {
		return nil, serviceauthority.ErrInvalid
	}
	traffic := serviceauthority.TrafficControl
	if r.Request.Operation == serviceauthority.CustodyPutObject {
		traffic = serviceauthority.TrafficBulk
	}
	if binding.TrafficClass != traffic {
		return nil, serviceauthority.ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, MaximumObjectScopeConsentDuration)
	scope, err := c.Registry.AcquireMutationLease(bounded, binding.Scope)
	if err != nil {
		cancel()
		return nil, err
	}
	a, err := c.Registry.AuthorizeMutationAt(binding, c.Now())
	if err != nil {
		scope.Release()
		cancel()
		return nil, err
	}
	row, err := c.Store.BeginSyncObjectScopePublication(bounded, credential, r, a)
	if err != nil {
		scope.Release()
		cancel()
		return nil, err
	}
	l := &ObjectScopePublicationLease{ctx: bounded, cancel: cancel, row: row, scope: scope, registry: c.Registry, now: c.Now, binding: binding}
	l.mu.Lock()
	l.stop = context.AfterFunc(bounded, func() { _ = l.Close() })
	l.mu.Unlock()
	if err := l.Revalidate(); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

func (l *ObjectScopePublicationLease) Revalidate() (err error) {
	if l == nil {
		return serviceauthority.ErrInvalid
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	defer func() {
		if err != nil {
			_ = l.closeLocked()
		}
	}()
	if l.closed || l.row == nil {
		return serviceauthority.ErrInvalid
	}
	if err := l.ctx.Err(); err != nil {
		return err
	}
	a, err := l.registry.AuthorizeMutationAt(l.binding, l.now())
	if err != nil {
		return err
	}
	return l.row.Revalidate(l.ctx, a)
}

func (l *ObjectScopePublicationLease) Close() error {
	if l == nil {
		return serviceauthority.ErrInvalid
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closeLocked()
}
func (l *ObjectScopePublicationLease) closeLocked() error {
	if l.closed {
		return l.closeErr
	}
	l.closed = true
	if l.stop != nil {
		l.stop()
	}
	if l.row != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		l.closeErr = l.row.Close(cleanup)
		cancel()
	}
	if l.scope != nil {
		l.scope.Release()
	}
	if l.cancel != nil {
		l.cancel()
	}
	return l.closeErr
}

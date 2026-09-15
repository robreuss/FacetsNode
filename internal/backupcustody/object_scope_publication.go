package backupcustody

import (
	"context"
	"sync"
	"time"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

// ObjectScopePublicationRequest identifies ONE exact preparation operation.
// It is not a link, receipt, restore grant, or authority to retire a publication.
type ObjectScopePublicationRequest struct {
	Consent ObjectScopeConsent
	Request serviceauthority.CustodyPeerRequest
}

func (r ObjectScopePublicationRequest) Validate() error {
	if r.Consent.Validate() != nil || r.Request.Validate() != nil || r.Request.BodyByteCount == 0 ||
		r.Request.Target != (serviceauthority.CustodyPeerTarget{BindingID: r.Consent.BindingID,
			ContentEpoch: r.Consent.ContentEpoch, ContentScopeID: r.Consent.ContentScopeID,
			LedgerID: r.Consent.LedgerID, PoolID: r.Consent.PoolID}) {
		return serviceauthority.ErrInvalid
	}
	switch r.Request.Operation {
	case serviceauthority.CustodyReserveObject, serviceauthority.CustodyPutObject,
		serviceauthority.CustodyBeginPublication, serviceauthority.CustodyAddPins,
		serviceauthority.CustodyPreparePublication:
		return nil
	default:
		return serviceauthority.ErrInvalid
	}
}

// ObjectScopePublicationTransaction holds the Backup account/control/target
// locks. Implementations validate the signed log, not a historical acceptance.
// Closing only commits the clock watermark; it does not commit object custody.
type ObjectScopePublicationTransaction interface {
	Revalidate(context.Context, serviceauthority.MutationAuthorization) error
	Close(context.Context) error
}

// Kept separate from Store: existing whole-generation Backup remains independent.
type ObjectScopePublicationStore interface {
	BeginObjectScopePublication(context.Context, CredentialUse, ObjectScopePublicationRequest,
		serviceauthority.MutationAuthorization) (ObjectScopePublicationTransaction, error)
}

type ObjectScopePublicationCustody struct {
	Store    ObjectScopePublicationStore
	Registry *serviceauthority.BindingRegistry
	Clock    Clock
}

// A machine-operation bound, not an interactive setup or password timeout.
const MaximumObjectScopePublicationDuration = 30 * time.Second

// ObjectScopePublicationLease is a source-side held transaction, NOT a portable
// effect permit. A future dispatcher must keep it live through the exact effect,
// check the bilateral link and receiver fence, and verify the actual body. No
// current ledger or endpoint accepts this value as authority.
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
	clock    Clock
	binding  serviceauthority.RequestBinding
}

func (l *ObjectScopePublicationLease) MarshalJSON() ([]byte, error) {
	return nil, serviceauthority.ErrInvalid
}
func (l *ObjectScopePublicationLease) String() string {
	return "backup-object-scope-transaction(not-an-effect-permit)"
}
func (l *ObjectScopePublicationLease) GoString() string { return l.String() }

func (c *ObjectScopePublicationCustody) Begin(ctx context.Context, credential TargetCredential,
	r ObjectScopePublicationRequest, binding serviceauthority.RequestBinding) (*ObjectScopePublicationLease, error) {
	if c == nil || c.Store == nil || c.Registry == nil || c.Clock == nil || ctx == nil || r.Validate() != nil ||
		binding.Scope != (serviceauthority.Scope{Kind: serviceauthority.ScopeBackupCustody, ScopeID: r.Consent.AccountID}) ||
		credential.Reference.AccountID != r.Consent.AccountID || credential.Reference.TargetID != r.Consent.TargetID ||
		credential.Reference.BackupSetID != r.Consent.BackupSetID {
		return nil, serviceauthority.ErrInvalid
	}
	traffic := serviceauthority.TrafficControl
	if r.Request.Operation == serviceauthority.CustodyPutObject {
		traffic = serviceauthority.TrafficBulk
	}
	if binding.TrafficClass != traffic {
		return nil, serviceauthority.ErrInvalid
	}
	credential.Reference.Capabilities = append([]Capability(nil), credential.Reference.Capabilities...)
	use, err := credentialUse(credential)
	if err != nil {
		return nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, MaximumObjectScopePublicationDuration)
	scope, err := c.Registry.AcquireMutationLease(bounded, binding.Scope)
	if err != nil {
		cancel()
		return nil, err
	}
	authorization, err := c.Registry.AuthorizeMutationAt(binding, c.Clock.Now())
	if err != nil {
		scope.Release()
		cancel()
		return nil, err
	}
	row, err := c.Store.BeginObjectScopePublication(bounded, use, r, authorization)
	if err != nil {
		scope.Release()
		cancel()
		return nil, err
	}
	l := &ObjectScopePublicationLease{ctx: bounded, cancel: cancel, row: row, scope: scope,
		registry: c.Registry, clock: c.Clock, binding: binding}
	// Register under the mutex: an already-cancelled context may run immediately.
	l.mu.Lock()
	l.stop = context.AfterFunc(bounded, func() { _ = l.Close() })
	l.mu.Unlock()
	// Pool/row-lock waits must never extend the credential's lifetime.
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
		return ErrUnauthorized
	}
	if err := l.ctx.Err(); err != nil {
		return err
	}
	authorization, err := l.registry.AuthorizeMutationAt(l.binding, l.clock.Now())
	if err != nil {
		return err
	}
	return l.row.Revalidate(l.ctx, authorization)
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
	// No content transaction is committed here. Persist the clock observation
	// even when the caller's operation failed or was cancelled, then release.
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

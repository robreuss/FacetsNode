package boxcontrol

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Store interface {
	Initialize(context.Context, State) error
	State(context.Context) (State, error)
	Claim(context.Context, string, string, string, time.Time) error
	ClaimAndAuthorizeConnection(context.Context, string, string, string, uuid.UUID, time.Time) error
	ChangeOwnerPassword(context.Context, string, time.Time) error
	CreateWebSession(context.Context, WebSession) error
	WebSession(context.Context, [32]byte, time.Time) (WebSession, error)
	TouchWebSession(context.Context, [32]byte, time.Time) error
	DeleteWebSession(context.Context, [32]byte) error
	RevokeAllWebSessions(context.Context) error
	LoginThrottle(context.Context, string) (LoginThrottle, error)
	RecordLoginFailure(context.Context, string, LoginThrottle) error
	ClearLoginFailures(context.Context, string) error
	CreateGrant(context.Context, ConnectionGrant) error
	Grant(context.Context, [32]byte, time.Time) (ConnectionGrant, error)
	ListGrants(context.Context) ([]ConnectionGrant, error)
	RevokeGrant(context.Context, uuid.UUID, time.Time) error
	RevokeAllGrants(context.Context, time.Time) error
	CreateConnectionInvitation(context.Context, ConnectionInvitation) error
	RedeemConnectionInvitation(context.Context, [32]byte, ConnectionRequest, time.Time) error
	CreateConnectionRequest(context.Context, ConnectionRequest) error
	ConnectionRequest(context.Context, uuid.UUID) (ConnectionRequest, error)
	CompleteConnectionRequest(context.Context, uuid.UUID, []byte) error
	AppendAudit(context.Context, AuditEvent) error
	RecentAudit(context.Context, int) ([]AuditEvent, error)
}

type MemoryStore struct {
	mu          sync.Mutex
	state       *State
	sessions    map[[32]byte]WebSession
	grants      map[uuid.UUID]ConnectionGrant
	invitations map[uuid.UUID]ConnectionInvitation
	requests    map[uuid.UUID]ConnectionRequest
	throttle    map[string]LoginThrottle
	audit       []AuditEvent
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions:    make(map[[32]byte]WebSession),
		grants:      make(map[uuid.UUID]ConnectionGrant),
		invitations: make(map[uuid.UUID]ConnectionInvitation),
		requests:    make(map[uuid.UUID]ConnectionRequest),
		throttle:    make(map[string]LoginThrottle),
	}
}

func (store *MemoryStore) CreateConnectionInvitation(
	_ context.Context,
	invitation ConnectionInvitation,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, present := store.invitations[invitation.InvitationID]; present {
		return errors.New("connection invitation collision")
	}
	for id, existing := range store.invitations {
		if existing.ApprovalCodeDigest == invitation.ApprovalCodeDigest {
			if existing.ExpiresAt.After(invitation.CreatedAt) && existing.RedeemedAt.IsZero() {
				return errors.New("connection code collision")
			}
			delete(store.invitations, id)
		}
	}
	store.invitations[invitation.InvitationID] = invitation
	return nil
}

func (store *MemoryStore) RedeemConnectionInvitation(
	_ context.Context,
	digest [32]byte,
	request ConnectionRequest,
	now time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	var invitationID uuid.UUID
	var invitation ConnectionInvitation
	for id, candidate := range store.invitations {
		if candidate.ApprovalCodeDigest == digest {
			invitationID = id
			invitation = candidate
			break
		}
	}
	if invitationID == uuid.Nil || !invitation.ExpiresAt.After(now) ||
		!invitation.RedeemedAt.IsZero() {
		return ErrInvalidCredential
	}
	if _, present := store.requests[request.RequestID]; present {
		return errors.New("connection request collision")
	}
	for _, existing := range store.requests {
		if existing.ApprovalCodeDigest == request.ApprovalCodeDigest {
			return errors.New("connection request collision")
		}
	}
	invitation.RedeemedRequestID = request.RequestID
	invitation.RedeemedAt = now
	request.AuthorizedAt = now
	store.invitations[invitationID] = invitation
	store.requests[request.RequestID] = request
	return nil
}

func (store *MemoryStore) Initialize(_ context.Context, state State) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state != nil {
		return ErrAlreadyInitialized
	}
	copy := state
	store.state = &copy
	return nil
}

func (store *MemoryStore) State(_ context.Context) (State, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state == nil {
		return State{}, ErrNotInitialized
	}
	return *store.state, nil
}

func (store *MemoryStore) Claim(
	_ context.Context,
	activationVerifier string,
	ownerVerifier string,
	displayName string,
	now time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state == nil {
		return ErrNotInitialized
	}
	if store.state.Claimed() {
		return ErrAlreadyClaimed
	}
	if store.state.ActivationVerifier != activationVerifier {
		return ErrInvalidCredential
	}
	store.state.OwnerVerifier = ownerVerifier
	store.state.ActivationVerifier = ""
	store.state.DisplayName = displayName
	store.state.ClaimedAt = now
	return nil
}

func (store *MemoryStore) ClaimAndAuthorizeConnection(
	_ context.Context,
	activationVerifier string,
	ownerVerifier string,
	displayName string,
	requestID uuid.UUID,
	now time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state == nil {
		return ErrNotInitialized
	}
	if store.state.Claimed() {
		return ErrAlreadyClaimed
	}
	if store.state.ActivationVerifier != activationVerifier {
		return ErrInvalidCredential
	}
	connection, present := store.requests[requestID]
	if !present || connection.ApprovalCodeDigest != claimRequestDigest(requestID) ||
		!connection.ExpiresAt.After(now) || !connection.AuthorizedAt.IsZero() ||
		len(connection.EncryptedResult) != 0 {
		return ErrInvalidCredential
	}
	store.state.OwnerVerifier = ownerVerifier
	store.state.ActivationVerifier = ""
	store.state.DisplayName = displayName
	store.state.ClaimedAt = now
	connection.AuthorizedAt = now
	store.requests[requestID] = connection
	return nil
}

func (store *MemoryStore) ChangeOwnerPassword(
	_ context.Context,
	ownerVerifier string,
	now time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state == nil || !store.state.Claimed() {
		return ErrNotInitialized
	}
	store.state.OwnerVerifier = ownerVerifier
	clear(store.sessions)
	for id, grant := range store.grants {
		grant.RevokedAt = now
		store.grants[id] = grant
	}
	return nil
}

func (store *MemoryStore) CreateWebSession(_ context.Context, session WebSession) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, present := store.sessions[session.TokenDigest]; present {
		return errors.New("web session collision")
	}
	store.sessions[session.TokenDigest] = session
	return nil
}

func (store *MemoryStore) WebSession(
	_ context.Context,
	digest [32]byte,
	now time.Time,
) (WebSession, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	session, present := store.sessions[digest]
	if !present || !session.ExpiresAt.After(now) ||
		now.Sub(session.LastSeenAt) > WebSessionIdleLifetime {
		delete(store.sessions, digest)
		return WebSession{}, ErrInvalidCredential
	}
	return session, nil
}

func (store *MemoryStore) TouchWebSession(_ context.Context, digest [32]byte, now time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	session, present := store.sessions[digest]
	if !present {
		return ErrInvalidCredential
	}
	session.LastSeenAt = now
	store.sessions[digest] = session
	return nil
}

func (store *MemoryStore) DeleteWebSession(_ context.Context, digest [32]byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.sessions, digest)
	return nil
}

func (store *MemoryStore) RevokeAllWebSessions(context.Context) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	clear(store.sessions)
	return nil
}

func (store *MemoryStore) LoginThrottle(_ context.Context, key string) (LoginThrottle, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.throttle[key], nil
}

func (store *MemoryStore) RecordLoginFailure(_ context.Context, key string, value LoginThrottle) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.throttle[key] = value
	return nil
}

func (store *MemoryStore) ClearLoginFailures(_ context.Context, key string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.throttle, key)
	return nil
}

func (store *MemoryStore) CreateGrant(_ context.Context, grant ConnectionGrant) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, present := store.grants[grant.GrantID]; present {
		return errors.New("connection grant collision")
	}
	store.grants[grant.GrantID] = grant
	return nil
}

func (store *MemoryStore) Grant(
	_ context.Context,
	digest [32]byte,
	now time.Time,
) (ConnectionGrant, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	for id, grant := range store.grants {
		if grant.TokenDigest == digest && grant.RevokedAt.IsZero() && grant.ExpiresAt.After(now) {
			grant.LastSeenAt = now
			store.grants[id] = grant
			return grant, nil
		}
	}
	return ConnectionGrant{}, ErrInvalidCredential
}

func (store *MemoryStore) ListGrants(context.Context) ([]ConnectionGrant, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	result := make([]ConnectionGrant, 0, len(store.grants))
	for _, grant := range store.grants {
		result = append(result, grant)
	}
	slices.SortFunc(result, func(left, right ConnectionGrant) int {
		return left.CreatedAt.Compare(right.CreatedAt)
	})
	return result, nil
}

func (store *MemoryStore) RevokeGrant(_ context.Context, grantID uuid.UUID, now time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	grant, present := store.grants[grantID]
	if !present {
		return ErrInvalidCredential
	}
	grant.RevokedAt = now
	store.grants[grantID] = grant
	return nil
}

func (store *MemoryStore) RevokeAllGrants(_ context.Context, now time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	for id, grant := range store.grants {
		grant.RevokedAt = now
		store.grants[id] = grant
	}
	return nil
}

func (store *MemoryStore) CreateConnectionRequest(_ context.Context, request ConnectionRequest) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, present := store.requests[request.RequestID]; present {
		return errors.New("connection request collision")
	}
	for id, existing := range store.requests {
		if existing.ApprovalCodeDigest == request.ApprovalCodeDigest {
			if existing.ExpiresAt.After(request.CreatedAt) {
				return errors.New("connection code collision")
			}
			delete(store.requests, id)
		}
	}
	store.requests[request.RequestID] = request
	return nil
}

func (store *MemoryStore) ConnectionRequest(_ context.Context, requestID uuid.UUID) (ConnectionRequest, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	request, present := store.requests[requestID]
	if !present {
		return ConnectionRequest{}, ErrInvalidCredential
	}
	request.EncryptedResult = append([]byte(nil), request.EncryptedResult...)
	return request, nil
}

func (store *MemoryStore) CompleteConnectionRequest(
	_ context.Context,
	requestID uuid.UUID,
	result []byte,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	request, present := store.requests[requestID]
	if !present || request.AuthorizedAt.IsZero() {
		return ErrInvalidCredential
	}
	if len(request.EncryptedResult) != 0 {
		return ErrRequestReplay
	}
	request.EncryptedResult = append([]byte(nil), result...)
	store.requests[requestID] = request
	return nil
}

func (store *MemoryStore) AppendAudit(_ context.Context, event AuditEvent) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.audit = append(store.audit, event)
	if len(store.audit) > 256 {
		store.audit = store.audit[len(store.audit)-256:]
	}
	return nil
}

func (store *MemoryStore) RecentAudit(_ context.Context, limit int) ([]AuditEvent, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if limit < 0 {
		limit = 0
	}
	start := len(store.audit) - min(limit, len(store.audit))
	result := append([]AuditEvent(nil), store.audit[start:]...)
	slices.Reverse(result)
	return result, nil
}

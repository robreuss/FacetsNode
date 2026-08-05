package rendezvous

import (
	"context"
	"sort"
	"sync"

	"github.com/google/uuid"
)

type memoryRoute struct {
	registration Registration
	entries      map[uuid.UUID]Entry
	closedAt     *int64
}

type MemoryStore struct {
	mu     sync.RWMutex
	routes map[uuid.UUID]*memoryRoute
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{routes: make(map[uuid.UUID]*memoryRoute)}
}

func (s *MemoryStore) CreateRoute(
	_ context.Context,
	registration Registration,
	sponsorToken string,
	nowMilliseconds int64,
) (Acceptance, error) {
	if err := registration.ValidateAt(nowMilliseconds); err != nil {
		return "", err
	}
	credential := Credential{
		RouteID: registration.RouteID,
		Role:    RoleSponsor,
		Token:   sponsorToken,
	}
	if err := registration.Authorize(credential, nowMilliseconds); err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.routes[registration.RouteID]; ok {
		if err := existing.registration.Authorize(credential, nowMilliseconds); err != nil {
			return "", err
		}
		if existing.registration == registration {
			return AcceptanceDuplicate, nil
		}
		return "", protocolError(CodeRouteCollision, "route ID was reused with different registration")
	}
	s.routes[registration.RouteID] = &memoryRoute{
		registration: registration,
		entries:      make(map[uuid.UUID]Entry),
	}
	return AcceptanceAccepted, nil
}

func (s *MemoryStore) Publish(
	_ context.Context,
	credential Credential,
	envelope Envelope,
	nowMilliseconds int64,
) (Acceptance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	route, err := s.authorizedRoute(credential, nowMilliseconds)
	if err != nil {
		return "", err
	}
	if err := envelope.ValidateForPublish(route.registration, nowMilliseconds); err != nil {
		return "", err
	}
	if existing, ok := route.entries[envelope.MessageID]; ok {
		if existing.PublisherRole == credential.Role && existing.Envelope == envelope {
			return AcceptanceDuplicate, nil
		}
		return "", protocolError(CodeMessageCollision, "message ID was reused with different content")
	}
	if route.closedAt != nil {
		return "", protocolError(CodeRouteClosed, "route is closed")
	}
	if len(route.entries) >= MaximumMessageCount {
		return "", protocolError(CodeMailboxFull, "route reached its message limit")
	}
	route.entries[envelope.MessageID] = Entry{
		PublisherRole: credential.Role,
		Envelope:      envelope,
	}
	return AcceptanceAccepted, nil
}

func (s *MemoryStore) Fetch(
	_ context.Context,
	credential Credential,
	nowMilliseconds int64,
) ([]Envelope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	route, err := s.authorizedRoute(credential, nowMilliseconds)
	if err != nil {
		return nil, err
	}
	envelopes := make([]Envelope, 0, len(route.entries))
	for _, entry := range route.entries {
		if entry.PublisherRole != credential.Role && !entry.Acknowledged &&
			entry.Envelope.CreatedAtMilliseconds <= nowMilliseconds &&
			entry.Envelope.ExpiresAtMilliseconds > nowMilliseconds {
			envelopes = append(envelopes, entry.Envelope)
		}
	}
	sort.Slice(envelopes, func(i, j int) bool {
		if envelopes[i].CreatedAtMilliseconds != envelopes[j].CreatedAtMilliseconds {
			return envelopes[i].CreatedAtMilliseconds < envelopes[j].CreatedAtMilliseconds
		}
		return envelopes[i].MessageID.String() < envelopes[j].MessageID.String()
	})
	return envelopes, nil
}

func (s *MemoryStore) Acknowledge(
	_ context.Context,
	credential Credential,
	messageID uuid.UUID,
	nowMilliseconds int64,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	route, err := s.authorizedRoute(credential, nowMilliseconds)
	if err != nil {
		return err
	}
	entry, ok := route.entries[messageID]
	if !ok {
		return protocolError(CodeMessageNotFound, "message was not found")
	}
	if entry.Envelope.ExpiresAtMilliseconds <= nowMilliseconds {
		return protocolError(CodeMessageExpired, "message is expired")
	}
	if entry.PublisherRole == credential.Role {
		return protocolError(CodeInvalidAcknowledgment, "publisher cannot acknowledge its message")
	}
	entry.Acknowledged = true
	route.entries[messageID] = entry
	return nil
}

func (s *MemoryStore) Close(
	_ context.Context,
	credential Credential,
	nowMilliseconds int64,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	route, err := s.authorizedRoute(credential, nowMilliseconds)
	if err != nil {
		return err
	}
	if credential.Role != RoleSponsor {
		return protocolError(CodeUnauthorized, "only the sponsor can close a route")
	}
	if route.closedAt == nil {
		closedAt := nowMilliseconds
		route.closedAt = &closedAt
	}
	return nil
}

func (s *MemoryStore) PurgeExpired(_ context.Context, nowMilliseconds int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for routeID, route := range s.routes {
		if route.registration.ExpiresAtMilliseconds <= nowMilliseconds {
			delete(s.routes, routeID)
			continue
		}
		for messageID, entry := range route.entries {
			if entry.Envelope.ExpiresAtMilliseconds <= nowMilliseconds {
				delete(route.entries, messageID)
			}
		}
	}
	return nil
}

func (s *MemoryStore) Ready(context.Context) error {
	return nil
}

func (s *MemoryStore) authorizedRoute(
	credential Credential,
	nowMilliseconds int64,
) (*memoryRoute, error) {
	route, ok := s.routes[credential.RouteID]
	if !ok {
		return nil, protocolError(CodeRouteNotFound, "route was not found")
	}
	if err := route.registration.Authorize(credential, nowMilliseconds); err != nil {
		return nil, err
	}
	return route, nil
}

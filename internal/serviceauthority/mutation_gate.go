package serviceauthority

import (
	"context"
	"sync"
)

// RequestAccess is explicit route metadata. It describes whether executing a
// handler can change service state; it is deliberately independent of the HTTP
// method because some GET and HEAD relay operations currently expire checkpoint
// state while some POST operations only issue short-lived signed evidence.
type RequestAccess uint8

const (
	RequestRead RequestAccess = iota + 1
	RequestMutation
)

func (access RequestAccess) Valid() bool {
	return access == RequestRead || access == RequestMutation
}

// ScopeLease releases one mutation admission or exclusive migration drain.
// Release is idempotent so callers can safely defer it immediately.
type ScopeLease struct {
	once    sync.Once
	release func()
}

func (lease *ScopeLease) Release() {
	if lease == nil {
		return
	}
	lease.once.Do(func() {
		if lease.release != nil {
			lease.release()
		}
	})
}

type scopeMutationState struct {
	mu               sync.Mutex
	changed          chan struct{}
	activeMutations  int
	exclusiveActive  bool
	exclusiveWaiters int
}

func newScopeMutationState() *scopeMutationState {
	return &scopeMutationState{changed: make(chan struct{})}
}

func (state *scopeMutationState) signalLocked() {
	close(state.changed)
	state.changed = make(chan struct{})
}

// ScopeMutationGate coordinates only writers in this process. It is not a
// durable database fence and does not coordinate another FacetsNode process.
type ScopeMutationGate struct {
	mu     sync.Mutex
	scopes map[Scope]*scopeMutationState
}

func NewScopeMutationGate() *ScopeMutationGate {
	return &ScopeMutationGate{scopes: make(map[Scope]*scopeMutationState)}
}

func (gate *ScopeMutationGate) state(scope Scope) (*scopeMutationState, error) {
	if gate == nil || scope.Validate() != nil {
		return nil, ErrInvalid
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	state := gate.scopes[scope]
	if state == nil {
		state = newScopeMutationState()
		gate.scopes[scope] = state
	}
	return state, nil
}

// AcquireMutation admits one mutation unless an exclusive migration drain is
// active or waiting. Blocking new mutations once a drain is queued ensures the
// drain cannot starve behind a continuous request stream.
func (gate *ScopeMutationGate) AcquireMutation(
	ctx context.Context,
	scope Scope,
) (*ScopeLease, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	state, err := gate.state(scope)
	if err != nil {
		return nil, err
	}
	for {
		state.mu.Lock()
		if !state.exclusiveActive && state.exclusiveWaiters == 0 {
			state.activeMutations++
			state.mu.Unlock()
			return &ScopeLease{release: func() {
				state.mu.Lock()
				state.activeMutations--
				state.signalLocked()
				state.mu.Unlock()
			}}, nil
		}
		changed := state.changed
		state.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}

// AcquireMigrationDrain blocks new mutations and waits for every mutation
// already admitted for this scope to finish. The caller must keep the returned
// lease until its snapshot callback and durable public fence staging complete.
func (gate *ScopeMutationGate) AcquireMigrationDrain(
	ctx context.Context,
	scope Scope,
) (*ScopeLease, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	state, err := gate.state(scope)
	if err != nil {
		return nil, err
	}
	state.mu.Lock()
	state.exclusiveWaiters++
	state.signalLocked()
	state.mu.Unlock()
	waiting := true
	defer func() {
		if !waiting {
			return
		}
		state.mu.Lock()
		state.exclusiveWaiters--
		state.signalLocked()
		state.mu.Unlock()
	}()
	for {
		state.mu.Lock()
		if !state.exclusiveActive && state.activeMutations == 0 {
			state.exclusiveWaiters--
			state.exclusiveActive = true
			state.signalLocked()
			state.mu.Unlock()
			waiting = false
			return &ScopeLease{release: func() {
				state.mu.Lock()
				state.exclusiveActive = false
				state.signalLocked()
				state.mu.Unlock()
			}}, nil
		}
		changed := state.changed
		state.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}

func (registry *BindingRegistry) AcquireMutationLease(
	ctx context.Context,
	scope Scope,
) (*ScopeLease, error) {
	if registry == nil || registry.mutationGate == nil ||
		!registry.hasCurrentScope(scope) {
		return nil, ErrInvalid
	}
	lease, err := registry.mutationGate.AcquireMutation(ctx, scope)
	if err != nil {
		return nil, err
	}
	if !registry.hasCurrentScope(scope) {
		lease.Release()
		return nil, ErrInvalid
	}
	return lease, nil
}

func (registry *BindingRegistry) AcquireMigrationDrain(
	ctx context.Context,
	scope Scope,
) (*ScopeLease, error) {
	if registry == nil || registry.mutationGate == nil ||
		!registry.hasCurrentScope(scope) {
		return nil, ErrInvalid
	}
	lease, err := registry.mutationGate.AcquireMigrationDrain(ctx, scope)
	if err != nil {
		return nil, err
	}
	if !registry.hasCurrentScope(scope) {
		lease.Release()
		return nil, ErrInvalid
	}
	return lease, nil
}

func (registry *BindingRegistry) hasCurrentScope(scope Scope) bool {
	if registry == nil || scope.Validate() != nil {
		return false
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	_, exists := registry.bindings[scope]
	return exists && !registry.poisoned
}

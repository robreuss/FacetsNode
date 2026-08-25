package serverapp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

// reconcileDeviceSyncServiceAuthority is a fail-closed startup gate. It may
// repair only the exact crash state in which BindingRegistry is already active
// while the same committed initial authority remains database-standby. It never
// installs or reconstructs a registry binding from database state.
func reconcileDeviceSyncServiceAuthority(
	ctx context.Context,
	store devicesync.AuthorityReconciliationStore,
	bindings *serviceauthority.BindingRegistry,
	nowMilliseconds int64,
) error {
	if ctx == nil || store == nil || bindings == nil || nowMilliseconds < 0 {
		return serviceauthority.ErrInvalid
	}
	states, err := store.ListDeviceSyncServiceAuthorityStates(ctx)
	if err != nil {
		return fmt.Errorf("list durable Device Sync authority state: %w", err)
	}
	registryBindings, err := bindings.CurrentBindingIdentitiesAt(
		serviceauthority.ScopeDeviceSync,
		time.UnixMilli(nowMilliseconds),
	)
	if err != nil {
		return fmt.Errorf("read Device Sync authority bindings: %w", err)
	}
	registryByScope := make(map[serviceauthority.Scope]serviceauthority.BindingIdentity, len(registryBindings))
	for _, binding := range registryBindings {
		if _, duplicate := registryByScope[binding.Scope]; duplicate {
			return errors.New("Device Sync binding registry contains a duplicate scope")
		}
		registryByScope[binding.Scope] = binding
	}

	stateByScope := make(map[serviceauthority.Scope]devicesync.DeviceSyncServiceAuthorityState, len(states))
	for _, state := range states {
		if err := state.Validate(); err != nil {
			return fmt.Errorf("invalid durable Device Sync authority state: %w", err)
		}
		if _, duplicate := stateByScope[state.Scope]; duplicate {
			return fmt.Errorf("duplicate durable Device Sync scope %s", state.Scope.ScopeID)
		}
		stateByScope[state.Scope] = state
		binding, exists := registryByScope[state.Scope]
		if !exists {
			return fmt.Errorf(
				"durable Device Sync scope %s has no registry authority",
				state.Scope.ScopeID,
			)
		}
		if err := exactDeviceSyncAuthorityMatch(state, binding); err != nil {
			return err
		}
		switch state.WriteState {
		case devicesync.ServiceAuthorityStandby:
			authority := state.Authority
			if authority.Revision != 1 ||
				authority.TransitionEvidenceDigest != nil {
				return fmt.Errorf(
					"Device Sync scope %s standby authority requires an explicit migration coordinator",
					state.Scope.ScopeID,
				)
			}
			if err := store.ActivateBoundDeviceSyncScope(
				ctx,
				state.Scope.ScopeID,
				authority.LocalDeploymentID,
				authority.Revision,
				authority.ManifestDigest,
				nowMilliseconds,
			); err != nil {
				return fmt.Errorf(
					"repair Device Sync scope %s standby activation: %w",
					state.Scope.ScopeID, err,
				)
			}
		case devicesync.ServiceAuthorityWritable:
			// Exact registry and database authority already agree.
		default:
			return fmt.Errorf(
				"Device Sync scope %s state %q requires an explicit migration coordinator",
				state.Scope.ScopeID, state.WriteState,
			)
		}
	}
	for scope := range registryByScope {
		if _, exists := stateByScope[scope]; !exists {
			return fmt.Errorf(
				"Device Sync registry scope %s has no durable enforcement row",
				scope.ScopeID,
			)
		}
	}

	// Re-read after all exact repairs. Readiness is granted only when each row is
	// now writable under the same binding; a store that acknowledges activation
	// without durably changing state cannot pass this gate.
	verified, err := store.ListDeviceSyncServiceAuthorityStates(ctx)
	if err != nil {
		return fmt.Errorf("verify durable Device Sync authority state: %w", err)
	}
	if len(verified) != len(states) {
		return errors.New("durable Device Sync authority scope set changed during startup")
	}
	verifiedScopes := make(map[serviceauthority.Scope]struct{}, len(verified))
	for _, state := range verified {
		if err := state.Validate(); err != nil {
			return fmt.Errorf(
				"invalid verified Device Sync authority state: %w",
				err,
			)
		}
		if state.WriteState != devicesync.ServiceAuthorityWritable {
			return fmt.Errorf(
				"Device Sync scope %s did not reach exact writable readiness",
				state.Scope.ScopeID,
			)
		}
		if _, duplicate := verifiedScopes[state.Scope]; duplicate {
			return fmt.Errorf("duplicate verified Device Sync scope %s", state.Scope.ScopeID)
		}
		verifiedScopes[state.Scope] = struct{}{}
		binding, exists := registryByScope[state.Scope]
		if !exists {
			return fmt.Errorf(
				"verified Device Sync scope %s has no registry authority",
				state.Scope.ScopeID,
			)
		}
		if err := exactDeviceSyncAuthorityMatch(state, binding); err != nil {
			return err
		}
	}
	return nil
}

func exactDeviceSyncAuthorityMatch(
	state devicesync.DeviceSyncServiceAuthorityState,
	binding serviceauthority.BindingIdentity,
) error {
	if state.Authority == nil {
		return fmt.Errorf(
			"durable Device Sync scope %s is not authority-bound",
			state.Scope.ScopeID,
		)
	}
	authority := state.Authority
	if binding.Scope != state.Scope || binding.WriteFenced ||
		authority.LocalDeploymentID != authority.ActiveDeploymentID ||
		authority.ActiveDeploymentID != binding.DeploymentID ||
		authority.Revision != binding.Revision ||
		authority.ManifestDigest != binding.Digest ||
		!equalOptionalDigest(
			authority.TransitionEvidenceDigest,
			binding.TransitionEvidenceDigest,
		) {
		return fmt.Errorf(
			"Device Sync scope %s database and registry authority conflict",
			state.Scope.ScopeID,
		)
	}
	return nil
}

func equalOptionalDigest(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

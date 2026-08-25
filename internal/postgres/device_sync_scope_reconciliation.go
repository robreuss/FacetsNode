package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

var _ devicesync.AuthorityReconciliationStore = (*RelayStore)(nil)

// ListDeviceSyncServiceAuthorityStates returns every durable Device Sync
// enforcement row after revalidating its stored signed manifest. The result is
// deterministic by scope ID so startup reconciliation is stable and auditable.
func (s *RelayStore) ListDeviceSyncServiceAuthorityStates(
	ctx context.Context,
) ([]devicesync.DeviceSyncServiceAuthorityState, error) {
	if ctx == nil || s == nil || s.pool == nil {
		return nil, serviceauthority.ErrInvalid
	}
	rows, err := s.pool.Query(ctx, `
		SELECT principal_id
		FROM device_sync_scope_enforcement
		ORDER BY principal_id
	`)
	if err != nil {
		return nil, fmt.Errorf("list Device Sync scope enforcement identities: %w", err)
	}
	principalIDs := make([]uuid.UUID, 0)
	for rows.Next() {
		var principalID uuid.UUID
		if err := rows.Scan(&principalID); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan Device Sync scope enforcement identity: %w", err)
		}
		principalIDs = append(principalIDs, principalID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate Device Sync scope enforcement identities: %w", err)
	}
	rows.Close()

	states := make([]devicesync.DeviceSyncServiceAuthorityState, 0, len(principalIDs))
	for _, principalID := range principalIDs {
		current, err := loadDeviceSyncScopeEnforcement(ctx, s.pool, principalID, "")
		if err != nil {
			return nil, fmt.Errorf(
				"revalidate Device Sync scope %s for startup: %w",
				principalID, err,
			)
		}
		state, err := deviceSyncServiceAuthorityState(current)
		if err != nil {
			return nil, fmt.Errorf(
				"project Device Sync scope %s for startup: %w",
				principalID, err,
			)
		}
		states = append(states, state)
	}
	return states, nil
}

func deviceSyncServiceAuthorityState(
	current DeviceSyncScopeEnforcement,
) (devicesync.DeviceSyncServiceAuthorityState, error) {
	state := devicesync.DeviceSyncServiceAuthorityState{
		Scope: serviceauthority.Scope{
			Kind:    serviceauthority.ScopeDeviceSync,
			ScopeID: current.PrincipalID,
		},
		WriteState: devicesync.ServiceAuthorityWriteState(current.State),
	}
	if current.Authority != nil && current.LocalDeploymentID != nil {
		state.Authority = &devicesync.ServiceAuthorityIdentity{
			LocalDeploymentID:  *current.LocalDeploymentID,
			ActiveDeploymentID: current.Authority.ActiveDeploymentID,
			Revision:           current.Authority.Revision,
			ManifestDigest:     current.Authority.ManifestDigest,
			TransitionEvidenceDigest: cloneStringPointer(
				current.Authority.TransitionEvidenceDigest,
			),
		}
	}
	if err := state.Validate(); err != nil {
		return devicesync.DeviceSyncServiceAuthorityState{}, err
	}
	return state, nil
}

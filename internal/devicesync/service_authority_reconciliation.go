package devicesync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

// ServiceAuthorityWriteState is the durable database-side write state for one
// Device Sync scope. It is deliberately distinct from the service-authority
// manifest transition: the manifest identifies authority, while this state
// decides whether the local database may accept writes.
type ServiceAuthorityWriteState string

const (
	ServiceAuthorityStandby         ServiceAuthorityWriteState = "standby"
	ServiceAuthorityWritable        ServiceAuthorityWriteState = "writable"
	ServiceAuthorityExportFenced    ServiceAuthorityWriteState = "export_fenced"
	ServiceAuthorityRollbackStandby ServiceAuthorityWriteState = "rollback_standby"
	ServiceAuthorityRetired         ServiceAuthorityWriteState = "retired"
)

func (state ServiceAuthorityWriteState) Valid() bool {
	return state == ServiceAuthorityStandby ||
		state == ServiceAuthorityWritable ||
		state == ServiceAuthorityExportFenced ||
		state == ServiceAuthorityRollbackStandby ||
		state == ServiceAuthorityRetired
}

// ServiceAuthorityIdentity contains only the committed facts needed to compare
// a Device Sync enforcement row with BindingRegistry. It intentionally omits
// the signed manifest record; both stores independently validate that record
// before exposing this identity.
type ServiceAuthorityIdentity struct {
	LocalDeploymentID        uuid.UUID
	ActiveDeploymentID       uuid.UUID
	Revision                 uint64
	ManifestDigest           string
	TransitionEvidenceDigest *string
}

func (identity ServiceAuthorityIdentity) Validate() error {
	if identity.LocalDeploymentID == uuid.Nil ||
		identity.ActiveDeploymentID == uuid.Nil || identity.Revision == 0 ||
		!validServiceAuthorityDigest(identity.ManifestDigest) ||
		(identity.TransitionEvidenceDigest != nil &&
			!validServiceAuthorityDigest(*identity.TransitionEvidenceDigest)) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

// DeviceSyncServiceAuthorityState is the revalidated database-side authority
// state used by the startup readiness gate. Authority is nil only for a
// pristine, unbound standby row; authority-enabled startup must reject such a
// row rather than infer authority for it.
type DeviceSyncServiceAuthorityState struct {
	Scope      serviceauthority.Scope
	WriteState ServiceAuthorityWriteState
	Authority  *ServiceAuthorityIdentity
}

func (state DeviceSyncServiceAuthorityState) Validate() error {
	if state.Scope.Validate() != nil ||
		state.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		!state.WriteState.Valid() {
		return serviceauthority.ErrInvalid
	}
	if state.Authority == nil {
		if state.WriteState != ServiceAuthorityStandby {
			return serviceauthority.ErrInvalid
		}
		return nil
	}
	return state.Authority.Validate()
}

// AuthorityReconciliationStore is the durable Device Sync capability
// required by authority-enabled process startup. The in-memory test store does
// not implement it and therefore is never represented as durable fencing.
type AuthorityReconciliationStore interface {
	ListDeviceSyncServiceAuthorityStates(
		context.Context,
	) ([]DeviceSyncServiceAuthorityState, error)
	ActivateBoundDeviceSyncScope(
		context.Context,
		uuid.UUID,
		uuid.UUID,
		uint64,
		string,
		int64,
	) error
}

func validServiceAuthorityDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

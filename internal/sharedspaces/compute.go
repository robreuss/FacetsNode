package sharedspaces

import (
	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computepool"
	"github.com/robreuss/FacetsNode/internal/relay"
)

type ComputeResourceCeiling = computepool.ResourceCeiling
type SpaceComputeBinding = computepool.SpaceBinding

// SpaceComputeBindingChange is a complete, retry-safe replacement of the
// reference and policy edge from one Shared Space to an independently owned
// Compute Pool. It never creates, renames, enables, or deletes that Pool.
type SpaceComputeBindingChange struct {
	Version                    int                             `json:"version"`
	RetryID                    uuid.UUID                       `json:"retryID"`
	SpaceID                    uuid.UUID                       `json:"spaceID"`
	BindingID                  uuid.UUID                       `json:"bindingID"`
	PoolAuthority              computepool.AuthorityReference  `json:"poolAuthority"`
	PreviousBindingRevision    uint64                          `json:"previousBindingRevision"`
	AllowedOperations          []string                        `json:"allowedOperations"`
	EligiblePrincipalIDs       []uuid.UUID                     `json:"eligiblePrincipalIDs"`
	EligibleRoleIdentifiers    []string                        `json:"eligibleRoleIdentifiers"`
	AllowedProviderIdentifiers []string                        `json:"allowedProviderIdentifiers"`
	ResourceCeiling            ComputeResourceCeiling          `json:"resourceCeiling"`
	BudgetCeiling              computepool.BudgetCeiling       `json:"budgetCeiling"`
	PricingRevision            uint64                          `json:"pricingRevision"`
	DataUseConstraints         []computepool.DataUseConstraint `json:"dataUseConstraints"`
	SourceAuthorityRevision    uint64                          `json:"sourceAuthorityRevision"`
	ChangedAtMilliseconds      int64                           `json:"changedAtMilliseconds"`
}

func (change SpaceComputeBindingChange) Validate() error {
	if change.Version != SchemaVersion || change.RetryID == uuid.Nil ||
		change.SpaceID == uuid.Nil || change.BindingID == uuid.Nil ||
		change.ChangedAtMilliseconds < 0 {
		return NewProtocolError(
			CodeInvalidComputeBinding,
			"Shared Space compute binding change fields are invalid",
		)
	}
	binding := change.binding(
		change.PreviousBindingRevision+1,
		change.ChangedAtMilliseconds,
		change.ChangedAtMilliseconds,
	)
	if err := binding.Validate(); err != nil {
		return NewProtocolError(
			CodeInvalidComputeBinding,
			"Shared Space compute binding policy is invalid",
		)
	}
	return nil
}

func (change SpaceComputeBindingChange) binding(
	revision uint64,
	createdAtMilliseconds int64,
	updatedAtMilliseconds int64,
) SpaceComputeBinding {
	return SpaceComputeBinding{
		Version: computepool.SchemaVersion, BindingID: change.BindingID,
		SpaceID: change.SpaceID, PoolAuthority: change.PoolAuthority,
		AllowedOperations:       append([]string(nil), change.AllowedOperations...),
		EligiblePrincipalIDs:    append([]uuid.UUID(nil), change.EligiblePrincipalIDs...),
		EligibleRoleIdentifiers: append([]string(nil), change.EligibleRoleIdentifiers...),
		AllowedProviderIdentifiers: append(
			[]string(nil),
			change.AllowedProviderIdentifiers...,
		),
		ResourceCeiling: change.ResourceCeiling, BudgetCeiling: change.BudgetCeiling,
		PricingRevision:    change.PricingRevision,
		DataUseConstraints: append([]computepool.DataUseConstraint(nil), change.DataUseConstraints...),
		Revision:           revision, SourceAuthorityRevision: change.SourceAuthorityRevision,
		CreatedAtMilliseconds: createdAtMilliseconds,
		UpdatedAtMilliseconds: updatedAtMilliseconds,
	}
}

// NextBinding materializes the next complete binding revision after Validate
// and authority checks have succeeded in a Store implementation.
func (change SpaceComputeBindingChange) NextBinding(
	createdAtMilliseconds int64,
) SpaceComputeBinding {
	return change.binding(
		change.PreviousBindingRevision+1,
		createdAtMilliseconds,
		change.ChangedAtMilliseconds,
	)
}

type SpaceComputeBindingChangeResult struct {
	Acceptance relay.Acceptance    `json:"acceptance"`
	RetryID    uuid.UUID           `json:"retryID"`
	Binding    SpaceComputeBinding `json:"binding"`
}

func (result SpaceComputeBindingChangeResult) Validate() error {
	if (result.Acceptance != relay.AcceptanceAccepted &&
		result.Acceptance != relay.AcceptanceDuplicate) || result.RetryID == uuid.Nil ||
		result.Binding.Validate() != nil {
		return NewProtocolError(
			CodeInvalidComputeBinding,
			"Shared Space compute binding result fields are invalid",
		)
	}
	return nil
}

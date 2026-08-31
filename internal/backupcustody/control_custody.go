package backupcustody

import (
	"context"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

// ControlCustody serializes portable owner-signed commands with the exact
// account service-authority generation. PostgreSQL remains the durable command
// order and validates the current control head under the account row lock.
type ControlCustody struct {
	Store    Store
	Registry *serviceauthority.BindingRegistry
	Clock    Clock
}

func (custody *ControlCustody) Submit(
	ctx context.Context,
	record SignedControlCommand,
	binding serviceauthority.RequestBinding,
) (ControlCommandAcceptance, error) {
	payload, err := record.DecodedPayload()
	if custody == nil || custody.Store == nil || custody.Registry == nil || custody.Clock == nil || err != nil {
		return ControlCommandAcceptance{}, serviceauthority.ErrInvalid
	}
	scope := serviceauthority.Scope{Kind: serviceauthority.ScopeBackupCustody, ScopeID: payload.AccountID}
	if binding.Scope != scope {
		return ControlCommandAcceptance{}, serviceauthority.ErrInvalid
	}
	lease, err := custody.Registry.AcquireMutationLease(ctx, scope)
	if err != nil {
		return ControlCommandAcceptance{}, err
	}
	defer lease.Release()
	authorization, err := custody.Registry.AuthorizeMutationAt(binding, custody.Clock.Now())
	if err != nil {
		return ControlCommandAcceptance{}, err
	}
	return custody.Store.ApplyControlCommand(ctx, record, authorization)
}

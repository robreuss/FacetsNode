package devicesync

import (
	"context"
	"reflect"
	"sync"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

type memoryPrincipal struct {
	admissionID  uuid.UUID
	provisioning PrincipalProvisioning
	result       relay.TenantProvisioningResult
}

type MemoryStore struct {
	mu             sync.Mutex
	relay          relay.Store
	admissions     map[uuid.UUID]AccountAdmission
	admissionRetry map[uuid.UUID]uuid.UUID
	principals     map[uuid.UUID]memoryPrincipal
}

func NewMemoryStore(relayStore relay.Store) *MemoryStore {
	return &MemoryStore{
		relay: relayStore, admissions: make(map[uuid.UUID]AccountAdmission),
		admissionRetry: make(map[uuid.UUID]uuid.UUID), principals: make(map[uuid.UUID]memoryPrincipal),
	}
}

func (s *MemoryStore) CreateAccountAdmission(_ context.Context, admission AccountAdmission, nowMilliseconds int64) (AdmissionCreateResult, error) {
	if err := admission.Validate(); err != nil {
		return AdmissionCreateResult{}, err
	}
	if nowMilliseconds < admission.CreatedAtMilliseconds || nowMilliseconds >= admission.ExpiresAtMilliseconds ||
		admission.ClaimedAtMilliseconds != nil {
		return AdmissionCreateResult{}, NewProtocolError(CodeInvalidAdmission, "account admission is not currently issuable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if admissionID, found := s.admissionRetry[admission.RetryID]; found {
		existing := s.admissions[admissionID]
		if existing == admission {
			return AdmissionCreateResult{Acceptance: relay.AcceptanceDuplicate, Admission: existing}, nil
		}
		return AdmissionCreateResult{}, NewProtocolError(CodeAdmissionCollision, "account admission retry ID was reused")
	}
	if existing, found := s.admissions[admission.AdmissionID]; found {
		if existing == admission {
			return AdmissionCreateResult{Acceptance: relay.AcceptanceDuplicate, Admission: existing}, nil
		}
		return AdmissionCreateResult{}, NewProtocolError(CodeAdmissionCollision, "account admission ID was reused")
	}
	s.admissions[admission.AdmissionID] = admission
	s.admissionRetry[admission.RetryID] = admission.AdmissionID
	return AdmissionCreateResult{Acceptance: relay.AcceptanceAccepted, Admission: admission}, nil
}

func (s *MemoryStore) ClaimAccountAdmission(ctx context.Context, credential AdmissionCredential, provisioning PrincipalProvisioning, nowMilliseconds int64) (PrincipalProvisioningResult, error) {
	if err := provisioning.Validate(); err != nil {
		return PrincipalProvisioningResult{}, err
	}
	if provisioning.CreatedAtMilliseconds > nowMilliseconds {
		return PrincipalProvisioningResult{}, NewProtocolError(CodeInvalidPrincipal, "principal starts in the future")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	admission, found := s.admissions[credential.AdmissionID]
	if !found {
		return PrincipalProvisioningResult{}, NewProtocolError(CodeAdmissionNotFound, "account admission was not found")
	}
	if err := admission.VerifyCredential(credential); err != nil {
		return PrincipalProvisioningResult{}, err
	}
	if admission.ClaimedAtMilliseconds != nil {
		existing, found := s.principals[*admission.ClaimedPrincipalID]
		if found && existing.admissionID == admission.AdmissionID && reflect.DeepEqual(existing.provisioning, provisioning) {
			return resultFor(provisioning, existing.result, relay.AcceptanceDuplicate), nil
		}
		return PrincipalProvisioningResult{}, NewProtocolError(CodeAdmissionClaimed, "account admission was already claimed")
	}
	if err := admission.RequireActive(nowMilliseconds); err != nil {
		return PrincipalProvisioningResult{}, err
	}
	if existing, found := s.principals[provisioning.PrincipalID]; found {
		if existing.admissionID != admission.AdmissionID || !reflect.DeepEqual(existing.provisioning, provisioning) {
			return PrincipalProvisioningResult{}, NewProtocolError(CodePrincipalCollision, "principal ID was reused")
		}
	}
	relayResult, err := s.relay.ProvisionTenant(ctx, provisioning.Tenant, provisioning.ControlDomain)
	if err != nil {
		return PrincipalProvisioningResult{}, err
	}
	claimedAt := nowMilliseconds
	principalID := provisioning.PrincipalID
	admission.ClaimedAtMilliseconds = &claimedAt
	admission.ClaimedPrincipalID = &principalID
	s.admissions[admission.AdmissionID] = admission
	s.principals[principalID] = memoryPrincipal{
		admissionID: admission.AdmissionID, provisioning: provisioning, result: relayResult,
	}
	return resultFor(provisioning, relayResult, relay.AcceptanceAccepted), nil
}

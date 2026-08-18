package devicesync

import (
	"context"
	"reflect"
	"sort"
	"sync"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

type memoryPrincipal struct {
	admissionID  uuid.UUID
	provisioning PrincipalProvisioning
	result       relay.TenantProvisioningResult
}

type memoryDeviceAdmission struct {
	admission DeviceAdmission
	result    *DeviceAdmissionClaimResult
}

type memorySpace struct {
	provisioning SpaceProvisioning
	result       relay.DomainProvisioningResult
	devices      map[uuid.UUID]bool
}

type memorySpaceDeviceAdmission struct {
	admission SpaceDeviceAdmission
	result    *SpaceDeviceAdmissionClaimResult
}

type MemoryStore struct {
	mu                        sync.Mutex
	relay                     relay.Store
	admissions                map[uuid.UUID]AccountAdmission
	admissionRetry            map[uuid.UUID]uuid.UUID
	principals                map[uuid.UUID]memoryPrincipal
	deviceAdmissions          map[uuid.UUID]memoryDeviceAdmission
	deviceAdmissionRetry      map[uuid.UUID]uuid.UUID
	spaces                    map[uuid.UUID]memorySpace
	spaceRetry                map[uuid.UUID]uuid.UUID
	spaceDeviceAdmissions     map[uuid.UUID]memorySpaceDeviceAdmission
	spaceDeviceAdmissionRetry map[uuid.UUID]uuid.UUID
}

func NewMemoryStore(relayStore relay.Store) *MemoryStore {
	return &MemoryStore{
		relay: relayStore, admissions: make(map[uuid.UUID]AccountAdmission),
		admissionRetry: make(map[uuid.UUID]uuid.UUID), principals: make(map[uuid.UUID]memoryPrincipal),
		deviceAdmissions:          make(map[uuid.UUID]memoryDeviceAdmission),
		deviceAdmissionRetry:      make(map[uuid.UUID]uuid.UUID),
		spaces:                    make(map[uuid.UUID]memorySpace),
		spaceRetry:                make(map[uuid.UUID]uuid.UUID),
		spaceDeviceAdmissions:     make(map[uuid.UUID]memorySpaceDeviceAdmission),
		spaceDeviceAdmissionRetry: make(map[uuid.UUID]uuid.UUID),
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

func (s *MemoryStore) CreateDeviceAdmission(
	ctx context.Context,
	credential relay.AdministrationCredential,
	admission DeviceAdmission,
	nowMilliseconds int64,
) (DeviceAdmissionCreateResult, error) {
	if err := admission.Validate(); err != nil {
		return DeviceAdmissionCreateResult{}, err
	}
	if admission.CreatedAtMilliseconds > nowMilliseconds ||
		admission.RelayAdmission.ExpiresAtMilliseconds <= nowMilliseconds {
		return DeviceAdmissionCreateResult{}, NewProtocolError(CodeInvalidAdmission, "device admission is not currently issuable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	principal, found := s.principals[admission.PrincipalID]
	if !found {
		return DeviceAdmissionCreateResult{}, NewProtocolError(CodeUnauthorized, "Device Sync principal was not found")
	}
	if credential.TenantID != admission.PrincipalID ||
		credential.DomainID != principal.provisioning.ControlDomain.Registration.DomainID ||
		admission.RelayAdmission.TenantID != admission.PrincipalID ||
		admission.RelayAdmission.DomainID != credential.DomainID ||
		admission.SubscriptionID == principal.provisioning.ControlDomain.Subscription.SubscriptionID {
		return DeviceAdmissionCreateResult{}, NewProtocolError(CodeWrongScope, "device admission belongs to another principal control domain")
	}
	if admissionID, found := s.deviceAdmissionRetry[admission.RetryID]; found {
		existing := s.deviceAdmissions[admissionID]
		if reflect.DeepEqual(existing.admission, admission) {
			return DeviceAdmissionCreateResult{Acceptance: relay.AcceptanceDuplicate, Admission: existing.admission}, nil
		}
		return DeviceAdmissionCreateResult{}, NewProtocolError(CodeAdmissionCollision, "device admission retry ID was reused")
	}
	if existing, found := s.deviceAdmissions[admission.RelayAdmission.AdmissionID]; found {
		if reflect.DeepEqual(existing.admission, admission) {
			return DeviceAdmissionCreateResult{Acceptance: relay.AcceptanceDuplicate, Admission: existing.admission}, nil
		}
		return DeviceAdmissionCreateResult{}, NewProtocolError(CodeAdmissionCollision, "device admission ID was reused")
	}
	if _, found := s.principalDevice(admission.PrincipalID, admission.DeviceID); found {
		return DeviceAdmissionCreateResult{}, NewProtocolError(CodeDeviceCollision, "device is already registered")
	}
	if _, err := s.relay.CreateSubscription(ctx, credential, relay.SubscriptionCreateRequest{
		RetryID:               admission.RetryID,
		SubscriptionID:        admission.SubscriptionID,
		CreatedAtMilliseconds: admission.CreatedAtMilliseconds,
	}); err != nil {
		return DeviceAdmissionCreateResult{}, err
	}
	relayResult, err := s.relay.CreateSubscriptionAdmission(
		ctx, credential, admission.SubscriptionID, admission.RelayAdmission, nowMilliseconds,
	)
	if err != nil {
		return DeviceAdmissionCreateResult{}, err
	}
	s.deviceAdmissions[admission.RelayAdmission.AdmissionID] = memoryDeviceAdmission{admission: admission}
	s.deviceAdmissionRetry[admission.RetryID] = admission.RelayAdmission.AdmissionID
	return DeviceAdmissionCreateResult{Acceptance: relayResult.Acceptance, Admission: admission}, nil
}

func (s *MemoryStore) ClaimDeviceAdmission(
	ctx context.Context,
	credential DeviceAdmissionCredential,
	claim DeviceAdmissionClaim,
	nowMilliseconds int64,
) (DeviceAdmissionClaimResult, error) {
	if err := claim.Validate(); err != nil {
		return DeviceAdmissionClaimResult{}, err
	}
	if claim.ClaimedAtMilliseconds != nowMilliseconds {
		return DeviceAdmissionClaimResult{}, NewProtocolError(CodeInvalidAdmission, "device claim time differs from server time")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, found := s.deviceAdmissions[credential.AdmissionID]
	if !found {
		return DeviceAdmissionClaimResult{}, NewProtocolError(CodeAdmissionNotFound, "device admission was not found")
	}
	if credential.PrincipalID != record.admission.PrincipalID ||
		claim.PrincipalID != record.admission.PrincipalID ||
		claim.DeviceID != record.admission.DeviceID {
		return DeviceAdmissionClaimResult{}, NewProtocolError(CodeWrongScope, "device claim belongs to another admission")
	}
	if record.result != nil {
		if record.result.DeviceID == claim.DeviceID &&
			record.result.Member.MemberRegistration.AuthorizationDigest == claim.RelayClaim.AuthorizationDigest {
			duplicate := *record.result
			duplicate.Acceptance = relay.AcceptanceDuplicate
			return duplicate, nil
		}
		return DeviceAdmissionClaimResult{}, NewProtocolError(CodeAdmissionClaimed, "device admission was already claimed")
	}
	relayResult, err := s.relay.ClaimSubscriptionAdmission(ctx, relay.AdmissionCredential{
		TenantID:    record.admission.PrincipalID,
		DomainID:    record.admission.RelayAdmission.DomainID,
		AdmissionID: credential.AdmissionID,
		Token:       credential.Token,
	}, claim.RelayClaim, nowMilliseconds)
	if err != nil {
		return DeviceAdmissionClaimResult{}, err
	}
	result := DeviceAdmissionClaimResult{
		Acceptance: relayResult.Acceptance, PrincipalID: claim.PrincipalID,
		DeviceID: claim.DeviceID, Member: relayResult.Member,
	}
	record.result = &result
	s.deviceAdmissions[credential.AdmissionID] = record
	return result, nil
}

func (s *MemoryStore) principalDevice(principalID, deviceID uuid.UUID) (memoryDeviceAdmission, bool) {
	for _, admission := range s.deviceAdmissions {
		if admission.admission.PrincipalID == principalID &&
			admission.admission.DeviceID == deviceID && admission.result != nil {
			return admission, true
		}
	}
	principal, found := s.principals[principalID]
	return memoryDeviceAdmission{}, found && principal.provisioning.InitialDeviceID == deviceID
}

func (s *MemoryStore) ProvisionSpace(
	ctx context.Context,
	credential relay.TenantCredential,
	provisioning SpaceProvisioning,
	nowMilliseconds int64,
) (SpaceProvisioningResult, error) {
	if err := provisioning.Validate(); err != nil {
		return SpaceProvisioningResult{}, err
	}
	if credential.TenantID != provisioning.PrincipalID ||
		provisioning.CreatedAtMilliseconds > nowMilliseconds {
		return SpaceProvisioningResult{}, NewProtocolError(
			CodeWrongScope, "Device Sync Space belongs to another principal",
		)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, found := s.principals[provisioning.PrincipalID]; !found {
		return SpaceProvisioningResult{}, NewProtocolError(CodeUnauthorized, "Device Sync principal was not found")
	}
	if _, found := s.principalDevice(provisioning.PrincipalID, provisioning.InitialDeviceID); !found {
		return SpaceProvisioningResult{}, NewProtocolError(CodeUnauthorized, "initial Space device is not enrolled")
	}
	if spaceID, found := s.spaceRetry[provisioning.RetryID]; found && spaceID != provisioning.SpaceID {
		return SpaceProvisioningResult{}, NewProtocolError(CodeSpaceCollision, "Device Sync Space retry ID was reused")
	}
	if existing, found := s.spaces[provisioning.SpaceID]; found {
		if !reflect.DeepEqual(existing.provisioning, provisioning) {
			return SpaceProvisioningResult{}, NewProtocolError(CodeSpaceCollision, "Device Sync Space ID was reused")
		}
		relayResult, err := s.relay.ProvisionDomain(ctx, credential, provisioning.Domain, nowMilliseconds)
		if err != nil {
			return SpaceProvisioningResult{}, err
		}
		return spaceProvisioningResult(provisioning, relayResult, relay.AcceptanceDuplicate), nil
	}
	relayResult, err := s.relay.ProvisionDomain(ctx, credential, provisioning.Domain, nowMilliseconds)
	if err != nil {
		return SpaceProvisioningResult{}, err
	}
	if relayResult.Acceptance != relay.AcceptanceAccepted {
		return SpaceProvisioningResult{}, NewProtocolError(CodeSpaceCollision, "Space relay domain already exists")
	}
	s.spaces[provisioning.SpaceID] = memorySpace{
		provisioning: provisioning, result: relayResult,
		devices: map[uuid.UUID]bool{provisioning.InitialDeviceID: true},
	}
	s.spaceRetry[provisioning.RetryID] = provisioning.SpaceID
	return spaceProvisioningResult(provisioning, relayResult, relay.AcceptanceAccepted), nil
}

func (s *MemoryStore) CreateSpaceDeviceAdmission(
	ctx context.Context,
	credential relay.AdministrationCredential,
	admission SpaceDeviceAdmission,
	nowMilliseconds int64,
) (SpaceDeviceAdmissionCreateResult, error) {
	if err := admission.Validate(); err != nil {
		return SpaceDeviceAdmissionCreateResult{}, err
	}
	if admission.CreatedAtMilliseconds > nowMilliseconds ||
		admission.RelayAdmission.ExpiresAtMilliseconds <= nowMilliseconds {
		return SpaceDeviceAdmissionCreateResult{}, NewProtocolError(
			CodeInvalidAdmission, "Space device admission is not currently issuable",
		)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, found := s.principalDevice(admission.PrincipalID, admission.DeviceID); !found {
		return SpaceDeviceAdmissionCreateResult{}, NewProtocolError(
			CodeUnauthorized, "Space device is not enrolled in the Device Sync principal",
		)
	}
	space, found := s.spaces[admission.SpaceID]
	if !found || space.provisioning.PrincipalID != admission.PrincipalID {
		return SpaceDeviceAdmissionCreateResult{}, NewProtocolError(CodeUnauthorized, "Device Sync Space was not found")
	}
	if credential.TenantID != admission.PrincipalID ||
		credential.DomainID != space.provisioning.Domain.Registration.DomainID ||
		admission.RelayAdmission.TenantID != admission.PrincipalID ||
		admission.RelayAdmission.DomainID != credential.DomainID ||
		admission.SubscriptionID == space.provisioning.Domain.Subscription.SubscriptionID {
		return SpaceDeviceAdmissionCreateResult{}, NewProtocolError(
			CodeWrongScope, "Space device admission belongs to another Space domain",
		)
	}
	if admissionID, found := s.spaceDeviceAdmissionRetry[admission.RetryID]; found {
		existing := s.spaceDeviceAdmissions[admissionID]
		if reflect.DeepEqual(existing.admission, admission) {
			return SpaceDeviceAdmissionCreateResult{Acceptance: relay.AcceptanceDuplicate, Admission: admission}, nil
		}
		return SpaceDeviceAdmissionCreateResult{}, NewProtocolError(CodeAdmissionCollision, "Space device admission retry ID was reused")
	}
	if existing, found := s.spaceDeviceAdmissions[admission.RelayAdmission.AdmissionID]; found {
		if reflect.DeepEqual(existing.admission, admission) {
			return SpaceDeviceAdmissionCreateResult{Acceptance: relay.AcceptanceDuplicate, Admission: admission}, nil
		}
		return SpaceDeviceAdmissionCreateResult{}, NewProtocolError(CodeAdmissionCollision, "Space device admission ID was reused")
	}
	if space.devices[admission.DeviceID] {
		return SpaceDeviceAdmissionCreateResult{}, NewProtocolError(CodeDeviceCollision, "device is already admitted to the Space")
	}
	for _, existing := range s.spaceDeviceAdmissions {
		if existing.admission.PrincipalID == admission.PrincipalID &&
			existing.admission.SpaceID == admission.SpaceID &&
			existing.admission.DeviceID == admission.DeviceID && existing.result == nil {
			return SpaceDeviceAdmissionCreateResult{}, NewProtocolError(CodeDeviceCollision, "device already has another pending Space admission")
		}
	}
	if _, err := s.relay.CreateSubscription(ctx, credential, relay.SubscriptionCreateRequest{
		RetryID:               admission.RetryID,
		SubscriptionID:        admission.SubscriptionID,
		CreatedAtMilliseconds: admission.CreatedAtMilliseconds,
	}); err != nil {
		return SpaceDeviceAdmissionCreateResult{}, err
	}
	relayResult, err := s.relay.CreateSubscriptionAdmission(
		ctx, credential, admission.SubscriptionID, admission.RelayAdmission, nowMilliseconds,
	)
	if err != nil {
		return SpaceDeviceAdmissionCreateResult{}, err
	}
	s.spaceDeviceAdmissions[admission.RelayAdmission.AdmissionID] = memorySpaceDeviceAdmission{admission: admission}
	s.spaceDeviceAdmissionRetry[admission.RetryID] = admission.RelayAdmission.AdmissionID
	return SpaceDeviceAdmissionCreateResult{Acceptance: relayResult.Acceptance, Admission: admission}, nil
}

func (s *MemoryStore) ClaimSpaceDeviceAdmission(
	ctx context.Context,
	credential SpaceDeviceAdmissionCredential,
	claim SpaceDeviceAdmissionClaim,
	nowMilliseconds int64,
) (SpaceDeviceAdmissionClaimResult, error) {
	if err := claim.Validate(); err != nil {
		return SpaceDeviceAdmissionClaimResult{}, err
	}
	if claim.ClaimedAtMilliseconds != nowMilliseconds {
		return SpaceDeviceAdmissionClaimResult{}, NewProtocolError(CodeInvalidAdmission, "Space device claim time differs from server time")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, found := s.spaceDeviceAdmissions[credential.AdmissionID]
	if !found {
		return SpaceDeviceAdmissionClaimResult{}, NewProtocolError(CodeAdmissionNotFound, "Space device admission was not found")
	}
	if credential.PrincipalID != record.admission.PrincipalID ||
		credential.SpaceID != record.admission.SpaceID ||
		claim.PrincipalID != record.admission.PrincipalID ||
		claim.SpaceID != record.admission.SpaceID ||
		claim.DeviceID != record.admission.DeviceID {
		return SpaceDeviceAdmissionClaimResult{}, NewProtocolError(CodeWrongScope, "Space device claim belongs to another admission")
	}
	if record.result != nil {
		if record.result.DeviceID == claim.DeviceID &&
			record.result.Member.MemberRegistration.AuthorizationDigest == claim.RelayClaim.AuthorizationDigest {
			duplicate := *record.result
			duplicate.Acceptance = relay.AcceptanceDuplicate
			return duplicate, nil
		}
		return SpaceDeviceAdmissionClaimResult{}, NewProtocolError(CodeAdmissionClaimed, "Space device admission was already claimed")
	}
	relayResult, err := s.relay.ClaimSubscriptionAdmission(ctx, relay.AdmissionCredential{
		TenantID: record.admission.PrincipalID, DomainID: record.admission.RelayAdmission.DomainID,
		AdmissionID: credential.AdmissionID, Token: credential.Token,
	}, claim.RelayClaim, nowMilliseconds)
	if err != nil {
		return SpaceDeviceAdmissionClaimResult{}, err
	}
	space := s.spaces[claim.SpaceID]
	space.devices[claim.DeviceID] = true
	s.spaces[claim.SpaceID] = space
	result := SpaceDeviceAdmissionClaimResult{
		Acceptance: relayResult.Acceptance, PrincipalID: claim.PrincipalID,
		SpaceID: claim.SpaceID, DeviceID: claim.DeviceID, Member: relayResult.Member,
	}
	record.result = &result
	s.spaceDeviceAdmissions[credential.AdmissionID] = record
	return result, nil
}

func spaceProvisioningResult(
	provisioning SpaceProvisioning,
	relayResult relay.DomainProvisioningResult,
	acceptance relay.Acceptance,
) SpaceProvisioningResult {
	relayResult.Acceptance = acceptance
	return SpaceProvisioningResult{
		Acceptance: acceptance, PrincipalID: provisioning.PrincipalID,
		SpaceID: provisioning.SpaceID, Domain: relayResult,
	}
}

func (s *MemoryStore) GetPrincipalStatus(
	ctx context.Context,
	credential relay.TenantCredential,
) (PrincipalStatus, error) {
	if _, err := s.relay.GetTenantStatus(ctx, credential); err != nil {
		return PrincipalStatus{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	principal, found := s.principals[credential.TenantID]
	if !found {
		return PrincipalStatus{}, NewProtocolError(CodeUnauthorized, "Device Sync principal was not found")
	}
	status := PrincipalStatus{
		Version: SchemaVersion, PrincipalID: credential.TenantID,
		ControlDomainID: principal.provisioning.ControlDomain.Registration.DomainID,
		Spaces:          []SpaceStatus{},
		Devices: []DeviceStatus{{
			DeviceID:              principal.provisioning.InitialDeviceID,
			ControlSubscriptionID: principal.provisioning.ControlDomain.Subscription.SubscriptionID,
			ControlMemberID:       principal.provisioning.ControlDomain.InitialMember.MemberID,
			CreatedAtMilliseconds: principal.provisioning.CreatedAtMilliseconds,
			RevokedAtMilliseconds: principal.provisioning.ControlDomain.InitialMember.RevokedAtMilliseconds,
		}},
	}
	for _, record := range s.deviceAdmissions {
		if record.result == nil || record.admission.PrincipalID != credential.TenantID {
			continue
		}
		status.Devices = append(status.Devices, DeviceStatus{
			DeviceID:              record.result.DeviceID,
			ControlSubscriptionID: record.result.Member.SubscriptionID,
			ControlMemberID:       record.result.Member.MemberRegistration.MemberID,
			CreatedAtMilliseconds: record.result.Member.MemberRegistration.CreatedAtMilliseconds,
			RevokedAtMilliseconds: record.result.Member.MemberRegistration.RevokedAtMilliseconds,
		})
	}
	for _, space := range s.spaces {
		if space.provisioning.PrincipalID != credential.TenantID {
			continue
		}
		spaceStatus := SpaceStatus{
			SpaceID:               space.provisioning.SpaceID,
			DomainID:              space.provisioning.Domain.Registration.DomainID,
			InitialDeviceID:       space.provisioning.InitialDeviceID,
			CreatedAtMilliseconds: space.provisioning.CreatedAtMilliseconds,
			Devices: []SpaceDeviceStatus{{
				DeviceID:              space.provisioning.InitialDeviceID,
				SubscriptionID:        space.provisioning.Domain.Subscription.SubscriptionID,
				MemberID:              space.provisioning.Domain.InitialMember.MemberID,
				CreatedAtMilliseconds: space.provisioning.Domain.InitialMember.CreatedAtMilliseconds,
				RevokedAtMilliseconds: space.provisioning.Domain.InitialMember.RevokedAtMilliseconds,
			}},
		}
		for _, record := range s.spaceDeviceAdmissions {
			if record.result == nil || record.admission.PrincipalID != credential.TenantID ||
				record.admission.SpaceID != space.provisioning.SpaceID {
				continue
			}
			spaceStatus.Devices = append(spaceStatus.Devices, SpaceDeviceStatus{
				DeviceID:              record.result.DeviceID,
				SubscriptionID:        record.result.Member.SubscriptionID,
				MemberID:              record.result.Member.MemberRegistration.MemberID,
				CreatedAtMilliseconds: record.result.Member.MemberRegistration.CreatedAtMilliseconds,
				RevokedAtMilliseconds: record.result.Member.MemberRegistration.RevokedAtMilliseconds,
			})
		}
		sort.Slice(spaceStatus.Devices, func(left, right int) bool {
			return spaceStatus.Devices[left].DeviceID.String() < spaceStatus.Devices[right].DeviceID.String()
		})
		status.Spaces = append(status.Spaces, spaceStatus)
	}
	sort.Slice(status.Devices, func(left, right int) bool {
		return status.Devices[left].DeviceID.String() < status.Devices[right].DeviceID.String()
	})
	sort.Slice(status.Spaces, func(left, right int) bool {
		return status.Spaces[left].SpaceID.String() < status.Spaces[right].SpaceID.String()
	})
	return status, nil
}

package devicesync

import (
	"context"

	"github.com/robreuss/FacetsNode/internal/relay"
)

func (s *MemoryStore) CancelSpaceDeviceAdmission(ctx context.Context, sponsor SpaceSponsorCredential, cancellation SpaceDeviceAdmissionCancellation, now int64) (SpaceDeviceAdmissionCancellationResult, error) {
	if err := cancellation.Validate(sponsor); err != nil {
		return SpaceDeviceAdmissionCancellationResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.relay.GetDomainStatus(ctx, sponsor.Administration); err != nil {
		return SpaceDeviceAdmissionCancellationResult{}, err
	}
	control, member, _, err := s.sponsorMembers(ctx, cancellation.PrincipalID, cancellation.SpaceID, cancellation.SponsorDeviceID, cancellation.SponsorDeviceID)
	if err != nil {
		return SpaceDeviceAdmissionCancellationResult{}, err
	}
	if err := AuthenticateSpaceSponsor(sponsor, control, member, now); err != nil {
		return SpaceDeviceAdmissionCancellationResult{}, err
	}
	result := SpaceDeviceAdmissionCancellationResult{AdmissionID: cancellation.AdmissionID, Cancelled: true}
	for _, old := range s.spaceAdmissionCancellations {
		if old.AdmissionID == cancellation.AdmissionID || old.RetryID == cancellation.RetryID {
			if old != cancellation {
				return SpaceDeviceAdmissionCancellationResult{}, NewProtocolError(CodeAdmissionCollision, "cancellation identity was reused")
			}
			return result, nil
		}
	}
	if record, found := s.spaceDeviceAdmissions[cancellation.AdmissionID]; found {
		a := record.admission
		if a.PrincipalID != cancellation.PrincipalID || a.SpaceID != cancellation.SpaceID || a.DeviceID != cancellation.DeviceID || a.RetryID != cancellation.RetryID || a.Sponsor.DeviceID != cancellation.SponsorDeviceID {
			return SpaceDeviceAdmissionCancellationResult{}, NewProtocolError(CodeWrongScope, "cancellation does not own this attempt")
		}
		if record.result != nil {
			result.Cancelled = false
			return result, nil
		}
		previous, err := s.relay.GetSubscription(ctx, sponsor.Administration, a.SubscriptionID)
		if err != nil {
			return SpaceDeviceAdmissionCancellationResult{}, err
		}
		if previous.Status != relay.SubscriptionRevoked {
			if _, err := s.relay.ChangeSubscriptionStatus(ctx, sponsor.Administration, a.SubscriptionID,
				relay.SubscriptionStatusChangeRequest{RetryID: a.RelayAdmission.AdmissionID, Status: relay.SubscriptionRevoked,
					ChangedAtMilliseconds: max(now, previous.UpdatedAtMilliseconds)}); err != nil {
				return SpaceDeviceAdmissionCancellationResult{}, err
			}
		}
	}
	// Includes never-accepted attempts so a delayed prepare cannot resurrect it.
	s.spaceAdmissionCancellations[cancellation.AdmissionID] = cancellation
	return result, nil
}

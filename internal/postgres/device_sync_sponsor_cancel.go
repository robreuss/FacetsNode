package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
)

func (s *RelayStore) CancelSpaceDeviceAdmission(ctx context.Context, sponsor devicesync.SpaceSponsorCredential, cancellation devicesync.SpaceDeviceAdmissionCancellation, now int64) (devicesync.SpaceDeviceAdmissionCancellationResult, error) {
	if err := cancellation.Validate(sponsor); err != nil {
		return devicesync.SpaceDeviceAdmissionCancellationResult{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return devicesync.SpaceDeviceAdmissionCancellationResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := loadRelayTenant(ctx, tx, cancellation.PrincipalID, "FOR UPDATE"); err != nil {
		return devicesync.SpaceDeviceAdmissionCancellationResult{}, err
	}
	if _, err := loadDeviceSyncPrincipalAuthority(ctx, tx, cancellation.PrincipalID, "FOR UPDATE"); err != nil {
		return devicesync.SpaceDeviceAdmissionCancellationResult{}, err
	}
	space, err := loadDeviceSyncSpaceAuthority(ctx, tx, cancellation.PrincipalID, cancellation.SpaceID, "FOR UPDATE")
	if err != nil {
		return devicesync.SpaceDeviceAdmissionCancellationResult{}, err
	}
	domain, _, _, _, _, _, err := loadRelayDomain(ctx, tx, cancellation.PrincipalID, space.domainID, "FOR UPDATE")
	if err != nil {
		return devicesync.SpaceDeviceAdmissionCancellationResult{}, err
	}
	if err := domain.Authorize(sponsor.Administration); err != nil {
		return devicesync.SpaceDeviceAdmissionCancellationResult{}, err
	}
	control, member, _, err := loadDeviceSyncSponsorMembers(ctx, tx, cancellation.PrincipalID, cancellation.SpaceID, cancellation.SponsorDeviceID, cancellation.SponsorDeviceID)
	if err != nil {
		return devicesync.SpaceDeviceAdmissionCancellationResult{}, err
	}
	if err := devicesync.AuthenticateSpaceSponsor(sponsor, control, member, now); err != nil {
		return devicesync.SpaceDeviceAdmissionCancellationResult{}, err
	}
	result := devicesync.SpaceDeviceAdmissionCancellationResult{AdmissionID: cancellation.AdmissionID, Cancelled: true}
	var old devicesync.SpaceDeviceAdmissionCancellation
	err = tx.QueryRow(ctx, `SELECT principal_id,space_id,admission_id,retry_id,device_id,sponsor_device_id
	 FROM device_sync_space_admission_cancellations WHERE principal_id=$1 AND space_id=$2 AND (admission_id=$3 OR retry_id=$4)`,
		cancellation.PrincipalID, cancellation.SpaceID, cancellation.AdmissionID, cancellation.RetryID).Scan(&old.PrincipalID, &old.SpaceID, &old.AdmissionID, &old.RetryID, &old.DeviceID, &old.SponsorDeviceID)
	if err == nil {
		if old != cancellation {
			return devicesync.SpaceDeviceAdmissionCancellationResult{}, devicesync.NewProtocolError(devicesync.CodeAdmissionCollision, "cancellation identity was reused")
		}
		return result, nil
	}
	if err != pgx.ErrNoRows {
		return devicesync.SpaceDeviceAdmissionCancellationResult{}, err
	}
	record, err := loadDeviceSyncSpaceDeviceAdmissionForClaim(ctx, tx, cancellation.PrincipalID, cancellation.SpaceID, cancellation.AdmissionID)
	if err != nil && !devicesync.ErrorHasCode(err, devicesync.CodeAdmissionNotFound) {
		return devicesync.SpaceDeviceAdmissionCancellationResult{}, err
	}
	if err == nil {
		if record.deviceID != cancellation.DeviceID || record.retryID != cancellation.RetryID || record.sponsor.DeviceID != cancellation.SponsorDeviceID {
			return devicesync.SpaceDeviceAdmissionCancellationResult{}, devicesync.NewProtocolError(devicesync.CodeWrongScope, "cancellation does not own this attempt")
		}
		if record.claimedAtMilliseconds != nil {
			result.Cancelled = false
			return result, nil
		}
		previous, _, found, err := loadSubscription(ctx, tx, record.principalID, record.domainID, record.subscriptionID, "FOR UPDATE")
		if err != nil {
			return devicesync.SpaceDeviceAdmissionCancellationResult{}, err
		}
		if !found {
			return devicesync.SpaceDeviceAdmissionCancellationResult{}, devicesync.NewProtocolError(devicesync.CodeAdmissionNotFound, "reservation unavailable")
		}
		if previous.Status != relay.SubscriptionRevoked {
			if _, err := s.changeSubscriptionStatusInTransaction(ctx, tx, sponsor.Administration, record.subscriptionID,
				relay.SubscriptionStatusChangeRequest{RetryID: record.admissionID, Status: relay.SubscriptionRevoked,
					ChangedAtMilliseconds: max(now, previous.UpdatedAtMilliseconds)}); err != nil {
				return devicesync.SpaceDeviceAdmissionCancellationResult{}, err
			}
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO device_sync_space_admission_cancellations
	 (principal_id,space_id,admission_id,retry_id,device_id,sponsor_device_id) VALUES ($1,$2,$3,$4,$5,$6)`,
		cancellation.PrincipalID, cancellation.SpaceID, cancellation.AdmissionID, cancellation.RetryID, cancellation.DeviceID, cancellation.SponsorDeviceID)
	if err != nil {
		return devicesync.SpaceDeviceAdmissionCancellationResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return devicesync.SpaceDeviceAdmissionCancellationResult{}, err
	}
	return result, nil
}

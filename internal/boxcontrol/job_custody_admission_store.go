package boxcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/jobcustody"
)

var ErrJobCustodyRouteAuthority = errors.New("BOX-JOB-CUSTODY-AUTHORITY: Job Custody route authority is invalid")

// BoxJobCustodyAdmissionPermitRequest is the participant-signed request for a
// short-lived Box route permit. AdmissionEnvelope is already protected and
// contains only the bounded Job Custody routing header and its source
// signature. ConnectionGrantID is authenticated transport state and is never
// accepted from the wire.
//
// Field declaration order is the canonical JSON representation signed by the
// participant device.
type BoxJobCustodyAdmissionPermitRequest struct {
	AccessGrantID           uuid.UUID                         `json:"accessGrantID"`
	AdmissionEnvelope       []byte                            `json:"admissionEnvelope"`
	AdmissionSigner         computequeue.ReceiptSignerBinding `json:"admissionSigner"`
	BoxID                   uuid.UUID                         `json:"boxID"`
	CapabilitiesDigest      string                            `json:"capabilitiesDigest"`
	DeviceID                uuid.UUID                         `json:"deviceID"`
	ExpiresAtMilliseconds   int64                             `json:"expiresAtMilliseconds"`
	ParticipantID           uuid.UUID                         `json:"participantID"`
	PermitID                uuid.UUID                         `json:"permitID"`
	RequestedAtMilliseconds int64                             `json:"requestedAtMilliseconds"`
	Version                 int                               `json:"version"`
	WorkerID                uuid.UUID                         `json:"workerID"`
	ConnectionGrantID       uuid.UUID                         `json:"-"`
}

func decodeJobCustodyAdmissionPermitRequest(
	data []byte,
	maximumBytes int,
	nowMilliseconds int64,
) (BoxJobCustodyAdmissionPermitRequest, error) {
	var value BoxJobCustodyAdmissionPermitRequest
	if strictBoundedJSON(data, &value, maximumBytes) != nil {
		return value, ErrJobCustodyRouteAuthority
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(data, canonical) || value.ConnectionGrantID != uuid.Nil ||
		value.validateAt(nowMilliseconds) != nil {
		return BoxJobCustodyAdmissionPermitRequest{}, ErrJobCustodyRouteAuthority
	}
	return value, nil
}

func (value BoxJobCustodyAdmissionPermitRequest) validateAt(nowMilliseconds int64) error {
	if value.Version != 1 || value.AccessGrantID == uuid.Nil || value.BoxID == uuid.Nil ||
		value.DeviceID == uuid.Nil || value.ParticipantID == uuid.Nil || value.PermitID == uuid.Nil ||
		value.WorkerID == uuid.Nil ||
		!validParticipantRequestDigest(value.CapabilitiesDigest) ||
		value.AdmissionSigner.Validate() != nil ||
		value.RequestedAtMilliseconds <= 0 || value.RequestedAtMilliseconds > nowMilliseconds ||
		nowMilliseconds-value.RequestedAtMilliseconds > maximumParticipantProofAgeMilliseconds ||
		value.ExpiresAtMilliseconds <= nowMilliseconds ||
		value.ExpiresAtMilliseconds-value.RequestedAtMilliseconds > jobcustody.MaximumAdmissionPermitLifetimeMillisecs {
		return ErrJobCustodyRouteAuthority
	}
	envelope, err := computequeue.DecodeJobCustodyAdmissionCanonical(value.AdmissionEnvelope)
	if err != nil || envelope.SignatureProfileID != value.AdmissionSigner.SignatureProfileID ||
		envelope.Header.RouteRecipientWorkerID != computequeue.WorkerID(value.WorkerID.String()) ||
		nowMilliseconds < int64(envelope.Header.NotBeforeAt) ||
		value.ExpiresAtMilliseconds > int64(envelope.Header.RetentionUntil) {
		return ErrJobCustodyRouteAuthority
	}
	return nil
}

type BoxJobCustodyRouteAuthority struct {
	requesterAuthorityDigest computequeue.Digest
	workerAccessGrantDigest  computequeue.Digest
	workerCapabilitiesDigest computequeue.Digest
}

func makeJobCustodyRouteAuthority(
	enrollment BoxParticipantEnrollment,
	grant BoxSharedWorkerAccessGrant,
) (BoxJobCustodyRouteAuthority, error) {
	capabilitiesDigest := computequeue.Digest(grant.CapabilitiesDigest)
	if capabilitiesDigest.Validate() != nil || !grant.validAt(grant.GrantedAtMilliseconds) {
		return BoxJobCustodyRouteAuthority{}, ErrJobCustodyRouteAuthority
	}
	requesterDigest := computequeue.SHA256Digest(
		"facets.box.job-custody.requester-authority.v1",
		enrollment.Anchor.BoxID.String(),
		enrollment.Anchor.ParticipantID.String(),
		enrollment.Anchor.BoxScopedPrincipalID.String(),
		enrollment.Device.DeviceID.String(),
		enrollment.Device.GrantID.String(),
		fmt.Sprint(enrollment.Device.DeviceGeneration),
	)
	// The human confirmation-code digest is deliberately excluded: exporting a
	// commitment derived from a six-digit secret would create an offline oracle.
	// These fields are the durable authorization and route semantics.
	grantDigest := computequeue.SHA256Digest(
		"facets.box.job-custody.worker-access-grant.v1",
		grant.GrantID.String(), grant.RequestID.String(), grant.BoxID.String(),
		grant.WorkerID.String(), grant.OwnerParticipantID.String(),
		grant.OwnerDeviceID.String(), grant.GranteeParticipantID.String(),
		grant.CapabilitiesDigest,
		fmt.Sprint(grant.Revision), fmt.Sprint(grant.GrantedAtMilliseconds),
		fmt.Sprint(grant.ExpiresAtMilliseconds), fmt.Sprint(grant.RevokedAtMilliseconds),
	)
	return BoxJobCustodyRouteAuthority{
		requesterAuthorityDigest: requesterDigest,
		workerAccessGrantDigest:  grantDigest,
		workerCapabilitiesDigest: capabilitiesDigest,
	}, nil
}

func (store *MemoryStore) AuthorizeJobCustodyAdmission(
	_ context.Context,
	request BoxJobCustodyAdmissionPermitRequest,
	nowMilliseconds int64,
) (BoxJobCustodyRouteAuthority, error) {
	if request.validateAt(nowMilliseconds) != nil || request.ConnectionGrantID == uuid.Nil {
		return BoxJobCustodyRouteAuthority{}, ErrJobCustodyRouteAuthority
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	grant, grantPresent := store.sharedWorkerGrants[request.AccessGrantID]
	accessRequest, requestPresent := store.sharedWorkerRequests[grant.RequestID]
	worker, workerPresent := store.sharedWorkers[request.WorkerID]
	requester, requesterPresent := store.participantEnrollments[request.ParticipantID]
	owner, ownerPresent := store.participantEnrollments[grant.OwnerParticipantID]
	connection, connectionPresent := store.grants[request.ConnectionGrantID]
	permitExpiry := time.UnixMilli(request.ExpiresAtMilliseconds)
	if store.state == nil || !store.state.Claimed() || store.state.BoxID != request.BoxID ||
		!grantPresent || !requestPresent || !workerPresent || !requesterPresent || !ownerPresent ||
		!connectionPresent || !connection.RevokedAt.IsZero() || !connection.ExpiresAt.After(time.UnixMilli(nowMilliseconds)) ||
		connection.ExpiresAt.Before(permitExpiry) || grant.BoxID != request.BoxID ||
		grant.WorkerID != request.WorkerID || grant.GranteeParticipantID != request.ParticipantID ||
		grant.CapabilitiesDigest != request.CapabilitiesDigest || grant.RevokedAtMilliseconds != 0 ||
		grant.GrantedAtMilliseconds > nowMilliseconds || grant.ExpiresAtMilliseconds < request.ExpiresAtMilliseconds ||
		accessRequest.RequestID != grant.RequestID || accessRequest.ConnectionGrantID != request.ConnectionGrantID ||
		accessRequest.RequesterParticipantID != request.ParticipantID || accessRequest.RequesterDeviceID != request.DeviceID ||
		accessRequest.Decision != SharedWorkerAccessApproved || worker.BoxID != request.BoxID ||
		worker.OwnerParticipantID != grant.OwnerParticipantID || worker.OwnerDeviceID != grant.OwnerDeviceID ||
		worker.CapabilitiesDigest != request.CapabilitiesDigest || worker.ExpiresAtMilliseconds < request.ExpiresAtMilliseconds ||
		requester.Device.DeviceID != request.DeviceID || !requester.validInitialAt(request.ExpiresAtMilliseconds) ||
		owner.Device.DeviceID != worker.OwnerDeviceID || !owner.validInitialAt(request.ExpiresAtMilliseconds) {
		return BoxJobCustodyRouteAuthority{}, ErrJobCustodyRouteAuthority
	}
	return makeJobCustodyRouteAuthority(requester, grant)
}

func (store *PostgresStore) AuthorizeJobCustodyAdmission(
	ctx context.Context,
	request BoxJobCustodyAdmissionPermitRequest,
	nowMilliseconds int64,
) (BoxJobCustodyRouteAuthority, error) {
	if request.validateAt(nowMilliseconds) != nil || request.ConnectionGrantID == uuid.Nil {
		return BoxJobCustodyRouteAuthority{}, ErrJobCustodyRouteAuthority
	}
	var enrollment BoxParticipantEnrollment
	var owner BoxParticipantEnrollment
	var grant BoxSharedWorkerAccessGrant
	var requesterRootRecord, requesterGrantRecord []byte
	var ownerRootRecord, ownerGrantRecord []byte
	var deviceGeneration, requesterRevokedThrough, ownerDeviceGeneration, ownerRevokedThrough, grantRevision int64
	grant.Version = 1
	row := store.pool.QueryRow(ctx, `
		SELECT p.box_id, p.participant_id, p.box_scoped_principal_id,
		       p.root_key_fingerprint, p.approved_at_milliseconds,
		       p.revoked_at_milliseconds, p.root_record,
		       d.participant_id, d.device_id, d.grant_id, d.device_generation,
		       d.signing_key_fingerprint, d.revoked_through_generation, d.grant_record,
		       op.box_id, op.participant_id, op.box_scoped_principal_id,
		       op.root_key_fingerprint, op.approved_at_milliseconds,
		       op.revoked_at_milliseconds, op.root_record,
		       od.participant_id, od.device_id, od.grant_id, od.device_generation,
		       od.signing_key_fingerprint, od.revoked_through_generation, od.grant_record,
		       g.grant_id, g.request_id, g.box_id, g.worker_id,
		       g.owner_participant_id, g.owner_device_id, g.grantee_participant_id,
		       g.capabilities_digest, g.confirmation_code_digest, g.revision,
		       g.granted_at_milliseconds, g.expires_at_milliseconds,
		       g.revoked_at_milliseconds
		FROM box_state s
		JOIN box_shared_workers w ON w.box_id = s.box_id AND w.worker_id = $2
		JOIN box_shared_worker_access_grants g ON g.box_id = s.box_id AND g.grant_id = $3
		JOIN box_shared_worker_access_requests r ON r.request_id = g.request_id
		JOIN box_participants p ON p.box_id = s.box_id AND p.participant_id = $4
		JOIN box_participant_devices d ON d.participant_id = p.participant_id AND d.device_id = $5
		JOIN box_participants op ON op.box_id = s.box_id AND op.participant_id = w.owner_participant_id
		JOIN box_participant_devices od ON od.participant_id = op.participant_id AND od.device_id = w.owner_device_id
		JOIN connection_grants c ON c.grant_id = $6
		WHERE s.box_id = $1 AND s.owner_verifier <> ''
		  AND w.owner_participant_id = g.owner_participant_id
		  AND w.owner_device_id = g.owner_device_id
		  AND w.capabilities_digest = $7 AND w.expires_at_milliseconds >= $8
		  AND g.worker_id = w.worker_id AND g.grantee_participant_id = $4
		  AND g.capabilities_digest = $7 AND g.granted_at_milliseconds <= $9
		  AND g.expires_at_milliseconds >= $8 AND g.revoked_at_milliseconds = 0
		  AND r.connection_grant_id = $6 AND r.requester_participant_id = $4
		  AND r.requester_device_id = $5 AND r.decision = 'approved'
		  AND p.revoked_at_milliseconds = 0
		  AND d.revoked_through_generation < d.device_generation
		  AND op.revoked_at_milliseconds = 0
		  AND od.revoked_through_generation < od.device_generation
		  AND c.revoked_at IS NULL AND c.expires_at >= $10`,
		request.BoxID, request.WorkerID, request.AccessGrantID, request.ParticipantID,
		request.DeviceID, request.ConnectionGrantID, request.CapabilitiesDigest,
		request.ExpiresAtMilliseconds, nowMilliseconds, time.UnixMilli(request.ExpiresAtMilliseconds))
	err := row.Scan(
		&enrollment.Anchor.BoxID, &enrollment.Anchor.ParticipantID,
		&enrollment.Anchor.BoxScopedPrincipalID, &enrollment.Anchor.RootKeyFingerprint,
		&enrollment.Anchor.ApprovedAtMilliseconds, &enrollment.Anchor.RevokedAtMilliseconds,
		&requesterRootRecord, &enrollment.Device.ParticipantID, &enrollment.Device.DeviceID,
		&enrollment.Device.GrantID, &deviceGeneration, &enrollment.Device.SigningKeyFingerprint,
		&requesterRevokedThrough, &requesterGrantRecord,
		&owner.Anchor.BoxID, &owner.Anchor.ParticipantID, &owner.Anchor.BoxScopedPrincipalID,
		&owner.Anchor.RootKeyFingerprint, &owner.Anchor.ApprovedAtMilliseconds,
		&owner.Anchor.RevokedAtMilliseconds, &ownerRootRecord,
		&owner.Device.ParticipantID, &owner.Device.DeviceID, &owner.Device.GrantID,
		&ownerDeviceGeneration, &owner.Device.SigningKeyFingerprint,
		&ownerRevokedThrough, &ownerGrantRecord,
		&grant.GrantID,
		&grant.RequestID, &grant.BoxID, &grant.WorkerID, &grant.OwnerParticipantID,
		&grant.OwnerDeviceID, &grant.GranteeParticipantID, &grant.CapabilitiesDigest,
		&grant.ConfirmationCodeDigest, &grantRevision, &grant.GrantedAtMilliseconds,
		&grant.ExpiresAtMilliseconds, &grant.RevokedAtMilliseconds,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return BoxJobCustodyRouteAuthority{}, ErrJobCustodyRouteAuthority
	}
	if err != nil {
		return BoxJobCustodyRouteAuthority{}, err
	}
	if deviceGeneration <= 0 || requesterRevokedThrough < 0 ||
		ownerDeviceGeneration <= 0 || ownerRevokedThrough < 0 || grantRevision <= 0 ||
		json.Unmarshal(requesterRootRecord, &enrollment.RootRecord) != nil ||
		json.Unmarshal(requesterGrantRecord, &enrollment.GrantRecord) != nil ||
		json.Unmarshal(ownerRootRecord, &owner.RootRecord) != nil ||
		json.Unmarshal(ownerGrantRecord, &owner.GrantRecord) != nil {
		return BoxJobCustodyRouteAuthority{}, ErrJobCustodyRouteAuthority
	}
	enrollment.Device.DeviceGeneration = uint64(deviceGeneration)
	enrollment.Device.RevokedThroughGeneration = uint64(requesterRevokedThrough)
	owner.Device.DeviceGeneration = uint64(ownerDeviceGeneration)
	owner.Device.RevokedThroughGeneration = uint64(ownerRevokedThrough)
	grant.Revision = uint64(grantRevision)
	if !enrollment.validInitialAt(request.ExpiresAtMilliseconds) ||
		!owner.validInitialAt(request.ExpiresAtMilliseconds) {
		return BoxJobCustodyRouteAuthority{}, ErrJobCustodyRouteAuthority
	}
	return makeJobCustodyRouteAuthority(enrollment, grant)
}

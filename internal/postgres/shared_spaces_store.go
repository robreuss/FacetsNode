package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/sharedspaces"
)

// SharedSpacesStore owns Shared Spaces product authority while delegating
// opaque delivery custody to the relay tables in the same transaction.
type SharedSpacesStore struct {
	pool  *pgxpool.Pool
	relay *RelayStore
}

func NewSharedSpacesStore(pool *pgxpool.Pool) *SharedSpacesStore {
	return &SharedSpacesStore{pool: pool, relay: NewRelayStore(pool)}
}

type storedSpaceProvisioning struct {
	Provisioning sharedspaces.SpaceProvisioning `json:"provisioning"`
	Domain       relay.DomainProvisioning       `json:"domain"`
}

func encodeSpaceProvisioning(provisioning sharedspaces.SpaceProvisioning) ([]byte, error) {
	payload := storedSpaceProvisioning{Provisioning: provisioning, Domain: provisioning.Domain}
	return json.Marshal(payload)
}

func decodeSpaceProvisioning(payload []byte) (sharedspaces.SpaceProvisioning, error) {
	var stored storedSpaceProvisioning
	if err := json.Unmarshal(payload, &stored); err != nil {
		return sharedspaces.SpaceProvisioning{}, err
	}
	stored.Provisioning.Domain = stored.Domain
	return stored.Provisioning, nil
}

func (s *SharedSpacesStore) ProvisionSpace(
	ctx context.Context,
	provisioning sharedspaces.SpaceProvisioning,
	nowMilliseconds int64,
) (sharedspaces.SpaceProvisioningResult, error) {
	if err := provisioning.Validate(); err != nil {
		return sharedspaces.SpaceProvisioningResult{}, err
	}
	if provisioning.CreatedAtMilliseconds > nowMilliseconds {
		return sharedspaces.SpaceProvisioningResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidSpace, "Shared Space starts in the future",
		)
	}
	payload, err := encodeSpaceProvisioning(provisioning)
	if err != nil {
		return sharedspaces.SpaceProvisioningResult{}, fmt.Errorf("encode Shared Space provisioning: %w", err)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return sharedspaces.SpaceProvisioningResult{}, fmt.Errorf("begin Shared Space provisioning: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var existingSpaceID uuid.UUID
	var existingPayload []byte
	var existingKeyEpoch uint64
	err = tx.QueryRow(ctx, `
		SELECT space_id,provisioning_payload,current_key_epoch
		FROM shared_spaces
		WHERE space_id=$1 OR provisioning_retry_id=$2
		FOR UPDATE
	`, provisioning.SpaceID, provisioning.RetryID).Scan(
		&existingSpaceID, &existingPayload, &existingKeyEpoch,
	)
	if err == nil {
		existing, decodeErr := decodeSpaceProvisioning(existingPayload)
		if decodeErr != nil {
			return sharedspaces.SpaceProvisioningResult{}, fmt.Errorf("decode Shared Space provisioning: %w", decodeErr)
		}
		if existingSpaceID != provisioning.SpaceID || !reflect.DeepEqual(existing, provisioning) {
			return sharedspaces.SpaceProvisioningResult{}, sharedspaces.NewProtocolError(
				sharedspaces.CodeSpaceCollision, "Shared Space ID or retry ID was reused",
			)
		}
		return postgresSharedSpaceProvisioningResult(
			existing, existingKeyEpoch, relay.AcceptanceDuplicate,
		), nil
	}
	if err != pgx.ErrNoRows {
		return sharedspaces.SpaceProvisioningResult{}, fmt.Errorf("load Shared Space provisioning: %w", err)
	}

	relayResult, err := s.relay.provisionTenantTx(ctx, tx, provisioning.Tenant, provisioning.Domain)
	if err != nil {
		return sharedspaces.SpaceProvisioningResult{}, err
	}
	initial := sharedspaces.Participant{
		Version: sharedspaces.SchemaVersion, SpaceID: provisioning.SpaceID,
		ParticipantID:  provisioning.InitialParticipantID,
		SubscriptionID: provisioning.Domain.Subscription.SubscriptionID,
		Kind:           provisioning.InitialParticipantKind, Role: sharedspaces.RoleHost,
		CreatedAtMilliseconds: provisioning.CreatedAtMilliseconds,
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO shared_spaces (
			space_id,provisioning_retry_id,version,security_mode,domain_id,
			initial_participant_id,initial_subscription_id,initial_participant_kind,
			provisioning_payload,created_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`, provisioning.SpaceID, provisioning.RetryID, provisioning.Version,
		string(provisioning.SecurityMode), provisioning.Domain.Registration.DomainID,
		provisioning.InitialParticipantID, initial.SubscriptionID,
		string(provisioning.InitialParticipantKind), payload,
		provisioning.CreatedAtMilliseconds); err != nil {
		return sharedspaces.SpaceProvisioningResult{}, fmt.Errorf("insert Shared Space: %w", err)
	}
	if err := insertSharedSpaceParticipant(ctx, tx, initial); err != nil {
		return sharedspaces.SpaceProvisioningResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sharedspaces.SpaceProvisioningResult{}, fmt.Errorf("commit Shared Space provisioning: %w", err)
	}
	return sharedspaces.SpaceProvisioningResult{
		Acceptance: relayResult.Acceptance, RetryID: provisioning.RetryID,
		SpaceID: provisioning.SpaceID, SecurityMode: provisioning.SecurityMode,
		CurrentKeyEpoch:    sharedspaces.InitialKeyEpoch,
		InitialParticipant: initial, Relay: relayResult,
	}, nil
}

func postgresSharedSpaceProvisioningResult(
	provisioning sharedspaces.SpaceProvisioning,
	currentKeyEpoch uint64,
	acceptance relay.Acceptance,
) sharedspaces.SpaceProvisioningResult {
	initial := sharedspaces.Participant{
		Version: sharedspaces.SchemaVersion, SpaceID: provisioning.SpaceID,
		ParticipantID:  provisioning.InitialParticipantID,
		SubscriptionID: provisioning.Domain.Subscription.SubscriptionID,
		Kind:           provisioning.InitialParticipantKind, Role: sharedspaces.RoleHost,
		CreatedAtMilliseconds: provisioning.CreatedAtMilliseconds,
	}
	return sharedspaces.SpaceProvisioningResult{
		Acceptance: acceptance, RetryID: provisioning.RetryID,
		SpaceID: provisioning.SpaceID, SecurityMode: provisioning.SecurityMode,
		CurrentKeyEpoch:    currentKeyEpoch,
		InitialParticipant: initial,
		Relay:              postgresTenantProvisioningResult(provisioning.Tenant, provisioning.Domain, acceptance),
	}
}

func insertSharedSpaceParticipant(ctx context.Context, tx pgx.Tx, participant sharedspaces.Participant) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO shared_space_participants (
			space_id,participant_id,domain_id,subscription_id,version,kind,role,
			created_at_milliseconds,revoked_at_milliseconds
		) SELECT $1,$2,domain_id,$3,$4,$5,$6,$7,$8
		  FROM shared_spaces WHERE space_id=$1
	`, participant.SpaceID, participant.ParticipantID, participant.SubscriptionID,
		participant.Version, string(participant.Kind), string(participant.Role),
		participant.CreatedAtMilliseconds, participant.RevokedAtMilliseconds); err != nil {
		return fmt.Errorf("insert Shared Space participant: %w", err)
	}
	return nil
}

func (s *SharedSpacesStore) CreateInvitation(
	ctx context.Context,
	credential relay.AdministrationCredential,
	invitation sharedspaces.Invitation,
	nowMilliseconds int64,
) (sharedspaces.InvitationCreateResult, error) {
	if err := invitation.Validate(); err != nil {
		return sharedspaces.InvitationCreateResult{}, err
	}
	if invitation.CreatedAtMilliseconds > nowMilliseconds ||
		invitation.RelayAdmission.ExpiresAtMilliseconds <= nowMilliseconds {
		return sharedspaces.InvitationCreateResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidInvitation, "Shared Space invitation is not currently issuable",
		)
	}
	payload, err := json.Marshal(invitation)
	if err != nil {
		return sharedspaces.InvitationCreateResult{}, fmt.Errorf("encode Shared Space invitation: %w", err)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return sharedspaces.InvitationCreateResult{}, fmt.Errorf("begin Shared Space invitation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	domainID, _, _, err := loadSharedSpaceAuthority(ctx, tx, invitation.SpaceID, credential, "FOR UPDATE")
	if err != nil {
		return sharedspaces.InvitationCreateResult{}, err
	}
	if invitation.RelayAdmission.DomainID != domainID || credential.TenantID != invitation.SpaceID {
		return sharedspaces.InvitationCreateResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "invitation belongs to another Shared Space",
		)
	}

	var existingSpaceID, existingInvitationID uuid.UUID
	var existingPayload []byte
	err = tx.QueryRow(ctx, `
		SELECT space_id,invitation_id,invitation_payload
		FROM shared_space_invitations
		WHERE (space_id=$1 AND invitation_id=$2) OR retry_id=$3
		FOR UPDATE
	`, invitation.SpaceID, invitation.InvitationID, invitation.RetryID).Scan(
		&existingSpaceID, &existingInvitationID, &existingPayload,
	)
	if err == nil {
		var existing sharedspaces.Invitation
		if decodeErr := json.Unmarshal(existingPayload, &existing); decodeErr != nil {
			return sharedspaces.InvitationCreateResult{}, fmt.Errorf("decode Shared Space invitation: %w", decodeErr)
		}
		if existingSpaceID == invitation.SpaceID && existingInvitationID == invitation.InvitationID &&
			reflect.DeepEqual(existing, invitation) {
			return sharedspaces.InvitationCreateResult{
				Acceptance: relay.AcceptanceDuplicate, Invitation: existing,
			}, nil
		}
		return sharedspaces.InvitationCreateResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvitationCollision, "Shared Space invitation ID or retry ID was reused",
		)
	}
	if err != pgx.ErrNoRows {
		return sharedspaces.InvitationCreateResult{}, fmt.Errorf("load Shared Space invitation: %w", err)
	}

	var activeParticipant bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM shared_space_participants
			WHERE space_id=$1 AND participant_id=$2 AND revoked_at_milliseconds IS NULL
		)
	`, invitation.SpaceID, invitation.ParticipantID).Scan(&activeParticipant); err != nil {
		return sharedspaces.InvitationCreateResult{}, fmt.Errorf("check Shared Space participant: %w", err)
	}
	if activeParticipant {
		return sharedspaces.InvitationCreateResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantCollision, "participant is already active",
		)
	}

	if _, err := s.relay.createSubscriptionTx(ctx, tx, credential, relay.SubscriptionCreateRequest{
		RetryID: invitation.RetryID, SubscriptionID: invitation.SubscriptionID,
		CreatedAtMilliseconds: invitation.CreatedAtMilliseconds,
	}); err != nil {
		return sharedspaces.InvitationCreateResult{}, err
	}
	created, err := s.relay.createSubscriptionAdmissionTx(
		ctx, tx, credential, invitation.SubscriptionID, invitation.RelayAdmission, nowMilliseconds,
	)
	if err != nil {
		return sharedspaces.InvitationCreateResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO shared_space_invitations (
			space_id,invitation_id,retry_id,domain_id,participant_id,subscription_id,
			version,kind,role,invitation_payload,created_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	`, invitation.SpaceID, invitation.InvitationID, invitation.RetryID, domainID,
		invitation.ParticipantID, invitation.SubscriptionID, invitation.Version,
		string(invitation.Kind), string(invitation.Role), payload,
		invitation.CreatedAtMilliseconds); err != nil {
		return sharedspaces.InvitationCreateResult{}, fmt.Errorf("insert Shared Space invitation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return sharedspaces.InvitationCreateResult{}, fmt.Errorf("commit Shared Space invitation: %w", err)
	}
	return sharedspaces.InvitationCreateResult{
		Acceptance: created.Acceptance, Invitation: invitation,
	}, nil
}

func (s *SharedSpacesStore) ClaimInvitation(
	ctx context.Context,
	credential sharedspaces.InvitationCredential,
	claim sharedspaces.InvitationClaim,
	nowMilliseconds int64,
) (sharedspaces.InvitationClaimResult, error) {
	if err := claim.Validate(); err != nil {
		return sharedspaces.InvitationClaimResult{}, err
	}
	if credential.SpaceID != claim.SpaceID || credential.InvitationID == uuid.Nil {
		return sharedspaces.InvitationClaimResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "invitation credential belongs to another Shared Space",
		)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return sharedspaces.InvitationClaimResult{}, fmt.Errorf("begin Shared Space invitation claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var payload []byte
	var domainID, subscriptionID, participantID uuid.UUID
	var claimedAt *int64
	var claimedMemberID *uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT invitation_payload,domain_id,subscription_id,participant_id,
		       claimed_at_milliseconds,claimed_member_id
		FROM shared_space_invitations
		WHERE space_id=$1 AND invitation_id=$2
		FOR UPDATE
	`, credential.SpaceID, credential.InvitationID).Scan(
		&payload, &domainID, &subscriptionID, &participantID, &claimedAt, &claimedMemberID,
	)
	if err == pgx.ErrNoRows {
		return sharedspaces.InvitationClaimResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvitationNotFound, "Shared Space invitation was not found",
		)
	}
	if err != nil {
		return sharedspaces.InvitationClaimResult{}, fmt.Errorf("load Shared Space invitation: %w", err)
	}
	if domainID != credential.DomainID || participantID != claim.ParticipantID {
		return sharedspaces.InvitationClaimResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "invitation claim scope differs",
		)
	}
	var invitation sharedspaces.Invitation
	if err := json.Unmarshal(payload, &invitation); err != nil {
		return sharedspaces.InvitationClaimResult{}, fmt.Errorf("decode Shared Space invitation: %w", err)
	}
	currentKeyEpoch, err := loadSharedSpaceKeyEpoch(ctx, tx, claim.SpaceID)
	if err != nil {
		return sharedspaces.InvitationClaimResult{}, err
	}

	if claimedAt != nil && claimedMemberID != nil {
		member, found, err := loadRelayMember(
			ctx, tx, credential.SpaceID, domainID, *claimedMemberID, "FOR SHARE",
		)
		if err != nil {
			return sharedspaces.InvitationClaimResult{}, err
		}
		if !found || *claimedMemberID != claim.ParticipantID ||
			member.AuthorizationDigest != claim.RelayClaim.AuthorizationDigest {
			return sharedspaces.InvitationClaimResult{}, sharedspaces.NewProtocolError(
				sharedspaces.CodeInvitationClaimed, "Shared Space invitation was already claimed",
			)
		}
		participant, err := loadSharedSpaceParticipant(ctx, tx, claim.SpaceID, claim.ParticipantID, "FOR SHARE")
		if err != nil {
			return sharedspaces.InvitationClaimResult{}, err
		}
		return sharedspaces.InvitationClaimResult{
			Acceptance: relay.AcceptanceDuplicate, Participant: participant,
			CurrentKeyEpoch: currentKeyEpoch,
			Member: relay.SubscriptionMemberRegistration{
				SubscriptionID: subscriptionID, MemberRegistration: member,
			},
		}, nil
	}

	relayResult, err := s.relay.claimSubscriptionAdmissionTx(ctx, tx, relay.AdmissionCredential{
		TenantID: credential.SpaceID, DomainID: credential.DomainID,
		AdmissionID: credential.InvitationID, Token: credential.Token,
	}, claim.RelayClaim, nowMilliseconds)
	if err != nil {
		return sharedspaces.InvitationClaimResult{}, err
	}
	participant := sharedspaces.Participant{
		Version: sharedspaces.SchemaVersion, SpaceID: claim.SpaceID,
		ParticipantID: claim.ParticipantID, SubscriptionID: invitation.SubscriptionID,
		Kind: invitation.Kind, Role: invitation.Role,
		CreatedAtMilliseconds: relayResult.Member.MemberRegistration.CreatedAtMilliseconds,
	}
	if err := insertSharedSpaceParticipant(ctx, tx, participant); err != nil {
		return sharedspaces.InvitationClaimResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE shared_space_invitations
		SET claimed_at_milliseconds=$3,claimed_member_id=$4,updated_at=now()
		WHERE space_id=$1 AND invitation_id=$2
	`, claim.SpaceID, credential.InvitationID,
		relayResult.Member.MemberRegistration.CreatedAtMilliseconds,
		relayResult.Member.MemberRegistration.MemberID); err != nil {
		return sharedspaces.InvitationClaimResult{}, fmt.Errorf("complete Shared Space invitation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return sharedspaces.InvitationClaimResult{}, fmt.Errorf("commit Shared Space invitation claim: %w", err)
	}
	return sharedspaces.InvitationClaimResult{
		Acceptance: relayResult.Acceptance, CurrentKeyEpoch: currentKeyEpoch,
		Participant: participant, Member: relayResult.Member,
	}, nil
}

func (s *SharedSpacesStore) GetSpaceStatus(
	ctx context.Context,
	credential relay.AdministrationCredential,
) (sharedspaces.SpaceStatus, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return sharedspaces.SpaceStatus{}, fmt.Errorf("begin Shared Space status: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	domainID, provisioning, _, err := loadSharedSpaceAuthority(
		ctx, tx, credential.TenantID, credential, "",
	)
	if err != nil {
		return sharedspaces.SpaceStatus{}, err
	}
	participants, err := loadSharedSpaceParticipants(ctx, tx, credential.TenantID)
	if err != nil {
		return sharedspaces.SpaceStatus{}, err
	}
	currentKeyEpoch, err := loadSharedSpaceKeyEpoch(ctx, tx, credential.TenantID)
	if err != nil {
		return sharedspaces.SpaceStatus{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sharedspaces.SpaceStatus{}, fmt.Errorf("commit Shared Space status snapshot: %w", err)
	}
	relayStatus, err := s.relay.GetDomainStatus(ctx, credential)
	if err != nil {
		return sharedspaces.SpaceStatus{}, err
	}
	return sharedspaces.SpaceStatus{
		Version: sharedspaces.SchemaVersion, SpaceID: provisioning.SpaceID,
		SecurityMode: provisioning.SecurityMode, DomainID: domainID,
		CurrentKeyEpoch:      currentKeyEpoch,
		InitialParticipantID: provisioning.InitialParticipantID,
		Participants:         participants, Relay: relayStatus,
		CreatedAtMilliseconds: provisioning.CreatedAtMilliseconds,
	}, nil
}

func (s *SharedSpacesStore) RevokeParticipant(
	ctx context.Context,
	credential relay.AdministrationCredential,
	revocation sharedspaces.ParticipantRevocation,
	nowMilliseconds int64,
) (sharedspaces.ParticipantRevocationResult, error) {
	if err := revocation.Validate(); err != nil {
		return sharedspaces.ParticipantRevocationResult{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return sharedspaces.ParticipantRevocationResult{}, fmt.Errorf("begin Shared Space participant revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	domainID, provisioning, _, err := loadSharedSpaceAuthority(
		ctx, tx, revocation.SpaceID, credential, "FOR UPDATE",
	)
	if err != nil {
		return sharedspaces.ParticipantRevocationResult{}, err
	}
	if revocation.ParticipantID == provisioning.InitialParticipantID {
		return sharedspaces.ParticipantRevocationResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInitialHost, "initial host cannot be revoked",
		)
	}

	var existingVersion int
	var existingParticipantID uuid.UUID
	var existingRevokedAt int64
	var existingPreviousKeyEpoch, existingNextKeyEpoch uint64
	err = tx.QueryRow(ctx, `
		SELECT version,participant_id,previous_key_epoch,next_key_epoch,revoked_at_milliseconds
		FROM shared_space_participant_revocations
		WHERE space_id=$1 AND retry_id=$2
		FOR UPDATE
	`, revocation.SpaceID, revocation.RetryID).Scan(
		&existingVersion, &existingParticipantID, &existingPreviousKeyEpoch,
		&existingNextKeyEpoch, &existingRevokedAt,
	)
	if err == nil {
		if existingVersion != revocation.Version || existingParticipantID != revocation.ParticipantID ||
			existingPreviousKeyEpoch != revocation.PreviousKeyEpoch ||
			existingNextKeyEpoch != revocation.NextKeyEpoch {
			return sharedspaces.ParticipantRevocationResult{}, sharedspaces.NewProtocolError(
				sharedspaces.CodeParticipantCollision, "participant revocation retry ID was reused",
			)
		}
		return sharedspaces.ParticipantRevocationResult{
			Acceptance: relay.AcceptanceDuplicate, RetryID: revocation.RetryID,
			SpaceID: revocation.SpaceID, ParticipantID: revocation.ParticipantID,
			PreviousKeyEpoch: existingPreviousKeyEpoch, CurrentKeyEpoch: existingNextKeyEpoch,
			RevokedAtMilliseconds: existingRevokedAt,
		}, nil
	}
	if err != pgx.ErrNoRows {
		return sharedspaces.ParticipantRevocationResult{}, fmt.Errorf("load Shared Space participant revocation: %w", err)
	}
	currentKeyEpoch, err := loadSharedSpaceKeyEpoch(ctx, tx, revocation.SpaceID)
	if err != nil {
		return sharedspaces.ParticipantRevocationResult{}, err
	}
	if currentKeyEpoch != revocation.PreviousKeyEpoch {
		return sharedspaces.ParticipantRevocationResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongKeyEpoch, "participant revocation key epoch is stale",
		)
	}

	participant, err := loadSharedSpaceParticipant(
		ctx, tx, revocation.SpaceID, revocation.ParticipantID, "FOR UPDATE",
	)
	if err != nil {
		return sharedspaces.ParticipantRevocationResult{}, err
	}
	if participant.RevokedAtMilliseconds != nil {
		return sharedspaces.ParticipantRevocationResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantRevoked, "participant is already revoked",
		)
	}
	member, found, err := loadRelayMember(
		ctx, tx, revocation.SpaceID, domainID, revocation.ParticipantID, "FOR UPDATE",
	)
	if err != nil {
		return sharedspaces.ParticipantRevocationResult{}, err
	}
	if !found {
		return sharedspaces.ParticipantRevocationResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantNotFound, "participant relay member was not found",
		)
	}
	subscription, _, found, err := loadSubscription(
		ctx, tx, revocation.SpaceID, domainID, participant.SubscriptionID, "FOR UPDATE",
	)
	if err != nil {
		return sharedspaces.ParticipantRevocationResult{}, err
	}
	if !found {
		return sharedspaces.ParticipantRevocationResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantNotFound, "participant relay subscription was not found",
		)
	}
	if nowMilliseconds < member.CreatedAtMilliseconds ||
		nowMilliseconds < subscription.CreatedAtMilliseconds {
		return sharedspaces.ParticipantRevocationResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidParticipant, "participant revocation predates membership",
		)
	}
	if member.RevokedAtMilliseconds != nil || subscription.Status == relay.SubscriptionRevoked {
		return sharedspaces.ParticipantRevocationResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantRevoked, "participant relay authority is already revoked",
		)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE relay_members
		SET revoked_at_milliseconds=$4,updated_at=now()
		WHERE tenant_id=$1 AND domain_id=$2 AND member_id=$3
	`, revocation.SpaceID, domainID, revocation.ParticipantID,
		nowMilliseconds); err != nil {
		return sharedspaces.ParticipantRevocationResult{}, fmt.Errorf("revoke Shared Space relay member: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE relay_subscriptions
		SET status='revoked',start_sequence=NULL,updated_at_milliseconds=$4,updated_at=now()
		WHERE tenant_id=$1 AND domain_id=$2 AND subscription_id=$3
	`, revocation.SpaceID, domainID, participant.SubscriptionID,
		nowMilliseconds); err != nil {
		return sharedspaces.ParticipantRevocationResult{}, fmt.Errorf("revoke Shared Space relay subscription: %w", err)
	}
	if err := insertDataPlaneAudit(
		ctx, tx, revocation.SpaceID, &domainID, &participant.SubscriptionID,
		&revocation.ParticipantID, "shared_space_participant_revoked",
		nowMilliseconds,
	); err != nil {
		return sharedspaces.ParticipantRevocationResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE shared_space_participants
		SET revoked_at_milliseconds=$3,updated_at=now()
		WHERE space_id=$1 AND participant_id=$2
	`, revocation.SpaceID, revocation.ParticipantID,
		nowMilliseconds); err != nil {
		return sharedspaces.ParticipantRevocationResult{}, fmt.Errorf("revoke Shared Space participant: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE shared_spaces
		SET current_key_epoch=$2
		WHERE space_id=$1
	`, revocation.SpaceID, revocation.NextKeyEpoch); err != nil {
		return sharedspaces.ParticipantRevocationResult{}, fmt.Errorf("advance Shared Space key epoch: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO shared_space_participant_revocations (
			space_id,retry_id,participant_id,version,previous_key_epoch,next_key_epoch,
			revoked_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, revocation.SpaceID, revocation.RetryID, revocation.ParticipantID,
		revocation.Version, revocation.PreviousKeyEpoch, revocation.NextKeyEpoch,
		nowMilliseconds); err != nil {
		return sharedspaces.ParticipantRevocationResult{}, fmt.Errorf("record Shared Space participant revocation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return sharedspaces.ParticipantRevocationResult{}, fmt.Errorf("commit Shared Space participant revocation: %w", err)
	}
	return sharedspaces.ParticipantRevocationResult{
		Acceptance: relay.AcceptanceAccepted, RetryID: revocation.RetryID,
		SpaceID: revocation.SpaceID, ParticipantID: revocation.ParticipantID,
		PreviousKeyEpoch: revocation.PreviousKeyEpoch, CurrentKeyEpoch: revocation.NextKeyEpoch,
		RevokedAtMilliseconds: nowMilliseconds,
	}, nil
}

func (s *SharedSpacesStore) PublishEnvelope(
	ctx context.Context,
	credential relay.Credential,
	envelope relay.Envelope,
	nowMilliseconds int64,
) (relay.PublishResult, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.PublishResult{}, fmt.Errorf("begin Shared Space envelope publish: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var domainID uuid.UUID
	var currentKeyEpoch uint64
	err = tx.QueryRow(ctx, `
		SELECT domain_id,current_key_epoch
		FROM shared_spaces
		WHERE space_id=$1
		FOR SHARE
	`, credential.TenantID).Scan(&domainID, &currentKeyEpoch)
	if err == pgx.ErrNoRows {
		return relay.PublishResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeSpaceNotFound, "Shared Space was not found",
		)
	}
	if err != nil {
		return relay.PublishResult{}, fmt.Errorf("load Shared Space publish authority: %w", err)
	}
	if credential.DomainID != domainID || envelope.TenantID != credential.TenantID ||
		envelope.DomainID != credential.DomainID {
		return relay.PublishResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "envelope belongs to another Shared Space",
		)
	}
	if envelope.KeyEpoch != currentKeyEpoch {
		return relay.PublishResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongKeyEpoch, "envelope key epoch is not current",
		)
	}

	result, err := s.relay.publishInTransaction(
		ctx, tx, credential, envelope, nowMilliseconds,
	)
	if err != nil {
		return relay.PublishResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.PublishResult{}, fmt.Errorf("commit Shared Space envelope publish: %w", err)
	}
	return result, nil
}

func (s *SharedSpacesStore) StageCheckpoint(
	ctx context.Context,
	credential relay.Credential,
	candidate relay.CheckpointCandidate,
	nowMilliseconds int64,
) (relay.CheckpointStageResponse, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.CheckpointStageResponse{}, fmt.Errorf("begin Shared Space checkpoint staging: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	domainID, currentKeyEpoch, err := loadSharedSpaceCheckpointAuthority(ctx, tx, credential.TenantID)
	if err != nil {
		return relay.CheckpointStageResponse{}, err
	}
	if credential.DomainID != domainID || candidate.TenantID != credential.TenantID ||
		candidate.DomainID != credential.DomainID {
		return relay.CheckpointStageResponse{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "checkpoint belongs to another Shared Space",
		)
	}
	if candidate.KeyEpoch != currentKeyEpoch {
		return relay.CheckpointStageResponse{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongKeyEpoch, "checkpoint key epoch is not current",
		)
	}
	result, err := s.relay.StageCheckpoint(ctx, credential, candidate, nowMilliseconds)
	if err != nil {
		return relay.CheckpointStageResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.CheckpointStageResponse{}, fmt.Errorf("commit Shared Space checkpoint staging: %w", err)
	}
	return result, nil
}

func (s *SharedSpacesStore) ActivateCheckpoint(
	ctx context.Context,
	credential relay.AdministrationCredential,
	request relay.CheckpointActivationRequest,
	nowMilliseconds int64,
) (relay.CheckpointActivationResponse, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return relay.CheckpointActivationResponse{}, fmt.Errorf("begin Shared Space checkpoint activation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	domainID, currentKeyEpoch, err := loadSharedSpaceCheckpointAuthority(ctx, tx, credential.TenantID)
	if err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	if credential.DomainID != domainID {
		return relay.CheckpointActivationResponse{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "checkpoint belongs to another Shared Space",
		)
	}
	var checkpointKeyEpoch uint64
	if err := tx.QueryRow(ctx, `
		SELECT key_epoch FROM relay_checkpoints
		WHERE tenant_id=$1 AND domain_id=$2 AND checkpoint_id=$3
	`, credential.TenantID, credential.DomainID, request.CheckpointID).Scan(&checkpointKeyEpoch); err == pgx.ErrNoRows {
		return relay.CheckpointActivationResponse{}, relay.NewProtocolError(
			relay.CodeCheckpointNotFound, "checkpoint was not found",
		)
	} else if err != nil {
		return relay.CheckpointActivationResponse{}, fmt.Errorf("load Shared Space checkpoint epoch: %w", err)
	}
	if checkpointKeyEpoch != currentKeyEpoch {
		return relay.CheckpointActivationResponse{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongKeyEpoch, "checkpoint key epoch is not current",
		)
	}
	result, err := s.relay.ActivateCheckpoint(ctx, credential, request, nowMilliseconds)
	if err != nil {
		return relay.CheckpointActivationResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return relay.CheckpointActivationResponse{}, fmt.Errorf("commit Shared Space checkpoint activation: %w", err)
	}
	return result, nil
}

func loadSharedSpaceCheckpointAuthority(
	ctx context.Context,
	tx pgx.Tx,
	spaceID uuid.UUID,
) (uuid.UUID, uint64, error) {
	var domainID uuid.UUID
	var currentKeyEpoch uint64
	if err := tx.QueryRow(ctx, `
		SELECT domain_id,current_key_epoch FROM shared_spaces
		WHERE space_id=$1 FOR SHARE
	`, spaceID).Scan(&domainID, &currentKeyEpoch); err == pgx.ErrNoRows {
		return uuid.Nil, 0, sharedspaces.NewProtocolError(
			sharedspaces.CodeSpaceNotFound, "Shared Space was not found",
		)
	} else if err != nil {
		return uuid.Nil, 0, fmt.Errorf("load Shared Space checkpoint authority: %w", err)
	}
	return domainID, currentKeyEpoch, nil
}

func loadSharedSpaceKeyEpoch(ctx context.Context, tx pgx.Tx, spaceID uuid.UUID) (uint64, error) {
	var keyEpoch uint64
	if err := tx.QueryRow(ctx, `
		SELECT current_key_epoch FROM shared_spaces WHERE space_id=$1
	`, spaceID).Scan(&keyEpoch); err != nil {
		return 0, fmt.Errorf("load Shared Space key epoch: %w", err)
	}
	return keyEpoch, nil
}

func loadSharedSpaceAuthority(
	ctx context.Context,
	tx pgx.Tx,
	spaceID uuid.UUID,
	credential relay.AdministrationCredential,
	lock string,
) (uuid.UUID, sharedspaces.SpaceProvisioning, relay.DomainRegistration, error) {
	var domainID uuid.UUID
	var payload []byte
	query := `SELECT domain_id,provisioning_payload FROM shared_spaces WHERE space_id=$1`
	if lock != "" {
		query += " " + lock
	}
	if err := tx.QueryRow(ctx, query, spaceID).Scan(&domainID, &payload); err == pgx.ErrNoRows {
		return uuid.Nil, sharedspaces.SpaceProvisioning{}, relay.DomainRegistration{},
			sharedspaces.NewProtocolError(sharedspaces.CodeSpaceNotFound, "Shared Space was not found")
	} else if err != nil {
		return uuid.Nil, sharedspaces.SpaceProvisioning{}, relay.DomainRegistration{},
			fmt.Errorf("load Shared Space authority: %w", err)
	}
	if credential.TenantID != spaceID || credential.DomainID != domainID {
		return uuid.Nil, sharedspaces.SpaceProvisioning{}, relay.DomainRegistration{},
			sharedspaces.NewProtocolError(sharedspaces.CodeWrongScope, "credential belongs to another Shared Space")
	}
	domain, _, _, _, _, _, err := loadRelayDomain(ctx, tx, spaceID, domainID, lock)
	if err != nil {
		return uuid.Nil, sharedspaces.SpaceProvisioning{}, relay.DomainRegistration{}, err
	}
	if err := domain.Authorize(credential); err != nil {
		return uuid.Nil, sharedspaces.SpaceProvisioning{}, relay.DomainRegistration{}, err
	}
	provisioning, err := decodeSpaceProvisioning(payload)
	if err != nil {
		return uuid.Nil, sharedspaces.SpaceProvisioning{}, relay.DomainRegistration{},
			fmt.Errorf("decode Shared Space authority: %w", err)
	}
	return domainID, provisioning, domain, nil
}

func loadSharedSpaceParticipant(
	ctx context.Context,
	tx pgx.Tx,
	spaceID, participantID uuid.UUID,
	lock string,
) (sharedspaces.Participant, error) {
	query := `
		SELECT version,space_id,participant_id,subscription_id,kind,role,
		       created_at_milliseconds,revoked_at_milliseconds
		FROM shared_space_participants
		WHERE space_id=$1 AND participant_id=$2`
	if lock != "" {
		query += " " + lock
	}
	var participant sharedspaces.Participant
	if err := tx.QueryRow(ctx, query, spaceID, participantID).Scan(
		&participant.Version, &participant.SpaceID, &participant.ParticipantID,
		&participant.SubscriptionID, &participant.Kind, &participant.Role,
		&participant.CreatedAtMilliseconds, &participant.RevokedAtMilliseconds,
	); err == pgx.ErrNoRows {
		return sharedspaces.Participant{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantNotFound, "participant was not found",
		)
	} else if err != nil {
		return sharedspaces.Participant{}, fmt.Errorf("load Shared Space participant: %w", err)
	}
	return participant, nil
}

func loadSharedSpaceParticipants(
	ctx context.Context,
	tx pgx.Tx,
	spaceID uuid.UUID,
) ([]sharedspaces.Participant, error) {
	rows, err := tx.Query(ctx, `
		SELECT version,space_id,participant_id,subscription_id,kind,role,
		       created_at_milliseconds,revoked_at_milliseconds
		FROM shared_space_participants
		WHERE space_id=$1
		ORDER BY participant_id
	`, spaceID)
	if err != nil {
		return nil, fmt.Errorf("query Shared Space participants: %w", err)
	}
	defer rows.Close()
	participants := []sharedspaces.Participant{}
	for rows.Next() {
		var participant sharedspaces.Participant
		if err := rows.Scan(
			&participant.Version, &participant.SpaceID, &participant.ParticipantID,
			&participant.SubscriptionID, &participant.Kind, &participant.Role,
			&participant.CreatedAtMilliseconds, &participant.RevokedAtMilliseconds,
		); err != nil {
			return nil, fmt.Errorf("scan Shared Space participant: %w", err)
		}
		participants = append(participants, participant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Shared Space participants: %w", err)
	}
	sort.Slice(participants, func(left, right int) bool {
		return participants[left].ParticipantID.String() < participants[right].ParticipantID.String()
	})
	return participants, nil
}

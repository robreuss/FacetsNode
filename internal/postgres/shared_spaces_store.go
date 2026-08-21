package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/keycustody"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/sharedspaces"
)

// SharedSpacesStore owns Shared Spaces product authority while delegating
// opaque delivery custody to the relay tables in the same transaction.
type SharedSpacesStore struct {
	pool               *pgxpool.Pool
	relay              *RelayStore
	managedContentKeys *keycustody.ManagedContentKeys
}

func NewSharedSpacesStore(
	pool *pgxpool.Pool,
	custodians ...*keycustody.ManagedContentKeys,
) *SharedSpacesStore {
	var custodian *keycustody.ManagedContentKeys
	if len(custodians) > 0 {
		custodian = custodians[0]
	}
	return &SharedSpacesStore{
		pool: pool, relay: NewRelayStore(pool), managedContentKeys: custodian,
	}
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

func encodeSecureRosterAttestation(attestation *sharedspaces.SecureRosterAttestation) ([]byte, error) {
	if attestation == nil {
		return nil, nil
	}
	return json.Marshal(attestation)
}

func decodeSecureRosterAttestation(payload []byte) (*sharedspaces.SecureRosterAttestation, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	var attestation sharedspaces.SecureRosterAttestation
	if err := json.Unmarshal(payload, &attestation); err != nil {
		return nil, err
	}
	return &attestation, nil
}

func secureRosterAttestationDigest(
	attestation *sharedspaces.SecureRosterAttestation,
) (*string, error) {
	if attestation == nil {
		return nil, nil
	}
	digest, err := attestation.Digest()
	if err != nil {
		return nil, fmt.Errorf("digest Shared Space roster attestation: %w", err)
	}
	return &digest, nil
}

// insertSharedSpaceSecureRosterAttestation records every accepted Secure
// membership transition. The current record on shared_spaces is useful for a
// fresh bootstrap, but an offline participant needs this whole signed chain to
// prove that no roster change was hidden or substituted by the service.
func insertSharedSpaceSecureRosterAttestation(
	ctx context.Context,
	tx pgx.Tx,
	attestation *sharedspaces.SecureRosterAttestation,
) error {
	if attestation == nil {
		return nil
	}
	payload, err := encodeSecureRosterAttestation(attestation)
	if err != nil {
		return fmt.Errorf("encode Shared Space roster attestation history: %w", err)
	}
	digest, err := attestation.Digest()
	if err != nil {
		return fmt.Errorf("digest Shared Space roster attestation history: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO shared_space_secure_roster_attestations (
			space_id,revision,attestation_digest,previous_digest,current_key_epoch,
			issuer_participant_id,created_at_milliseconds,attestation
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, attestation.SpaceID, attestation.Revision, digest, attestation.PreviousDigest,
		attestation.CurrentKeyEpoch, attestation.IssuerParticipantID,
		attestation.CreatedAtMilliseconds, payload); err != nil {
		return fmt.Errorf("record Shared Space roster attestation history: %w", err)
	}
	return nil
}

func cloneSecureRosterAttestation(
	attestation *sharedspaces.SecureRosterAttestation,
) *sharedspaces.SecureRosterAttestation {
	if attestation == nil {
		return nil
	}
	copy := *attestation
	return &copy
}

func activeSharedSpaceParticipants(participants []sharedspaces.Participant) []sharedspaces.Participant {
	active := make([]sharedspaces.Participant, 0, len(participants))
	for _, participant := range participants {
		if participant.RevokedAtMilliseconds == nil {
			active = append(active, participant)
		}
	}
	sort.Slice(active, func(left, right int) bool {
		return active[left].ParticipantID.String() < active[right].ParticipantID.String()
	})
	return active
}

func participantFromSharedSpaceInvitation(invitation sharedspaces.Invitation) sharedspaces.Participant {
	return sharedspaces.Participant{
		Version: sharedspaces.SchemaVersion, SpaceID: invitation.SpaceID,
		ParticipantID: invitation.ParticipantID, SubscriptionID: invitation.SubscriptionID,
		Kind: invitation.Kind, Role: invitation.Role, SigningKey: invitation.ParticipantSigningKey,
		DeviceKeys:            invitation.ParticipantDeviceKeys,
		CreatedAtMilliseconds: invitation.CreatedAtMilliseconds,
	}
}

func validateSharedSpaceInvitationRosterAttestation(
	securityMode sharedspaces.SecurityMode,
	current *sharedspaces.SecureRosterAttestation,
	participants []sharedspaces.Participant,
	currentKeyEpoch uint64,
	invitation sharedspaces.Invitation,
) error {
	if securityMode != sharedspaces.SecurityModeSecure {
		if invitation.ActivationSecureRosterAttestation != nil {
			return sharedspaces.NewProtocolError(sharedspaces.CodeInvalidInvitation, "only Secure Shared Spaces may carry a roster attestation")
		}
		return nil
	}
	if current == nil || invitation.ActivationSecureRosterAttestation == nil {
		return sharedspaces.NewProtocolError(sharedspaces.CodeInvalidInvitation, "Secure Shared Space invitation is missing its roster authority attestation")
	}
	expected := append(activeSharedSpaceParticipants(participants), participantFromSharedSpaceInvitation(invitation))
	sort.Slice(expected, func(left, right int) bool {
		return expected[left].ParticipantID.String() < expected[right].ParticipantID.String()
	})
	return invitation.ActivationSecureRosterAttestation.ValidateSuccessor(*current, expected, currentKeyEpoch)
}

func validateSharedSpaceRoleChangeRosterAttestation(
	securityMode sharedspaces.SecurityMode,
	current *sharedspaces.SecureRosterAttestation,
	participants []sharedspaces.Participant,
	currentKeyEpoch uint64,
	change sharedspaces.ParticipantRoleChange,
) error {
	if securityMode != sharedspaces.SecurityModeSecure {
		if change.SecureRosterAttestation != nil {
			return sharedspaces.NewProtocolError(sharedspaces.CodeInvalidParticipant, "only Secure Shared Spaces may carry a roster attestation")
		}
		return nil
	}
	if current == nil || change.SecureRosterAttestation == nil {
		return sharedspaces.NewProtocolError(sharedspaces.CodeInvalidParticipant, "Secure Shared Space role change is missing its roster authority attestation")
	}
	expected := activeSharedSpaceParticipants(participants)
	for index := range expected {
		if expected[index].ParticipantID == change.ParticipantID {
			expected[index].Role = change.NextRole
			break
		}
	}
	return change.SecureRosterAttestation.ValidateSuccessor(*current, expected, currentKeyEpoch)
}

func validateSharedSpaceDeviceEnrollmentRosterAttestation(
	securityMode sharedspaces.SecurityMode,
	current *sharedspaces.SecureRosterAttestation,
	participants []sharedspaces.Participant,
	currentKeyEpoch uint64,
	enrollment sharedspaces.ParticipantDeviceEnrollment,
) error {
	if securityMode != sharedspaces.SecurityModeSecure {
		if enrollment.SecureRosterAttestation != nil {
			return sharedspaces.NewProtocolError(sharedspaces.CodeInvalidParticipant, "only Secure Shared Spaces may carry a roster attestation")
		}
		return nil
	}
	if current == nil || enrollment.SecureRosterAttestation == nil {
		return sharedspaces.NewProtocolError(sharedspaces.CodeInvalidParticipant, "Secure Shared Space device enrollment is missing its roster authority attestation")
	}
	expected := activeSharedSpaceParticipants(participants)
	found := false
	for index := range expected {
		if expected[index].ParticipantID != enrollment.ParticipantID {
			continue
		}
		expected[index].DeviceKeys = append(expected[index].DeviceKeys, enrollment.DeviceKey)
		sort.Slice(expected[index].DeviceKeys, func(left, right int) bool {
			return expected[index].DeviceKeys[left].DeviceID.String() <
				expected[index].DeviceKeys[right].DeviceID.String()
		})
		found = true
		break
	}
	if !found {
		return sharedspaces.NewProtocolError(sharedspaces.CodeParticipantNotFound, "participant was not found")
	}
	return enrollment.SecureRosterAttestation.ValidateSuccessor(
		*current, expected, currentKeyEpoch,
	)
}

func validateSharedSpaceRevocationRosterAttestation(
	securityMode sharedspaces.SecurityMode,
	current *sharedspaces.SecureRosterAttestation,
	participants []sharedspaces.Participant,
	revocation sharedspaces.ParticipantRevocation,
) error {
	if securityMode != sharedspaces.SecurityModeSecure {
		if revocation.SecureRosterAttestation != nil {
			return sharedspaces.NewProtocolError(sharedspaces.CodeInvalidParticipant, "only Secure Shared Spaces may carry a roster attestation")
		}
		return nil
	}
	if current == nil || revocation.SecureRosterAttestation == nil {
		return sharedspaces.NewProtocolError(sharedspaces.CodeInvalidParticipant, "Secure Shared Space revocation is missing its roster authority attestation")
	}
	expected := make([]sharedspaces.Participant, 0, len(participants)-1)
	for _, participant := range activeSharedSpaceParticipants(participants) {
		if participant.ParticipantID != revocation.ParticipantID {
			expected = append(expected, participant)
		}
	}
	return revocation.SecureRosterAttestation.ValidateSuccessor(*current, expected, revocation.NextKeyEpoch)
}

func validateSharedSpaceDeviceRevocationRosterAttestation(
	securityMode sharedspaces.SecurityMode,
	current *sharedspaces.SecureRosterAttestation,
	participants []sharedspaces.Participant,
	revocation sharedspaces.ParticipantDeviceRevocation,
) error {
	if securityMode != sharedspaces.SecurityModeSecure {
		if revocation.SecureRosterAttestation != nil {
			return sharedspaces.NewProtocolError(sharedspaces.CodeInvalidParticipant, "only Secure Shared Spaces may carry a roster attestation")
		}
		return nil
	}
	if current == nil || revocation.SecureRosterAttestation == nil {
		return sharedspaces.NewProtocolError(sharedspaces.CodeInvalidParticipant, "Secure Shared Space device revocation is missing its roster authority attestation")
	}
	expected := activeSharedSpaceParticipants(participants)
	found := false
	for participantIndex := range expected {
		if expected[participantIndex].ParticipantID != revocation.ParticipantID {
			continue
		}
		for deviceIndex := range expected[participantIndex].DeviceKeys {
			if expected[participantIndex].DeviceKeys[deviceIndex].DeviceID == revocation.DeviceID &&
				expected[participantIndex].DeviceKeys[deviceIndex].RevokedAtMilliseconds == nil {
				expected[participantIndex].DeviceKeys[deviceIndex] = revocation.DeviceKey
				found = true
				break
			}
		}
		break
	}
	if !found {
		return sharedspaces.NewProtocolError(sharedspaces.CodeParticipantNotFound, "active participant device was not found")
	}
	return revocation.SecureRosterAttestation.ValidateSuccessor(
		*current, expected, revocation.NextKeyEpoch,
	)
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
	rosterAttestationPayload, err := encodeSecureRosterAttestation(provisioning.InitialSecureRosterAttestation)
	if err != nil {
		return sharedspaces.SpaceProvisioningResult{}, fmt.Errorf("encode Shared Space initial roster attestation: %w", err)
	}
	rosterAttestationDigest, err := secureRosterAttestationDigest(provisioning.InitialSecureRosterAttestation)
	if err != nil {
		return sharedspaces.SpaceProvisioningResult{}, err
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
	var managedWrappedKey []byte
	if provisioning.SecurityMode == sharedspaces.SecurityModeManaged {
		if s.managedContentKeys == nil {
			return sharedspaces.SpaceProvisioningResult{}, sharedspaces.NewProtocolError(
				sharedspaces.CodeInvalidSpace, "managed content-key custody is not configured",
			)
		}
		_, managedWrappedKey, err = s.managedContentKeys.Generate(
			provisioning.SpaceID, sharedspaces.InitialKeyEpoch,
		)
		if err != nil {
			return sharedspaces.SpaceProvisioningResult{}, fmt.Errorf("generate initial managed content key: %w", err)
		}
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
		SigningKey:            provisioning.InitialParticipantSigningKey,
		DeviceKeys:            provisioning.InitialParticipantDeviceKeys,
		CreatedAtMilliseconds: provisioning.CreatedAtMilliseconds,
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO shared_spaces (
			space_id,provisioning_retry_id,version,security_mode,interaction_mode,domain_id,
			initial_participant_id,initial_subscription_id,initial_participant_kind,
			provisioning_payload,secure_roster_attestation,created_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
	`, provisioning.SpaceID, provisioning.RetryID, provisioning.Version,
		string(provisioning.SecurityMode), string(provisioning.InteractionMode),
		provisioning.Domain.Registration.DomainID,
		provisioning.InitialParticipantID, initial.SubscriptionID,
		string(provisioning.InitialParticipantKind), payload,
		rosterAttestationPayload,
		provisioning.CreatedAtMilliseconds); err != nil {
		return sharedspaces.SpaceProvisioningResult{}, fmt.Errorf("insert Shared Space: %w", err)
	}
	if err := insertSharedSpaceSecureRosterAttestation(
		ctx, tx, provisioning.InitialSecureRosterAttestation,
	); err != nil {
		return sharedspaces.SpaceProvisioningResult{}, err
	}
	if err := insertSharedSpaceParticipant(ctx, tx, initial); err != nil {
		return sharedspaces.SpaceProvisioningResult{}, err
	}
	if managedWrappedKey != nil {
		if err := insertSharedSpaceManagedContentKey(
			ctx, tx, provisioning.SpaceID, sharedspaces.InitialKeyEpoch,
			managedWrappedKey, provisioning.CreatedAtMilliseconds,
		); err != nil {
			return sharedspaces.SpaceProvisioningResult{}, err
		}
	}
	if err := insertSharedSpaceAuthorityEvent(ctx, tx, sharedspaces.AuthorityEvent{
		EventID: provisioning.RetryID, SpaceID: provisioning.SpaceID,
		DomainID:               provisioning.Domain.Registration.DomainID,
		EventType:              sharedspaces.AuthorityEventSpaceProvisioned,
		SubjectParticipantID:   &initial.ParticipantID,
		CurrentRole:            rolePointer(sharedspaces.RoleHost),
		CurrentKeyEpoch:        uint64Pointer(sharedspaces.InitialKeyEpoch),
		SecureRosterDigest:     rosterAttestationDigest,
		OccurredAtMilliseconds: provisioning.CreatedAtMilliseconds,
	}); err != nil {
		return sharedspaces.SpaceProvisioningResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sharedspaces.SpaceProvisioningResult{}, fmt.Errorf("commit Shared Space provisioning: %w", err)
	}
	return sharedspaces.SpaceProvisioningResult{
		Acceptance: relayResult.Acceptance, RetryID: provisioning.RetryID,
		SpaceID: provisioning.SpaceID, SecurityMode: provisioning.SecurityMode,
		InteractionMode:    provisioning.InteractionMode,
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
		SigningKey:            provisioning.InitialParticipantSigningKey,
		DeviceKeys:            provisioning.InitialParticipantDeviceKeys,
		CreatedAtMilliseconds: provisioning.CreatedAtMilliseconds,
	}
	return sharedspaces.SpaceProvisioningResult{
		Acceptance: acceptance, RetryID: provisioning.RetryID,
		SpaceID: provisioning.SpaceID, SecurityMode: provisioning.SecurityMode,
		InteractionMode:    provisioning.InteractionMode,
		CurrentKeyEpoch:    currentKeyEpoch,
		InitialParticipant: initial,
		Relay:              postgresTenantProvisioningResult(provisioning.Tenant, provisioning.Domain, acceptance),
	}
}

func insertSharedSpaceParticipant(ctx context.Context, tx pgx.Tx, participant sharedspaces.Participant) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO shared_space_participants (
			space_id,participant_id,domain_id,subscription_id,version,kind,role,
			signing_key_algorithm,signing_public_key_x963,signing_key_fingerprint,
			created_at_milliseconds,revoked_at_milliseconds
		) SELECT $1,$2,domain_id,$3,$4,$5,$6,$7,$8,$9,$10,$11
		  FROM shared_spaces WHERE space_id=$1
	`, participant.SpaceID, participant.ParticipantID, participant.SubscriptionID,
		participant.Version, string(participant.Kind), string(participant.Role),
		participant.SigningKey.Algorithm, participant.SigningKey.PublicKeyX963,
		participant.SigningKey.SigningKeyFingerprint,
		participant.CreatedAtMilliseconds, participant.RevokedAtMilliseconds); err != nil {
		return fmt.Errorf("insert Shared Space participant: %w", err)
	}
	for _, deviceKey := range participant.DeviceKeys {
		if err := insertSharedSpaceParticipantDeviceKey(ctx, tx, participant, deviceKey); err != nil {
			return err
		}
	}
	return nil
}

func insertSharedSpaceParticipantDeviceKey(
	ctx context.Context,
	tx pgx.Tx,
	participant sharedspaces.Participant,
	deviceKey sharedspaces.ParticipantDeviceKey,
) error {
	if err := deviceKey.Validate(participant); err != nil {
		return fmt.Errorf("validate Shared Space participant device key: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO shared_space_participant_device_keys (
			space_id,participant_id,device_id,version,algorithm,
			agreement_public_key_x963,agreement_key_fingerprint,
			created_at_milliseconds,revoked_at_milliseconds,
			signature_algorithm,signature_public_signing_key_x963,
			signature_signing_key_fingerprint,signature
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
	`, deviceKey.SpaceID, deviceKey.ParticipantID, deviceKey.DeviceID,
		deviceKey.Version, deviceKey.Algorithm,
		deviceKey.AgreementPublicKeyX963, deviceKey.AgreementKeyFingerprint,
		deviceKey.CreatedAtMilliseconds, deviceKey.RevokedAtMilliseconds,
		deviceKey.Signature.Algorithm, deviceKey.Signature.PublicSigningKeyX963,
		deviceKey.Signature.SigningKeyFingerprint, deviceKey.Signature.Signature,
	); err != nil {
		return fmt.Errorf("insert Shared Space participant device key: %w", err)
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
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return sharedspaces.InvitationCreateResult{}, fmt.Errorf("begin Shared Space invitation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	domainID, provisioning, _, err := loadSharedSpaceAuthority(ctx, tx, invitation.SpaceID, credential, "FOR UPDATE")
	if err != nil {
		return sharedspaces.InvitationCreateResult{}, err
	}
	if invitation.RelayAdmission.DomainID != domainID || credential.TenantID != invitation.SpaceID {
		return sharedspaces.InvitationCreateResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "invitation belongs to another Shared Space",
		)
	}
	if invitation.InteractionMode != provisioning.InteractionMode {
		return sharedspaces.InvitationCreateResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidInvitation,
			"invitation interaction mode differs from the Shared Space",
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

	currentKeyEpoch, err := loadSharedSpaceKeyEpoch(ctx, tx, invitation.SpaceID)
	if err != nil {
		return sharedspaces.InvitationCreateResult{}, err
	}
	currentRosterAttestation, err := loadSharedSpaceSecureRosterAttestation(ctx, tx, invitation.SpaceID)
	if err != nil {
		return sharedspaces.InvitationCreateResult{}, err
	}
	participants, err := loadSharedSpaceParticipants(ctx, tx, invitation.SpaceID)
	if err != nil {
		return sharedspaces.InvitationCreateResult{}, err
	}
	if err := validateSharedSpaceInvitationRosterAttestation(
		provisioning.SecurityMode, currentRosterAttestation, participants, currentKeyEpoch, invitation,
	); err != nil {
		return sharedspaces.InvitationCreateResult{}, err
	}
	var bootstrapReady bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM relay_checkpoints
			WHERE tenant_id=$1 AND domain_id=$2 AND state='activated' AND key_epoch=$3
		)
	`, invitation.SpaceID, domainID, currentKeyEpoch).Scan(&bootstrapReady); err != nil {
		return sharedspaces.InvitationCreateResult{}, fmt.Errorf("check Shared Space bootstrap checkpoint: %w", err)
	}
	if !bootstrapReady {
		return sharedspaces.InvitationCreateResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeBootstrapNotReady,
			"Shared Space does not have an activated checkpoint for the current key epoch",
		)
	}
	if err := invitation.ValidateKeyGrant(provisioning.SecurityMode, currentKeyEpoch); err != nil {
		return sharedspaces.InvitationCreateResult{}, err
	}
	if invitation.KeyGrant != nil {
		var issuerRole sharedspaces.Role
		var issuerSigningKey sharedspaces.ParticipantSigningKey
		err := tx.QueryRow(ctx, `
			SELECT role,signing_key_algorithm,signing_public_key_x963,signing_key_fingerprint
			FROM shared_space_participants
			WHERE space_id=$1 AND participant_id=$2 AND revoked_at_milliseconds IS NULL
		`, invitation.SpaceID, invitation.KeyGrant.IssuerParticipantID).Scan(
			&issuerRole, &issuerSigningKey.Algorithm, &issuerSigningKey.PublicKeyX963,
			&issuerSigningKey.SigningKeyFingerprint,
		)
		if err == pgx.ErrNoRows ||
			(err == nil && issuerRole != sharedspaces.RoleHost && issuerRole != sharedspaces.RoleModerator) {
			return sharedspaces.InvitationCreateResult{}, sharedspaces.NewProtocolError(
				sharedspaces.CodeUnauthorized,
				"participant key grant issuer is not an active Shared Space host or moderator",
			)
		}
		if err != nil {
			return sharedspaces.InvitationCreateResult{}, fmt.Errorf("load participant key grant issuer: %w", err)
		}
		if !issuerSigningKey.MatchesGrantSignature(invitation.KeyGrant.Signature) {
			return sharedspaces.InvitationCreateResult{}, sharedspaces.NewProtocolError(
				sharedspaces.CodeUnauthorized,
				"participant key grant signature is not bound to its issuer",
			)
		}
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
	payload, err := json.Marshal(invitation)
	if err != nil {
		return sharedspaces.InvitationCreateResult{}, fmt.Errorf("encode Shared Space invitation: %w", err)
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
	if err := insertSharedSpaceAuthorityEvent(ctx, tx, sharedspaces.AuthorityEvent{
		EventID: invitation.RetryID, SpaceID: invitation.SpaceID,
		DomainID: domainID, EventType: sharedspaces.AuthorityEventInvitationCreated,
		SubjectParticipantID:   &invitation.ParticipantID,
		InvitationID:           &invitation.InvitationID,
		CurrentRole:            &invitation.Role,
		CurrentKeyEpoch:        &currentKeyEpoch,
		OccurredAtMilliseconds: invitation.CreatedAtMilliseconds,
	}); err != nil {
		return sharedspaces.InvitationCreateResult{}, err
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
	var cancelled bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM shared_space_invitation_cancellations
			WHERE space_id=$1 AND invitation_id=$2
		)
	`, credential.SpaceID, credential.InvitationID).Scan(&cancelled); err != nil {
		return sharedspaces.InvitationClaimResult{}, fmt.Errorf("check Shared Space invitation cancellation: %w", err)
	}
	if cancelled {
		return sharedspaces.InvitationClaimResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvitationCancelled, "Shared Space invitation was cancelled",
		)
	}
	var invitation sharedspaces.Invitation
	if err := json.Unmarshal(payload, &invitation); err != nil {
		return sharedspaces.InvitationClaimResult{}, fmt.Errorf("decode Shared Space invitation: %w", err)
	}
	if err := invitation.Validate(); err != nil {
		return sharedspaces.InvitationClaimResult{}, err
	}
	var currentKeyEpoch uint64
	var securityMode sharedspaces.SecurityMode
	var interactionMode sharedspaces.InteractionMode
	var currentRosterAttestationPayload []byte
	if err := tx.QueryRow(ctx, `
		SELECT current_key_epoch,security_mode,interaction_mode,secure_roster_attestation
		FROM shared_spaces
		WHERE space_id=$1
		FOR UPDATE
	`, claim.SpaceID).Scan(&currentKeyEpoch, &securityMode, &interactionMode, &currentRosterAttestationPayload); err == pgx.ErrNoRows {
		return sharedspaces.InvitationClaimResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeSpaceNotFound, "Shared Space was not found",
		)
	} else if err != nil {
		return sharedspaces.InvitationClaimResult{}, fmt.Errorf("load Shared Space invitation claim authority: %w", err)
	}
	if invitation.InteractionMode != interactionMode {
		return sharedspaces.InvitationClaimResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidInvitation,
			"invitation interaction mode differs from the Shared Space",
		)
	}
	currentRosterAttestation, err := decodeSecureRosterAttestation(currentRosterAttestationPayload)
	if err != nil {
		return sharedspaces.InvitationClaimResult{}, fmt.Errorf("decode Shared Space invitation claim roster attestation: %w", err)
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
			CurrentKeyEpoch: currentKeyEpoch, KeyGrant: invitation.KeyGrant,
			SecureRosterAttestation: cloneSecureRosterAttestation(invitation.ActivationSecureRosterAttestation),
			Member: relay.SubscriptionMemberRegistration{
				SubscriptionID: subscriptionID, MemberRegistration: member,
			},
		}, nil
	}
	if err := invitation.ValidateKeyGrant(securityMode, currentKeyEpoch); err != nil {
		return sharedspaces.InvitationClaimResult{}, err
	}
	participants, err := loadSharedSpaceParticipants(ctx, tx, claim.SpaceID)
	if err != nil {
		return sharedspaces.InvitationClaimResult{}, err
	}
	if err := validateSharedSpaceInvitationRosterAttestation(
		securityMode, currentRosterAttestation, participants, currentKeyEpoch, invitation,
	); err != nil {
		return sharedspaces.InvitationClaimResult{}, err
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
		SigningKey:            invitation.ParticipantSigningKey,
		DeviceKeys:            invitation.ParticipantDeviceKeys,
		CreatedAtMilliseconds: invitation.CreatedAtMilliseconds,
	}
	if err := insertSharedSpaceParticipant(ctx, tx, participant); err != nil {
		return sharedspaces.InvitationClaimResult{}, err
	}
	if invitation.KeyGrant != nil {
		if err := insertSharedSpaceParticipantKeyGrant(ctx, tx, *invitation.KeyGrant); err != nil {
			return sharedspaces.InvitationClaimResult{}, err
		}
	}
	newRosterAttestationPayload, err := encodeSecureRosterAttestation(invitation.ActivationSecureRosterAttestation)
	if err != nil {
		return sharedspaces.InvitationClaimResult{}, fmt.Errorf("encode Shared Space invitation claim roster attestation: %w", err)
	}
	newRosterAttestationDigest, err := secureRosterAttestationDigest(invitation.ActivationSecureRosterAttestation)
	if err != nil {
		return sharedspaces.InvitationClaimResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE shared_spaces
		SET secure_roster_attestation=$2
		WHERE space_id=$1
	`, claim.SpaceID, newRosterAttestationPayload); err != nil {
		return sharedspaces.InvitationClaimResult{}, fmt.Errorf("advance Shared Space invitation claim roster authority: %w", err)
	}
	if err := insertSharedSpaceSecureRosterAttestation(
		ctx, tx, invitation.ActivationSecureRosterAttestation,
	); err != nil {
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
	if err := insertSharedSpaceAuthorityEvent(ctx, tx, sharedspaces.AuthorityEvent{
		EventID: credential.InvitationID, SpaceID: claim.SpaceID,
		DomainID: domainID, EventType: sharedspaces.AuthorityEventInvitationClaimed,
		SubjectParticipantID:   &participant.ParticipantID,
		InvitationID:           &credential.InvitationID,
		CurrentRole:            &participant.Role,
		CurrentKeyEpoch:        &currentKeyEpoch,
		SecureRosterDigest:     newRosterAttestationDigest,
		OccurredAtMilliseconds: claim.ClaimedAtMilliseconds,
	}); err != nil {
		return sharedspaces.InvitationClaimResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sharedspaces.InvitationClaimResult{}, fmt.Errorf("commit Shared Space invitation claim: %w", err)
	}
	return sharedspaces.InvitationClaimResult{
		Acceptance: relayResult.Acceptance, CurrentKeyEpoch: currentKeyEpoch,
		KeyGrant: invitation.KeyGrant, Participant: participant,
		SecureRosterAttestation: cloneSecureRosterAttestation(invitation.ActivationSecureRosterAttestation),
		Member:                  relayResult.Member,
	}, nil
}

func (s *SharedSpacesStore) CancelInvitation(
	ctx context.Context,
	credential relay.AdministrationCredential,
	cancellation sharedspaces.InvitationCancellation,
	nowMilliseconds int64,
) (sharedspaces.InvitationCancellationResult, error) {
	if err := cancellation.Validate(); err != nil {
		return sharedspaces.InvitationCancellationResult{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return sharedspaces.InvitationCancellationResult{}, fmt.Errorf("begin Shared Space invitation cancellation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	domainID, _, _, err := loadSharedSpaceAuthority(ctx, tx, cancellation.SpaceID, credential, "FOR UPDATE")
	if err != nil {
		return sharedspaces.InvitationCancellationResult{}, err
	}
	var existingVersion int
	var existingInvitationID uuid.UUID
	var existingCancelledAt int64
	err = tx.QueryRow(ctx, `
		SELECT version,invitation_id,cancelled_at_milliseconds
		FROM shared_space_invitation_cancellations
		WHERE space_id=$1 AND retry_id=$2
		FOR UPDATE
	`, cancellation.SpaceID, cancellation.RetryID).Scan(
		&existingVersion, &existingInvitationID, &existingCancelledAt,
	)
	if err == nil {
		if existingVersion != cancellation.Version || existingInvitationID != cancellation.InvitationID ||
			existingCancelledAt != cancellation.CancelledAtMilliseconds {
			return sharedspaces.InvitationCancellationResult{}, sharedspaces.NewProtocolError(
				sharedspaces.CodeInvitationCancellationCollision, "invitation cancellation retry ID was reused",
			)
		}
		return sharedspaces.InvitationCancellationResult{
			Acceptance: relay.AcceptanceDuplicate, RetryID: cancellation.RetryID,
			SpaceID: cancellation.SpaceID, InvitationID: cancellation.InvitationID,
			CancelledAtMilliseconds: existingCancelledAt,
		}, nil
	}
	if err != pgx.ErrNoRows {
		return sharedspaces.InvitationCancellationResult{}, fmt.Errorf("load Shared Space invitation cancellation: %w", err)
	}
	var invitationDomainID, subscriptionID, participantID uuid.UUID
	var createdAt int64
	var claimedAt *int64
	err = tx.QueryRow(ctx, `
		SELECT domain_id,subscription_id,participant_id,created_at_milliseconds,claimed_at_milliseconds
		FROM shared_space_invitations
		WHERE space_id=$1 AND invitation_id=$2
		FOR UPDATE
	`, cancellation.SpaceID, cancellation.InvitationID).Scan(
		&invitationDomainID, &subscriptionID, &participantID, &createdAt, &claimedAt,
	)
	if err == pgx.ErrNoRows {
		return sharedspaces.InvitationCancellationResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvitationNotFound, "Shared Space invitation was not found",
		)
	}
	if err != nil {
		return sharedspaces.InvitationCancellationResult{}, fmt.Errorf("load Shared Space invitation for cancellation: %w", err)
	}
	if invitationDomainID != domainID {
		return sharedspaces.InvitationCancellationResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "invitation cancellation belongs to another Shared Space",
		)
	}
	if claimedAt != nil {
		return sharedspaces.InvitationCancellationResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvitationClaimed, "claimed Shared Space invitation cannot be cancelled",
		)
	}
	if cancellation.CancelledAtMilliseconds < createdAt || cancellation.CancelledAtMilliseconds > nowMilliseconds {
		return sharedspaces.InvitationCancellationResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidInvitation, "Shared Space invitation cancellation time is invalid",
		)
	}
	var priorRetryID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT retry_id FROM shared_space_invitation_cancellations
		WHERE space_id=$1 AND invitation_id=$2
		FOR UPDATE
	`, cancellation.SpaceID, cancellation.InvitationID).Scan(&priorRetryID)
	if err == nil {
		return sharedspaces.InvitationCancellationResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvitationCancellationCollision, "Shared Space invitation was already cancelled by another request",
		)
	}
	if err != pgx.ErrNoRows {
		return sharedspaces.InvitationCancellationResult{}, fmt.Errorf("check prior Shared Space invitation cancellation: %w", err)
	}
	acceptance, err := s.relay.revokeAdmissionInTransaction(
		ctx, tx, credential, cancellation.InvitationID, cancellation.CancelledAtMilliseconds,
	)
	if err != nil {
		return sharedspaces.InvitationCancellationResult{}, err
	}
	if _, err := s.relay.changeSubscriptionStatusInTransaction(
		ctx, tx, credential, subscriptionID, relay.SubscriptionStatusChangeRequest{
			RetryID: cancellation.RetryID, Status: relay.SubscriptionRevoked,
			ChangedAtMilliseconds: cancellation.CancelledAtMilliseconds,
		},
	); err != nil {
		return sharedspaces.InvitationCancellationResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO shared_space_invitation_cancellations (
			space_id,retry_id,invitation_id,version,cancelled_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5)
	`, cancellation.SpaceID, cancellation.RetryID, cancellation.InvitationID,
		cancellation.Version, cancellation.CancelledAtMilliseconds); err != nil {
		return sharedspaces.InvitationCancellationResult{}, fmt.Errorf("record Shared Space invitation cancellation: %w", err)
	}
	if err := insertDataPlaneAudit(
		ctx, tx, cancellation.SpaceID, &domainID, &subscriptionID, &participantID,
		"shared_space_invitation_cancelled", cancellation.CancelledAtMilliseconds,
	); err != nil {
		return sharedspaces.InvitationCancellationResult{}, err
	}
	if err := insertSharedSpaceAuthorityEvent(ctx, tx, sharedspaces.AuthorityEvent{
		EventID: cancellation.RetryID, SpaceID: cancellation.SpaceID,
		DomainID: domainID, EventType: sharedspaces.AuthorityEventInvitationCancelled,
		SubjectParticipantID:   &participantID,
		InvitationID:           &cancellation.InvitationID,
		OccurredAtMilliseconds: cancellation.CancelledAtMilliseconds,
	}); err != nil {
		return sharedspaces.InvitationCancellationResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sharedspaces.InvitationCancellationResult{}, fmt.Errorf("commit Shared Space invitation cancellation: %w", err)
	}
	return sharedspaces.InvitationCancellationResult{
		Acceptance: acceptance, RetryID: cancellation.RetryID,
		SpaceID: cancellation.SpaceID, InvitationID: cancellation.InvitationID,
		CancelledAtMilliseconds: cancellation.CancelledAtMilliseconds,
	}, nil
}

func (s *SharedSpacesStore) ListInvitations(
	ctx context.Context,
	credential relay.AdministrationCredential,
	nowMilliseconds int64,
) (sharedspaces.InvitationList, error) {
	if nowMilliseconds < 0 {
		return sharedspaces.InvitationList{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidInvitation, "invitation status time is invalid",
		)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return sharedspaces.InvitationList{}, fmt.Errorf("begin Shared Space invitation list: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, _, _, err := loadSharedSpaceAuthority(
		ctx, tx, credential.TenantID, credential, "",
	); err != nil {
		return sharedspaces.InvitationList{}, err
	}
	rows, err := tx.Query(ctx, `
		SELECT i.invitation_payload,i.claimed_at_milliseconds,c.cancelled_at_milliseconds
		FROM shared_space_invitations i
		LEFT JOIN shared_space_invitation_cancellations c
		  ON c.space_id=i.space_id AND c.invitation_id=i.invitation_id
		WHERE i.space_id=$1
		ORDER BY i.invitation_id
	`, credential.TenantID)
	if err != nil {
		return sharedspaces.InvitationList{}, fmt.Errorf("query Shared Space invitations: %w", err)
	}
	defer rows.Close()
	statuses := []sharedspaces.InvitationStatus{}
	for rows.Next() {
		var payload []byte
		var claimedAt, cancelledAt *int64
		if err := rows.Scan(&payload, &claimedAt, &cancelledAt); err != nil {
			return sharedspaces.InvitationList{}, fmt.Errorf("scan Shared Space invitation status: %w", err)
		}
		var invitation sharedspaces.Invitation
		if err := json.Unmarshal(payload, &invitation); err != nil {
			return sharedspaces.InvitationList{}, fmt.Errorf("decode Shared Space invitation status: %w", err)
		}
		state := sharedspaces.InvitationPending
		if claimedAt != nil {
			state = sharedspaces.InvitationClaimed
		} else if cancelledAt != nil {
			state = sharedspaces.InvitationCancelled
		} else if invitation.RelayAdmission.ExpiresAtMilliseconds <= nowMilliseconds {
			state = sharedspaces.InvitationExpired
		}
		statuses = append(statuses, sharedspaces.InvitationStatus{
			Version: invitation.Version, SpaceID: invitation.SpaceID,
			InvitationID: invitation.InvitationID, ParticipantID: invitation.ParticipantID,
			SubscriptionID: invitation.SubscriptionID, Kind: invitation.Kind,
			Role: invitation.Role, InteractionMode: invitation.InteractionMode, State: state,
			CreatedAtMilliseconds: invitation.CreatedAtMilliseconds,
			ExpiresAtMilliseconds: invitation.RelayAdmission.ExpiresAtMilliseconds,
			ClaimedAtMilliseconds: claimedAt, CancelledAtMilliseconds: cancelledAt,
		})
	}
	if err := rows.Err(); err != nil {
		return sharedspaces.InvitationList{}, fmt.Errorf("iterate Shared Space invitation status: %w", err)
	}
	rows.Close()
	if err := tx.Commit(ctx); err != nil {
		return sharedspaces.InvitationList{}, fmt.Errorf("commit Shared Space invitation list: %w", err)
	}
	return sharedspaces.InvitationList{
		Version: sharedspaces.SchemaVersion, SpaceID: credential.TenantID, Invitations: statuses,
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
	presentations, err := loadSharedSpaceParticipantPresentations(ctx, tx, credential.TenantID)
	if err != nil {
		return sharedspaces.SpaceStatus{}, err
	}
	computePools, computeBindings, err := loadSharedSpaceComputePools(ctx, tx, credential.TenantID)
	if err != nil {
		return sharedspaces.SpaceStatus{}, err
	}
	currentKeyEpoch, err := loadSharedSpaceKeyEpoch(ctx, tx, credential.TenantID)
	if err != nil {
		return sharedspaces.SpaceStatus{}, err
	}
	var activeCheckpointEpochValue *int64
	if err := tx.QueryRow(ctx, `
		SELECT key_epoch FROM relay_checkpoints
		WHERE tenant_id=$1 AND domain_id=$2 AND state='activated'
		ORDER BY activation_ordinal DESC LIMIT 1
	`, credential.TenantID, domainID).Scan(&activeCheckpointEpochValue); err != nil && err != pgx.ErrNoRows {
		return sharedspaces.SpaceStatus{}, fmt.Errorf("load Shared Space active checkpoint epoch: %w", err)
	}
	var activeCheckpointEpoch *uint64
	if activeCheckpointEpochValue != nil {
		epoch := uint64(*activeCheckpointEpochValue)
		activeCheckpointEpoch = &epoch
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
		SecurityMode: provisioning.SecurityMode, InteractionMode: provisioning.InteractionMode,
		DomainID:              domainID,
		CurrentKeyEpoch:       currentKeyEpoch,
		BootstrapReady:        activeCheckpointEpoch != nil && *activeCheckpointEpoch == currentKeyEpoch,
		ActiveCheckpointEpoch: activeCheckpointEpoch,
		InitialParticipantID:  provisioning.InitialParticipantID,
		Participants:          participants, Presentations: presentations,
		ComputePools: computePools, ComputeBindings: computeBindings, Relay: relayStatus,
		CreatedAtMilliseconds: provisioning.CreatedAtMilliseconds,
	}, nil
}

func (s *SharedSpacesStore) ChangeComputePool(
	ctx context.Context,
	credential relay.AdministrationCredential,
	change sharedspaces.ComputePoolChange,
	nowMilliseconds int64,
) (sharedspaces.ComputePoolChangeResult, error) {
	if err := change.Validate(); err != nil {
		return sharedspaces.ComputePoolChangeResult{}, err
	}
	if change.ChangedAtMilliseconds > nowMilliseconds {
		return sharedspaces.ComputePoolChangeResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidComputePool, "Shared Space compute pool change starts in the future",
		)
	}
	requestPayload, err := json.Marshal(change)
	if err != nil {
		return sharedspaces.ComputePoolChangeResult{}, fmt.Errorf("encode Shared Space compute pool change: %w", err)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return sharedspaces.ComputePoolChangeResult{}, fmt.Errorf("begin Shared Space compute pool change: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	domainID, _, _, err := loadSharedSpaceAuthority(ctx, tx, change.SpaceID, credential, "FOR UPDATE")
	if err != nil {
		return sharedspaces.ComputePoolChangeResult{}, err
	}
	var existingRequestPayload, existingResponsePayload []byte
	err = tx.QueryRow(ctx, `
		SELECT request_payload,response_payload
		FROM shared_space_compute_pool_changes
		WHERE space_id=$1 AND retry_id=$2
		FOR UPDATE
	`, change.SpaceID, change.RetryID).Scan(&existingRequestPayload, &existingResponsePayload)
	if err == nil {
		var existingRequest sharedspaces.ComputePoolChange
		var result sharedspaces.ComputePoolChangeResult
		if decodeErr := json.Unmarshal(existingRequestPayload, &existingRequest); decodeErr != nil {
			return sharedspaces.ComputePoolChangeResult{}, fmt.Errorf("decode Shared Space compute pool retry request: %w", decodeErr)
		}
		if decodeErr := json.Unmarshal(existingResponsePayload, &result); decodeErr != nil {
			return sharedspaces.ComputePoolChangeResult{}, fmt.Errorf("decode Shared Space compute pool retry response: %w", decodeErr)
		}
		if !reflect.DeepEqual(existingRequest, change) {
			return sharedspaces.ComputePoolChangeResult{}, sharedspaces.NewProtocolError(
				sharedspaces.CodeComputePoolCollision, "compute pool retry ID was reused",
			)
		}
		result.Acceptance = relay.AcceptanceDuplicate
		return result, nil
	}
	if err != pgx.ErrNoRows {
		return sharedspaces.ComputePoolChangeResult{}, fmt.Errorf("load Shared Space compute pool retry: %w", err)
	}
	var existingPoolPayload, existingBindingPayload []byte
	var existingRevision uint64
	var createdAt, updatedAt int64
	err = tx.QueryRow(ctx, `
		SELECT pool_payload,binding_payload,current_revision,
		       created_at_milliseconds,updated_at_milliseconds
		FROM shared_space_compute_pools
		WHERE space_id=$1 AND pool_id=$2
		FOR UPDATE
	`, change.SpaceID, change.PoolID).Scan(
		&existingPoolPayload, &existingBindingPayload, &existingRevision, &createdAt, &updatedAt,
	)
	if err == pgx.ErrNoRows {
		if change.PreviousPoolRevision != 0 {
			return sharedspaces.ComputePoolChangeResult{}, sharedspaces.NewProtocolError(
				sharedspaces.CodeComputePoolNotFound, "compute pool was not found",
			)
		}
		createdAt = change.ChangedAtMilliseconds
	} else if err != nil {
		return sharedspaces.ComputePoolChangeResult{}, fmt.Errorf("load Shared Space compute pool: %w", err)
	} else if existingRevision != change.PreviousPoolRevision ||
		change.PreviousPoolRevision != change.PreviousBindingRevision {
		return sharedspaces.ComputePoolChangeResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeComputePoolCollision, "compute pool revision changed",
		)
	} else if change.ChangedAtMilliseconds < updatedAt {
		return sharedspaces.ComputePoolChangeResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidComputePool, "compute pool change predates current state",
		)
	}
	nextRevision := change.PreviousPoolRevision + 1
	pool := sharedspaces.ComputePool{
		Version: sharedspaces.SchemaVersion, SpaceID: change.SpaceID, PoolID: change.PoolID,
		DisplayName: change.DisplayName, Enabled: change.Enabled, Revision: nextRevision,
		CreatedAtMilliseconds: createdAt, UpdatedAtMilliseconds: change.ChangedAtMilliseconds,
	}
	binding := sharedspaces.SpaceComputeBinding{
		Version: sharedspaces.SchemaVersion, SpaceID: change.SpaceID, PoolID: change.PoolID,
		AllowedOperations: append([]string(nil), change.AllowedOperations...),
		ResourceCeiling:   change.ResourceCeiling, PricingRevision: change.PricingRevision,
		DataSensitivityContract: change.DataSensitivityContract,
		ProcessingContract:      change.ProcessingContract,
		Revision:                nextRevision, CreatedAtMilliseconds: createdAt,
		UpdatedAtMilliseconds: change.ChangedAtMilliseconds,
	}
	poolPayload, err := json.Marshal(pool)
	if err != nil {
		return sharedspaces.ComputePoolChangeResult{}, fmt.Errorf("encode Shared Space compute pool: %w", err)
	}
	bindingPayload, err := json.Marshal(binding)
	if err != nil {
		return sharedspaces.ComputePoolChangeResult{}, fmt.Errorf("encode Shared Space compute binding: %w", err)
	}
	result := sharedspaces.ComputePoolChangeResult{
		Acceptance: relay.AcceptanceAccepted, RetryID: change.RetryID, Pool: pool, Binding: binding,
	}
	responsePayload, err := json.Marshal(result)
	if err != nil {
		return sharedspaces.ComputePoolChangeResult{}, fmt.Errorf("encode Shared Space compute pool result: %w", err)
	}
	if existingRevision == 0 {
		_, err = tx.Exec(ctx, `
			INSERT INTO shared_space_compute_pools (
				space_id,pool_id,current_revision,pool_payload,binding_payload,
				created_at_milliseconds,updated_at_milliseconds
			) VALUES ($1,$2,$3,$4,$5,$6,$7)
		`, change.SpaceID, change.PoolID, nextRevision, poolPayload, bindingPayload,
			createdAt, change.ChangedAtMilliseconds)
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE shared_space_compute_pools
			SET current_revision=$3,pool_payload=$4,binding_payload=$5,
			    updated_at_milliseconds=$6,stored_at=now()
			WHERE space_id=$1 AND pool_id=$2
		`, change.SpaceID, change.PoolID, nextRevision, poolPayload, bindingPayload,
			change.ChangedAtMilliseconds)
	}
	if err != nil {
		return sharedspaces.ComputePoolChangeResult{}, fmt.Errorf("store Shared Space compute pool: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO shared_space_compute_pool_changes (
			space_id,retry_id,pool_id,request_payload,response_payload,changed_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6)
	`, change.SpaceID, change.RetryID, change.PoolID, requestPayload,
		responsePayload, change.ChangedAtMilliseconds); err != nil {
		return sharedspaces.ComputePoolChangeResult{}, fmt.Errorf("record Shared Space compute pool change: %w", err)
	}
	if err := insertSharedSpaceAuthorityEvent(ctx, tx, sharedspaces.AuthorityEvent{
		EventID: change.RetryID, SpaceID: change.SpaceID, DomainID: domainID,
		EventType:     sharedspaces.AuthorityEventSpaceComputeBindingChanged,
		ComputePoolID: &change.PoolID, PreviousBindingRevision: &change.PreviousBindingRevision,
		CurrentBindingRevision: &nextRevision,
		OccurredAtMilliseconds: change.ChangedAtMilliseconds,
	}); err != nil {
		return sharedspaces.ComputePoolChangeResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sharedspaces.ComputePoolChangeResult{}, fmt.Errorf("commit Shared Space compute pool change: %w", err)
	}
	return result, nil
}

func (s *SharedSpacesStore) ListAuthorityEvents(
	ctx context.Context,
	credential relay.AdministrationCredential,
	afterSequence uint64,
	limit int,
) (sharedspaces.AuthorityEventPage, error) {
	if limit < 1 || limit > sharedspaces.MaximumAuthorityEventPageSize {
		return sharedspaces.AuthorityEventPage{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidAuthorityEvent,
			"Shared Space authority event page size is invalid",
		)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return sharedspaces.AuthorityEventPage{}, fmt.Errorf("begin Shared Space authority event list: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, _, _, err := loadSharedSpaceAuthority(
		ctx, tx, credential.TenantID, credential, "",
	); err != nil {
		return sharedspaces.AuthorityEventPage{}, err
	}
	rows, err := tx.Query(ctx, `
		SELECT sequence,event_id,space_id,domain_id,version,event_type,
		       subject_participant_id,subject_device_id,invitation_id,previous_role,resulting_role,
		       previous_key_epoch,current_key_epoch,compute_pool_id,
		       previous_binding_revision,current_binding_revision,
		       secure_roster_digest,
		       occurred_at_milliseconds
		FROM shared_space_authority_events
		WHERE space_id=$1 AND sequence>$2
		ORDER BY sequence
		LIMIT $3
	`, credential.TenantID, afterSequence, limit)
	if err != nil {
		return sharedspaces.AuthorityEventPage{}, fmt.Errorf("query Shared Space authority events: %w", err)
	}
	defer rows.Close()
	events := make([]sharedspaces.AuthorityEvent, 0, limit)
	nextSequence := afterSequence
	for rows.Next() {
		var event sharedspaces.AuthorityEvent
		var previousRole, currentRole *string
		var previousKeyEpoch, currentKeyEpoch *int64
		var previousBindingRevision, currentBindingRevision *int64
		var secureRosterDigest *string
		if err := rows.Scan(
			&event.Sequence, &event.EventID, &event.SpaceID, &event.DomainID,
			&event.Version, &event.EventType, &event.SubjectParticipantID, &event.SubjectDeviceID,
			&event.InvitationID, &previousRole, &currentRole,
			&previousKeyEpoch, &currentKeyEpoch, &event.ComputePoolID,
			&previousBindingRevision, &currentBindingRevision,
			&secureRosterDigest,
			&event.OccurredAtMilliseconds,
		); err != nil {
			return sharedspaces.AuthorityEventPage{}, fmt.Errorf("scan Shared Space authority event: %w", err)
		}
		if previousRole != nil {
			role := sharedspaces.Role(*previousRole)
			event.PreviousRole = &role
		}
		if currentRole != nil {
			role := sharedspaces.Role(*currentRole)
			event.CurrentRole = &role
		}
		if previousKeyEpoch != nil {
			epoch := uint64(*previousKeyEpoch)
			event.PreviousKeyEpoch = &epoch
		}
		if currentKeyEpoch != nil {
			epoch := uint64(*currentKeyEpoch)
			event.CurrentKeyEpoch = &epoch
		}
		if previousBindingRevision != nil {
			revision := uint64(*previousBindingRevision)
			event.PreviousBindingRevision = &revision
		}
		if currentBindingRevision != nil {
			revision := uint64(*currentBindingRevision)
			event.CurrentBindingRevision = &revision
		}
		event.SecureRosterDigest = secureRosterDigest
		if err := event.Validate(); err != nil {
			return sharedspaces.AuthorityEventPage{}, fmt.Errorf("stored Shared Space authority event failed validation: %v", err)
		}
		events = append(events, event)
		nextSequence = event.Sequence
	}
	if err := rows.Err(); err != nil {
		return sharedspaces.AuthorityEventPage{}, fmt.Errorf("iterate Shared Space authority events: %w", err)
	}
	rows.Close()
	if err := tx.Commit(ctx); err != nil {
		return sharedspaces.AuthorityEventPage{}, fmt.Errorf("commit Shared Space authority event list: %w", err)
	}
	return sharedspaces.AuthorityEventPage{
		Version: sharedspaces.SchemaVersion, SpaceID: credential.TenantID,
		Events: events, NextSequence: nextSequence,
	}, nil
}

func (s *SharedSpacesStore) ChangeParticipantRole(
	ctx context.Context,
	credential relay.AdministrationCredential,
	change sharedspaces.ParticipantRoleChange,
	nowMilliseconds int64,
) (sharedspaces.ParticipantRoleChangeResult, error) {
	if err := change.Validate(); err != nil {
		return sharedspaces.ParticipantRoleChangeResult{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return sharedspaces.ParticipantRoleChangeResult{}, fmt.Errorf("begin Shared Space participant role change: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	domainID, provisioning, _, err := loadSharedSpaceAuthority(
		ctx, tx, change.SpaceID, credential, "FOR UPDATE",
	)
	if err != nil {
		return sharedspaces.ParticipantRoleChangeResult{}, err
	}
	if change.ParticipantID == provisioning.InitialParticipantID ||
		change.PreviousRole == sharedspaces.RoleHost || change.NextRole == sharedspaces.RoleHost {
		return sharedspaces.ParticipantRoleChangeResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInitialHost, "initial host role cannot be changed",
		)
	}

	var existingVersion int
	var existingParticipantID uuid.UUID
	var existingPreviousRole, existingNextRole string
	var existingChangedAt int64
	var existingRosterAttestationPayload []byte
	err = tx.QueryRow(ctx, `
		SELECT version,participant_id,previous_role,next_role,changed_at_milliseconds,
		       secure_roster_attestation
		FROM shared_space_participant_role_changes
		WHERE space_id=$1 AND retry_id=$2
		FOR UPDATE
	`, change.SpaceID, change.RetryID).Scan(
		&existingVersion, &existingParticipantID, &existingPreviousRole,
		&existingNextRole, &existingChangedAt, &existingRosterAttestationPayload,
	)
	if err == nil {
		existingRosterAttestation, decodeErr := decodeSecureRosterAttestation(existingRosterAttestationPayload)
		if decodeErr != nil {
			return sharedspaces.ParticipantRoleChangeResult{}, fmt.Errorf("decode Shared Space participant role change roster attestation: %w", decodeErr)
		}
		if existingVersion != change.Version || existingParticipantID != change.ParticipantID ||
			sharedspaces.Role(existingPreviousRole) != change.PreviousRole ||
			sharedspaces.Role(existingNextRole) != change.NextRole ||
			existingChangedAt != change.ChangedAtMilliseconds ||
			!reflect.DeepEqual(existingRosterAttestation, change.SecureRosterAttestation) {
			return sharedspaces.ParticipantRoleChangeResult{}, sharedspaces.NewProtocolError(
				sharedspaces.CodeParticipantRoleCollision, "participant role change retry ID was reused",
			)
		}
		return sharedspaces.ParticipantRoleChangeResult{
			Acceptance: relay.AcceptanceDuplicate, RetryID: change.RetryID,
			SpaceID: change.SpaceID, ParticipantID: change.ParticipantID,
			PreviousRole: change.PreviousRole, CurrentRole: change.NextRole,
			ChangedAtMilliseconds: existingChangedAt,
		}, nil
	}
	if err != pgx.ErrNoRows {
		return sharedspaces.ParticipantRoleChangeResult{}, fmt.Errorf("load Shared Space participant role change: %w", err)
	}
	participant, err := loadSharedSpaceParticipant(
		ctx, tx, change.SpaceID, change.ParticipantID, "FOR UPDATE",
	)
	if err != nil {
		return sharedspaces.ParticipantRoleChangeResult{}, err
	}
	if participant.RevokedAtMilliseconds != nil {
		return sharedspaces.ParticipantRoleChangeResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantRevoked, "participant is revoked",
		)
	}
	if change.ChangedAtMilliseconds > nowMilliseconds ||
		change.ChangedAtMilliseconds < participant.CreatedAtMilliseconds {
		return sharedspaces.ParticipantRoleChangeResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidParticipant, "participant role change time is invalid",
		)
	}
	if participant.Role != change.PreviousRole {
		return sharedspaces.ParticipantRoleChangeResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantRoleCollision, "participant role changed concurrently",
		)
	}
	currentKeyEpoch, err := loadSharedSpaceKeyEpoch(ctx, tx, change.SpaceID)
	if err != nil {
		return sharedspaces.ParticipantRoleChangeResult{}, err
	}
	currentRosterAttestation, err := loadSharedSpaceSecureRosterAttestation(ctx, tx, change.SpaceID)
	if err != nil {
		return sharedspaces.ParticipantRoleChangeResult{}, err
	}
	participants, err := loadSharedSpaceParticipants(ctx, tx, change.SpaceID)
	if err != nil {
		return sharedspaces.ParticipantRoleChangeResult{}, err
	}
	if err := validateSharedSpaceRoleChangeRosterAttestation(
		provisioning.SecurityMode, currentRosterAttestation, participants, currentKeyEpoch, change,
	); err != nil {
		return sharedspaces.ParticipantRoleChangeResult{}, err
	}
	if _, err := s.relay.changeMemberCapabilitiesInTransaction(
		ctx, tx, credential, relay.MemberCapabilityChange{
			Version: relay.SchemaVersion, RetryID: change.RetryID, MemberID: change.ParticipantID,
			PreviousCapabilities:  change.PreviousRole.Capabilities(provisioning.InteractionMode),
			NextCapabilities:      change.NextRole.Capabilities(provisioning.InteractionMode),
			ChangedAtMilliseconds: change.ChangedAtMilliseconds,
		}, nowMilliseconds,
	); err != nil {
		return sharedspaces.ParticipantRoleChangeResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE shared_space_participants
		SET role=$3,updated_at=now()
		WHERE space_id=$1 AND participant_id=$2
	`, change.SpaceID, change.ParticipantID, string(change.NextRole)); err != nil {
		return sharedspaces.ParticipantRoleChangeResult{}, fmt.Errorf("change Shared Space participant role: %w", err)
	}
	newRosterAttestationPayload, err := encodeSecureRosterAttestation(change.SecureRosterAttestation)
	if err != nil {
		return sharedspaces.ParticipantRoleChangeResult{}, fmt.Errorf("encode Shared Space participant role change roster attestation: %w", err)
	}
	newRosterAttestationDigest, err := secureRosterAttestationDigest(change.SecureRosterAttestation)
	if err != nil {
		return sharedspaces.ParticipantRoleChangeResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE shared_spaces
		SET secure_roster_attestation=$2
		WHERE space_id=$1
	`, change.SpaceID, newRosterAttestationPayload); err != nil {
		return sharedspaces.ParticipantRoleChangeResult{}, fmt.Errorf("advance Shared Space participant role roster authority: %w", err)
	}
	if err := insertSharedSpaceSecureRosterAttestation(ctx, tx, change.SecureRosterAttestation); err != nil {
		return sharedspaces.ParticipantRoleChangeResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO shared_space_participant_role_changes (
			space_id,retry_id,participant_id,version,previous_role,next_role,
			changed_at_milliseconds,secure_roster_attestation
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, change.SpaceID, change.RetryID, change.ParticipantID, change.Version,
		string(change.PreviousRole), string(change.NextRole), change.ChangedAtMilliseconds,
		newRosterAttestationPayload); err != nil {
		return sharedspaces.ParticipantRoleChangeResult{}, fmt.Errorf("record Shared Space participant role change: %w", err)
	}
	participantSubscriptionID := participant.SubscriptionID
	if err := insertDataPlaneAudit(
		ctx, tx, change.SpaceID, &domainID, &participantSubscriptionID,
		&change.ParticipantID, "shared_space_participant_role_changed",
		change.ChangedAtMilliseconds,
	); err != nil {
		return sharedspaces.ParticipantRoleChangeResult{}, err
	}
	if err := insertSharedSpaceAuthorityEvent(ctx, tx, sharedspaces.AuthorityEvent{
		EventID: change.RetryID, SpaceID: change.SpaceID,
		DomainID: domainID, EventType: sharedspaces.AuthorityEventParticipantRoleChanged,
		SubjectParticipantID:   &change.ParticipantID,
		PreviousRole:           &change.PreviousRole,
		CurrentRole:            &change.NextRole,
		SecureRosterDigest:     newRosterAttestationDigest,
		OccurredAtMilliseconds: change.ChangedAtMilliseconds,
	}); err != nil {
		return sharedspaces.ParticipantRoleChangeResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sharedspaces.ParticipantRoleChangeResult{}, fmt.Errorf("commit Shared Space participant role change: %w", err)
	}
	return sharedspaces.ParticipantRoleChangeResult{
		Acceptance: relay.AcceptanceAccepted, RetryID: change.RetryID,
		SpaceID: change.SpaceID, ParticipantID: change.ParticipantID,
		PreviousRole: change.PreviousRole, CurrentRole: change.NextRole,
		ChangedAtMilliseconds: change.ChangedAtMilliseconds,
	}, nil
}

func (s *SharedSpacesStore) EnrollParticipantDevice(
	ctx context.Context,
	credential relay.AdministrationCredential,
	enrollment sharedspaces.ParticipantDeviceEnrollment,
	nowMilliseconds int64,
) (sharedspaces.ParticipantDeviceEnrollmentResult, error) {
	if err := enrollment.Validate(); err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, fmt.Errorf("begin Shared Space participant device enrollment: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	domainID, provisioning, _, err := loadSharedSpaceAuthority(
		ctx, tx, enrollment.SpaceID, credential, "FOR UPDATE",
	)
	if err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, err
	}

	var existingRequestPayload, existingResponsePayload []byte
	err = tx.QueryRow(ctx, `
		SELECT request_payload,response_payload
		FROM shared_space_participant_device_enrollments
		WHERE space_id=$1 AND retry_id=$2
		FOR UPDATE
	`, enrollment.SpaceID, enrollment.RetryID).Scan(
		&existingRequestPayload, &existingResponsePayload,
	)
	if err == nil {
		var existingRequest sharedspaces.ParticipantDeviceEnrollment
		var existingResponse sharedspaces.ParticipantDeviceEnrollmentResult
		if decodeErr := json.Unmarshal(existingRequestPayload, &existingRequest); decodeErr != nil {
			return sharedspaces.ParticipantDeviceEnrollmentResult{}, fmt.Errorf("decode Shared Space participant device enrollment request: %w", decodeErr)
		}
		if decodeErr := json.Unmarshal(existingResponsePayload, &existingResponse); decodeErr != nil {
			return sharedspaces.ParticipantDeviceEnrollmentResult{}, fmt.Errorf("decode Shared Space participant device enrollment response: %w", decodeErr)
		}
		if !reflect.DeepEqual(existingRequest, enrollment) {
			return sharedspaces.ParticipantDeviceEnrollmentResult{}, sharedspaces.NewProtocolError(
				sharedspaces.CodeParticipantCollision, "participant device enrollment retry ID was reused",
			)
		}
		existingResponse.Acceptance = relay.AcceptanceDuplicate
		return existingResponse, nil
	}
	if err != pgx.ErrNoRows {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, fmt.Errorf("load Shared Space participant device enrollment: %w", err)
	}

	participant, err := loadSharedSpaceParticipant(
		ctx, tx, enrollment.SpaceID, enrollment.ParticipantID, "FOR UPDATE",
	)
	if err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, err
	}
	if participant.RevokedAtMilliseconds != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantRevoked, "participant is revoked",
		)
	}
	if enrollment.EnrolledAtMilliseconds > nowMilliseconds ||
		enrollment.EnrolledAtMilliseconds < participant.CreatedAtMilliseconds {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidParticipant, "participant device enrollment time is invalid",
		)
	}
	for _, deviceKey := range participant.DeviceKeys {
		if deviceKey.DeviceID == enrollment.DeviceKey.DeviceID {
			return sharedspaces.ParticipantDeviceEnrollmentResult{}, sharedspaces.NewProtocolError(
				sharedspaces.CodeParticipantCollision, "participant device is already registered",
			)
		}
	}
	if err := enrollment.DeviceKey.Validate(participant); err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, err
	}
	currentKeyEpoch, err := loadSharedSpaceKeyEpoch(ctx, tx, enrollment.SpaceID)
	if err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, err
	}
	var bootstrapReady bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM relay_checkpoints
			WHERE tenant_id=$1 AND domain_id=$2 AND state='activated' AND key_epoch=$3
		)
	`, enrollment.SpaceID, domainID, currentKeyEpoch).Scan(&bootstrapReady); err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, fmt.Errorf("check Shared Space bootstrap checkpoint: %w", err)
	}
	if !bootstrapReady {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeBootstrapNotReady,
			"Shared Space does not have an activated checkpoint for the current key epoch",
		)
	}
	participants, err := loadSharedSpaceParticipants(ctx, tx, enrollment.SpaceID)
	if err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, err
	}
	if err := enrollment.ValidateKeyGrant(
		provisioning.SecurityMode, currentKeyEpoch, participants, nowMilliseconds,
	); err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, err
	}
	currentRosterAttestation, err := loadSharedSpaceSecureRosterAttestation(ctx, tx, enrollment.SpaceID)
	if err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, err
	}
	if err := validateSharedSpaceDeviceEnrollmentRosterAttestation(
		provisioning.SecurityMode, currentRosterAttestation, participants,
		currentKeyEpoch, enrollment,
	); err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, err
	}
	if err := insertSharedSpaceParticipantDeviceKey(
		ctx, tx, participant, enrollment.DeviceKey,
	); err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, err
	}
	if err := insertSharedSpaceParticipantKeyGrant(ctx, tx, *enrollment.KeyGrant); err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, err
	}
	newRosterAttestationPayload, err := encodeSecureRosterAttestation(enrollment.SecureRosterAttestation)
	if err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, fmt.Errorf("encode Shared Space participant device enrollment roster attestation: %w", err)
	}
	newRosterAttestationDigest, err := secureRosterAttestationDigest(enrollment.SecureRosterAttestation)
	if err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE shared_spaces
		SET secure_roster_attestation=$2
		WHERE space_id=$1
	`, enrollment.SpaceID, newRosterAttestationPayload); err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, fmt.Errorf("advance Shared Space participant device roster authority: %w", err)
	}
	if err := insertSharedSpaceSecureRosterAttestation(ctx, tx, enrollment.SecureRosterAttestation); err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, err
	}
	result := sharedspaces.ParticipantDeviceEnrollmentResult{
		Acceptance: relay.AcceptanceAccepted, RetryID: enrollment.RetryID,
		SpaceID: enrollment.SpaceID, ParticipantID: enrollment.ParticipantID,
		DeviceID: enrollment.DeviceKey.DeviceID, CurrentKeyEpoch: currentKeyEpoch,
		EnrolledAtMilliseconds: enrollment.EnrolledAtMilliseconds,
	}
	requestPayload, err := json.Marshal(enrollment)
	if err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, fmt.Errorf("encode Shared Space participant device enrollment request: %w", err)
	}
	responsePayload, err := json.Marshal(result)
	if err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, fmt.Errorf("encode Shared Space participant device enrollment response: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO shared_space_participant_device_enrollments (
			space_id,retry_id,participant_id,device_id,request_payload,response_payload,
			enrolled_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, enrollment.SpaceID, enrollment.RetryID, enrollment.ParticipantID,
		enrollment.DeviceKey.DeviceID, requestPayload, responsePayload,
		enrollment.EnrolledAtMilliseconds); err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, fmt.Errorf("record Shared Space participant device enrollment: %w", err)
	}
	if err := insertSharedSpaceAuthorityEvent(ctx, tx, sharedspaces.AuthorityEvent{
		EventID: enrollment.RetryID, SpaceID: enrollment.SpaceID,
		DomainID: domainID, EventType: sharedspaces.AuthorityEventParticipantDeviceEnrolled,
		SubjectParticipantID:   &enrollment.ParticipantID,
		SubjectDeviceID:        &enrollment.DeviceKey.DeviceID,
		CurrentKeyEpoch:        &currentKeyEpoch,
		SecureRosterDigest:     newRosterAttestationDigest,
		OccurredAtMilliseconds: enrollment.EnrolledAtMilliseconds,
	}); err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sharedspaces.ParticipantDeviceEnrollmentResult{}, fmt.Errorf("commit Shared Space participant device enrollment: %w", err)
	}
	return result, nil
}

func (s *SharedSpacesStore) RevokeParticipantDevice(
	ctx context.Context,
	credential relay.AdministrationCredential,
	revocation sharedspaces.ParticipantDeviceRevocation,
	nowMilliseconds int64,
) (sharedspaces.ParticipantDeviceRevocationResult, error) {
	if err := revocation.Validate(); err != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, fmt.Errorf("begin Shared Space participant device revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	domainID, provisioning, _, err := loadSharedSpaceAuthority(
		ctx, tx, revocation.SpaceID, credential, "FOR UPDATE",
	)
	if err != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, err
	}

	var existingRequestPayload, existingResponsePayload []byte
	err = tx.QueryRow(ctx, `
		SELECT request_payload,response_payload
		FROM shared_space_participant_device_revocations
		WHERE space_id=$1 AND retry_id=$2
		FOR UPDATE
	`, revocation.SpaceID, revocation.RetryID).Scan(&existingRequestPayload, &existingResponsePayload)
	if err == nil {
		var existingRequest sharedspaces.ParticipantDeviceRevocation
		var existingResponse sharedspaces.ParticipantDeviceRevocationResult
		if decodeErr := json.Unmarshal(existingRequestPayload, &existingRequest); decodeErr != nil {
			return sharedspaces.ParticipantDeviceRevocationResult{}, fmt.Errorf("decode Shared Space participant device revocation request: %w", decodeErr)
		}
		if decodeErr := json.Unmarshal(existingResponsePayload, &existingResponse); decodeErr != nil {
			return sharedspaces.ParticipantDeviceRevocationResult{}, fmt.Errorf("decode Shared Space participant device revocation response: %w", decodeErr)
		}
		if !existingRequest.Equivalent(revocation) {
			return sharedspaces.ParticipantDeviceRevocationResult{}, sharedspaces.NewProtocolError(
				sharedspaces.CodeParticipantCollision, "participant device revocation retry ID was reused",
			)
		}
		existingResponse.Acceptance = relay.AcceptanceDuplicate
		return existingResponse, nil
	}
	if err != pgx.ErrNoRows {
		return sharedspaces.ParticipantDeviceRevocationResult{}, fmt.Errorf("load Shared Space participant device revocation: %w", err)
	}
	if provisioning.SecurityMode == sharedspaces.SecurityModeManaged {
		return sharedspaces.ParticipantDeviceRevocationResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidParticipant, "managed Shared Spaces do not revoke participant agreement-key devices",
		)
	}
	currentKeyEpoch, err := loadSharedSpaceKeyEpoch(ctx, tx, revocation.SpaceID)
	if err != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, err
	}
	if currentKeyEpoch != revocation.PreviousKeyEpoch {
		return sharedspaces.ParticipantDeviceRevocationResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongKeyEpoch, "participant device revocation key epoch is stale",
		)
	}
	var bootstrapReady bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM relay_checkpoints
			WHERE tenant_id=$1 AND domain_id=$2 AND state='activated' AND key_epoch=$3
		)
	`, revocation.SpaceID, domainID, currentKeyEpoch).Scan(&bootstrapReady); err != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, fmt.Errorf("check Shared Space bootstrap checkpoint: %w", err)
	}
	if !bootstrapReady {
		return sharedspaces.ParticipantDeviceRevocationResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeBootstrapNotReady, "Shared Space does not have an activated checkpoint for the current key epoch",
		)
	}
	participant, err := loadSharedSpaceParticipant(
		ctx, tx, revocation.SpaceID, revocation.ParticipantID, "FOR UPDATE",
	)
	if err != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, err
	}
	if participant.RevokedAtMilliseconds != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantRevoked, "participant is revoked",
		)
	}
	activeDeviceCount := 0
	var targetDevice *sharedspaces.ParticipantDeviceKey
	for index := range participant.DeviceKeys {
		deviceKey := &participant.DeviceKeys[index]
		if deviceKey.RevokedAtMilliseconds == nil {
			activeDeviceCount++
			if deviceKey.DeviceID == revocation.DeviceID {
				targetDevice = deviceKey
			}
		}
	}
	if targetDevice == nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantNotFound, "active participant device was not found",
		)
	}
	if activeDeviceCount == 1 {
		return sharedspaces.ParticipantDeviceRevocationResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidParticipant, "participant's last active device cannot be revoked",
		)
	}
	if nowMilliseconds < targetDevice.CreatedAtMilliseconds {
		return sharedspaces.ParticipantDeviceRevocationResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidParticipant, "participant device revocation predates device enrollment",
		)
	}
	if err := revocation.ValidateDeviceKey(participant, *targetDevice, nowMilliseconds); err != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, err
	}
	participants, err := loadSharedSpaceParticipants(ctx, tx, revocation.SpaceID)
	if err != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, err
	}
	if err := revocation.ValidateKeyGrants(provisioning.SecurityMode, participants, nowMilliseconds); err != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, err
	}
	currentRosterAttestation, err := loadSharedSpaceSecureRosterAttestation(ctx, tx, revocation.SpaceID)
	if err != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, err
	}
	if err := validateSharedSpaceDeviceRevocationRosterAttestation(
		provisioning.SecurityMode, currentRosterAttestation, participants, revocation,
	); err != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, err
	}
	revokedAtMilliseconds := *revocation.DeviceKey.RevokedAtMilliseconds

	if _, err := tx.Exec(ctx, `
		UPDATE shared_space_participant_device_keys
		SET revoked_at_milliseconds=$4,
		    signature_algorithm=$5,
		    signature_public_signing_key_x963=$6,
		    signature_signing_key_fingerprint=$7,
		    signature=$8
		WHERE space_id=$1 AND participant_id=$2 AND device_id=$3 AND revoked_at_milliseconds IS NULL
	`, revocation.SpaceID, revocation.ParticipantID, revocation.DeviceID,
		*revocation.DeviceKey.RevokedAtMilliseconds,
		revocation.DeviceKey.Signature.Algorithm,
		revocation.DeviceKey.Signature.PublicSigningKeyX963,
		revocation.DeviceKey.Signature.SigningKeyFingerprint,
		revocation.DeviceKey.Signature.Signature); err != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, fmt.Errorf("revoke Shared Space participant device: %w", err)
	}
	for _, grant := range revocation.KeyGrants {
		if err := insertSharedSpaceParticipantKeyGrant(ctx, tx, grant); err != nil {
			return sharedspaces.ParticipantDeviceRevocationResult{}, err
		}
	}
	newRosterPayload, err := encodeSecureRosterAttestation(revocation.SecureRosterAttestation)
	if err != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, fmt.Errorf("encode Shared Space participant device revocation roster attestation: %w", err)
	}
	newRosterDigest, err := secureRosterAttestationDigest(revocation.SecureRosterAttestation)
	if err != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE shared_spaces
		SET current_key_epoch=$2,secure_roster_attestation=$3
		WHERE space_id=$1
	`, revocation.SpaceID, revocation.NextKeyEpoch, newRosterPayload); err != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, fmt.Errorf("advance Shared Space device revocation authority: %w", err)
	}
	if err := insertSharedSpaceSecureRosterAttestation(ctx, tx, revocation.SecureRosterAttestation); err != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, err
	}
	result := sharedspaces.ParticipantDeviceRevocationResult{
		Acceptance: relay.AcceptanceAccepted, RetryID: revocation.RetryID,
		SpaceID: revocation.SpaceID, ParticipantID: revocation.ParticipantID,
		DeviceID: revocation.DeviceID, PreviousKeyEpoch: revocation.PreviousKeyEpoch,
		CurrentKeyEpoch: revocation.NextKeyEpoch, RevokedAtMilliseconds: revokedAtMilliseconds,
	}
	requestPayload, err := json.Marshal(revocation)
	if err != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, fmt.Errorf("encode Shared Space participant device revocation request: %w", err)
	}
	responsePayload, err := json.Marshal(result)
	if err != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, fmt.Errorf("encode Shared Space participant device revocation response: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO shared_space_participant_device_revocations (
			space_id,retry_id,participant_id,device_id,request_payload,response_payload,
			revoked_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, revocation.SpaceID, revocation.RetryID, revocation.ParticipantID,
		revocation.DeviceID, requestPayload, responsePayload, revokedAtMilliseconds); err != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, fmt.Errorf("record Shared Space participant device revocation: %w", err)
	}
	if err := insertSharedSpaceAuthorityEvent(ctx, tx, sharedspaces.AuthorityEvent{
		EventID: revocation.RetryID, SpaceID: revocation.SpaceID, DomainID: domainID,
		EventType:            sharedspaces.AuthorityEventParticipantDeviceRevoked,
		SubjectParticipantID: &revocation.ParticipantID, SubjectDeviceID: &revocation.DeviceID,
		PreviousKeyEpoch: &revocation.PreviousKeyEpoch, CurrentKeyEpoch: &revocation.NextKeyEpoch,
		SecureRosterDigest: newRosterDigest, OccurredAtMilliseconds: revokedAtMilliseconds,
	}); err != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sharedspaces.ParticipantDeviceRevocationResult{}, fmt.Errorf("commit Shared Space participant device revocation: %w", err)
	}
	return result, nil
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
	var existingRosterAttestationPayload []byte
	err = tx.QueryRow(ctx, `
		SELECT version,participant_id,previous_key_epoch,next_key_epoch,revoked_at_milliseconds,
		       secure_roster_attestation
		FROM shared_space_participant_revocations
		WHERE space_id=$1 AND retry_id=$2
		FOR UPDATE
	`, revocation.SpaceID, revocation.RetryID).Scan(
		&existingVersion, &existingParticipantID, &existingPreviousKeyEpoch,
		&existingNextKeyEpoch, &existingRevokedAt, &existingRosterAttestationPayload,
	)
	if err == nil {
		existingRosterAttestation, decodeErr := decodeSecureRosterAttestation(existingRosterAttestationPayload)
		if decodeErr != nil {
			return sharedspaces.ParticipantRevocationResult{}, fmt.Errorf("decode Shared Space participant revocation roster attestation: %w", decodeErr)
		}
		existingKeyGrants, err := loadSharedSpaceParticipantKeyGrants(
			ctx, tx, revocation.SpaceID, existingNextKeyEpoch,
		)
		if err != nil {
			return sharedspaces.ParticipantRevocationResult{}, err
		}
		existing := sharedspaces.ParticipantRevocation{
			Version: existingVersion, RetryID: revocation.RetryID,
			SpaceID: revocation.SpaceID, ParticipantID: existingParticipantID,
			PreviousKeyEpoch: existingPreviousKeyEpoch, NextKeyEpoch: existingNextKeyEpoch,
			KeyGrants:               existingKeyGrants,
			SecureRosterAttestation: existingRosterAttestation,
		}
		if !existing.Equivalent(revocation) {
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
	participants, err := loadSharedSpaceParticipants(ctx, tx, revocation.SpaceID)
	if err != nil {
		return sharedspaces.ParticipantRevocationResult{}, err
	}
	currentRosterAttestation, err := loadSharedSpaceSecureRosterAttestation(ctx, tx, revocation.SpaceID)
	if err != nil {
		return sharedspaces.ParticipantRevocationResult{}, err
	}
	if err := validateSharedSpaceRevocationRosterAttestation(
		provisioning.SecurityMode, currentRosterAttestation, participants, revocation,
	); err != nil {
		return sharedspaces.ParticipantRevocationResult{}, err
	}
	if err := revocation.ValidateKeyGrants(
		provisioning.SecurityMode, participants, nowMilliseconds,
	); err != nil {
		return sharedspaces.ParticipantRevocationResult{}, err
	}
	var managedWrappedKey []byte
	if provisioning.SecurityMode == sharedspaces.SecurityModeManaged {
		if s.managedContentKeys == nil {
			return sharedspaces.ParticipantRevocationResult{}, sharedspaces.NewProtocolError(
				sharedspaces.CodeInvalidSpace, "managed content-key custody is not configured",
			)
		}
		_, managedWrappedKey, err = s.managedContentKeys.Generate(
			revocation.SpaceID, revocation.NextKeyEpoch,
		)
		if err != nil {
			return sharedspaces.ParticipantRevocationResult{}, fmt.Errorf("rotate managed content key: %w", err)
		}
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
	for _, grant := range revocation.KeyGrants {
		if err := insertSharedSpaceParticipantKeyGrant(ctx, tx, grant); err != nil {
			return sharedspaces.ParticipantRevocationResult{}, err
		}
	}
	if managedWrappedKey != nil {
		if err := insertSharedSpaceManagedContentKey(
			ctx, tx, revocation.SpaceID, revocation.NextKeyEpoch,
			managedWrappedKey, nowMilliseconds,
		); err != nil {
			return sharedspaces.ParticipantRevocationResult{}, err
		}
	}
	newRosterAttestationPayload, err := encodeSecureRosterAttestation(revocation.SecureRosterAttestation)
	if err != nil {
		return sharedspaces.ParticipantRevocationResult{}, fmt.Errorf("encode Shared Space participant revocation roster attestation: %w", err)
	}
	newRosterAttestationDigest, err := secureRosterAttestationDigest(revocation.SecureRosterAttestation)
	if err != nil {
		return sharedspaces.ParticipantRevocationResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE shared_spaces
		SET current_key_epoch=$2,secure_roster_attestation=$3
		WHERE space_id=$1
	`, revocation.SpaceID, revocation.NextKeyEpoch, newRosterAttestationPayload); err != nil {
		return sharedspaces.ParticipantRevocationResult{}, fmt.Errorf("advance Shared Space key epoch: %w", err)
	}
	if err := insertSharedSpaceSecureRosterAttestation(ctx, tx, revocation.SecureRosterAttestation); err != nil {
		return sharedspaces.ParticipantRevocationResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO shared_space_participant_revocations (
			space_id,retry_id,participant_id,version,previous_key_epoch,next_key_epoch,
			revoked_at_milliseconds,secure_roster_attestation
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, revocation.SpaceID, revocation.RetryID, revocation.ParticipantID,
		revocation.Version, revocation.PreviousKeyEpoch, revocation.NextKeyEpoch,
		nowMilliseconds, newRosterAttestationPayload); err != nil {
		return sharedspaces.ParticipantRevocationResult{}, fmt.Errorf("record Shared Space participant revocation: %w", err)
	}
	if err := insertSharedSpaceAuthorityEvent(ctx, tx, sharedspaces.AuthorityEvent{
		EventID: revocation.RetryID, SpaceID: revocation.SpaceID,
		DomainID: domainID, EventType: sharedspaces.AuthorityEventParticipantRevoked,
		SubjectParticipantID:   &revocation.ParticipantID,
		PreviousKeyEpoch:       &revocation.PreviousKeyEpoch,
		CurrentKeyEpoch:        &revocation.NextKeyEpoch,
		SecureRosterDigest:     newRosterAttestationDigest,
		OccurredAtMilliseconds: nowMilliseconds,
	}); err != nil {
		return sharedspaces.ParticipantRevocationResult{}, err
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

func (s *SharedSpacesStore) GetParticipantKeyGrant(
	ctx context.Context,
	credential relay.Credential,
	recipientDeviceID uuid.UUID,
	nowMilliseconds int64,
) (sharedspaces.ParticipantKeyGrantResult, error) {
	if credential.TenantID == uuid.Nil || credential.DomainID == uuid.Nil || credential.MemberID == uuid.Nil || recipientDeviceID == uuid.Nil {
		return sharedspaces.ParticipantKeyGrantResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "participant key grant credential scope is invalid",
		)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return sharedspaces.ParticipantKeyGrantResult{}, fmt.Errorf("begin Shared Space participant key grant fetch: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var domainID uuid.UUID
	var securityMode sharedspaces.SecurityMode
	var currentKeyEpoch uint64
	if err := tx.QueryRow(ctx, `
		SELECT domain_id,security_mode,current_key_epoch
		FROM shared_spaces
		WHERE space_id=$1
	`, credential.TenantID).Scan(&domainID, &securityMode, &currentKeyEpoch); err == pgx.ErrNoRows {
		return sharedspaces.ParticipantKeyGrantResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeSpaceNotFound, "Shared Space was not found",
		)
	} else if err != nil {
		return sharedspaces.ParticipantKeyGrantResult{}, fmt.Errorf("load Shared Space participant key grant authority: %w", err)
	}
	if credential.DomainID != domainID {
		return sharedspaces.ParticipantKeyGrantResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "participant key grant belongs to another Shared Space",
		)
	}
	participant, err := loadSharedSpaceParticipant(
		ctx, tx, credential.TenantID, credential.MemberID, "",
	)
	if err != nil {
		return sharedspaces.ParticipantKeyGrantResult{}, err
	}
	if participant.RevokedAtMilliseconds != nil {
		return sharedspaces.ParticipantKeyGrantResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantRevoked, "participant is revoked",
		)
	}
	member, found, err := loadRelayMember(
		ctx, tx, credential.TenantID, domainID, credential.MemberID, "",
	)
	if err != nil {
		return sharedspaces.ParticipantKeyGrantResult{}, err
	}
	if !found {
		return sharedspaces.ParticipantKeyGrantResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantNotFound, "participant relay member was not found",
		)
	}
	if err := member.VerifyCredential(credential, nowMilliseconds); err != nil {
		return sharedspaces.ParticipantKeyGrantResult{}, err
	}
	if !securityMode.ContentBlind() {
		return sharedspaces.ParticipantKeyGrantResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeKeyGrantNotFound, "managed Shared Spaces do not have participant key grants",
		)
	}
	grants, err := loadSharedSpaceParticipantKeyGrants(
		ctx, tx, credential.TenantID, currentKeyEpoch,
	)
	if err != nil {
		return sharedspaces.ParticipantKeyGrantResult{}, err
	}
	for _, grant := range grants {
		if grant.ParticipantID != credential.MemberID || grant.RecipientDeviceID != recipientDeviceID {
			continue
		}
		if !participant.HasActiveDeviceKey(
			grant.RecipientDeviceID, grant.RecipientAgreementKeyFingerprint,
		) {
			continue
		}
		if err := tx.Commit(ctx); err != nil {
			return sharedspaces.ParticipantKeyGrantResult{}, fmt.Errorf("commit Shared Space participant key grant fetch: %w", err)
		}
		return sharedspaces.ParticipantKeyGrantResult{
			Version: sharedspaces.SchemaVersion, SpaceID: credential.TenantID,
			ParticipantID: credential.MemberID, CurrentKeyEpoch: currentKeyEpoch,
			KeyGrant: grant,
		}, nil
	}
	return sharedspaces.ParticipantKeyGrantResult{}, sharedspaces.NewProtocolError(
		sharedspaces.CodeKeyGrantNotFound, "current participant key grant was not found",
	)
}

func (s *SharedSpacesStore) GetParticipantStatus(
	ctx context.Context,
	credential relay.Credential,
	nowMilliseconds int64,
) (sharedspaces.ParticipantStatus, error) {
	bootstrap, err := s.getParticipantBootstrap(ctx, credential, uuid.Nil, nowMilliseconds, false)
	if err != nil {
		return sharedspaces.ParticipantStatus{}, err
	}
	return bootstrap.Status, nil
}

func (s *SharedSpacesStore) GetParticipantRoster(
	ctx context.Context,
	credential relay.Credential,
	nowMilliseconds int64,
) (sharedspaces.ParticipantRoster, error) {
	status, err := s.GetParticipantStatus(ctx, credential, nowMilliseconds)
	if err != nil {
		return sharedspaces.ParticipantRoster{}, err
	}
	if status.SecurityMode != sharedspaces.SecurityModeSecure {
		return sharedspaces.ParticipantRoster{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantRosterUnavailable,
			"participant roster is available only for Secure Shared Spaces",
		)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return sharedspaces.ParticipantRoster{}, fmt.Errorf("begin Shared Space participant roster: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var currentKeyEpoch uint64
	var rosterAttestationPayload []byte
	if err := tx.QueryRow(ctx, `
		SELECT current_key_epoch,secure_roster_attestation
		FROM shared_spaces
		WHERE space_id=$1
	`, status.SpaceID).Scan(&currentKeyEpoch, &rosterAttestationPayload); err == pgx.ErrNoRows {
		return sharedspaces.ParticipantRoster{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeSpaceNotFound, "Shared Space was not found",
		)
	} else if err != nil {
		return sharedspaces.ParticipantRoster{}, fmt.Errorf("load Shared Space participant roster authority: %w", err)
	}
	roster, err := loadCurrentSecureParticipantRoster(
		ctx, tx, status, currentKeyEpoch, rosterAttestationPayload,
	)
	if err != nil {
		return sharedspaces.ParticipantRoster{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sharedspaces.ParticipantRoster{}, fmt.Errorf("commit Shared Space participant roster: %w", err)
	}
	return roster, nil
}

// loadCurrentSecureParticipantRoster builds a verified roster using the
// caller's existing repeatable-read transaction. Keeping it in the bootstrap
// transaction prevents a key grant and its membership authority from being
// assembled from different key epochs or roster revisions.
func loadCurrentSecureParticipantRoster(
	ctx context.Context,
	tx pgx.Tx,
	status sharedspaces.ParticipantStatus,
	currentKeyEpoch uint64,
	rosterAttestationPayload []byte,
) (sharedspaces.ParticipantRoster, error) {
	rosterAttestation, err := decodeSecureRosterAttestation(rosterAttestationPayload)
	if err != nil {
		return sharedspaces.ParticipantRoster{}, fmt.Errorf("decode Shared Space participant roster attestation: %w", err)
	}
	if rosterAttestation == nil {
		return sharedspaces.ParticipantRoster{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidParticipant, "Secure Shared Space roster authority attestation is unavailable",
		)
	}
	participants, err := loadSharedSpaceParticipants(ctx, tx, status.SpaceID)
	if err != nil {
		return sharedspaces.ParticipantRoster{}, err
	}
	activeParticipants := make([]sharedspaces.Participant, 0, len(participants))
	for _, participant := range participants {
		if participant.RevokedAtMilliseconds == nil {
			activeParticipants = append(activeParticipants, participant)
		}
	}
	presentations, err := loadSharedSpaceParticipantPresentations(ctx, tx, status.SpaceID)
	if err != nil {
		return sharedspaces.ParticipantRoster{}, err
	}
	activeParticipantsByID := make(map[uuid.UUID]struct{}, len(activeParticipants))
	for _, participant := range activeParticipants {
		activeParticipantsByID[participant.ParticipantID] = struct{}{}
	}
	activePresentations := make([]sharedspaces.ParticipantPresentation, 0, len(presentations))
	for _, presentation := range presentations {
		if _, found := activeParticipantsByID[presentation.ParticipantID]; found {
			activePresentations = append(activePresentations, presentation)
		}
	}
	var authoritySequence int64
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(MAX(sequence), 0)
		FROM shared_space_authority_events
		WHERE space_id=$1
	`, status.SpaceID).Scan(&authoritySequence); err != nil {
		return sharedspaces.ParticipantRoster{}, fmt.Errorf("query Shared Space roster authority sequence: %w", err)
	}
	if authoritySequence < 1 {
		return sharedspaces.ParticipantRoster{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidAuthorityEvent,
			"Shared Space roster authority sequence is unavailable",
		)
	}
	roster := sharedspaces.ParticipantRoster{
		Version: sharedspaces.SchemaVersion, SpaceID: status.SpaceID,
		DomainID: status.DomainID, SecurityMode: status.SecurityMode,
		AuthoritySequence: uint64(authoritySequence),
		CurrentKeyEpoch:   currentKeyEpoch, AuthorityAttestation: *rosterAttestation,
		Participants: activeParticipants, Presentations: activePresentations,
		CreatedAtMilliseconds: status.CreatedAtMilliseconds,
	}
	if err := roster.Validate(); err != nil {
		return sharedspaces.ParticipantRoster{}, err
	}
	return roster, nil
}

// ListSecureRosterAttestations returns the signed membership-history segment a
// still-active Secure participant needs to bridge a saved roster revision to
// the current authority record. It intentionally remains unavailable for
// Private and Managed Spaces and for revoked participants, because historic
// rosters can identify people who are no longer current members.
func (s *SharedSpacesStore) ListSecureRosterAttestations(
	ctx context.Context,
	credential relay.Credential,
	afterRevision uint64,
	limit int,
	nowMilliseconds int64,
) (sharedspaces.SecureRosterAttestationPage, error) {
	if limit < 1 || limit > sharedspaces.MaximumSecureRosterAttestationPageSize {
		return sharedspaces.SecureRosterAttestationPage{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidParticipant,
			"Secure Shared Space roster authority page size is invalid",
		)
	}
	status, err := s.GetParticipantStatus(ctx, credential, nowMilliseconds)
	if err != nil {
		return sharedspaces.SecureRosterAttestationPage{}, err
	}
	if status.SecurityMode != sharedspaces.SecurityModeSecure {
		return sharedspaces.SecureRosterAttestationPage{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantRosterUnavailable,
			"roster authority is available only for Secure Shared Spaces",
		)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return sharedspaces.SecureRosterAttestationPage{}, fmt.Errorf("begin Shared Space roster authority page: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `
		SELECT attestation
		FROM shared_space_secure_roster_attestations
		WHERE space_id=$1 AND revision>$2
		ORDER BY revision
		LIMIT $3
	`, status.SpaceID, afterRevision, limit)
	if err != nil {
		return sharedspaces.SecureRosterAttestationPage{}, fmt.Errorf("query Shared Space roster authority page: %w", err)
	}
	defer rows.Close()
	page := sharedspaces.SecureRosterAttestationPage{
		Version: sharedspaces.SchemaVersion, SpaceID: status.SpaceID, DomainID: status.DomainID,
		Attestations: make([]sharedspaces.SecureRosterAttestation, 0, limit),
		NextRevision: afterRevision,
	}
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return sharedspaces.SecureRosterAttestationPage{}, fmt.Errorf("scan Shared Space roster authority page: %w", err)
		}
		attestation, err := decodeSecureRosterAttestation(payload)
		if err != nil {
			return sharedspaces.SecureRosterAttestationPage{}, fmt.Errorf("decode Shared Space roster authority page: %w", err)
		}
		if attestation == nil {
			return sharedspaces.SecureRosterAttestationPage{}, sharedspaces.NewProtocolError(
				sharedspaces.CodeInvalidParticipant,
				"Shared Space roster authority history contains an empty record",
			)
		}
		page.Attestations = append(page.Attestations, *attestation)
		page.NextRevision = attestation.Revision
	}
	if err := rows.Err(); err != nil {
		return sharedspaces.SecureRosterAttestationPage{}, fmt.Errorf("iterate Shared Space roster authority page: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return sharedspaces.SecureRosterAttestationPage{}, fmt.Errorf("commit Shared Space roster authority page: %w", err)
	}
	if err := page.Validate(); err != nil {
		return sharedspaces.SecureRosterAttestationPage{}, err
	}
	return page, nil
}

func (s *SharedSpacesStore) AuthorizeComputeCapability(
	ctx context.Context,
	credential relay.Credential,
	request sharedspaces.ComputeCapabilityRequest,
	nowMilliseconds int64,
) (sharedspaces.ComputeCapabilityAuthorization, error) {
	if err := request.Validate(); err != nil {
		return sharedspaces.ComputeCapabilityAuthorization{}, err
	}
	if credential.TenantID != request.SpaceID || credential.DomainID == uuid.Nil ||
		credential.MemberID == uuid.Nil {
		return sharedspaces.ComputeCapabilityAuthorization{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "compute capability credential scope is invalid",
		)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return sharedspaces.ComputeCapabilityAuthorization{}, fmt.Errorf(
			"begin Shared Space compute capability authorization: %w", err,
		)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var domainID uuid.UUID
	var currentKeyEpoch uint64
	if err := tx.QueryRow(ctx, `
		SELECT domain_id,current_key_epoch
		FROM shared_spaces
		WHERE space_id=$1
	`, request.SpaceID).Scan(&domainID, &currentKeyEpoch); err == pgx.ErrNoRows {
		return sharedspaces.ComputeCapabilityAuthorization{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeSpaceNotFound, "Shared Space was not found",
		)
	} else if err != nil {
		return sharedspaces.ComputeCapabilityAuthorization{}, fmt.Errorf(
			"load Shared Space compute capability authority: %w", err,
		)
	}
	if credential.DomainID != domainID {
		return sharedspaces.ComputeCapabilityAuthorization{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "compute capability belongs to another Shared Space",
		)
	}
	participant, err := loadSharedSpaceParticipant(
		ctx, tx, request.SpaceID, credential.MemberID, "",
	)
	if err != nil {
		return sharedspaces.ComputeCapabilityAuthorization{}, err
	}
	if participant.RevokedAtMilliseconds != nil {
		return sharedspaces.ComputeCapabilityAuthorization{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantRevoked, "participant is revoked",
		)
	}
	member, found, err := loadRelayMember(
		ctx, tx, request.SpaceID, domainID, credential.MemberID, "",
	)
	if err != nil {
		return sharedspaces.ComputeCapabilityAuthorization{}, err
	}
	if !found {
		return sharedspaces.ComputeCapabilityAuthorization{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantNotFound, "participant relay member was not found",
		)
	}
	if err := member.VerifyCredential(credential, nowMilliseconds); err != nil {
		return sharedspaces.ComputeCapabilityAuthorization{}, err
	}

	var poolPayload, bindingPayload []byte
	if err := tx.QueryRow(ctx, `
		SELECT pool_payload,binding_payload
		FROM shared_space_compute_pools
		WHERE space_id=$1 AND pool_id=$2
	`, request.SpaceID, request.PoolID).Scan(&poolPayload, &bindingPayload); err == pgx.ErrNoRows {
		return sharedspaces.ComputeCapabilityAuthorization{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeComputePoolNotFound, "compute pool was not found",
		)
	} else if err != nil {
		return sharedspaces.ComputeCapabilityAuthorization{}, fmt.Errorf(
			"load Shared Space compute capability policy: %w", err,
		)
	}
	var pool sharedspaces.ComputePool
	var binding sharedspaces.SpaceComputeBinding
	if err := json.Unmarshal(poolPayload, &pool); err != nil {
		return sharedspaces.ComputeCapabilityAuthorization{}, fmt.Errorf(
			"decode Shared Space compute pool: %w", err,
		)
	}
	if err := json.Unmarshal(bindingPayload, &binding); err != nil {
		return sharedspaces.ComputeCapabilityAuthorization{}, fmt.Errorf(
			"decode Shared Space compute binding: %w", err,
		)
	}
	authorization, err := sharedspaces.AuthorizeComputeCapability(
		request, participant.ParticipantID, currentKeyEpoch, pool, binding, nowMilliseconds,
	)
	if err != nil {
		return sharedspaces.ComputeCapabilityAuthorization{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sharedspaces.ComputeCapabilityAuthorization{}, fmt.Errorf(
			"commit Shared Space compute capability authorization: %w", err,
		)
	}
	return authorization, nil
}

func (s *SharedSpacesStore) UpdateParticipantPresentation(
	ctx context.Context,
	credential relay.Credential,
	update sharedspaces.ParticipantPresentationUpdate,
	nowMilliseconds int64,
) (sharedspaces.ParticipantPresentationUpdateResult, error) {
	if err := update.Validate(); err != nil {
		return sharedspaces.ParticipantPresentationUpdateResult{}, err
	}
	if credential.TenantID == uuid.Nil || credential.DomainID == uuid.Nil ||
		credential.MemberID == uuid.Nil || credential.TenantID != update.SpaceID ||
		credential.MemberID != update.ParticipantID {
		return sharedspaces.ParticipantPresentationUpdateResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "participant presentation belongs to another participant",
		)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return sharedspaces.ParticipantPresentationUpdateResult{}, fmt.Errorf(
			"begin Shared Space participant presentation update: %w", err,
		)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var domainID uuid.UUID
	var interactionMode sharedspaces.InteractionMode
	if err := tx.QueryRow(ctx, `
		SELECT domain_id,interaction_mode
		FROM shared_spaces
		WHERE space_id=$1
		FOR SHARE
	`, update.SpaceID).Scan(&domainID, &interactionMode); err == pgx.ErrNoRows {
		return sharedspaces.ParticipantPresentationUpdateResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeSpaceNotFound, "Shared Space was not found",
		)
	} else if err != nil {
		return sharedspaces.ParticipantPresentationUpdateResult{}, fmt.Errorf(
			"load Shared Space participant presentation authority: %w", err,
		)
	}
	if credential.DomainID != domainID {
		return sharedspaces.ParticipantPresentationUpdateResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "participant presentation belongs to another Shared Space",
		)
	}
	participant, err := loadSharedSpaceParticipant(
		ctx, tx, update.SpaceID, update.ParticipantID, "FOR UPDATE",
	)
	if err != nil {
		return sharedspaces.ParticipantPresentationUpdateResult{}, err
	}
	if participant.RevokedAtMilliseconds != nil {
		return sharedspaces.ParticipantPresentationUpdateResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantRevoked, "participant is revoked",
		)
	}
	member, found, err := loadRelayMember(
		ctx, tx, update.SpaceID, domainID, update.ParticipantID, "",
	)
	if err != nil {
		return sharedspaces.ParticipantPresentationUpdateResult{}, err
	}
	if !found {
		return sharedspaces.ParticipantPresentationUpdateResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantNotFound, "participant relay member was not found",
		)
	}
	if err := member.VerifyCredential(credential, nowMilliseconds); err != nil {
		return sharedspaces.ParticipantPresentationUpdateResult{}, err
	}
	if !reflect.DeepEqual(member.Capabilities, participant.Role.Capabilities(interactionMode)) {
		return sharedspaces.ParticipantPresentationUpdateResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidParticipant,
			"participant relay capabilities do not match Shared Space authority",
		)
	}

	var existingPayload []byte
	var existingPresentation sharedspaces.ParticipantPresentation
	err = tx.QueryRow(ctx, `
		SELECT request_payload,version,space_id,participant_id,display_name,revision,
		       updated_at_milliseconds
		FROM shared_space_participant_presentations
		WHERE retry_id=$1
	`, update.RetryID).Scan(
		&existingPayload, &existingPresentation.Version, &existingPresentation.SpaceID,
		&existingPresentation.ParticipantID, &existingPresentation.DisplayName,
		&existingPresentation.Revision, &existingPresentation.UpdatedAtMilliseconds,
	)
	if err == nil {
		var existingUpdate sharedspaces.ParticipantPresentationUpdate
		if decodeErr := json.Unmarshal(existingPayload, &existingUpdate); decodeErr != nil {
			return sharedspaces.ParticipantPresentationUpdateResult{}, fmt.Errorf(
				"decode Shared Space participant presentation update: %w", decodeErr,
			)
		}
		if !reflect.DeepEqual(existingUpdate, update) {
			return sharedspaces.ParticipantPresentationUpdateResult{}, sharedspaces.NewProtocolError(
				sharedspaces.CodeParticipantPresentationCollision,
				"participant presentation retry ID was reused",
			)
		}
		return sharedspaces.ParticipantPresentationUpdateResult{
			Acceptance: relay.AcceptanceDuplicate, RetryID: update.RetryID,
			Presentation: existingPresentation,
		}, nil
	}
	if err != pgx.ErrNoRows {
		return sharedspaces.ParticipantPresentationUpdateResult{}, fmt.Errorf(
			"load Shared Space participant presentation retry: %w", err,
		)
	}
	if update.UpdatedAtMilliseconds > nowMilliseconds ||
		update.UpdatedAtMilliseconds < participant.CreatedAtMilliseconds {
		return sharedspaces.ParticipantPresentationUpdateResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidParticipantPresentation,
			"participant presentation update time is invalid",
		)
	}
	currentRevision := uint64(0)
	current, err := loadSharedSpaceParticipantPresentation(
		ctx, tx, update.SpaceID, update.ParticipantID,
	)
	if err != nil {
		return sharedspaces.ParticipantPresentationUpdateResult{}, err
	}
	if current != nil {
		currentRevision = current.Revision
	}
	if update.PreviousRevision != currentRevision {
		return sharedspaces.ParticipantPresentationUpdateResult{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantPresentationCollision,
			"participant presentation changed concurrently",
		)
	}
	presentation := sharedspaces.ParticipantPresentation{
		Version: sharedspaces.SchemaVersion, SpaceID: update.SpaceID,
		ParticipantID: update.ParticipantID, DisplayName: update.DisplayName,
		Revision: currentRevision + 1, UpdatedAtMilliseconds: update.UpdatedAtMilliseconds,
	}
	payload, err := json.Marshal(update)
	if err != nil {
		return sharedspaces.ParticipantPresentationUpdateResult{}, fmt.Errorf(
			"encode Shared Space participant presentation update: %w", err,
		)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO shared_space_participant_presentations (
			space_id,participant_id,revision,retry_id,version,request_payload,
			display_name,updated_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, presentation.SpaceID, presentation.ParticipantID, presentation.Revision,
		update.RetryID, presentation.Version, payload, presentation.DisplayName,
		presentation.UpdatedAtMilliseconds); err != nil {
		return sharedspaces.ParticipantPresentationUpdateResult{}, fmt.Errorf(
			"record Shared Space participant presentation update: %w", err,
		)
	}
	if err := tx.Commit(ctx); err != nil {
		return sharedspaces.ParticipantPresentationUpdateResult{}, fmt.Errorf(
			"commit Shared Space participant presentation update: %w", err,
		)
	}
	return sharedspaces.ParticipantPresentationUpdateResult{
		Acceptance: relay.AcceptanceAccepted, RetryID: update.RetryID,
		Presentation: presentation,
	}, nil
}

func (s *SharedSpacesStore) GetParticipantBootstrap(
	ctx context.Context,
	credential relay.Credential,
	recipientDeviceID uuid.UUID,
	nowMilliseconds int64,
) (sharedspaces.ParticipantBootstrap, error) {
	return s.getParticipantBootstrap(ctx, credential, recipientDeviceID, nowMilliseconds, true)
}

func (s *SharedSpacesStore) getParticipantBootstrap(
	ctx context.Context,
	credential relay.Credential,
	recipientDeviceID uuid.UUID,
	nowMilliseconds int64,
	includeKeyGrant bool,
) (sharedspaces.ParticipantBootstrap, error) {
	if credential.TenantID == uuid.Nil || credential.DomainID == uuid.Nil || credential.MemberID == uuid.Nil {
		return sharedspaces.ParticipantBootstrap{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "participant bootstrap credential scope is invalid",
		)
	}
	if includeKeyGrant && recipientDeviceID == uuid.Nil {
		return sharedspaces.ParticipantBootstrap{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "participant bootstrap recipient device is invalid",
		)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return sharedspaces.ParticipantBootstrap{}, fmt.Errorf("begin Shared Space participant bootstrap fetch: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var domainID uuid.UUID
	var securityMode sharedspaces.SecurityMode
	var interactionMode sharedspaces.InteractionMode
	var currentKeyEpoch uint64
	var provisioningPayload []byte
	var rosterAttestationPayload []byte
	if err := tx.QueryRow(ctx, `
		SELECT domain_id,security_mode,interaction_mode,current_key_epoch,provisioning_payload,secure_roster_attestation
		FROM shared_spaces
		WHERE space_id=$1
	`, credential.TenantID).Scan(
		&domainID, &securityMode, &interactionMode, &currentKeyEpoch, &provisioningPayload, &rosterAttestationPayload,
	); err == pgx.ErrNoRows {
		return sharedspaces.ParticipantBootstrap{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeSpaceNotFound, "Shared Space was not found",
		)
	} else if err != nil {
		return sharedspaces.ParticipantBootstrap{}, fmt.Errorf("load Shared Space participant bootstrap authority: %w", err)
	}
	if credential.DomainID != domainID {
		return sharedspaces.ParticipantBootstrap{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeWrongScope, "participant bootstrap belongs to another Shared Space",
		)
	}
	provisioning, err := decodeSpaceProvisioning(provisioningPayload)
	if err != nil {
		return sharedspaces.ParticipantBootstrap{}, fmt.Errorf("decode Shared Space participant bootstrap authority: %w", err)
	}
	participant, err := loadSharedSpaceParticipant(
		ctx, tx, credential.TenantID, credential.MemberID, "",
	)
	if err != nil {
		return sharedspaces.ParticipantBootstrap{}, err
	}
	if participant.RevokedAtMilliseconds != nil {
		return sharedspaces.ParticipantBootstrap{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantRevoked, "participant is revoked",
		)
	}
	member, found, err := loadRelayMember(
		ctx, tx, credential.TenantID, domainID, credential.MemberID, "",
	)
	if err != nil {
		return sharedspaces.ParticipantBootstrap{}, err
	}
	if !found {
		return sharedspaces.ParticipantBootstrap{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantNotFound, "participant relay member was not found",
		)
	}
	if err := member.VerifyCredential(credential, nowMilliseconds); err != nil {
		return sharedspaces.ParticipantBootstrap{}, err
	}
	expectedCapabilities := participant.Role.Capabilities(interactionMode)
	if !reflect.DeepEqual(member.Capabilities, expectedCapabilities) {
		return sharedspaces.ParticipantBootstrap{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeInvalidParticipant, "participant relay capabilities do not match Shared Space authority",
		)
	}
	var activeCheckpointEpochValue *int64
	if err := tx.QueryRow(ctx, `
		SELECT key_epoch FROM relay_checkpoints
		WHERE tenant_id=$1 AND domain_id=$2 AND state='activated'
		ORDER BY activation_ordinal DESC LIMIT 1
	`, credential.TenantID, domainID).Scan(&activeCheckpointEpochValue); err != nil && err != pgx.ErrNoRows {
		return sharedspaces.ParticipantBootstrap{}, fmt.Errorf("load Shared Space participant bootstrap epoch: %w", err)
	}
	var activeCheckpointEpoch *uint64
	if activeCheckpointEpochValue != nil {
		epoch := uint64(*activeCheckpointEpochValue)
		activeCheckpointEpoch = &epoch
	}
	status := sharedspaces.ParticipantStatus{
		Version: sharedspaces.SchemaVersion, SpaceID: credential.TenantID, DomainID: domainID,
		SecurityMode: securityMode, InteractionMode: interactionMode, CurrentKeyEpoch: currentKeyEpoch,
		BootstrapReady:        activeCheckpointEpoch != nil && *activeCheckpointEpoch == currentKeyEpoch,
		ActiveCheckpointEpoch: activeCheckpointEpoch,
		Participant:           participant,
		Capabilities:          member.Capabilities,
		CreatedAtMilliseconds: provisioning.CreatedAtMilliseconds,
	}
	presentation, err := loadSharedSpaceParticipantPresentation(
		ctx, tx, credential.TenantID, credential.MemberID,
	)
	if err != nil {
		return sharedspaces.ParticipantBootstrap{}, err
	}
	status.Presentation = presentation
	if err := status.Validate(); err != nil {
		return sharedspaces.ParticipantBootstrap{}, err
	}
	result := sharedspaces.ParticipantBootstrap{Version: sharedspaces.SchemaVersion, Status: status}
	if includeKeyGrant && securityMode.ContentBlind() {
		grants, err := loadSharedSpaceParticipantKeyGrants(
			ctx, tx, credential.TenantID, currentKeyEpoch,
		)
		if err != nil {
			return sharedspaces.ParticipantBootstrap{}, err
		}
		for _, grant := range grants {
			if grant.ParticipantID == credential.MemberID && grant.RecipientDeviceID == recipientDeviceID {
				if !participant.HasActiveDeviceKey(
					grant.RecipientDeviceID, grant.RecipientAgreementKeyFingerprint,
				) {
					continue
				}
				result.KeyGrant = &sharedspaces.ParticipantKeyGrantResult{
					Version: sharedspaces.SchemaVersion, SpaceID: credential.TenantID,
					ParticipantID: credential.MemberID, CurrentKeyEpoch: currentKeyEpoch,
					KeyGrant: grant,
				}
				break
			}
		}
		if result.KeyGrant == nil {
			return sharedspaces.ParticipantBootstrap{}, sharedspaces.NewProtocolError(
				sharedspaces.CodeKeyGrantNotFound, "current participant key grant was not found",
			)
		}
	} else if includeKeyGrant && securityMode == sharedspaces.SecurityModeManaged {
		wrapped, err := loadSharedSpaceManagedContentKey(
			ctx, tx, credential.TenantID, currentKeyEpoch,
		)
		if err != nil {
			return sharedspaces.ParticipantBootstrap{}, err
		}
		if s.managedContentKeys == nil {
			return sharedspaces.ParticipantBootstrap{}, sharedspaces.NewProtocolError(
				sharedspaces.CodeKeyGrantNotFound, "managed content-key custody is not configured",
			)
		}
		plaintext, err := s.managedContentKeys.Unwrap(
			credential.TenantID, currentKeyEpoch, wrapped,
		)
		if err != nil {
			return sharedspaces.ParticipantBootstrap{}, fmt.Errorf("unwrap managed content key: %w", err)
		}
		result.ManagedContentKey = &sharedspaces.ManagedContentKey{
			Version: sharedspaces.SchemaVersion, SpaceID: credential.TenantID,
			ParticipantID: credential.MemberID, KeyEpoch: currentKeyEpoch,
			Algorithm:   sharedspaces.ManagedContentKeyAlgorithm,
			KeyMaterial: base64.RawURLEncoding.EncodeToString(plaintext),
		}
	}
	// A status-only read deliberately avoids materializing the complete Secure
	// roster. The atomic bootstrap endpoint requests the grant and roster from
	// this same transaction; status callers need only their own authority.
	if includeKeyGrant && securityMode == sharedspaces.SecurityModeSecure {
		roster, err := loadCurrentSecureParticipantRoster(
			ctx, tx, status, currentKeyEpoch, rosterAttestationPayload,
		)
		if err != nil {
			return sharedspaces.ParticipantBootstrap{}, err
		}
		result.Roster = &roster
	}
	if includeKeyGrant {
		if err := result.Validate(); err != nil {
			return sharedspaces.ParticipantBootstrap{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return sharedspaces.ParticipantBootstrap{}, fmt.Errorf("commit Shared Space participant bootstrap fetch: %w", err)
	}
	return result, nil
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

func loadSharedSpaceSecureRosterAttestation(
	ctx context.Context,
	tx pgx.Tx,
	spaceID uuid.UUID,
) (*sharedspaces.SecureRosterAttestation, error) {
	var payload []byte
	if err := tx.QueryRow(ctx, `
		SELECT secure_roster_attestation FROM shared_spaces WHERE space_id=$1
	`, spaceID).Scan(&payload); err == pgx.ErrNoRows {
		return nil, sharedspaces.NewProtocolError(
			sharedspaces.CodeSpaceNotFound, "Shared Space was not found",
		)
	} else if err != nil {
		return nil, fmt.Errorf("load Shared Space roster attestation: %w", err)
	}
	attestation, err := decodeSecureRosterAttestation(payload)
	if err != nil {
		return nil, fmt.Errorf("decode Shared Space roster attestation: %w", err)
	}
	return attestation, nil
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
		       signing_key_algorithm,signing_public_key_x963,signing_key_fingerprint,
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
		&participant.SigningKey.Algorithm, &participant.SigningKey.PublicKeyX963,
		&participant.SigningKey.SigningKeyFingerprint,
		&participant.CreatedAtMilliseconds, &participant.RevokedAtMilliseconds,
	); err == pgx.ErrNoRows {
		return sharedspaces.Participant{}, sharedspaces.NewProtocolError(
			sharedspaces.CodeParticipantNotFound, "participant was not found",
		)
	} else if err != nil {
		return sharedspaces.Participant{}, fmt.Errorf("load Shared Space participant: %w", err)
	}
	deviceKeys, err := loadSharedSpaceParticipantDeviceKeys(ctx, tx, participant)
	if err != nil {
		return sharedspaces.Participant{}, err
	}
	participant.DeviceKeys = deviceKeys
	return participant, nil
}

func loadSharedSpaceParticipants(
	ctx context.Context,
	tx pgx.Tx,
	spaceID uuid.UUID,
) ([]sharedspaces.Participant, error) {
	rows, err := tx.Query(ctx, `
		SELECT version,space_id,participant_id,subscription_id,kind,role,
		       signing_key_algorithm,signing_public_key_x963,signing_key_fingerprint,
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
			&participant.SigningKey.Algorithm, &participant.SigningKey.PublicKeyX963,
			&participant.SigningKey.SigningKeyFingerprint,
			&participant.CreatedAtMilliseconds, &participant.RevokedAtMilliseconds,
		); err != nil {
			return nil, fmt.Errorf("scan Shared Space participant: %w", err)
		}
		participants = append(participants, participant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Shared Space participants: %w", err)
	}
	for index := range participants {
		deviceKeys, err := loadSharedSpaceParticipantDeviceKeys(ctx, tx, participants[index])
		if err != nil {
			return nil, err
		}
		participants[index].DeviceKeys = deviceKeys
	}
	sort.Slice(participants, func(left, right int) bool {
		return participants[left].ParticipantID.String() < participants[right].ParticipantID.String()
	})
	return participants, nil
}

func loadSharedSpaceParticipantDeviceKeys(
	ctx context.Context,
	tx pgx.Tx,
	participant sharedspaces.Participant,
) ([]sharedspaces.ParticipantDeviceKey, error) {
	rows, err := tx.Query(ctx, `
		SELECT version,space_id,participant_id,device_id,algorithm,
		       agreement_public_key_x963,agreement_key_fingerprint,
		       created_at_milliseconds,revoked_at_milliseconds,
		       signature_algorithm,signature_public_signing_key_x963,
		       signature_signing_key_fingerprint,signature
		FROM shared_space_participant_device_keys
		WHERE space_id=$1 AND participant_id=$2
		ORDER BY device_id
	`, participant.SpaceID, participant.ParticipantID)
	if err != nil {
		return nil, fmt.Errorf("query Shared Space participant device keys: %w", err)
	}
	defer rows.Close()
	deviceKeys := []sharedspaces.ParticipantDeviceKey{}
	for rows.Next() {
		var deviceKey sharedspaces.ParticipantDeviceKey
		if err := rows.Scan(
			&deviceKey.Version, &deviceKey.SpaceID, &deviceKey.ParticipantID,
			&deviceKey.DeviceID, &deviceKey.Algorithm,
			&deviceKey.AgreementPublicKeyX963, &deviceKey.AgreementKeyFingerprint,
			&deviceKey.CreatedAtMilliseconds, &deviceKey.RevokedAtMilliseconds,
			&deviceKey.Signature.Algorithm, &deviceKey.Signature.PublicSigningKeyX963,
			&deviceKey.Signature.SigningKeyFingerprint, &deviceKey.Signature.Signature,
		); err != nil {
			return nil, fmt.Errorf("scan Shared Space participant device key: %w", err)
		}
		if err := deviceKey.Validate(participant); err != nil {
			return nil, fmt.Errorf("stored Shared Space participant device key failed validation: %w", err)
		}
		deviceKeys = append(deviceKeys, deviceKey)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Shared Space participant device keys: %w", err)
	}
	return deviceKeys, nil
}

func loadSharedSpaceParticipantPresentation(
	ctx context.Context,
	tx pgx.Tx,
	spaceID, participantID uuid.UUID,
) (*sharedspaces.ParticipantPresentation, error) {
	var presentation sharedspaces.ParticipantPresentation
	if err := tx.QueryRow(ctx, `
		SELECT version,space_id,participant_id,display_name,revision,updated_at_milliseconds
		FROM shared_space_participant_presentations
		WHERE space_id=$1 AND participant_id=$2
		ORDER BY revision DESC
		LIMIT 1
	`, spaceID, participantID).Scan(
		&presentation.Version, &presentation.SpaceID, &presentation.ParticipantID,
		&presentation.DisplayName, &presentation.Revision,
		&presentation.UpdatedAtMilliseconds,
	); err == pgx.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("load Shared Space participant presentation: %w", err)
	}
	if err := presentation.Validate(); err != nil {
		return nil, fmt.Errorf("stored Shared Space participant presentation failed validation: %v", err)
	}
	return &presentation, nil
}

func loadSharedSpaceParticipantPresentations(
	ctx context.Context,
	tx pgx.Tx,
	spaceID uuid.UUID,
) ([]sharedspaces.ParticipantPresentation, error) {
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT ON (participant_id)
		       version,space_id,participant_id,display_name,revision,updated_at_milliseconds
		FROM shared_space_participant_presentations
		WHERE space_id=$1
		ORDER BY participant_id,revision DESC
	`, spaceID)
	if err != nil {
		return nil, fmt.Errorf("query Shared Space participant presentations: %w", err)
	}
	defer rows.Close()
	presentations := []sharedspaces.ParticipantPresentation{}
	for rows.Next() {
		var presentation sharedspaces.ParticipantPresentation
		if err := rows.Scan(
			&presentation.Version, &presentation.SpaceID, &presentation.ParticipantID,
			&presentation.DisplayName, &presentation.Revision,
			&presentation.UpdatedAtMilliseconds,
		); err != nil {
			return nil, fmt.Errorf("scan Shared Space participant presentation: %w", err)
		}
		if err := presentation.Validate(); err != nil {
			return nil, fmt.Errorf("stored Shared Space participant presentation failed validation: %v", err)
		}
		presentations = append(presentations, presentation)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Shared Space participant presentations: %w", err)
	}
	return presentations, nil
}

func loadSharedSpaceComputePools(
	ctx context.Context,
	querier relayQuerier,
	spaceID uuid.UUID,
) ([]sharedspaces.ComputePool, []sharedspaces.SpaceComputeBinding, error) {
	rows, err := querier.Query(ctx, `
		SELECT pool_payload,binding_payload
		FROM shared_space_compute_pools
		WHERE space_id=$1
		ORDER BY pool_id
	`, spaceID)
	if err != nil {
		return nil, nil, fmt.Errorf("query Shared Space compute pools: %w", err)
	}
	defer rows.Close()
	pools := []sharedspaces.ComputePool{}
	bindings := []sharedspaces.SpaceComputeBinding{}
	for rows.Next() {
		var poolPayload, bindingPayload []byte
		if err := rows.Scan(&poolPayload, &bindingPayload); err != nil {
			return nil, nil, fmt.Errorf("scan Shared Space compute pool: %w", err)
		}
		var pool sharedspaces.ComputePool
		if err := json.Unmarshal(poolPayload, &pool); err != nil {
			return nil, nil, fmt.Errorf("decode Shared Space compute pool: %w", err)
		}
		var binding sharedspaces.SpaceComputeBinding
		if err := json.Unmarshal(bindingPayload, &binding); err != nil {
			return nil, nil, fmt.Errorf("decode Shared Space compute binding: %w", err)
		}
		if err := pool.Validate(); err != nil {
			return nil, nil, fmt.Errorf("stored Shared Space compute pool failed validation: %v", err)
		}
		if err := binding.Validate(); err != nil {
			return nil, nil, fmt.Errorf("stored Shared Space compute binding failed validation: %v", err)
		}
		if pool.SpaceID != spaceID || binding.SpaceID != spaceID ||
			pool.PoolID != binding.PoolID || pool.Revision != binding.Revision {
			return nil, nil, fmt.Errorf("stored Shared Space compute pool scope is inconsistent")
		}
		pools = append(pools, pool)
		bindings = append(bindings, binding)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate Shared Space compute pools: %w", err)
	}
	return pools, bindings, nil
}

func insertSharedSpaceParticipantKeyGrant(
	ctx context.Context,
	tx pgx.Tx,
	grant sharedspaces.ParticipantKeyGrant,
) error {
	payload, err := json.Marshal(grant)
	if err != nil {
		return fmt.Errorf("encode Shared Space participant key grant: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO shared_space_participant_key_grants (
			space_id,key_epoch,participant_id,issuer_participant_id,
			version,grant_payload,created_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, grant.SpaceID, grant.KeyEpoch, grant.ParticipantID,
		grant.IssuerParticipantID, grant.Version, payload,
		grant.CreatedAtMilliseconds); err != nil {
		return fmt.Errorf("insert Shared Space participant key grant: %w", err)
	}
	return nil
}

func insertSharedSpaceManagedContentKey(
	ctx context.Context,
	tx pgx.Tx,
	spaceID uuid.UUID,
	keyEpoch uint64,
	wrappedKey []byte,
	createdAtMilliseconds int64,
) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO shared_space_managed_content_keys (
			space_id,key_epoch,algorithm,wrapped_key,created_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5)
	`, spaceID, keyEpoch, sharedspaces.ManagedContentKeyAlgorithm,
		wrappedKey, createdAtMilliseconds); err != nil {
		return fmt.Errorf("insert Shared Space managed content key: %w", err)
	}
	return nil
}

func loadSharedSpaceManagedContentKey(
	ctx context.Context,
	tx pgx.Tx,
	spaceID uuid.UUID,
	keyEpoch uint64,
) ([]byte, error) {
	var wrapped []byte
	if err := tx.QueryRow(ctx, `
		SELECT wrapped_key
		FROM shared_space_managed_content_keys
		WHERE space_id=$1 AND key_epoch=$2
	`, spaceID, keyEpoch).Scan(&wrapped); err == pgx.ErrNoRows {
		return nil, sharedspaces.NewProtocolError(
			sharedspaces.CodeKeyGrantNotFound, "current managed content key was not found",
		)
	} else if err != nil {
		return nil, fmt.Errorf("load Shared Space managed content key: %w", err)
	}
	return wrapped, nil
}

func insertSharedSpaceAuthorityEvent(
	ctx context.Context,
	tx pgx.Tx,
	event sharedspaces.AuthorityEvent,
) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO shared_space_authority_events (
			space_id,domain_id,event_id,version,event_type,subject_participant_id,
			subject_device_id,invitation_id,previous_role,resulting_role,previous_key_epoch,current_key_epoch,
			compute_pool_id,previous_binding_revision,current_binding_revision,
			secure_roster_digest,
			occurred_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
	`, event.SpaceID, event.DomainID, event.EventID, sharedspaces.SchemaVersion,
		string(event.EventType), event.SubjectParticipantID, event.SubjectDeviceID, event.InvitationID,
		nullableSharedSpaceRole(event.PreviousRole), nullableSharedSpaceRole(event.CurrentRole),
		nullableSharedSpaceKeyEpoch(event.PreviousKeyEpoch),
		nullableSharedSpaceKeyEpoch(event.CurrentKeyEpoch), event.ComputePoolID,
		nullableSharedSpaceRevision(event.PreviousBindingRevision),
		nullableSharedSpaceRevision(event.CurrentBindingRevision),
		event.SecureRosterDigest, event.OccurredAtMilliseconds); err != nil {
		return fmt.Errorf("insert Shared Space authority event: %w", err)
	}
	return nil
}

func nullableSharedSpaceRole(role *sharedspaces.Role) any {
	if role == nil {
		return nil
	}
	return string(*role)
}

func nullableSharedSpaceKeyEpoch(epoch *uint64) any {
	if epoch == nil {
		return nil
	}
	return int64(*epoch)
}

func nullableSharedSpaceRevision(revision *uint64) any {
	if revision == nil {
		return nil
	}
	return int64(*revision)
}

func rolePointer(role sharedspaces.Role) *sharedspaces.Role { return &role }

func uint64Pointer(value uint64) *uint64 { return &value }

func loadSharedSpaceParticipantKeyGrants(
	ctx context.Context,
	querier relayQuerier,
	spaceID uuid.UUID,
	keyEpoch uint64,
) ([]sharedspaces.ParticipantKeyGrant, error) {
	rows, err := querier.Query(ctx, `
		SELECT grant_payload
		FROM shared_space_participant_key_grants
		WHERE space_id=$1 AND key_epoch=$2
		ORDER BY participant_id,(grant_payload->>'recipientDeviceID')
	`, spaceID, keyEpoch)
	if err != nil {
		return nil, fmt.Errorf("query Shared Space participant key grants: %w", err)
	}
	defer rows.Close()
	grants := []sharedspaces.ParticipantKeyGrant{}
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan Shared Space participant key grant: %w", err)
		}
		var grant sharedspaces.ParticipantKeyGrant
		if err := json.Unmarshal(payload, &grant); err != nil {
			return nil, fmt.Errorf("decode Shared Space participant key grant: %w", err)
		}
		if err := grant.Validate(); err != nil {
			return nil, fmt.Errorf("stored Shared Space participant key grant failed validation: %v", err)
		}
		if grant.SpaceID != spaceID || grant.KeyEpoch != keyEpoch {
			return nil, fmt.Errorf("stored Shared Space participant key grant scope differs")
		}
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Shared Space participant key grants: %w", err)
	}
	return grants, nil
}

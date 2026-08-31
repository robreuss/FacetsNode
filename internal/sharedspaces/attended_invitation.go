package sharedspaces

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"reflect"
	"sort"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const (
	MaximumAttendedInvitationComponentRecordByteCount = 1_500_000
	MaximumAttendedInvitationServiceSnapshotByteCount = 400_000
	MaximumAttendedInvitationPayloadByteCount         = 3_000_000
	MaximumAttendedInvitationRecordByteCount          = 4_500_000

	acceptedInvitationReferenceDomain     = "Facets Shared Space accepted invitation reference v1\x00"
	participantKeyGrantReferenceDomain    = "Facets Shared Space participant key grant reference v1\x00"
	attendedInvitationSignatureDomain     = "Facets Shared Space attended invitation checkpoint v1\x00"
	attendedInvitationReferenceDomain     = "Facets Shared Space attended invitation checkpoint reference v1\x00"
	serviceAuthorityAnchorReferenceDomain = "Facets service authority trust anchor reference v1\x00"
)

var ErrInvalidAttendedInvitation = errors.New("invalid attended Shared Space invitation checkpoint")

// AttendedInvitationSignature proves possession of one activation-roster
// participant key. It does not, by itself, prove that the roster chain is
// trusted or create recipient, key-use, claim, Node, or Sentry authority.
type AttendedInvitationSignature struct {
	Algorithm             string    `json:"algorithm"`
	PublicSigningKeyX963  string    `json:"publicSigningKeyX963"`
	Signature             string    `json:"signature"`
	SignerParticipantID   uuid.UUID `json:"signerParticipantID"`
	SigningKeyFingerprint string    `json:"signingKeyFingerprint"`
}

// AttendedInvitationPayload binds the exact accepted invitation and exact
// historical service-authority snapshot to explicit routing and participant
// facts. AcceptedInvitationRecord never contains the relay bearer.
type AttendedInvitationPayload struct {
	AcceptedInvitationRecord                []byte                        `json:"acceptedInvitationRecord"`
	AcceptedInvitationReferenceDigest       string                        `json:"acceptedInvitationReferenceDigest"`
	ActivationRosterCurrentKeyEpoch         uint64                        `json:"activationRosterCurrentKeyEpoch"`
	ActivationRosterDigest                  string                        `json:"activationRosterDigest"`
	ActivationRosterPreviousDigest          string                        `json:"activationRosterPreviousDigest"`
	ActivationRosterRevision                uint64                        `json:"activationRosterRevision"`
	CreatedAtMilliseconds                   int64                         `json:"createdAtMilliseconds"`
	DomainID                                uuid.UUID                     `json:"domainID"`
	ExpiresAtMilliseconds                   int64                         `json:"expiresAtMilliseconds"`
	InteractionMode                         InteractionMode               `json:"interactionMode"`
	InvitationID                            uuid.UUID                     `json:"invitationID"`
	KeyGrantReferenceDigest                 string                        `json:"keyGrantReferenceDigest"`
	MemberExpiresAtMilliseconds             *int64                        `json:"memberExpiresAtMilliseconds,omitempty"`
	ParticipantID                           uuid.UUID                     `json:"participantID"`
	ParticipantKind                         ParticipantKind               `json:"participantKind"`
	ParticipantRole                         Role                          `json:"participantRole"`
	ParticipantSigningKeyFingerprint        string                        `json:"participantSigningKeyFingerprint"`
	RecipientAgreementKeyFingerprint        string                        `json:"recipientAgreementKeyFingerprint"`
	RecipientDeviceID                       uuid.UUID                     `json:"recipientDeviceID"`
	RelayAdmissionAuthorizationDigest       string                        `json:"relayAdmissionAuthorizationDigest"`
	RelayCapabilities                       []relay.Capability            `json:"relayCapabilities"`
	RetryID                                 uuid.UUID                     `json:"retryID"`
	SecurityMode                            SecurityMode                  `json:"securityMode"`
	ServiceActiveDeploymentID               uuid.UUID                     `json:"serviceActiveDeploymentID"`
	ServiceAuthorityAnchorReferenceDigest   string                        `json:"serviceAuthorityAnchorReferenceDigest"`
	ServiceAuthorityManifestReferenceDigest string                        `json:"serviceAuthorityManifestReferenceDigest"`
	ServiceAuthorityManifestRevision        uint64                        `json:"serviceAuthorityManifestRevision"`
	ServiceAuthoritySnapshotRecord          []byte                        `json:"serviceAuthoritySnapshotRecord"`
	ServiceControlRouteID                   uuid.UUID                     `json:"serviceControlRouteID"`
	ServiceTrafficClass                     serviceauthority.TrafficClass `json:"serviceTrafficClass"`
	SpaceID                                 uuid.UUID                     `json:"spaceID"`
	SubscriptionID                          uuid.UUID                     `json:"subscriptionID"`
	Version                                 int                           `json:"version"`
}

type AttendedInvitationRecord struct {
	Payload   []byte                      `json:"payload"`
	Signature AttendedInvitationSignature `json:"signature"`
}

// AttendedInvitationServiceAuthoritySnapshot is the full public authority
// snapshot transferred by Swift. It is exact historical state, not a request
// to resolve a successor or fall forward to a current route.
type AttendedInvitationServiceAuthoritySnapshot struct {
	Anchor         serviceauthority.TrustAnchor `json:"anchor"`
	Manifest       serviceauthority.Manifest    `json:"manifest"`
	ManifestDigest string                       `json:"manifestDigest"`
}

type attendedInvitationMaterial struct {
	invitation       Invitation
	activationRoster SecureRosterAttestation
	keyGrant         ParticipantKeyGrant
	keyGrantRecord   []byte
}

// DecodeAttendedInvitationRecord strictly decodes and self-verifies a portable
// checkpoint. Its result proves record integrity and signer-key possession
// only; callers must validate the complete roster history independently.
func DecodeAttendedInvitationRecord(data []byte) (AttendedInvitationRecord, error) {
	var record AttendedInvitationRecord
	if decodeCanonicalAttendedInvitation(
		data,
		MaximumAttendedInvitationRecordByteCount,
		&record,
	) != nil {
		return AttendedInvitationRecord{}, ErrInvalidAttendedInvitation
	}
	if _, err := record.VerifiedPayload(); err != nil {
		return AttendedInvitationRecord{}, err
	}
	return record, nil
}

// VerifiedPayload authenticates and closes every internal reference. It does
// not construct roster authority, recipient authority, key access, relay-claim
// authority, or Node/Sentry intake authority.
func (record AttendedInvitationRecord) VerifiedPayload() (AttendedInvitationPayload, error) {
	var payload AttendedInvitationPayload
	if decodeCanonicalAttendedInvitation(
		record.Payload,
		MaximumAttendedInvitationPayloadByteCount,
		&payload,
	) != nil || verifyAttendedInvitationSignature(record.Signature, record.Payload) != nil {
		return AttendedInvitationPayload{}, ErrInvalidAttendedInvitation
	}
	material, err := validateAttendedInvitationPayload(payload)
	if err != nil || validateAttendedInvitationPackageSigner(
		record.Signature,
		material.activationRoster,
	) != nil {
		return AttendedInvitationPayload{}, ErrInvalidAttendedInvitation
	}
	return payload, nil
}

func (record AttendedInvitationRecord) CanonicalRecordBytes() ([]byte, error) {
	if _, err := record.VerifiedPayload(); err != nil {
		return nil, err
	}
	encoded, err := canonicalAttendedInvitationJSON(record)
	if err != nil || len(encoded) > MaximumAttendedInvitationRecordByteCount {
		return nil, ErrInvalidAttendedInvitation
	}
	return encoded, nil
}

func (record AttendedInvitationRecord) ReferenceDigest() (string, error) {
	encoded, err := record.CanonicalRecordBytes()
	if err != nil {
		return "", err
	}
	return attendedInvitationReferenceDigest(attendedInvitationReferenceDomain, encoded), nil
}

func (record AttendedInvitationRecord) AcceptedInvitation() (Invitation, error) {
	payload, err := record.VerifiedPayload()
	if err != nil {
		return Invitation{}, err
	}
	var invitation Invitation
	if decodeCanonicalAttendedInvitation(
		payload.AcceptedInvitationRecord,
		MaximumAttendedInvitationComponentRecordByteCount,
		&invitation,
	) != nil {
		return Invitation{}, ErrInvalidAttendedInvitation
	}
	return invitation, nil
}

// AcceptedInvitationReferenceDigest exposes the domain-separated reference
// vocabulary for an exact canonical accepted invitation record.
func AcceptedInvitationReferenceDigest(canonicalRecord []byte) (string, error) {
	var invitation Invitation
	if decodeCanonicalAttendedInvitation(
		canonicalRecord,
		MaximumAttendedInvitationComponentRecordByteCount,
		&invitation,
	) != nil {
		return "", ErrInvalidAttendedInvitation
	}
	if _, err := validateAttendedInvitationMaterial(invitation); err != nil {
		return "", err
	}
	return attendedInvitationReferenceDigest(
		acceptedInvitationReferenceDomain,
		canonicalRecord,
	), nil
}

// ParticipantKeyGrantReferenceDigest covers the complete canonical signed
// wrapper, including its signature, under a distinct reference domain.
func ParticipantKeyGrantReferenceDigest(grant ParticipantKeyGrant) (string, error) {
	if err := grant.Validate(); err != nil || validateCanonicalGrantSignature(grant.Signature) != nil {
		return "", ErrInvalidAttendedInvitation
	}
	record, err := canonicalAttendedInvitationJSON(grant)
	if err != nil || len(record) > MaximumAttendedInvitationComponentRecordByteCount {
		return "", ErrInvalidAttendedInvitation
	}
	return attendedInvitationReferenceDigest(participantKeyGrantReferenceDomain, record), nil
}

func validateAttendedInvitationPayload(payload AttendedInvitationPayload) (attendedInvitationMaterial, error) {
	if payload.Version != SchemaVersion || payload.SecurityMode != SecurityModeSecure ||
		payload.ServiceTrafficClass != serviceauthority.TrafficControl ||
		payload.RetryID == uuid.Nil || payload.SpaceID == uuid.Nil || payload.DomainID == uuid.Nil ||
		payload.InvitationID == uuid.Nil || payload.ParticipantID == uuid.Nil ||
		payload.SubscriptionID == uuid.Nil || payload.RecipientDeviceID == uuid.Nil ||
		payload.ServiceActiveDeploymentID == uuid.Nil || payload.ServiceControlRouteID == uuid.Nil ||
		payload.CreatedAtMilliseconds < 0 || payload.ExpiresAtMilliseconds <= payload.CreatedAtMilliseconds ||
		(payload.MemberExpiresAtMilliseconds != nil &&
			*payload.MemberExpiresAtMilliseconds <= payload.ExpiresAtMilliseconds) ||
		!validFingerprint(payload.AcceptedInvitationReferenceDigest) ||
		!validFingerprint(payload.ActivationRosterDigest) ||
		!validFingerprint(payload.ActivationRosterPreviousDigest) ||
		!validFingerprint(payload.KeyGrantReferenceDigest) ||
		!validFingerprint(payload.ParticipantSigningKeyFingerprint) ||
		!validFingerprint(payload.RecipientAgreementKeyFingerprint) ||
		!validFingerprint(payload.RelayAdmissionAuthorizationDigest) ||
		!validFingerprint(payload.ServiceAuthorityAnchorReferenceDigest) ||
		!validFingerprint(payload.ServiceAuthorityManifestReferenceDigest) {
		return attendedInvitationMaterial{}, ErrInvalidAttendedInvitation
	}

	var invitation Invitation
	if decodeCanonicalAttendedInvitation(
		payload.AcceptedInvitationRecord,
		MaximumAttendedInvitationComponentRecordByteCount,
		&invitation,
	) != nil {
		return attendedInvitationMaterial{}, ErrInvalidAttendedInvitation
	}
	material, err := validateAttendedInvitationMaterial(invitation)
	if err != nil {
		return attendedInvitationMaterial{}, err
	}
	rosterDigest, err := material.activationRoster.Digest()
	if err != nil {
		return attendedInvitationMaterial{}, ErrInvalidAttendedInvitation
	}
	if payload.AcceptedInvitationReferenceDigest != attendedInvitationReferenceDigest(
		acceptedInvitationReferenceDomain,
		payload.AcceptedInvitationRecord,
	) || payload.RetryID != invitation.RetryID || payload.SpaceID != invitation.SpaceID ||
		payload.DomainID != invitation.RelayAdmission.DomainID ||
		payload.InvitationID != invitation.InvitationID ||
		payload.ParticipantID != invitation.ParticipantID ||
		payload.SubscriptionID != invitation.SubscriptionID ||
		payload.ParticipantKind != invitation.Kind || payload.ParticipantRole != invitation.Role ||
		payload.InteractionMode != invitation.InteractionMode ||
		!reflect.DeepEqual(payload.RelayCapabilities, invitation.RelayAdmission.Capabilities) ||
		payload.CreatedAtMilliseconds != invitation.CreatedAtMilliseconds ||
		payload.ExpiresAtMilliseconds != invitation.RelayAdmission.ExpiresAtMilliseconds ||
		!equalOptionalInt64(payload.MemberExpiresAtMilliseconds, invitation.RelayAdmission.MemberExpiresAtMilliseconds) ||
		payload.ParticipantSigningKeyFingerprint != invitation.ParticipantSigningKey.SigningKeyFingerprint ||
		payload.RecipientDeviceID != material.keyGrant.RecipientDeviceID ||
		payload.RecipientAgreementKeyFingerprint != material.keyGrant.RecipientAgreementKeyFingerprint ||
		payload.RelayAdmissionAuthorizationDigest != invitation.RelayAdmission.AuthorizationDigest ||
		payload.ActivationRosterRevision != material.activationRoster.Revision ||
		payload.ActivationRosterRevision < 2 ||
		payload.ActivationRosterPreviousDigest != material.activationRoster.PreviousDigest ||
		payload.ActivationRosterCurrentKeyEpoch != material.activationRoster.CurrentKeyEpoch ||
		payload.ActivationRosterDigest != rosterDigest ||
		payload.KeyGrantReferenceDigest != attendedInvitationReferenceDigest(
			participantKeyGrantReferenceDomain,
			material.keyGrantRecord,
		) {
		return attendedInvitationMaterial{}, ErrInvalidAttendedInvitation
	}

	var snapshot AttendedInvitationServiceAuthoritySnapshot
	if decodeCanonicalAttendedInvitation(
		payload.ServiceAuthoritySnapshotRecord,
		MaximumAttendedInvitationServiceSnapshotByteCount,
		&snapshot,
	) != nil || validateAttendedInvitationServiceAuthority(payload, snapshot) != nil {
		return attendedInvitationMaterial{}, ErrInvalidAttendedInvitation
	}
	return material, nil
}

func validateAttendedInvitationMaterial(invitation Invitation) (attendedInvitationMaterial, error) {
	if invitation.Validate() != nil || invitation.KeyGrant == nil ||
		invitation.ActivationSecureRosterAttestation == nil ||
		invitation.ActivationSecureRosterAttestation.Revision < 2 ||
		!validFingerprint(invitation.ActivationSecureRosterAttestation.PreviousDigest) ||
		invitation.RelayAdmission.ClaimedAtMilliseconds != nil ||
		invitation.RelayAdmission.ClaimedMemberID != nil ||
		invitation.RelayAdmission.RevokedAtMilliseconds != nil ||
		!reflect.DeepEqual(
			invitation.RelayAdmission.Capabilities,
			invitation.Role.Capabilities(invitation.InteractionMode),
		) || validateCanonicalParticipantSigningKey(invitation.ParticipantSigningKey) != nil {
		return attendedInvitationMaterial{}, ErrInvalidAttendedInvitation
	}

	roster := *invitation.ActivationSecureRosterAttestation
	grant := *invitation.KeyGrant
	if roster.Validate() != nil || grant.Validate() != nil ||
		validateCanonicalRosterSignatures(roster) != nil ||
		validateCanonicalGrantSignature(grant.Signature) != nil ||
		roster.SpaceID != invitation.SpaceID || roster.DomainID != invitation.RelayAdmission.DomainID ||
		grant.SpaceID != invitation.SpaceID || grant.ParticipantID != invitation.ParticipantID ||
		grant.CreatedAtMilliseconds != invitation.CreatedAtMilliseconds ||
		grant.KeyEpoch != roster.CurrentKeyEpoch {
		return attendedInvitationMaterial{}, ErrInvalidAttendedInvitation
	}

	invitedParticipant := participantByID(roster.Participants, invitation.ParticipantID)
	grantIssuer := participantByID(roster.Participants, grant.IssuerParticipantID)
	rosterIssuer := participantByID(roster.Participants, roster.IssuerParticipantID)
	activeDeviceKeys := activeAttendedInvitationDeviceKeys(invitation.ParticipantDeviceKeys)
	if invitedParticipant == nil || invitedParticipant.SpaceID != invitation.SpaceID ||
		invitedParticipant.SubscriptionID != invitation.SubscriptionID ||
		invitedParticipant.Kind != invitation.Kind || invitedParticipant.Role != invitation.Role ||
		!reflect.DeepEqual(invitedParticipant.SigningKey, invitation.ParticipantSigningKey) ||
		!reflect.DeepEqual(invitedParticipant.DeviceKeys, invitation.ParticipantDeviceKeys) ||
		invitedParticipant.CreatedAtMilliseconds != invitation.CreatedAtMilliseconds ||
		invitedParticipant.RevokedAtMilliseconds != nil || len(activeDeviceKeys) != 1 ||
		activeDeviceKeys[0].DeviceID != grant.RecipientDeviceID ||
		activeDeviceKeys[0].AgreementKeyFingerprint != grant.RecipientAgreementKeyFingerprint ||
		grantIssuer == nil || grantIssuer.RevokedAtMilliseconds != nil ||
		(grantIssuer.Role != RoleHost && grantIssuer.Role != RoleModerator) ||
		!grantIssuer.SigningKey.MatchesGrantSignature(grant.Signature) ||
		rosterIssuer == nil || rosterIssuer.RevokedAtMilliseconds != nil ||
		(rosterIssuer.Role != RoleHost && rosterIssuer.Role != RoleModerator) ||
		!rosterIssuer.SigningKey.MatchesGrantSignature(roster.Signature) {
		return attendedInvitationMaterial{}, ErrInvalidAttendedInvitation
	}

	grantRecord, err := canonicalAttendedInvitationJSON(grant)
	if err != nil || len(grantRecord) > MaximumAttendedInvitationComponentRecordByteCount {
		return attendedInvitationMaterial{}, ErrInvalidAttendedInvitation
	}
	return attendedInvitationMaterial{
		invitation: invitation, activationRoster: roster, keyGrant: grant, keyGrantRecord: grantRecord,
	}, nil
}

func activeAttendedInvitationDeviceKeys(keys []ParticipantDeviceKey) []ParticipantDeviceKey {
	active := make([]ParticipantDeviceKey, 0, len(keys))
	for _, key := range keys {
		if key.RevokedAtMilliseconds == nil {
			active = append(active, key)
		}
	}
	return active
}

func validateAttendedInvitationServiceAuthority(
	payload AttendedInvitationPayload,
	snapshot AttendedInvitationServiceAuthoritySnapshot,
) error {
	expectedScope := serviceauthority.Scope{
		Kind:    serviceauthority.ScopeSharedSpace,
		ScopeID: payload.SpaceID,
	}
	manifest, err := snapshot.Manifest.Authorize(snapshot.Anchor, payload.CreatedAtMilliseconds)
	manifestDigest, digestErr := snapshot.Manifest.ReferenceDigest()
	anchorRecord, anchorErr := canonicalAttendedInvitationJSON(snapshot.Anchor)
	if err != nil || digestErr != nil || anchorErr != nil || snapshot.Anchor.Scope != expectedScope ||
		snapshot.ManifestDigest != manifestDigest || manifest.Scope != expectedScope ||
		payload.ServiceAuthorityAnchorReferenceDigest != attendedInvitationReferenceDigest(
			serviceAuthorityAnchorReferenceDomain,
			anchorRecord,
		) || payload.ServiceAuthorityManifestReferenceDigest != manifestDigest ||
		payload.ServiceAuthorityManifestRevision != manifest.Revision ||
		payload.ServiceActiveDeploymentID != manifest.ActiveDeployment.DeploymentID ||
		manifest.ValidUntilMilliseconds == nil || payload.ExpiresAtMilliseconds > *manifest.ValidUntilMilliseconds ||
		!containsUUID(manifest.TransportPolicy.ControlRouteIDs, payload.ServiceControlRouteID) ||
		!deploymentContainsRoute(manifest.ActiveDeployment, payload.ServiceControlRouteID) {
		return ErrInvalidAttendedInvitation
	}
	return nil
}

func validateAttendedInvitationPackageSigner(
	signature AttendedInvitationSignature,
	roster SecureRosterAttestation,
) error {
	signer := participantByID(roster.Participants, signature.SignerParticipantID)
	if signer == nil || signer.RevokedAtMilliseconds != nil ||
		(signer.Role != RoleHost && signer.Role != RoleModerator) ||
		signer.SigningKey.Algorithm != signature.Algorithm ||
		signer.SigningKey.PublicKeyX963 != signature.PublicSigningKeyX963 ||
		signer.SigningKey.SigningKeyFingerprint != signature.SigningKeyFingerprint {
		return ErrInvalidAttendedInvitation
	}
	return nil
}

func verifyAttendedInvitationSignature(signature AttendedInvitationSignature, payload []byte) error {
	if signature.Algorithm != ParticipantKeyGrantSignatureAlgorithm ||
		signature.SignerParticipantID == uuid.Nil || !validFingerprint(signature.SigningKeyFingerprint) {
		return ErrInvalidAttendedInvitation
	}
	keyBytes, err := decodeCanonicalRawBase64URL(signature.PublicSigningKeyX963, 65)
	if err != nil || attendedInvitationFingerprint(keyBytes) != signature.SigningKeyFingerprint {
		return ErrInvalidAttendedInvitation
	}
	signatureBytes, err := decodeCanonicalRawBase64URL(signature.Signature, 64)
	if err != nil || !isCanonicalAttendedInvitationES256Signature(signatureBytes) {
		return ErrInvalidAttendedInvitation
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), keyBytes)
	if x == nil || y == nil {
		return ErrInvalidAttendedInvitation
	}
	digest := sha256.Sum256(append([]byte(attendedInvitationSignatureDomain), payload...))
	if !ecdsa.Verify(
		&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
		digest[:],
		new(big.Int).SetBytes(signatureBytes[:32]),
		new(big.Int).SetBytes(signatureBytes[32:]),
	) {
		return ErrInvalidAttendedInvitation
	}
	return nil
}

func validateCanonicalRosterSignatures(roster SecureRosterAttestation) error {
	if validateCanonicalGrantSignature(roster.Signature) != nil {
		return ErrInvalidAttendedInvitation
	}
	for _, participant := range roster.Participants {
		if validateCanonicalParticipantSigningKey(participant.SigningKey) != nil {
			return ErrInvalidAttendedInvitation
		}
		for _, device := range participant.DeviceKeys {
			if validateCanonicalGrantSignature(device.Signature) != nil {
				return ErrInvalidAttendedInvitation
			}
			agreementKey, err := decodeCanonicalRawBase64URL(device.AgreementPublicKeyX963, 65)
			if err != nil || attendedInvitationFingerprint(agreementKey) != device.AgreementKeyFingerprint {
				return ErrInvalidAttendedInvitation
			}
		}
	}
	return nil
}

func validateCanonicalParticipantSigningKey(key ParticipantSigningKey) error {
	if key.Algorithm != ParticipantKeyGrantSignatureAlgorithm || !validFingerprint(key.SigningKeyFingerprint) {
		return ErrInvalidAttendedInvitation
	}
	keyBytes, err := decodeCanonicalRawBase64URL(key.PublicKeyX963, 65)
	if err != nil || attendedInvitationFingerprint(keyBytes) != key.SigningKeyFingerprint {
		return ErrInvalidAttendedInvitation
	}
	if x, y := elliptic.Unmarshal(elliptic.P256(), keyBytes); x == nil || y == nil {
		return ErrInvalidAttendedInvitation
	}
	return nil
}

func validateCanonicalGrantSignature(signature ParticipantKeyGrantSignature) error {
	if signature.Algorithm != ParticipantKeyGrantSignatureAlgorithm ||
		!validFingerprint(signature.SigningKeyFingerprint) {
		return ErrInvalidAttendedInvitation
	}
	keyBytes, err := decodeCanonicalRawBase64URL(signature.PublicSigningKeyX963, 65)
	if err != nil || attendedInvitationFingerprint(keyBytes) != signature.SigningKeyFingerprint {
		return ErrInvalidAttendedInvitation
	}
	signatureBytes, err := decodeCanonicalRawBase64URL(signature.Signature, 64)
	if err != nil || !isCanonicalAttendedInvitationES256Signature(signatureBytes) {
		return ErrInvalidAttendedInvitation
	}
	return nil
}

func canonicalAttendedInvitationJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var object any
	if err := decoder.Decode(&object); err != nil {
		return nil, err
	}
	var result bytes.Buffer
	if err := appendCanonicalAttendedInvitationJSON(&result, object); err != nil {
		return nil, err
	}
	return result.Bytes(), nil
}

func appendCanonicalAttendedInvitationJSON(result *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		result.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				result.WriteByte(',')
			}
			encodedKey, _ := json.Marshal(key)
			result.Write(encodedKey)
			result.WriteByte(':')
			if err := appendCanonicalAttendedInvitationJSON(result, typed[key]); err != nil {
				return err
			}
		}
		result.WriteByte('}')
		return nil
	case []any:
		result.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				result.WriteByte(',')
			}
			if err := appendCanonicalAttendedInvitationJSON(result, item); err != nil {
				return err
			}
		}
		result.WriteByte(']')
		return nil
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return err
		}
		result.Write(encoded)
		return nil
	}
}

func decodeCanonicalAttendedInvitation(data []byte, maximum int, destination any) error {
	if len(data) == 0 || len(data) > maximum {
		return ErrInvalidAttendedInvitation
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidAttendedInvitation
	}
	if err := requireAttendedInvitationEOF(decoder); err != nil {
		return ErrInvalidAttendedInvitation
	}
	canonical, err := canonicalAttendedInvitationJSON(destination)
	if err != nil || !bytes.Equal(canonical, data) {
		return ErrInvalidAttendedInvitation
	}
	return nil
}

func requireAttendedInvitationEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ErrInvalidAttendedInvitation
	}
	return nil
}

func attendedInvitationReferenceDigest(domain string, record []byte) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(domain))
	_, _ = digest.Write(record)
	return hex.EncodeToString(digest.Sum(nil))
}

func attendedInvitationFingerprint(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func decodeCanonicalRawBase64URL(value string, expectedCount int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != expectedCount || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalidAttendedInvitation
	}
	return decoded, nil
}

func isCanonicalAttendedInvitationES256Signature(signature []byte) bool {
	if len(signature) != 64 {
		return false
	}
	curveOrder := elliptic.P256().Params().N
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(curveOrder), 1)
	return r.Sign() > 0 && r.Cmp(curveOrder) < 0 && s.Sign() > 0 && s.Cmp(halfOrder) <= 0
}

func participantByID(participants []Participant, participantID uuid.UUID) *Participant {
	for index := range participants {
		if participants[index].ParticipantID == participantID {
			return &participants[index]
		}
	}
	return nil
}

func containsUUID(values []uuid.UUID, wanted uuid.UUID) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func deploymentContainsRoute(deployment serviceauthority.DeploymentDescriptor, routeID uuid.UUID) bool {
	for _, route := range deployment.Routes {
		if route.RouteID == routeID {
			return true
		}
	}
	return false
}

func equalOptionalInt64(left, right *int64) bool {
	return (left == nil && right == nil) ||
		(left != nil && right != nil && *left == *right)
}

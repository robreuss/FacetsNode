package sharedspaces

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type attendedInvitationPortableFixture struct {
	AcceptedInvitationReference string `json:"acceptedInvitationReference"`
	CanonicalPayload            string `json:"canonicalPayload"`
	KeyGrantReference           string `json:"keyGrantReference"`
	RecordReference             string `json:"recordReference"`
	RelayAuthorizationDigest    string `json:"relayAuthorizationDigest"`
	RosterDigest                string `json:"rosterDigest"`
	Signature                   string `json:"signature"`
	SignedRecord                string `json:"signedRecord"`
	TrustedRosterPredecessor    string `json:"trustedRosterPredecessor"`
}

type attendedInvitationTestMaterial struct {
	record             AttendedInvitationRecord
	hostPrivateKey     *ecdsa.PrivateKey
	inviteePrivateKey  *ecdsa.PrivateKey
	admissionToken     string
	trustedPredecessor SecureRosterAttestation
}

func TestAttendedInvitationPortableFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(
		"testdata",
		"shared-space-attended-invitation-bootstrap-portable-v1.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	var fixture attendedInvitationPortableFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	recordBytes := decodeFixtureBase64(t, fixture.SignedRecord)
	record, err := DecodeAttendedInvitationRecord(recordBytes)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := record.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	reference, err := record.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(record.Payload, decodeFixtureBase64(t, fixture.CanonicalPayload)) ||
		record.Signature.Signature != fixture.Signature ||
		reference != fixture.RecordReference ||
		payload.AcceptedInvitationReferenceDigest != fixture.AcceptedInvitationReference ||
		payload.ActivationRosterDigest != fixture.RosterDigest ||
		payload.KeyGrantReferenceDigest != fixture.KeyGrantReference ||
		payload.RelayAdmissionAuthorizationDigest != fixture.RelayAuthorizationDigest {
		t.Fatal("portable fixture differs from the exact verified record")
	}
	if bytes.Contains(record.Payload, []byte("attended-invitation-bearer")) ||
		bytes.Contains(recordBytes, []byte("attended-invitation-bearer")) {
		t.Fatal("relay bearer escaped into signed or reference bytes")
	}
	var predecessor SecureRosterAttestation
	if err := json.Unmarshal(
		decodeFixtureBase64(t, fixture.TrustedRosterPredecessor),
		&predecessor,
	); err != nil {
		t.Fatal(err)
	}
	invitation, err := record.AcceptedInvitation()
	if err != nil || invitation.ActivationSecureRosterAttestation == nil ||
		invitation.ActivationSecureRosterAttestation.ValidateSuccessor(
			predecessor,
			invitation.ActivationSecureRosterAttestation.Participants,
			invitation.ActivationSecureRosterAttestation.CurrentKeyEpoch,
		) != nil {
		t.Fatal("fixture activation is not the exact trusted successor")
	}
}

func TestAttendedInvitationVerifierRejectsHostileCanonicalAndAuthorityChanges(t *testing.T) {
	fixture := makeAttendedInvitationTestMaterial(t, "")
	if _, err := fixture.record.VerifiedPayload(); err != nil {
		t.Fatal(err)
	}
	canonical, err := fixture.record.CanonicalRecordBytes()
	if err != nil {
		t.Fatal(err)
	}

	withExtra := append([]byte{}, canonical[:len(canonical)-1]...)
	withExtra = append(withExtra, []byte(",\"unknown\":true}")...)
	if _, err := DecodeAttendedInvitationRecord(withExtra); err == nil {
		t.Fatal("accepted an unknown record field")
	}
	if _, err := DecodeAttendedInvitationRecord(append([]byte(" "), canonical...)); err == nil {
		t.Fatal("accepted noncanonical whitespace")
	}
	if _, err := DecodeAttendedInvitationRecord(make([]byte, MaximumAttendedInvitationRecordByteCount+1)); err == nil {
		t.Fatal("accepted an oversized record")
	}

	highSignature := fixture.record
	highSignature.Signature.Signature = alternateES256Signature(t, highSignature.Signature.Signature)
	if _, err := highSignature.VerifiedPayload(); err == nil {
		t.Fatal("accepted an alternate high-S package signature")
	}
	paddedSignature := fixture.record
	paddedSignature.Signature.Signature += "="
	if _, err := paddedSignature.VerifiedPayload(); err == nil {
		t.Fatal("accepted noncanonical package-signature base64")
	}
	wrongDomain := fixture.record
	wrongDomain.Signature = attendedInvitationTestSignature(
		t,
		fixture.hostPrivateKey,
		wrongDomain.Signature.SignerParticipantID,
		append([]byte("wrong attended invitation domain\x00"), wrongDomain.Payload...),
	)
	if _, err := wrongDomain.VerifiedPayload(); err == nil {
		t.Fatal("accepted the wrong package signature domain")
	}

	for name, mutate := range map[string]func(*AttendedInvitationPayload){
		"invitation":   func(payload *AttendedInvitationPayload) { payload.InvitationID = uuid.New() },
		"subscription": func(payload *AttendedInvitationPayload) { payload.SubscriptionID = uuid.New() },
		"role":         func(payload *AttendedInvitationPayload) { payload.ParticipantRole = RoleReader },
		"interaction":  func(payload *AttendedInvitationPayload) { payload.InteractionMode = InteractionModeBroadcast },
		"capabilities": func(payload *AttendedInvitationPayload) { payload.RelayCapabilities = payload.RelayCapabilities[:1] },
		"member-expiry": func(payload *AttendedInvitationPayload) {
			value := int64(6_001)
			payload.MemberExpiresAtMilliseconds = &value
		},
		"recipient-device": func(payload *AttendedInvitationPayload) { payload.RecipientDeviceID = uuid.New() },
		"signing-fingerprint": func(payload *AttendedInvitationPayload) {
			payload.ParticipantSigningKeyFingerprint = strings.Repeat("a", 64)
		},
		"relay-digest": func(payload *AttendedInvitationPayload) {
			payload.RelayAdmissionAuthorizationDigest = strings.Repeat("b", 64)
		},
		"activation-revision": func(payload *AttendedInvitationPayload) { payload.ActivationRosterRevision = 1 },
		"key-epoch":           func(payload *AttendedInvitationPayload) { payload.ActivationRosterCurrentKeyEpoch++ },
		"service-scope":       func(payload *AttendedInvitationPayload) { payload.SpaceID = uuid.New() },
		"service-deployment":  func(payload *AttendedInvitationPayload) { payload.ServiceActiveDeploymentID = uuid.New() },
		"service-route":       func(payload *AttendedInvitationPayload) { payload.ServiceControlRouteID = uuid.New() },
		"service-class":       func(payload *AttendedInvitationPayload) { payload.ServiceTrafficClass = serviceauthority.TrafficBulk },
		"manifest-revision":   func(payload *AttendedInvitationPayload) { payload.ServiceAuthorityManifestRevision++ },
		"finite-expiry":       func(payload *AttendedInvitationPayload) { payload.ExpiresAtMilliseconds = 5_001 },
		"digest-case": func(payload *AttendedInvitationPayload) {
			payload.AcceptedInvitationReferenceDigest = strings.ToUpper(payload.AcceptedInvitationReferenceDigest)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := resignAttendedInvitationPayload(t, fixture, mutate)
			if _, err := changed.VerifiedPayload(); err == nil {
				t.Fatal("accepted a signed internal authority mismatch")
			}
		})
	}
}

func TestAttendedInvitationVerifierRejectsAlternateNestedSignatures(t *testing.T) {
	for _, hostile := range []string{
		"activation-revision-one",
		"device-high-s",
		"grant-epoch-mismatch",
		"grant-high-s",
		"grant-participant-issuer",
		"multiple-active-devices",
		"package-participant-signer",
		"roster-high-s",
		"roster-participant-issuer",
	} {
		t.Run(hostile, func(t *testing.T) {
			fixture := makeAttendedInvitationTestMaterial(t, hostile)
			if _, err := fixture.record.VerifiedPayload(); err == nil {
				t.Fatal("accepted a valid-but-noncanonical nested signature")
			}
			if hostile == "multiple-active-devices" {
				var payload AttendedInvitationPayload
				if err := decodeCanonicalAttendedInvitation(
					fixture.record.Payload,
					MaximumAttendedInvitationPayloadByteCount,
					&payload,
				); err != nil {
					t.Fatal(err)
				}
				if _, err := AcceptedInvitationReferenceDigest(
					payload.AcceptedInvitationRecord,
				); err == nil {
					t.Fatal("accepted-invitation reference helper accepted multiple active devices")
				}
			}
		})
	}
}

func TestAttendedInvitationSelfVerificationIsChainDeferred(t *testing.T) {
	fixture := makeAttendedInvitationTestMaterial(t, "untrusted-predecessor")
	payload, err := fixture.record.VerifiedPayload()
	if err != nil {
		t.Fatalf("self-verification should preserve, not invent, predecessor trust: %v", err)
	}
	if payload.ActivationRosterPreviousDigest != strings.Repeat("a", 64) {
		t.Fatal("the exact untrusted predecessor reference was not preserved")
	}
	// The only result is public integrity material. No roster trust store,
	// recipient key, relay bearer, or intake authorization is constructed.
	if strings.Contains(string(fixture.record.Payload), fixture.admissionToken) {
		t.Fatal("self-verification exposed the relay bearer")
	}
}

func TestAttendedInvitationFixtureGenerator(t *testing.T) {
	if os.Getenv("FACETS_WRITE_ATTENDED_INVITATION_FIXTURE") == "" {
		t.Skip("fixture generator is opt-in")
	}
	fixture := makeAttendedInvitationTestMaterial(t, "")
	payload, err := fixture.record.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	recordBytes, err := fixture.record.CanonicalRecordBytes()
	if err != nil {
		t.Fatal(err)
	}
	reference, err := fixture.record.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	value := attendedInvitationPortableFixture{
		AcceptedInvitationReference: payload.AcceptedInvitationReferenceDigest,
		CanonicalPayload:            base64.StdEncoding.EncodeToString(fixture.record.Payload),
		KeyGrantReference:           payload.KeyGrantReferenceDigest,
		RecordReference:             reference,
		RelayAuthorizationDigest:    payload.RelayAdmissionAuthorizationDigest,
		RosterDigest:                payload.ActivationRosterDigest,
		Signature:                   fixture.record.Signature.Signature,
		SignedRecord:                base64.StdEncoding.EncodeToString(recordBytes),
		TrustedRosterPredecessor: base64.StdEncoding.EncodeToString(
			mustJSONMarshalAttendedInvitation(t, fixture.trustedPredecessor),
		),
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(
		"testdata",
		"shared-space-attended-invitation-bootstrap-portable-v1.json",
	)
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func makeAttendedInvitationTestMaterial(t *testing.T, hostile string) attendedInvitationTestMaterial {
	t.Helper()
	spaceID := uuid.MustParse("10000000-0000-4000-8000-000000000001")
	domainID := uuid.MustParse("20000000-0000-4000-8000-000000000002")
	hostID := uuid.MustParse("30000000-0000-4000-8000-000000000003")
	inviteeID := uuid.MustParse("40000000-0000-4000-8000-000000000004")
	hostSubscriptionID := uuid.MustParse("50000000-0000-4000-8000-000000000005")
	inviteeSubscriptionID := uuid.MustParse("60000000-0000-4000-8000-000000000006")
	hostDeviceID := uuid.MustParse("70000000-0000-4000-8000-000000000007")
	inviteeDeviceID := uuid.MustParse("80000000-0000-4000-8000-000000000008")
	invitationID := uuid.MustParse("90000000-0000-4000-8000-000000000009")
	retryID := uuid.MustParse("a0000000-0000-4000-8000-00000000000a")

	hostPrivateKey := attendedInvitationTestPrivateKey(t, 3)
	inviteePrivateKey := attendedInvitationTestPrivateKey(t, 4)
	hostSigningKey := attendedInvitationTestSigningKey(hostPrivateKey)
	inviteeSigningKey := attendedInvitationTestSigningKey(inviteePrivateKey)
	hostDevice := attendedInvitationTestDeviceKey(
		t, spaceID, hostID, hostDeviceID, attendedInvitationTestPrivateKey(t, 5),
		hostPrivateKey, 1_000, false,
	)
	inviteeDevice := attendedInvitationTestDeviceKey(
		t, spaceID, inviteeID, inviteeDeviceID, attendedInvitationTestPrivateKey(t, 6),
		inviteePrivateKey, 2_000, hostile == "device-high-s",
	)
	host := Participant{
		Version: SchemaVersion, SpaceID: spaceID, ParticipantID: hostID,
		SubscriptionID: hostSubscriptionID, Kind: ParticipantPerson, Role: RoleHost,
		SigningKey: hostSigningKey, DeviceKeys: []ParticipantDeviceKey{hostDevice},
		CreatedAtMilliseconds: 1_000,
	}
	invitee := Participant{
		Version: SchemaVersion, SpaceID: spaceID, ParticipantID: inviteeID,
		SubscriptionID: inviteeSubscriptionID, Kind: ParticipantPerson, Role: RoleParticipant,
		SigningKey: inviteeSigningKey, DeviceKeys: []ParticipantDeviceKey{inviteeDevice},
		CreatedAtMilliseconds: 2_000,
	}
	if hostile == "multiple-active-devices" {
		invitee.DeviceKeys = append(
			invitee.DeviceKeys,
			attendedInvitationTestDeviceKey(
				t,
				spaceID,
				inviteeID,
				uuid.MustParse("81000000-0000-4000-8000-000000000008"),
				attendedInvitationTestPrivateKey(t, 10),
				inviteePrivateKey,
				2_000,
				false,
			),
		)
	}
	initialRoster := attendedInvitationTestRoster(
		t, spaceID, domainID, 1, "", []Participant{host}, hostID, 1_000,
		hostPrivateKey, false,
	)
	previousDigest, err := initialRoster.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if hostile == "untrusted-predecessor" {
		previousDigest = strings.Repeat("a", 64)
	}
	activationRevision := uint64(2)
	if hostile == "activation-revision-one" {
		activationRevision = 1
		previousDigest = ""
	}
	activationRoster := attendedInvitationTestRoster(
		t, spaceID, domainID, activationRevision, previousDigest, []Participant{host, invitee}, hostID,
		2_100, hostPrivateKey, hostile == "roster-high-s",
	)
	if hostile == "roster-participant-issuer" {
		activationRoster.IssuerParticipantID = inviteeID
		payload, err := activationRoster.SigningPayload()
		if err != nil {
			t.Fatal(err)
		}
		activationRoster.Signature = attendedInvitationTestGrantSignature(
			t, inviteePrivateKey, payload, false,
		)
	}
	grant := attendedInvitationTestGrant(
		t, spaceID, invitee, inviteeDevice, hostID, hostPrivateKey,
		hostile == "grant-high-s",
	)
	if hostile == "grant-epoch-mismatch" || hostile == "grant-participant-issuer" {
		grantSigningKey := hostPrivateKey
		if hostile == "grant-epoch-mismatch" {
			grant.KeyEpoch++
		} else {
			grant.IssuerParticipantID = inviteeID
			grantSigningKey = inviteePrivateKey
		}
		payload, err := grant.SigningPayload()
		if err != nil {
			t.Fatal(err)
		}
		grant.Signature = attendedInvitationTestGrantSignature(
			t, grantSigningKey, payload, false,
		)
	}

	admissionToken := base64.RawURLEncoding.EncodeToString(
		[]byte("attended-invitation-bearer-00001"),
	)
	credential := relay.AdmissionCredential{
		TenantID: spaceID, DomainID: domainID, AdmissionID: invitationID, Token: admissionToken,
	}
	admissionDigest, err := relay.AdmissionAuthorizationDigest(credential)
	if err != nil {
		t.Fatal(err)
	}
	memberExpiry := int64(6_000)
	invitation := Invitation{
		Version: SchemaVersion, RetryID: retryID, SpaceID: spaceID,
		InvitationID: invitationID, ParticipantID: inviteeID,
		SubscriptionID: inviteeSubscriptionID, Kind: ParticipantPerson,
		Role: RoleParticipant, InteractionMode: InteractionModeCollaborative,
		ParticipantSigningKey: inviteeSigningKey,
		ParticipantDeviceKeys: invitee.DeviceKeys,
		KeyGrant:              &grant, ActivationSecureRosterAttestation: &activationRoster,
		RelayAdmission: relay.MemberAdmission{
			Version: relay.SchemaVersion, TenantID: spaceID, DomainID: domainID,
			AdmissionID: invitationID, AuthorizationDigest: admissionDigest,
			Capabilities:          RoleParticipant.Capabilities(InteractionModeCollaborative),
			CreatedAtMilliseconds: 2_000, ExpiresAtMilliseconds: 4_000,
			MemberExpiresAtMilliseconds: &memberExpiry,
		},
		CreatedAtMilliseconds: 2_000,
	}
	acceptedRecord := mustCanonicalAttendedInvitationJSON(t, invitation)
	grantRecord := mustCanonicalAttendedInvitationJSON(t, grant)
	rosterDigest, err := activationRoster.Digest()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, controlRouteID := attendedInvitationTestServiceSnapshot(t, spaceID)
	snapshotRecord := mustCanonicalAttendedInvitationJSON(t, snapshot)
	anchorRecord := mustCanonicalAttendedInvitationJSON(t, snapshot.Anchor)
	manifestPayload, err := snapshot.Manifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	payload := AttendedInvitationPayload{
		AcceptedInvitationRecord:          acceptedRecord,
		AcceptedInvitationReferenceDigest: attendedInvitationReferenceDigest(acceptedInvitationReferenceDomain, acceptedRecord),
		ActivationRosterCurrentKeyEpoch:   activationRoster.CurrentKeyEpoch,
		ActivationRosterDigest:            rosterDigest, ActivationRosterPreviousDigest: activationRoster.PreviousDigest,
		ActivationRosterRevision: activationRoster.Revision, CreatedAtMilliseconds: 2_000,
		DomainID: domainID, ExpiresAtMilliseconds: 4_000,
		InteractionMode: invitation.InteractionMode, InvitationID: invitationID,
		KeyGrantReferenceDigest:     attendedInvitationReferenceDigest(participantKeyGrantReferenceDomain, grantRecord),
		MemberExpiresAtMilliseconds: &memberExpiry, ParticipantID: inviteeID,
		ParticipantKind: invitation.Kind, ParticipantRole: invitation.Role,
		ParticipantSigningKeyFingerprint: inviteeSigningKey.SigningKeyFingerprint,
		RecipientAgreementKeyFingerprint: grant.RecipientAgreementKeyFingerprint,
		RecipientDeviceID:                inviteeDeviceID, RelayAdmissionAuthorizationDigest: admissionDigest,
		RelayCapabilities: invitation.RelayAdmission.Capabilities, RetryID: retryID,
		SecurityMode:                            SecurityModeSecure,
		ServiceActiveDeploymentID:               manifestPayload.ActiveDeployment.DeploymentID,
		ServiceAuthorityAnchorReferenceDigest:   attendedInvitationReferenceDigest(serviceAuthorityAnchorReferenceDomain, anchorRecord),
		ServiceAuthorityManifestReferenceDigest: snapshot.ManifestDigest,
		ServiceAuthorityManifestRevision:        manifestPayload.Revision,
		ServiceAuthoritySnapshotRecord:          snapshotRecord, ServiceControlRouteID: controlRouteID,
		ServiceTrafficClass: serviceauthority.TrafficControl, SpaceID: spaceID,
		SubscriptionID: inviteeSubscriptionID, Version: SchemaVersion,
	}
	payloadBytes := mustCanonicalAttendedInvitationJSON(t, payload)
	signerID := hostID
	signerKey := hostPrivateKey
	if hostile == "package-participant-signer" {
		signerID = inviteeID
		signerKey = inviteePrivateKey
	}
	record := AttendedInvitationRecord{
		Payload: payloadBytes,
		Signature: attendedInvitationTestSignature(
			t, signerKey, signerID,
			append([]byte(attendedInvitationSignatureDomain), payloadBytes...),
		),
	}
	return attendedInvitationTestMaterial{
		record: record, hostPrivateKey: hostPrivateKey,
		inviteePrivateKey: inviteePrivateKey, admissionToken: admissionToken,
		trustedPredecessor: initialRoster,
	}
}

func attendedInvitationTestDeviceKey(
	t *testing.T,
	spaceID, participantID, deviceID uuid.UUID,
	agreementPrivateKey, signingPrivateKey *ecdsa.PrivateKey,
	createdAt int64,
	highS bool,
) ParticipantDeviceKey {
	agreementBytes := elliptic.Marshal(
		elliptic.P256(), agreementPrivateKey.PublicKey.X, agreementPrivateKey.PublicKey.Y,
	)
	key := ParticipantDeviceKey{
		Version: SchemaVersion, SpaceID: spaceID, ParticipantID: participantID,
		DeviceID: deviceID, Algorithm: "P256",
		AgreementPublicKeyX963:  base64.RawURLEncoding.EncodeToString(agreementBytes),
		AgreementKeyFingerprint: attendedInvitationFingerprint(agreementBytes),
		CreatedAtMilliseconds:   createdAt,
	}
	payload, err := key.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	key.Signature = attendedInvitationTestGrantSignature(t, signingPrivateKey, payload, highS)
	return key
}

func attendedInvitationTestRoster(
	t *testing.T,
	spaceID, domainID uuid.UUID,
	revision uint64,
	previousDigest string,
	participants []Participant,
	issuerID uuid.UUID,
	createdAt int64,
	signingPrivateKey *ecdsa.PrivateKey,
	highS bool,
) SecureRosterAttestation {
	roster := SecureRosterAttestation{
		Version: SchemaVersion, SpaceID: spaceID, DomainID: domainID,
		Revision: revision, PreviousDigest: previousDigest, CurrentKeyEpoch: 1,
		Participants: participants, IssuerParticipantID: issuerID,
		CreatedAtMilliseconds: createdAt,
	}
	payload, err := roster.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	roster.Signature = attendedInvitationTestGrantSignature(t, signingPrivateKey, payload, highS)
	return roster
}

func attendedInvitationTestGrant(
	t *testing.T,
	spaceID uuid.UUID,
	invitee Participant,
	device ParticipantDeviceKey,
	issuerID uuid.UUID,
	signingPrivateKey *ecdsa.PrivateKey,
	highS bool,
) ParticipantKeyGrant {
	ephemeralKey := attendedInvitationTestPrivateKey(t, 9)
	ephemeralBytes := elliptic.Marshal(
		elliptic.P256(), ephemeralKey.PublicKey.X, ephemeralKey.PublicKey.Y,
	)
	grant := ParticipantKeyGrant{
		Version: SchemaVersion, SpaceID: spaceID, ParticipantID: invitee.ParticipantID,
		RecipientDeviceID: device.DeviceID, IssuerParticipantID: issuerID,
		KeyEpoch: 1, Algorithm: ParticipantKeyGrantAlgorithm,
		RecipientAgreementKeyFingerprint: device.AgreementKeyFingerprint,
		EphemeralAgreementPublicKeyX963:  base64.RawURLEncoding.EncodeToString(ephemeralBytes),
		Nonce:                            base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 12)),
		Ciphertext:                       base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32)),
		AuthenticationTag:                base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 16)),
		CreatedAtMilliseconds:            2_000,
	}
	payload, err := grant.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	grant.Signature = attendedInvitationTestGrantSignature(t, signingPrivateKey, payload, highS)
	return grant
}

func attendedInvitationTestServiceSnapshot(
	t *testing.T,
	spaceID uuid.UUID,
) (AttendedInvitationServiceAuthoritySnapshot, uuid.UUID) {
	authorityID := uuid.MustParse("b0000000-0000-4000-8000-00000000000b")
	deploymentID := uuid.MustParse("c0000000-0000-4000-8000-00000000000c")
	routeID := uuid.MustParse("d0000000-0000-4000-8000-00000000000d")
	authorityKey := attendedInvitationTestPrivateKey(t, 7)
	deploymentKey := attendedInvitationTestPrivateKey(t, 8)
	authorityPublic := attendedInvitationTestPublicBytes(authorityKey)
	deploymentPublic := attendedInvitationTestPublicBytes(deploymentKey)
	scope := serviceauthority.Scope{Kind: serviceauthority.ScopeSharedSpace, ScopeID: spaceID}
	anchor := serviceauthority.TrustAnchor{
		Version: serviceauthority.SchemaVersion, Scope: scope, SignerID: authorityID,
		PublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(authorityPublic),
		SigningKeyFingerprint: attendedInvitationFingerprint(authorityPublic),
	}
	deployment := serviceauthority.DeploymentDescriptor{
		Version: serviceauthority.SchemaVersion, DeploymentID: deploymentID,
		PublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(deploymentPublic),
		SigningKeyFingerprint: attendedInvitationFingerprint(deploymentPublic),
		Routes: []serviceauthority.TransportRoute{{
			RouteID: routeID, Kind: serviceauthority.RouteDirectHTTPS,
			NetworkScope:         serviceauthority.NetworkTrustedLAN,
			Endpoint:             "https://spaces.example.test",
			ServerAuthentication: serviceauthority.ServerAuthentication{Kind: "web_pki"},
		}},
		CreatedAtMilliseconds: 1_000,
	}
	validUntil := int64(5_000)
	manifestPayload := serviceauthority.ManifestPayload{
		Version: serviceauthority.SchemaVersion, Scope: scope, Revision: 1,
		Transition:       serviceauthority.TransitionInitialActivation,
		ActiveDeployment: deployment, PreparedDeployments: []serviceauthority.DeploymentDescriptor{},
		TransportPolicy: serviceauthority.TransportPolicy{
			Version: serviceauthority.SchemaVersion, ControlRouteIDs: []uuid.UUID{routeID},
			MessageRouteIDs: []uuid.UUID{routeID}, BulkRouteIDs: []uuid.UUID{routeID},
			AllowsPublicDirectBulkTransfer: false,
		},
		IssuedAtMilliseconds: 1_000, ValidFromMilliseconds: 1_000,
		ValidUntilMilliseconds: &validUntil,
	}
	payloadBytes, err := json.Marshal(manifestPayload)
	if err != nil {
		t.Fatal(err)
	}
	manifest := serviceauthority.Manifest{
		Payload: payloadBytes,
		Signature: serviceauthority.Signature{
			Algorithm: "ES256", PublicSigningKeyX963: anchor.PublicSigningKeyX963,
			SignerID: authorityID, SigningKeyFingerprint: anchor.SigningKeyFingerprint,
			Signature: attendedInvitationTestRawSignature(
				t, authorityKey,
				append([]byte("Facets service authority manifest v1\x00"), payloadBytes...),
				false,
			),
		},
	}
	digest, err := manifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	return AttendedInvitationServiceAuthoritySnapshot{
		Anchor: anchor, Manifest: manifest, ManifestDigest: digest,
	}, routeID
}

func resignAttendedInvitationPayload(
	t *testing.T,
	fixture attendedInvitationTestMaterial,
	mutate func(*AttendedInvitationPayload),
) AttendedInvitationRecord {
	var payload AttendedInvitationPayload
	if err := decodeCanonicalAttendedInvitation(
		fixture.record.Payload,
		MaximumAttendedInvitationPayloadByteCount,
		&payload,
	); err != nil {
		t.Fatal(err)
	}
	mutate(&payload)
	payloadBytes := mustCanonicalAttendedInvitationJSON(t, payload)
	record := AttendedInvitationRecord{Payload: payloadBytes}
	record.Signature = attendedInvitationTestSignature(
		t,
		fixture.hostPrivateKey,
		fixture.record.Signature.SignerParticipantID,
		append([]byte(attendedInvitationSignatureDomain), payloadBytes...),
	)
	return record
}

func attendedInvitationTestPrivateKey(t *testing.T, scalar byte) *ecdsa.PrivateKey {
	t.Helper()
	d := new(big.Int).SetInt64(int64(scalar))
	x, y := elliptic.P256().ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d,
	}
}

func attendedInvitationTestSigningKey(key *ecdsa.PrivateKey) ParticipantSigningKey {
	public := attendedInvitationTestPublicBytes(key)
	return ParticipantSigningKey{
		Algorithm:             ParticipantKeyGrantSignatureAlgorithm,
		PublicKeyX963:         base64.RawURLEncoding.EncodeToString(public),
		SigningKeyFingerprint: attendedInvitationFingerprint(public),
	}
}

func attendedInvitationTestSignature(
	t *testing.T,
	key *ecdsa.PrivateKey,
	signerID uuid.UUID,
	message []byte,
) AttendedInvitationSignature {
	public := attendedInvitationTestPublicBytes(key)
	return AttendedInvitationSignature{
		Algorithm:             ParticipantKeyGrantSignatureAlgorithm,
		PublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(public),
		Signature:             attendedInvitationTestRawSignature(t, key, message, false),
		SignerParticipantID:   signerID,
		SigningKeyFingerprint: attendedInvitationFingerprint(public),
	}
}

func attendedInvitationTestGrantSignature(
	t *testing.T,
	key *ecdsa.PrivateKey,
	message []byte,
	highS bool,
) ParticipantKeyGrantSignature {
	public := attendedInvitationTestPublicBytes(key)
	return ParticipantKeyGrantSignature{
		Algorithm:             ParticipantKeyGrantSignatureAlgorithm,
		PublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(public),
		SigningKeyFingerprint: attendedInvitationFingerprint(public),
		Signature:             attendedInvitationTestRawSignature(t, key, message, highS),
	}
}

func attendedInvitationTestRawSignature(
	t *testing.T,
	key *ecdsa.PrivateKey,
	message []byte,
	highS bool,
) string {
	t.Helper()
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	half := new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)
	if (s.Cmp(half) > 0) != highS {
		s.Sub(elliptic.P256().Params().N, s)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	return base64.RawURLEncoding.EncodeToString(raw)
}

func alternateES256Signature(t *testing.T, value string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != 64 {
		t.Fatal("invalid fixture signature")
	}
	s := new(big.Int).SetBytes(raw[32:])
	s.Sub(elliptic.P256().Params().N, s)
	s.FillBytes(raw[32:])
	return base64.RawURLEncoding.EncodeToString(raw)
}

func attendedInvitationTestPublicBytes(key *ecdsa.PrivateKey) []byte {
	return elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
}

func mustCanonicalAttendedInvitationJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := canonicalAttendedInvitationJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustJSONMarshalAttendedInvitation(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func decodeFixtureBase64(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != value {
		t.Fatal("fixture contains noncanonical base64")
	}
	return decoded
}

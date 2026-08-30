package testfixture_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	serviceauthority "github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const nodeTransportObservationPortableFixtureSHA256 = "7ad6ebe91e3a999d6e62c4583661ce8c89027eec072415469414ee0fa1fa56b7"

//go:embed node-transport-observation-portable-v1.json
var nodeTransportObservationPortableFixture []byte

type portableNodeTransportObservationFixture struct {
	ExpectedPayload                                      serviceauthority.NodeTransportObservationPayload `json:"expectedPayload"`
	ExpectedProtectedEnvelopeReferenceDigest             string                                           `json:"expectedProtectedEnvelopeReferenceDigest"`
	ExpectedRecipientPrincipalDeviceGrantReferenceDigest string                                           `json:"expectedRecipientPrincipalDeviceGrantReferenceDigest"`
	ExpectedRecordReferenceDigest                        string                                           `json:"expectedRecordReferenceDigest"`
	Format                                               string                                           `json:"format"`
	ProtectedObservationEnvelope                         []byte                                           `json:"protectedObservationEnvelope"`
	RecipientPrincipalDeviceGrantRecord                  []byte                                           `json:"recipientPrincipalDeviceGrantRecord"`
	Record                                               serviceauthority.NodeTransportObservation        `json:"record"`
	TrustedDeployment                                    serviceauthority.DeploymentDescriptor            `json:"trustedDeployment"`
}

type nodeObservationFixture struct {
	anchor           serviceauthority.TrustAnchor
	authorityKey     *ecdsa.PrivateKey
	deploymentKey    *ecdsa.PrivateKey
	deploymentSigner *serviceauthority.DeploymentSigner
	descriptor       serviceauthority.DeploymentDescriptor
	manifest         serviceauthority.Manifest
	manifestDigest   string
	payload          serviceauthority.NodeTransportObservationPayload
	recipient        serviceauthority.NodeTransportExpectedRecipient
}

func TestNodeTransportObservationPortableFixture(t *testing.T) {
	fileDigest := sha256Hex(nodeTransportObservationPortableFixture)
	if fileDigest != nodeTransportObservationPortableFixtureSHA256 {
		t.Fatalf(
			"portable fixture file digest=%s want=%s",
			fileDigest,
			nodeTransportObservationPortableFixtureSHA256,
		)
	}

	var fixture portableNodeTransportObservationFixture
	decodeStrict(t, nodeTransportObservationPortableFixture, &fixture)
	if fixture.Format != "facets.node-transport-observation.portable.v1" {
		t.Fatalf("unexpected portable format %q", fixture.Format)
	}
	if fixture.TrustedDeployment.Validate() != nil {
		t.Fatal("fixture trusted deployment is structurally invalid")
	}
	var decodedPayload serviceauthority.NodeTransportObservationPayload
	if err := json.Unmarshal(fixture.Record.Payload, &decodedPayload); err != nil {
		t.Fatalf("portable payload decode failed: %v", err)
	}
	reencodedPayload, err := json.Marshal(decodedPayload)
	if err != nil || !bytes.Equal(reencodedPayload, fixture.Record.Payload) {
		t.Fatalf(
			"portable payload is not Go-canonical: equal=%v err=%v\n got=%s\nwant=%s",
			bytes.Equal(reencodedPayload, fixture.Record.Payload),
			err,
			reencodedPayload,
			fixture.Record.Payload,
		)
	}
	if err := decodedPayload.Validate(); err != nil {
		t.Fatalf("portable payload structure rejected: %v", err)
	}

	verified, err := fixture.Record.VerifiedPayload()
	if err != nil || !reflect.DeepEqual(verified, fixture.ExpectedPayload) {
		t.Fatalf("portable record verification mismatch: payload=%+v err=%v", verified, err)
	}
	expectedPayloadBytes, err := json.Marshal(fixture.ExpectedPayload)
	if err != nil || !bytes.Equal(expectedPayloadBytes, fixture.Record.Payload) {
		t.Fatal("portable record payload is not the exact canonical expected payload")
	}
	assertCanonicalJSON(t, fixture.Record.Payload)
	recordBytes, err := json.Marshal(fixture.Record)
	if err != nil {
		t.Fatal(err)
	}
	decodedRecord, err := serviceauthority.DecodeNodeTransportObservation(recordBytes)
	if err != nil || decodedRecord.ValidateExactReplay(fixture.Record) != nil {
		t.Fatalf("portable canonical record wrapper rejected: %v", err)
	}
	recordDigest, err := fixture.Record.ReferenceDigest()
	if err != nil || recordDigest != fixture.ExpectedRecordReferenceDigest {
		t.Fatalf(
			"portable record reference=%q want=%q err=%v",
			recordDigest,
			fixture.ExpectedRecordReferenceDigest,
			err,
		)
	}

	protectedDigest, err := serviceauthority.ProtectedObservationEnvelopeReferenceDigest(
		fixture.ProtectedObservationEnvelope,
	)
	if err != nil || protectedDigest != fixture.ExpectedProtectedEnvelopeReferenceDigest ||
		verified.DeliveryProtection.ProtectedObservationEnvelopeReferenceDigest != protectedDigest ||
		verified.DeliveryProtection.ProtectedObservationEnvelopeByteCount !=
			uint64(len(fixture.ProtectedObservationEnvelope)) {
		t.Fatalf("portable protected-envelope binding mismatch: digest=%q err=%v", protectedDigest, err)
	}
	grantDigest, err := serviceauthority.RecipientPrincipalDeviceGrantRecordReferenceDigest(
		fixture.RecipientPrincipalDeviceGrantRecord,
	)
	if err != nil || grantDigest != fixture.ExpectedRecipientPrincipalDeviceGrantReferenceDigest ||
		verified.DeliveryProtection.RecipientAuthorityReference.ReferenceDigest != grantDigest {
		t.Fatalf("portable recipient grant reference mismatch: digest=%q err=%v", grantDigest, err)
	}

	if fixture.Record.Signature.SignerID != fixture.TrustedDeployment.DeploymentID ||
		fixture.Record.Signature.PublicSigningKeyX963 !=
			fixture.TrustedDeployment.PublicSigningKeyX963 ||
		fixture.Record.Signature.SigningKeyFingerprint !=
			fixture.TrustedDeployment.SigningKeyFingerprint ||
		verified.DeploymentID != fixture.TrustedDeployment.DeploymentID ||
		verified.SigningKeyFingerprint != fixture.TrustedDeployment.SigningKeyFingerprint {
		t.Fatal("portable signature does not bind the exact trusted deployment")
	}
	if verified.ServiceKind != verified.Authority.Scope.Kind ||
		verified.Authority.Scope.Kind != serviceauthority.ScopeDeviceSync ||
		verified.Authority.Scope.ScopeID !=
			uuid.MustParse("71000000-0000-0000-0000-000000000002") ||
		verified.Authority.AuthorityRevision != 7 ||
		verified.Authority.AuthorityManifestDigest != strings.Repeat("e", 64) ||
		verified.DeliveryProtection.DeliveryRecipientDeviceID !=
			uuid.MustParse("71000000-0000-0000-0000-000000000005") ||
		verified.DeliveryProtection.RecipientAgreementKeyFingerprint !=
			"89896264c58fca553508257b18703781fcd99c22a66186aa74f56e76f9b27cbe" ||
		verified.DeliveryProtection.RecipientAuthorityReference.Kind !=
			serviceauthority.NodeTransportDeviceSyncPrincipalGrantReference ||
		verified.DeliveryProtection.RecipientAuthorityReference.GrantID == nil ||
		*verified.DeliveryProtection.RecipientAuthorityReference.GrantID !=
			uuid.MustParse("71000000-0000-0000-0000-000000000008") ||
		verified.DeliveryProtection.RecipientAuthorityReference.DeviceGeneration == nil ||
		*verified.DeliveryProtection.RecipientAuthorityReference.DeviceGeneration != 3 {
		t.Fatal("portable authority/service/recipient binding differs from frozen expected values")
	}

	lowerPayload := bytes.ToLower(fixture.Record.Payload)
	for _, forbidden := range []string{
		"localspaceinstanceid", "localspace", "runtimegeneration", "packagepath", "path",
		"receipt", "finding", "action", "backup",
	} {
		if bytes.Contains(lowerPayload, []byte(forbidden)) {
			t.Fatalf("portable record contains forbidden local/semantic field %q", forbidden)
		}
	}
}

func TestNodeTransportObservationSeparatesIntegrityAuthorityAndRecipientBinding(t *testing.T) {
	fixture := newNodeObservationFixture(t)
	observation := signNodeObservation(t, fixture, fixture.payload)

	verified, err := observation.VerifiedPayload()
	if err != nil || !reflect.DeepEqual(verified, fixture.payload) {
		t.Fatalf("self-verification failed: payload=%+v err=%v", verified, err)
	}
	if _, err := observation.Authorize(fixture.manifest, fixture.anchor); err != nil {
		t.Fatalf("independently trusted manifest did not authorize observation: %v", err)
	}
	earlierOccurrence := fixture.payload
	earlierOccurrence.OccurredAtMilliseconds = 900
	earlierOccurrence.CommittedAtMilliseconds = 1_101
	if _, err := signNodeObservation(t, fixture, earlierOccurrence).Authorize(
		fixture.manifest,
		fixture.anchor,
	); err != nil {
		t.Fatalf("descriptive occurrence time improperly became authority time: %v", err)
	}
	if err := observation.ValidateRecipientBinding(fixture.recipient); err != nil {
		t.Fatalf("exact recipient binding rejected: %v", err)
	}

	wrongAnchor := fixture.anchor
	wrongAnchor.SignerID = uuid.New()
	if _, err := observation.Authorize(fixture.manifest, wrongAnchor); err == nil {
		t.Fatal("embedded deployment signature authorized itself without the trusted authority")
	}
	wrongAuthorityPayload := fixture.payload
	wrongAuthorityPayload.Authority.AuthorityManifestDigest = strings.Repeat("f", 64)
	wrongAuthority := signNodeObservation(t, fixture, wrongAuthorityPayload)
	if _, err := wrongAuthority.VerifiedPayload(); err != nil {
		t.Fatalf("self-verification unexpectedly became authority validation: %v", err)
	}
	if _, err := wrongAuthority.Authorize(fixture.manifest, fixture.anchor); err == nil {
		t.Fatal("self-verified record authorized against a different manifest digest")
	}
	wrongRecipient := fixture.recipient
	wrongRecipient.AgreementKeyFingerprint = strings.Repeat("f", 64)
	if err := observation.ValidateRecipientBinding(wrongRecipient); err == nil {
		t.Fatal("observation accepted another recipient agreement key")
	}
	wrongRecipient = fixture.recipient
	wrongGeneration := *wrongRecipient.RecipientAuthorityReference.DeviceGeneration + 1
	wrongRecipient.RecipientAuthorityReference.DeviceGeneration = &wrongGeneration
	if err := observation.ValidateRecipientBinding(wrongRecipient); err == nil {
		t.Fatal("observation accepted another recipient authority generation")
	}
	wrongRecipient = fixture.recipient
	wrongRecipient.EncryptionSuite = "P256-HKDF-SHA256+A128GCM"
	if err := observation.ValidateRecipientBinding(wrongRecipient); err == nil {
		t.Fatal("observation accepted another recipient encryption suite")
	}
	// Service authorization does not authorize the recipient key or prove that
	// the referenced protected envelope can be decrypted.
	if _, err := observation.Authorize(fixture.manifest, fixture.anchor); err != nil {
		t.Fatal("recipient comparison improperly became service authorization")
	}

	encoded, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := serviceauthority.DecodeNodeTransportObservation(encoded)
	if err != nil || decoded.ValidateExactReplay(observation) != nil {
		t.Fatalf("strict canonical wrapper decode failed: %v", err)
	}
	unknown := bytes.Replace(encoded, []byte(`{"payload":`), []byte(`{"extra":1,"payload":`), 1)
	if _, err := serviceauthority.DecodeNodeTransportObservation(unknown); err == nil {
		t.Fatal("wrapper with unknown field decoded")
	}
}

func TestNodeTransportObservationRecipientAuthorityReferenceIsClosedAndScopeBound(t *testing.T) {
	fixture := newNodeObservationFixture(t)
	observation := signNodeObservation(t, fixture, fixture.payload)

	wrongReference := fixture.recipient
	wrongReference.RecipientAuthorityReference.ReferenceDigest = strings.Repeat("a", 64)
	if err := observation.ValidateRecipientBinding(wrongReference); err == nil {
		t.Fatal("observation accepted another recipient authority record")
	}
	wrongGrantID := fixture.recipient
	replacementGrantID := uuid.New()
	wrongGrantID.RecipientAuthorityReference.GrantID = &replacementGrantID
	if err := observation.ValidateRecipientBinding(wrongGrantID); err == nil {
		t.Fatal("observation accepted another recipient grant identity")
	}

	participantID := uuid.MustParse("23000000-0000-0000-0000-000000000003")
	sharedReference := sharedSpaceRecipientAuthorityReference(
		participantID,
		9,
		strings.Repeat("9", 64),
	)
	sharedPayload := fixture.payload
	sharedPayload.ServiceKind = serviceauthority.ScopeSharedSpace
	sharedPayload.Authority.Scope.Kind = serviceauthority.ScopeSharedSpace
	sharedPayload.DeliveryProtection.RecipientAuthorityReference = sharedReference
	sharedObservation, err := fixture.deploymentSigner.SignNodeTransportObservation(sharedPayload)
	if err != nil {
		t.Fatalf("valid Shared Space roster reference rejected: %v", err)
	}
	sharedExpected := serviceauthority.NodeTransportExpectedRecipient{
		DeviceID:                    fixture.recipient.DeviceID,
		AgreementKeyFingerprint:     fixture.recipient.AgreementKeyFingerprint,
		RecipientAuthorityReference: sharedReference,
		EncryptionSuite:             fixture.recipient.EncryptionSuite,
	}
	if err := sharedObservation.ValidateRecipientBinding(sharedExpected); err != nil {
		t.Fatalf("exact Shared Space roster binding rejected: %v", err)
	}
	wrongRosterRevision := *sharedReference.RosterRevision + 1
	sharedExpected.RecipientAuthorityReference.RosterRevision = &wrongRosterRevision
	if err := sharedObservation.ValidateRecipientBinding(sharedExpected); err == nil {
		t.Fatal("observation accepted another Shared Space roster revision")
	}

	hostile := []struct {
		name   string
		mutate func(*serviceauthority.NodeTransportObservationPayload)
	}{
		{"device scope with shared roster", func(value *serviceauthority.NodeTransportObservationPayload) {
			value.DeliveryProtection.RecipientAuthorityReference = sharedReference
		}},
		{"shared scope with device grant", func(value *serviceauthority.NodeTransportObservationPayload) {
			value.ServiceKind = serviceauthority.ScopeSharedSpace
			value.Authority.Scope.Kind = serviceauthority.ScopeSharedSpace
		}},
		{"compute scope with recipient reference", func(value *serviceauthority.NodeTransportObservationPayload) {
			value.ServiceKind = serviceauthority.ScopeComputePool
			value.Authority.Scope.Kind = serviceauthority.ScopeComputePool
		}},
		{"device grant missing generation", func(value *serviceauthority.NodeTransportObservationPayload) {
			value.DeliveryProtection.RecipientAuthorityReference.DeviceGeneration = nil
		}},
		{"device grant missing grant identity", func(value *serviceauthority.NodeTransportObservationPayload) {
			value.DeliveryProtection.RecipientAuthorityReference.GrantID = nil
		}},
		{"device grant zero generation", func(value *serviceauthority.NodeTransportObservationPayload) {
			zero := uint64(0)
			value.DeliveryProtection.RecipientAuthorityReference.DeviceGeneration = &zero
		}},
		{"device grant with participant", func(value *serviceauthority.NodeTransportObservationPayload) {
			value.DeliveryProtection.RecipientAuthorityReference.ParticipantID = &participantID
		}},
		{"device grant with roster revision", func(value *serviceauthority.NodeTransportObservationPayload) {
			revision := uint64(1)
			value.DeliveryProtection.RecipientAuthorityReference.RosterRevision = &revision
		}},
		{"shared roster missing participant", func(value *serviceauthority.NodeTransportObservationPayload) {
			value.ServiceKind = serviceauthority.ScopeSharedSpace
			value.Authority.Scope.Kind = serviceauthority.ScopeSharedSpace
			value.DeliveryProtection.RecipientAuthorityReference = sharedReference
			value.DeliveryProtection.RecipientAuthorityReference.ParticipantID = nil
		}},
		{"shared roster missing revision", func(value *serviceauthority.NodeTransportObservationPayload) {
			value.ServiceKind = serviceauthority.ScopeSharedSpace
			value.Authority.Scope.Kind = serviceauthority.ScopeSharedSpace
			value.DeliveryProtection.RecipientAuthorityReference = sharedReference
			value.DeliveryProtection.RecipientAuthorityReference.RosterRevision = nil
		}},
		{"shared roster zero revision", func(value *serviceauthority.NodeTransportObservationPayload) {
			value.ServiceKind = serviceauthority.ScopeSharedSpace
			value.Authority.Scope.Kind = serviceauthority.ScopeSharedSpace
			value.DeliveryProtection.RecipientAuthorityReference = sharedReference
			zero := uint64(0)
			value.DeliveryProtection.RecipientAuthorityReference.RosterRevision = &zero
		}},
		{"shared roster with grant", func(value *serviceauthority.NodeTransportObservationPayload) {
			value.ServiceKind = serviceauthority.ScopeSharedSpace
			value.Authority.Scope.Kind = serviceauthority.ScopeSharedSpace
			value.DeliveryProtection.RecipientAuthorityReference = sharedReference
			grantID := uuid.New()
			value.DeliveryProtection.RecipientAuthorityReference.GrantID = &grantID
		}},
		{"shared roster with device generation", func(value *serviceauthority.NodeTransportObservationPayload) {
			value.ServiceKind = serviceauthority.ScopeSharedSpace
			value.Authority.Scope.Kind = serviceauthority.ScopeSharedSpace
			value.DeliveryProtection.RecipientAuthorityReference = sharedReference
			generation := uint64(1)
			value.DeliveryProtection.RecipientAuthorityReference.DeviceGeneration = &generation
		}},
		{"unknown recipient authority kind", func(value *serviceauthority.NodeTransportObservationPayload) {
			value.DeliveryProtection.RecipientAuthorityReference.Kind =
				serviceauthority.NodeTransportRecipientAuthorityReferenceKind("generic")
		}},
	}
	for _, test := range hostile {
		t.Run(test.name, func(t *testing.T) {
			payload := fixture.payload
			test.mutate(&payload)
			if _, err := fixture.deploymentSigner.SignNodeTransportObservation(payload); err == nil {
				t.Fatal("hostile recipient-authority shape was signed")
			}
		})
	}

	// Strict canonical verification rejects each unknown/mixed field on its
	// own, even when a deployment key signs those exact hostile bytes.
	rawHostile := []struct {
		name   string
		mutate func(delivery map[string]any, reference map[string]any)
	}{
		{"legacy common epoch field", func(delivery map[string]any, _ map[string]any) {
			delivery["recipientEncryptionKeyEpoch"] = float64(3)
		}},
		{"mixed participant field", func(_ map[string]any, reference map[string]any) {
			reference["participantID"] = participantID.String()
		}},
		{"unknown authority field", func(_ map[string]any, reference map[string]any) {
			reference["unknownAuthorityField"] = true
		}},
	}
	for _, test := range rawHostile {
		t.Run("signed JSON "+test.name, func(t *testing.T) {
			validBytes, err := json.Marshal(fixture.payload)
			if err != nil {
				t.Fatal(err)
			}
			var raw map[string]any
			if err := json.Unmarshal(validBytes, &raw); err != nil {
				t.Fatal(err)
			}
			delivery := raw["deliveryProtection"].(map[string]any)
			reference := delivery["recipientAuthorityReference"].(map[string]any)
			test.mutate(delivery, reference)
			hostileBytes, err := json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			hostileObservation := serviceauthority.NodeTransportObservation{
				Payload: hostileBytes,
				Signature: signPortableRecord(
					t,
					fixture.deploymentKey,
					fixture.descriptor.DeploymentID,
					serviceauthority.NodeTransportObservationSignatureDomain,
					hostileBytes,
				),
			}
			if _, err := hostileObservation.VerifiedPayload(); err == nil {
				t.Fatal("signed hostile recipient-authority JSON verified")
			}
		})
	}
}

func TestNodeTransportObservationStreamContinuityAndExactReplay(t *testing.T) {
	fixture := newNodeObservationFixture(t)
	first := signNodeObservation(t, fixture, fixture.payload)
	firstDigest, err := first.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	nextPayload := fixture.payload
	nextPayload.ObservationID = uuid.MustParse("24000000-0000-0000-0000-000000000002")
	nextPayload.Sequence = 2
	nextPayload.PredecessorReferenceDigest = &firstDigest
	nextPayload.OccurredAtMilliseconds++
	nextPayload.CommittedAtMilliseconds++
	next := signNodeObservation(t, fixture, nextPayload)
	if _, err := next.ValidateSuccessor(first); err != nil {
		t.Fatalf("exact successor rejected: %v", err)
	}

	if err := first.ValidateExactReplay(first); err != nil {
		t.Fatalf("byte-identical replay rejected: %v", err)
	}
	resigned := signNodeObservation(t, fixture, fixture.payload)
	if err := resigned.ValidateExactReplay(first); err == nil {
		t.Fatal("fresh ES256 signature accepted as exact record retry")
	}

	wrongPredecessor := nextPayload
	wrongDigest := strings.Repeat("e", 64)
	wrongPredecessor.PredecessorReferenceDigest = &wrongDigest
	if _, err := signNodeObservation(t, fixture, wrongPredecessor).ValidateSuccessor(first); err == nil {
		t.Fatal("successor accepted the wrong predecessor reference")
	}
	wrongSequence := nextPayload
	wrongSequence.Sequence = 3
	if _, err := signNodeObservation(t, fixture, wrongSequence).ValidateSuccessor(first); err == nil {
		t.Fatal("successor skipped a stream sequence")
	}
	wrongStream := nextPayload
	wrongStream.StreamID = uuid.New()
	if _, err := signNodeObservation(t, fixture, wrongStream).ValidateSuccessor(first); err == nil {
		t.Fatal("successor crossed streams")
	}
	wrongScope := nextPayload
	wrongScope.Authority.Scope.ScopeID = uuid.New()
	if _, err := signNodeObservation(t, fixture, wrongScope).ValidateSuccessor(first); err == nil {
		t.Fatal("successor crossed service scopes")
	}

	// Manifest revision/digest may advance under the same scope, deployment,
	// signing key, and stream. Each record is authorized against its own exact
	// historical manifest outside stream continuity validation.
	advancedAuthority := nextPayload
	advancedAuthority.Authority.AuthorityRevision++
	advancedAuthority.Authority.AuthorityManifestDigest = strings.Repeat("d", 64)
	if _, err := signNodeObservation(t, fixture, advancedAuthority).ValidateSuccessor(first); err != nil {
		t.Fatalf("continuity incorrectly froze authority revision: %v", err)
	}
}

func TestNodeTransportObservationRejectsHostileFactAndHeaderShapes(t *testing.T) {
	fixture := newNodeObservationFixture(t)
	uuidValue := uuid.MustParse("25000000-0000-0000-0000-000000000001")
	digest := strings.Repeat("a", 64)
	otherDigest := strings.Repeat("b", 64)
	component := "relay_store"
	one, two, three := uint64(1), uint64(2), uint64(3)

	validFacts := []serviceauthority.NodeTransportFact{
		factWith(
			serviceauthority.NodeTransportInvalidEnvelope,
			[]serviceauthority.NodeTransportFactReference{digestReference(serviceauthority.NodeTransportRelayEnvelopeReference, digest)},
			nil,
			serviceauthority.NodeTransportTransportRecordEvidence,
		),
		factWith(
			serviceauthority.NodeTransportReplayedEnvelope,
			[]serviceauthority.NodeTransportFactReference{digestReference(serviceauthority.NodeTransportRelayEnvelopeReference, digest)},
			nil,
			serviceauthority.NodeTransportTransportRecordEvidence,
		),
		factWith(
			serviceauthority.NodeTransportCursorRollback,
			[]serviceauthority.NodeTransportFactReference{uuidReference(serviceauthority.NodeTransportSubscriptionReference, uuidValue)},
			&serviceauthority.NodeTransportFactMeasurement{
				Kind:             serviceauthority.NodeTransportSequenceMeasurement,
				ExpectedSequence: &two, ObservedSequence: &one,
			},
			serviceauthority.NodeTransportTransportRecordEvidence,
		),
		factWith(
			serviceauthority.NodeTransportDeliveryGap,
			[]serviceauthority.NodeTransportFactReference{uuidReference(serviceauthority.NodeTransportSubscriptionReference, uuidValue)},
			&serviceauthority.NodeTransportFactMeasurement{
				Kind:             serviceauthority.NodeTransportSequenceMeasurement,
				ExpectedSequence: &one, ObservedSequence: &two,
			},
			serviceauthority.NodeTransportTransportRecordEvidence,
		),
		factWith(
			serviceauthority.NodeTransportBlobDigestMismatch,
			[]serviceauthority.NodeTransportFactReference{digestReference(serviceauthority.NodeTransportBlobReference, digest)},
			&serviceauthority.NodeTransportFactMeasurement{
				Kind:           serviceauthority.NodeTransportDigestMeasurement,
				ExpectedDigest: &digest, ObservedDigest: &otherDigest,
			},
			serviceauthority.NodeTransportTransportRecordEvidence,
		),
		factWith(
			serviceauthority.NodeTransportRoutingLeaseConflict,
			[]serviceauthority.NodeTransportFactReference{
				uuidReference(serviceauthority.NodeTransportLeaseReference, uuidValue),
				uuidReference(serviceauthority.NodeTransportMessageReference, uuid.New()),
			},
			nil,
			serviceauthority.NodeTransportTransportRecordEvidence,
		),
		factWith(
			serviceauthority.NodeTransportQuotaRateAnomaly,
			[]serviceauthority.NodeTransportFactReference{uuidReference(serviceauthority.NodeTransportMemberReference, uuidValue)},
			&serviceauthority.NodeTransportFactMeasurement{
				Kind:  serviceauthority.NodeTransportLimitMeasurement,
				Limit: &one, ObservedCount: &two, WindowMilliseconds: &three,
			},
			serviceauthority.NodeTransportTransportRecordEvidence,
		),
		factWith(
			serviceauthority.NodeTransportUnexpectedProtocolVersion,
			[]serviceauthority.NodeTransportFactReference{componentReference(component)},
			&serviceauthority.NodeTransportFactMeasurement{
				Kind:            serviceauthority.NodeTransportProtocolVersionMeasurement,
				ObservedVersion: &two, SupportedMaximum: &one,
			},
			serviceauthority.NodeTransportProtocolRecordEvidence,
		),
		factWith(
			serviceauthority.NodeTransportServiceHealthDegraded,
			[]serviceauthority.NodeTransportFactReference{componentReference(component)},
			nil,
			serviceauthority.NodeTransportServiceHealthEvidence,
		),
	}
	// Evidence is optional. When present, the kind matrix and digest/byte
	// reference remain closed; this first case proves the explicit empty form.
	validFacts[0].Evidence = []serviceauthority.NodeTransportFactEvidence{}
	for _, fact := range validFacts {
		payload := fixture.payload
		payload.Fact = fact
		if _, err := fixture.deploymentSigner.SignNodeTransportObservation(payload); err != nil {
			t.Fatalf("valid closed fact %q rejected: %v", fact.Kind, err)
		}
	}

	hostile := []struct {
		name   string
		mutate func(*serviceauthority.NodeTransportObservationPayload)
	}{
		{"missing authenticated authority", func(value *serviceauthority.NodeTransportObservationPayload) {
			value.Authority = serviceauthority.NodeTransportObservationAuthority{}
		}},
		{"service kind aliases implementation", func(value *serviceauthority.NodeTransportObservationPayload) {
			value.ServiceKind = serviceauthority.ScopeKind("facets_node")
		}},
		{"recipient authority without recipient key fingerprint", func(value *serviceauthority.NodeTransportObservationPayload) {
			value.DeliveryProtection.RecipientAgreementKeyFingerprint = ""
		}},
		{"noncanonical source revision", func(value *serviceauthority.NodeTransportObservationPayload) {
			value.Implementation.SourceRevision = strings.Repeat("A", 40)
		}},
		{"first sequence with predecessor", func(value *serviceauthority.NodeTransportObservationPayload) {
			value.PredecessorReferenceDigest = &digest
		}},
		{"wrong reference discriminator field", func(value *serviceauthority.NodeTransportObservationPayload) {
			value.Fact.References[0].Identifier = &uuidValue
		}},
		{"relay envelope under compute pool", func(value *serviceauthority.NodeTransportObservationPayload) {
			value.ServiceKind = serviceauthority.ScopeComputePool
			value.Authority.Scope.Kind = serviceauthority.ScopeComputePool
		}},
		{"measurement added to no-measurement fact", func(value *serviceauthority.NodeTransportObservationPayload) {
			value.Fact.Measurement = &serviceauthority.NodeTransportFactMeasurement{
				Kind:             serviceauthority.NodeTransportSequenceMeasurement,
				ExpectedSequence: &one, ObservedSequence: &two,
			}
		}},
		{"zero observed rollback sequence", func(value *serviceauthority.NodeTransportObservationPayload) {
			zero := uint64(0)
			value.Fact = factWith(
				serviceauthority.NodeTransportCursorRollback,
				[]serviceauthority.NodeTransportFactReference{uuidReference(serviceauthority.NodeTransportSubscriptionReference, uuidValue)},
				&serviceauthority.NodeTransportFactMeasurement{
					Kind:             serviceauthority.NodeTransportSequenceMeasurement,
					ExpectedSequence: &one, ObservedSequence: &zero,
				},
				serviceauthority.NodeTransportTransportRecordEvidence,
			)
		}},
		{"zero observed protocol version", func(value *serviceauthority.NodeTransportObservationPayload) {
			zero := uint64(0)
			value.Fact = factWith(
				serviceauthority.NodeTransportUnexpectedProtocolVersion,
				[]serviceauthority.NodeTransportFactReference{componentReference(component)},
				&serviceauthority.NodeTransportFactMeasurement{
					Kind:            serviceauthority.NodeTransportProtocolVersionMeasurement,
					ObservedVersion: &zero, SupportedMaximum: &one,
				},
				serviceauthority.NodeTransportProtocolRecordEvidence,
			)
		}},
		{"wrong evidence kind", func(value *serviceauthority.NodeTransportObservationPayload) {
			value.Fact.Evidence = []serviceauthority.NodeTransportFactEvidence{{
				ByteCount: 1, Kind: serviceauthority.NodeTransportProtocolRecordEvidence,
				ReferenceDigest: digest,
			}}
		}},
	}
	for _, test := range hostile {
		t.Run(test.name, func(t *testing.T) {
			payload := fixture.payload
			payload.Fact.References = append(
				[]serviceauthority.NodeTransportFactReference{},
				fixture.payload.Fact.References...,
			)
			test.mutate(&payload)
			if _, err := fixture.deploymentSigner.SignNodeTransportObservation(payload); err == nil {
				t.Fatal("hostile shape was signed")
			}
		})
	}
}

func TestNodeTransportObservationRejectsNoncanonicalAndHighSSignatures(t *testing.T) {
	fixture := newNodeObservationFixture(t)
	observation := signNodeObservation(t, fixture, fixture.payload)

	var decoded map[string]any
	if err := json.Unmarshal(observation.Payload, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded["unknown"] = true
	hostilePayload, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	hostile := serviceauthority.NodeTransportObservation{
		Payload: hostilePayload,
		Signature: signPortableRecord(
			t,
			fixture.deploymentKey,
			fixture.descriptor.DeploymentID,
			serviceauthority.NodeTransportObservationSignatureDomain,
			hostilePayload,
		),
	}
	if _, err := hostile.VerifiedPayload(); err == nil {
		t.Fatal("cryptographically valid payload with unknown field verified")
	}

	highS := observation
	raw, err := base64.RawURLEncoding.Strict().DecodeString(highS.Signature.Signature)
	if err != nil {
		t.Fatal(err)
	}
	s := new(big.Int).SetBytes(raw[32:])
	s.Sub(elliptic.P256().Params().N, s)
	s.FillBytes(raw[32:])
	highS.Signature.Signature = base64.RawURLEncoding.EncodeToString(raw)
	if _, err := highS.VerifiedPayload(); err == nil {
		t.Fatal("high-S equivalent signature verified")
	}
}

func TestNodeTransportProtectedEnvelopeReferenceBindsExactBytes(t *testing.T) {
	first := []byte(`{"ciphertext":"AQID","ephemeralKey":"BA","nonce":"AA","tag":"BB"}`)
	digest, err := serviceauthority.ProtectedObservationEnvelopeReferenceDigest(first)
	if err != nil || len(digest) != 64 {
		t.Fatalf("protected envelope reference failed: digest=%q err=%v", digest, err)
	}
	second := append([]byte{}, first...)
	second[len(second)-2] = 'C'
	other, err := serviceauthority.ProtectedObservationEnvelopeReferenceDigest(second)
	if err != nil || other == digest {
		t.Fatal("protected envelope metadata/ciphertext change did not change reference")
	}
	if _, err := serviceauthority.ProtectedObservationEnvelopeReferenceDigest(nil); err == nil {
		t.Fatal("empty protected envelope admitted")
	}
}

func TestNodeTransportPrincipalDeviceGrantReferenceBindsFullSignedRecord(t *testing.T) {
	first := []byte(`{"payload":"AQID","signature":{"algorithm":"ES256","signature":"AA"}}`)
	digest, err := serviceauthority.RecipientPrincipalDeviceGrantRecordReferenceDigest(first)
	if err != nil || len(digest) != 64 {
		t.Fatalf("principal-device-grant reference failed: digest=%q err=%v", digest, err)
	}
	second := bytes.Replace(first, []byte(`"signature":"AA"`), []byte(`"signature":"AB"`), 1)
	other, err := serviceauthority.RecipientPrincipalDeviceGrantRecordReferenceDigest(second)
	if err != nil || other == digest {
		t.Fatal("principal-device-grant signature mutation did not change reference")
	}
	if _, err := serviceauthority.RecipientPrincipalDeviceGrantRecordReferenceDigest(nil); err == nil {
		t.Fatal("empty principal-device-grant record admitted")
	}
	tooLarge := make(
		[]byte,
		serviceauthority.MaximumRecipientPrincipalDeviceGrantRecordByteCount+1,
	)
	if _, err := serviceauthority.RecipientPrincipalDeviceGrantRecordReferenceDigest(tooLarge); err == nil {
		t.Fatal("oversized principal-device-grant record admitted")
	}
}

func newNodeObservationFixture(t *testing.T) nodeObservationFixture {
	t.Helper()
	deploymentID := uuid.MustParse("21000000-0000-0000-0000-000000000001")
	deploymentScalar := make([]byte, 32)
	deploymentScalar[31] = 2
	deploymentKey := privateKey(t, deploymentScalar)
	deploymentSigner, err := serviceauthority.NewDeploymentSigner(deploymentID, deploymentScalar)
	if err != nil {
		t.Fatal(err)
	}
	pin := strings.Repeat("1", 64)
	routeID := uuid.MustParse("21000000-0000-0000-0000-000000000002")
	descriptor := serviceauthority.DeploymentDescriptor{
		CreatedAtMilliseconds: 1_000,
		DeploymentID:          deploymentID,
		PublicSigningKeyX963:  deploymentSigner.PublicSigningKeyX963(),
		Routes: []serviceauthority.TransportRoute{{
			Endpoint: "https://node.example:8443", Kind: serviceauthority.RouteDirectHTTPS,
			NetworkScope: serviceauthority.NetworkPublic, RouteID: routeID,
			ServerAuthentication: serviceauthority.ServerAuthentication{
				Kind: "pinned_spki_sha256", PinnedSPKISHA256: &pin,
			},
		}},
		SigningKeyFingerprint: deploymentSigner.SigningKeyFingerprint(),
		Version:               serviceauthority.SchemaVersion,
	}
	scope := serviceauthority.Scope{
		Kind:    serviceauthority.ScopeDeviceSync,
		ScopeID: uuid.MustParse("22000000-0000-0000-0000-000000000001"),
	}
	authorityScalar := make([]byte, 32)
	authorityScalar[31] = 3
	authorityKey := privateKey(t, authorityScalar)
	authorityID := uuid.MustParse("22000000-0000-0000-0000-000000000002")
	authorityPublic := elliptic.Marshal(
		elliptic.P256(), authorityKey.PublicKey.X, authorityKey.PublicKey.Y,
	)
	anchor := serviceauthority.TrustAnchor{
		PublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(authorityPublic),
		Scope:                 scope,
		SignerID:              authorityID,
		SigningKeyFingerprint: sha256Hex(authorityPublic),
		Version:               serviceauthority.SchemaVersion,
	}
	policy := serviceauthority.TransportPolicy{
		AllowsPublicDirectBulkTransfer: true,
		BulkRouteIDs:                   []uuid.UUID{routeID}, ControlRouteIDs: []uuid.UUID{routeID},
		MessageRouteIDs: []uuid.UUID{routeID}, Version: serviceauthority.SchemaVersion,
	}
	manifestPayload := serviceauthority.ManifestPayload{
		ActiveDeployment: descriptor, IssuedAtMilliseconds: 1_000,
		PreparedDeployments: []serviceauthority.DeploymentDescriptor{},
		Revision:            1, Scope: scope, Transition: "initial_activation", TransportPolicy: policy,
		ValidFromMilliseconds: 1_000, Version: serviceauthority.SchemaVersion,
	}
	manifestBytes, err := json.Marshal(manifestPayload)
	if err != nil {
		t.Fatal(err)
	}
	manifest := serviceauthority.Manifest{
		Payload: manifestBytes,
		Signature: signPortableRecord(
			t,
			authorityKey,
			authorityID,
			"Facets service authority manifest v1\x00",
			manifestBytes,
		),
	}
	manifestDigest, err := manifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	protectedEnvelope := []byte(`{"ciphertext":"AQID","ephemeralKey":"BA","nonce":"AA","tag":"BB"}`)
	protectedDigest, err := serviceauthority.ProtectedObservationEnvelopeReferenceDigest(
		protectedEnvelope,
	)
	if err != nil {
		t.Fatal(err)
	}
	recipient := serviceauthority.NodeTransportExpectedRecipient{
		DeviceID:                uuid.MustParse("23000000-0000-0000-0000-000000000001"),
		AgreementKeyFingerprint: strings.Repeat("c", 64),
		RecipientAuthorityReference: deviceSyncRecipientAuthorityReference(
			uuid.MustParse("23000000-0000-0000-0000-000000000002"),
			4,
			strings.Repeat("f", 64),
		),
		EncryptionSuite: serviceauthority.NodeTransportObservationEncryptionSuite,
	}
	relayDigest := strings.Repeat("d", 64)
	payload := serviceauthority.NodeTransportObservationPayload{
		Authority: serviceauthority.NodeTransportObservationAuthority{
			AuthorityManifestDigest: manifestDigest, AuthorityRevision: 1, Scope: scope,
		},
		CommittedAtMilliseconds: 1_101,
		DeliveryProtection: serviceauthority.NodeTransportDeliveryProtection{
			DeliveryRecipientDeviceID:                   recipient.DeviceID,
			EncryptionSuite:                             serviceauthority.NodeTransportObservationEncryptionSuite,
			ProtectedObservationEnvelopeByteCount:       uint64(len(protectedEnvelope)),
			ProtectedObservationEnvelopeReferenceDigest: protectedDigest,
			RecipientAgreementKeyFingerprint:            recipient.AgreementKeyFingerprint,
			RecipientAuthorityReference:                 recipient.RecipientAuthorityReference,
		},
		DeploymentID: deploymentID,
		Fact: factWith(
			serviceauthority.NodeTransportReplayedEnvelope,
			[]serviceauthority.NodeTransportFactReference{
				digestReference(serviceauthority.NodeTransportRelayEnvelopeReference, relayDigest),
			},
			nil,
			serviceauthority.NodeTransportTransportRecordEvidence,
		),
		Implementation: serviceauthority.NodeTransportImplementation{
			ImplementationIdentifier:   serviceauthority.NodeTransportObservationImplementationID,
			ObservationProtocolVersion: serviceauthority.NodeTransportObservationVersion,
			ServiceProtocolIdentifier:  "facets_node_http", ServiceProtocolVersion: 1,
			SourceRevision: strings.Repeat("a", 40), SourceTreeDigest: strings.Repeat("b", 64),
		},
		ObservationID:          uuid.MustParse("24000000-0000-0000-0000-000000000001"),
		OccurredAtMilliseconds: 1_100,
		Sequence:               1, ServiceKind: scope.Kind,
		SigningKeyFingerprint: deploymentSigner.SigningKeyFingerprint(),
		StreamID:              uuid.MustParse("24000000-0000-0000-0000-000000000003"),
		Version:               serviceauthority.NodeTransportObservationVersion,
	}
	return nodeObservationFixture{
		anchor: anchor, authorityKey: authorityKey, deploymentKey: deploymentKey,
		deploymentSigner: deploymentSigner, descriptor: descriptor, manifest: manifest,
		manifestDigest: manifestDigest, payload: payload, recipient: recipient,
	}
}

func deviceSyncRecipientAuthorityReference(
	grantID uuid.UUID,
	deviceGeneration uint64,
	referenceDigest string,
) serviceauthority.NodeTransportRecipientAuthorityReference {
	return serviceauthority.NodeTransportRecipientAuthorityReference{
		DeviceGeneration: &deviceGeneration,
		GrantID:          &grantID,
		Kind:             serviceauthority.NodeTransportDeviceSyncPrincipalGrantReference,
		ReferenceDigest:  referenceDigest,
	}
}

func sharedSpaceRecipientAuthorityReference(
	participantID uuid.UUID,
	rosterRevision uint64,
	referenceDigest string,
) serviceauthority.NodeTransportRecipientAuthorityReference {
	return serviceauthority.NodeTransportRecipientAuthorityReference{
		Kind:            serviceauthority.NodeTransportSharedSpaceRosterReference,
		ParticipantID:   &participantID,
		ReferenceDigest: referenceDigest,
		RosterRevision:  &rosterRevision,
	}
}

func factWith(
	kind serviceauthority.NodeTransportFactKind,
	references []serviceauthority.NodeTransportFactReference,
	measurement *serviceauthority.NodeTransportFactMeasurement,
	evidenceKind serviceauthority.NodeTransportFactEvidenceKind,
) serviceauthority.NodeTransportFact {
	return serviceauthority.NodeTransportFact{
		Evidence: []serviceauthority.NodeTransportFactEvidence{{
			ByteCount: 12, Kind: evidenceKind, ReferenceDigest: strings.Repeat("e", 64),
		}},
		Kind: kind, Measurement: measurement, References: references,
	}
}

func uuidReference(
	kind serviceauthority.NodeTransportFactReferenceKind,
	value uuid.UUID,
) serviceauthority.NodeTransportFactReference {
	return serviceauthority.NodeTransportFactReference{Identifier: &value, Kind: kind}
}

func digestReference(
	kind serviceauthority.NodeTransportFactReferenceKind,
	value string,
) serviceauthority.NodeTransportFactReference {
	return serviceauthority.NodeTransportFactReference{Kind: kind, ReferenceDigest: &value}
}

func componentReference(value string) serviceauthority.NodeTransportFactReference {
	return serviceauthority.NodeTransportFactReference{
		Component: &value, Kind: serviceauthority.NodeTransportServiceComponentReference,
	}
}

func signNodeObservation(
	t *testing.T,
	fixture nodeObservationFixture,
	payload serviceauthority.NodeTransportObservationPayload,
) serviceauthority.NodeTransportObservation {
	t.Helper()
	observation, err := fixture.deploymentSigner.SignNodeTransportObservation(payload)
	if err != nil {
		t.Fatalf("sign Node transport observation: %v", err)
	}
	return observation
}

func privateKey(t *testing.T, scalar []byte) *ecdsa.PrivateKey {
	t.Helper()
	curve := elliptic.P256()
	d := new(big.Int).SetBytes(scalar)
	if len(scalar) != 32 || d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		t.Fatal("invalid test private scalar")
	}
	x, y := curve.ScalarBaseMult(scalar)
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d,
	}
}

func signPortableRecord(
	t *testing.T,
	key *ecdsa.PrivateKey,
	signerID uuid.UUID,
	domain string,
	payload []byte,
) serviceauthority.Signature {
	t.Helper()
	digest := sha256.Sum256(append([]byte(domain), payload...))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	order := elliptic.P256().Params().N
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(order), 1)) > 0 {
		s.Sub(order, s)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	public := elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
	return serviceauthority.Signature{
		Algorithm: "ES256", PublicSigningKeyX963: base64.RawURLEncoding.EncodeToString(public),
		Signature: base64.RawURLEncoding.EncodeToString(raw), SignerID: signerID,
		SigningKeyFingerprint: sha256Hex(public),
	}
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

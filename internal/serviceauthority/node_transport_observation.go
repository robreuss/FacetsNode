package serviceauthority

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/google/uuid"
)

const (
	NodeTransportObservationVersion                     = 1
	MaximumNodeTransportObservationPayloadByteCount     = 64 * 1024
	MaximumProtectedObservationEnvelopeByteCount        = 128 * 1024
	MaximumNodeTransportFactEvidenceByteCount           = 128 * 1024
	NodeTransportObservationSignatureDomain             = "Facets Node transport observation v1\x00"
	NodeTransportObservationReferenceDomain             = "Facets Node transport observation reference v1\x00"
	NodeTransportProtectedEnvelopeReferenceDomain       = "Facets Node protected observation envelope reference v1\x00"
	NodeTransportRecipientPrincipalGrantReferenceDomain = "Facets Node recipient principal device grant record reference v1\x00"
	NodeTransportObservationEncryptionSuite             = "P256-HKDF-SHA256+A256GCM"
	NodeTransportObservationImplementationID            = "facets_node_go"
	MaximumRecipientPrincipalDeviceGrantRecordByteCount = 64 * 1024
)

var nodeTransportMachineIdentifier = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type NodeTransportFactKind string

const (
	NodeTransportInvalidEnvelope           NodeTransportFactKind = "invalid_envelope"
	NodeTransportReplayedEnvelope          NodeTransportFactKind = "replayed_envelope"
	NodeTransportCursorRollback            NodeTransportFactKind = "cursor_rollback"
	NodeTransportDeliveryGap               NodeTransportFactKind = "delivery_gap"
	NodeTransportBlobDigestMismatch        NodeTransportFactKind = "blob_digest_mismatch"
	NodeTransportRoutingLeaseConflict      NodeTransportFactKind = "routing_lease_conflict"
	NodeTransportQuotaRateAnomaly          NodeTransportFactKind = "quota_rate_anomaly"
	NodeTransportUnexpectedProtocolVersion NodeTransportFactKind = "unexpected_protocol_version"
	NodeTransportServiceHealthDegraded     NodeTransportFactKind = "service_health_degraded"
)

type NodeTransportFactReferenceKind string

const (
	NodeTransportSubscriptionReference     NodeTransportFactReferenceKind = "subscription"
	NodeTransportMemberReference           NodeTransportFactReferenceKind = "member"
	NodeTransportReplicaReference          NodeTransportFactReferenceKind = "replica"
	NodeTransportLeaseReference            NodeTransportFactReferenceKind = "lease"
	NodeTransportMessageReference          NodeTransportFactReferenceKind = "message"
	NodeTransportRelayEnvelopeReference    NodeTransportFactReferenceKind = "relay_envelope"
	NodeTransportBlobReference             NodeTransportFactReferenceKind = "blob"
	NodeTransportServiceComponentReference NodeTransportFactReferenceKind = "service_component"
)

type NodeTransportFactMeasurementKind string

const (
	NodeTransportSequenceMeasurement        NodeTransportFactMeasurementKind = "sequence"
	NodeTransportDigestMeasurement          NodeTransportFactMeasurementKind = "digest"
	NodeTransportLimitMeasurement           NodeTransportFactMeasurementKind = "limit"
	NodeTransportProtocolVersionMeasurement NodeTransportFactMeasurementKind = "protocol_version"
)

type NodeTransportFactEvidenceKind string

const (
	NodeTransportTransportRecordEvidence NodeTransportFactEvidenceKind = "transport_record"
	NodeTransportProtocolRecordEvidence  NodeTransportFactEvidenceKind = "protocol_record"
	NodeTransportServiceHealthEvidence   NodeTransportFactEvidenceKind = "service_health_record"
)

// NodeTransportFactReference is a closed discriminated reference. UUID,
// digest, and component kinds use distinct fields so an attacker-controlled
// identifier cannot be reinterpreted as another reference class.
type NodeTransportFactReference struct {
	Component       *string                        `json:"component,omitempty"`
	Identifier      *uuid.UUID                     `json:"identifier,omitempty"`
	Kind            NodeTransportFactReferenceKind `json:"kind"`
	ReferenceDigest *string                        `json:"referenceDigest,omitempty"`
}

// NodeTransportFactMeasurement is a closed discriminated measurement. Every
// kind admits exactly its named fields; absent values remain absent on wire.
type NodeTransportFactMeasurement struct {
	ExpectedDigest     *string                          `json:"expectedDigest,omitempty"`
	ExpectedSequence   *uint64                          `json:"expectedSequence,omitempty"`
	Kind               NodeTransportFactMeasurementKind `json:"kind"`
	Limit              *uint64                          `json:"limit,omitempty"`
	ObservedCount      *uint64                          `json:"observedCount,omitempty"`
	ObservedDigest     *string                          `json:"observedDigest,omitempty"`
	ObservedSequence   *uint64                          `json:"observedSequence,omitempty"`
	ObservedVersion    *uint64                          `json:"observedVersion,omitempty"`
	SupportedMaximum   *uint64                          `json:"supportedMaximum,omitempty"`
	WindowMilliseconds *uint64                          `json:"windowMilliseconds,omitempty"`
}

type NodeTransportFactEvidence struct {
	ByteCount       uint64                        `json:"byteCount"`
	Kind            NodeTransportFactEvidenceKind `json:"kind"`
	ReferenceDigest string                        `json:"referenceDigest"`
}

// NodeTransportFact is deliberately closed and content-blind. Validate gives
// every fact kind one exact reference/measurement/evidence shape. No map,
// arbitrary text, path, content value, prompt, or device-local Space runtime
// can enter a portable recipient-visible record through this vocabulary.
type NodeTransportFact struct {
	Evidence    []NodeTransportFactEvidence   `json:"evidence"`
	Kind        NodeTransportFactKind         `json:"kind"`
	Measurement *NodeTransportFactMeasurement `json:"measurement,omitempty"`
	References  []NodeTransportFactReference  `json:"references"`
}

type NodeTransportObservationAuthority struct {
	AuthorityManifestDigest string `json:"authorityManifestDigest"`
	AuthorityRevision       uint64 `json:"authorityRevision"`
	Scope                   Scope  `json:"scope"`
}

type NodeTransportRecipientAuthorityReferenceKind string

const (
	NodeTransportDeviceSyncPrincipalGrantReference NodeTransportRecipientAuthorityReferenceKind = "device_sync_principal_grant"
	NodeTransportSharedSpaceRosterReference        NodeTransportRecipientAuthorityReferenceKind = "shared_space_roster"
)

// NodeTransportRecipientAuthorityReference identifies the exact independently
// authenticated recipient-authority record that a later inbox must consult.
// It does not itself authorize that record, recipient, key, or capability.
// The declaration order is canonical sorted-key JSON.
type NodeTransportRecipientAuthorityReference struct {
	DeviceGeneration *uint64                                      `json:"deviceGeneration,omitempty"`
	GrantID          *uuid.UUID                                   `json:"grantID,omitempty"`
	Kind             NodeTransportRecipientAuthorityReferenceKind `json:"kind"`
	ParticipantID    *uuid.UUID                                   `json:"participantID,omitempty"`
	ReferenceDigest  string                                       `json:"referenceDigest"`
	RosterRevision   *uint64                                      `json:"rosterRevision,omitempty"`
}

type NodeTransportDeliveryProtection struct {
	DeliveryRecipientDeviceID                   uuid.UUID                                `json:"deliveryRecipientDeviceID"`
	EncryptionSuite                             string                                   `json:"encryptionSuite"`
	ProtectedObservationEnvelopeByteCount       uint64                                   `json:"protectedObservationEnvelopeByteCount"`
	ProtectedObservationEnvelopeReferenceDigest string                                   `json:"protectedObservationEnvelopeReferenceDigest"`
	RecipientAgreementKeyFingerprint            string                                   `json:"recipientAgreementKeyFingerprint"`
	RecipientAuthorityReference                 NodeTransportRecipientAuthorityReference `json:"recipientAuthorityReference"`
}

type NodeTransportImplementation struct {
	ImplementationIdentifier   string `json:"implementationIdentifier"`
	ObservationProtocolVersion int    `json:"observationProtocolVersion"`
	ServiceProtocolIdentifier  string `json:"serviceProtocolIdentifier"`
	ServiceProtocolVersion     uint64 `json:"serviceProtocolVersion"`
	SourceRevision             string `json:"sourceRevision"`
	SourceTreeDigest           string `json:"sourceTreeDigest"`
}

// NodeTransportObservationPayload is a deployment-signed, recipient-bound
// transport fact. It is not a local Facets SecurityObservation, receipt,
// finding, action, backup claim, or proof that the deployment told the whole
// truth. Field declaration order is canonical sorted-key JSON and must remain
// in lockstep with the Swift portable contract.
type NodeTransportObservationPayload struct {
	Authority                  NodeTransportObservationAuthority `json:"authority"`
	CommittedAtMilliseconds    int64                             `json:"committedAtMilliseconds"`
	DeliveryProtection         NodeTransportDeliveryProtection   `json:"deliveryProtection"`
	DeploymentID               uuid.UUID                         `json:"deploymentID"`
	Fact                       NodeTransportFact                 `json:"fact"`
	Implementation             NodeTransportImplementation       `json:"implementation"`
	ObservationID              uuid.UUID                         `json:"observationID"`
	OccurredAtMilliseconds     int64                             `json:"occurredAtMilliseconds"`
	PredecessorReferenceDigest *string                           `json:"predecessorReferenceDigest,omitempty"`
	Sequence                   uint64                            `json:"sequence"`
	ServiceKind                ScopeKind                         `json:"serviceKind"`
	SigningKeyFingerprint      string                            `json:"signingKeyFingerprint"`
	StreamID                   uuid.UUID                         `json:"streamID"`
	Version                    int                               `json:"version"`
}

type NodeTransportObservation struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

type NodeTransportExpectedRecipient struct {
	DeviceID                    uuid.UUID
	AgreementKeyFingerprint     string
	RecipientAuthorityReference NodeTransportRecipientAuthorityReference
	EncryptionSuite             string
}

func (authority NodeTransportObservationAuthority) Validate() error {
	if authority.Scope.Validate() != nil || authority.AuthorityRevision == 0 ||
		!validDigest(authority.AuthorityManifestDigest) {
		return ErrInvalid
	}
	return nil
}

func (reference NodeTransportRecipientAuthorityReference) Validate() error {
	if !validDigest(reference.ReferenceDigest) {
		return ErrInvalid
	}
	switch reference.Kind {
	case NodeTransportDeviceSyncPrincipalGrantReference:
		if reference.DeviceGeneration == nil || *reference.DeviceGeneration == 0 ||
			reference.GrantID == nil || *reference.GrantID == uuid.Nil ||
			reference.ParticipantID != nil || reference.RosterRevision != nil {
			return ErrInvalid
		}
	case NodeTransportSharedSpaceRosterReference:
		if reference.DeviceGeneration != nil || reference.GrantID != nil ||
			reference.ParticipantID == nil || *reference.ParticipantID == uuid.Nil ||
			reference.RosterRevision == nil || *reference.RosterRevision == 0 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (reference NodeTransportRecipientAuthorityReference) equals(
	other NodeTransportRecipientAuthorityReference,
) bool {
	if reference.Kind != other.Kind || reference.ReferenceDigest != other.ReferenceDigest {
		return false
	}
	switch reference.Kind {
	case NodeTransportDeviceSyncPrincipalGrantReference:
		return reference.DeviceGeneration != nil && other.DeviceGeneration != nil &&
			*reference.DeviceGeneration == *other.DeviceGeneration &&
			reference.GrantID != nil && other.GrantID != nil &&
			*reference.GrantID == *other.GrantID
	case NodeTransportSharedSpaceRosterReference:
		return reference.ParticipantID != nil && other.ParticipantID != nil &&
			*reference.ParticipantID == *other.ParticipantID &&
			reference.RosterRevision != nil && other.RosterRevision != nil &&
			*reference.RosterRevision == *other.RosterRevision
	default:
		return false
	}
}

func (protection NodeTransportDeliveryProtection) Validate() error {
	if protection.DeliveryRecipientDeviceID == uuid.Nil ||
		protection.EncryptionSuite != NodeTransportObservationEncryptionSuite ||
		protection.ProtectedObservationEnvelopeByteCount == 0 ||
		protection.ProtectedObservationEnvelopeByteCount > MaximumProtectedObservationEnvelopeByteCount ||
		!validDigest(protection.ProtectedObservationEnvelopeReferenceDigest) ||
		!validDigest(protection.RecipientAgreementKeyFingerprint) ||
		protection.RecipientAuthorityReference.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

func (implementation NodeTransportImplementation) Validate() error {
	if !nodeTransportMachineIdentifier.MatchString(implementation.ImplementationIdentifier) ||
		implementation.ObservationProtocolVersion != NodeTransportObservationVersion ||
		!nodeTransportMachineIdentifier.MatchString(implementation.ServiceProtocolIdentifier) ||
		implementation.ServiceProtocolVersion <= 0 ||
		len(implementation.SourceRevision) != 40 ||
		strings.ToLower(implementation.SourceRevision) != implementation.SourceRevision ||
		!isHex(implementation.SourceRevision) || !validDigest(implementation.SourceTreeDigest) {
		return ErrInvalid
	}
	return nil
}

func (payload NodeTransportObservationPayload) Validate() error {
	if payload.Version != NodeTransportObservationVersion ||
		payload.Authority.Validate() != nil || payload.DeliveryProtection.Validate() != nil ||
		payload.Implementation.Validate() != nil || payload.Fact.Validate() != nil ||
		payload.DeploymentID == uuid.Nil || payload.ObservationID == uuid.Nil ||
		payload.StreamID == uuid.Nil || payload.Sequence == 0 ||
		payload.ServiceKind != payload.Authority.Scope.Kind ||
		(payload.Fact.hasRelayEnvelopeReference() &&
			payload.ServiceKind != ScopeDeviceSync &&
			payload.ServiceKind != ScopeSharedSpace) ||
		!validDigest(payload.SigningKeyFingerprint) ||
		payload.OccurredAtMilliseconds < 0 ||
		payload.CommittedAtMilliseconds < payload.OccurredAtMilliseconds {
		return ErrInvalid
	}
	switch payload.ServiceKind {
	case ScopeDeviceSync:
		if payload.DeliveryProtection.RecipientAuthorityReference.Kind !=
			NodeTransportDeviceSyncPrincipalGrantReference {
			return ErrInvalid
		}
	case ScopeSharedSpace:
		if payload.DeliveryProtection.RecipientAuthorityReference.Kind !=
			NodeTransportSharedSpaceRosterReference {
			return ErrInvalid
		}
	case ScopeComputePool:
		return ErrInvalid
	default:
		return ErrInvalid
	}
	if payload.Sequence == 1 {
		if payload.PredecessorReferenceDigest != nil {
			return ErrInvalid
		}
	} else if payload.PredecessorReferenceDigest == nil ||
		!validDigest(*payload.PredecessorReferenceDigest) {
		return ErrInvalid
	}
	return nil
}

func (fact NodeTransportFact) hasRelayEnvelopeReference() bool {
	for _, reference := range fact.References {
		if reference.Kind == NodeTransportRelayEnvelopeReference {
			return true
		}
	}
	return false
}

func (fact NodeTransportFact) Validate() error {
	if fact.Evidence == nil || fact.References == nil ||
		len(fact.Evidence) > 8 || len(fact.References) > 16 ||
		!sortedUniqueFactEvidence(fact.Evidence) ||
		!sortedUniqueFactReferences(fact.References) {
		return ErrInvalid
	}
	for _, reference := range fact.References {
		if reference.Validate() != nil {
			return ErrInvalid
		}
	}
	for _, evidence := range fact.Evidence {
		if evidence.Validate() != nil {
			return ErrInvalid
		}
	}
	if fact.Measurement != nil && fact.Measurement.Validate() != nil {
		return ErrInvalid
	}

	switch fact.Kind {
	case NodeTransportInvalidEnvelope, NodeTransportReplayedEnvelope:
		return fact.requires(
			[]NodeTransportFactReferenceKind{NodeTransportRelayEnvelopeReference},
			"",
			NodeTransportTransportRecordEvidence,
		)
	case NodeTransportCursorRollback:
		if fact.requires(
			[]NodeTransportFactReferenceKind{NodeTransportSubscriptionReference},
			NodeTransportSequenceMeasurement,
			NodeTransportTransportRecordEvidence,
		) != nil || *fact.Measurement.ObservedSequence >= *fact.Measurement.ExpectedSequence {
			return ErrInvalid
		}
		return nil
	case NodeTransportDeliveryGap:
		if fact.requires(
			[]NodeTransportFactReferenceKind{NodeTransportSubscriptionReference},
			NodeTransportSequenceMeasurement,
			NodeTransportTransportRecordEvidence,
		) != nil || *fact.Measurement.ExpectedSequence == 0 ||
			*fact.Measurement.ObservedSequence <= *fact.Measurement.ExpectedSequence {
			return ErrInvalid
		}
		return nil
	case NodeTransportBlobDigestMismatch:
		if fact.requires(
			[]NodeTransportFactReferenceKind{NodeTransportBlobReference},
			NodeTransportDigestMeasurement,
			NodeTransportTransportRecordEvidence,
		) != nil || *fact.Measurement.ExpectedDigest == *fact.Measurement.ObservedDigest {
			return ErrInvalid
		}
		return nil
	case NodeTransportRoutingLeaseConflict:
		return fact.requires(
			[]NodeTransportFactReferenceKind{NodeTransportLeaseReference, NodeTransportMessageReference},
			"",
			NodeTransportTransportRecordEvidence,
		)
	case NodeTransportQuotaRateAnomaly:
		if len(fact.References) != 1 ||
			(fact.References[0].Kind != NodeTransportSubscriptionReference &&
				fact.References[0].Kind != NodeTransportMemberReference &&
				fact.References[0].Kind != NodeTransportReplicaReference) ||
			fact.requires(
				[]NodeTransportFactReferenceKind{fact.References[0].Kind},
				NodeTransportLimitMeasurement,
				NodeTransportTransportRecordEvidence,
			) != nil || *fact.Measurement.Limit == 0 ||
			*fact.Measurement.WindowMilliseconds == 0 ||
			*fact.Measurement.ObservedCount <= *fact.Measurement.Limit {
			return ErrInvalid
		}
		return nil
	case NodeTransportUnexpectedProtocolVersion:
		if fact.requires(
			[]NodeTransportFactReferenceKind{NodeTransportServiceComponentReference},
			NodeTransportProtocolVersionMeasurement,
			NodeTransportProtocolRecordEvidence,
		) != nil || *fact.Measurement.ObservedVersion == *fact.Measurement.SupportedMaximum {
			return ErrInvalid
		}
		return nil
	case NodeTransportServiceHealthDegraded:
		return fact.requires(
			[]NodeTransportFactReferenceKind{NodeTransportServiceComponentReference},
			"",
			NodeTransportServiceHealthEvidence,
		)
	default:
		return ErrInvalid
	}
}

func (reference NodeTransportFactReference) Validate() error {
	identifierPresent := reference.Identifier != nil
	digestPresent := reference.ReferenceDigest != nil
	componentPresent := reference.Component != nil
	if boolCount(identifierPresent, digestPresent, componentPresent) != 1 {
		return ErrInvalid
	}
	switch reference.Kind {
	case NodeTransportSubscriptionReference, NodeTransportMemberReference,
		NodeTransportReplicaReference, NodeTransportLeaseReference,
		NodeTransportMessageReference:
		if !identifierPresent || *reference.Identifier == uuid.Nil {
			return ErrInvalid
		}
	case NodeTransportRelayEnvelopeReference, NodeTransportBlobReference:
		if !digestPresent || !validDigest(*reference.ReferenceDigest) {
			return ErrInvalid
		}
	case NodeTransportServiceComponentReference:
		if !componentPresent || !nodeTransportMachineIdentifier.MatchString(*reference.Component) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (measurement NodeTransportFactMeasurement) Validate() error {
	fields := boolCount(
		measurement.ExpectedDigest != nil,
		measurement.ExpectedSequence != nil,
		measurement.Limit != nil,
		measurement.ObservedCount != nil,
		measurement.ObservedDigest != nil,
		measurement.ObservedSequence != nil,
		measurement.ObservedVersion != nil,
		measurement.SupportedMaximum != nil,
		measurement.WindowMilliseconds != nil,
	)
	switch measurement.Kind {
	case NodeTransportSequenceMeasurement:
		if fields != 2 || measurement.ExpectedSequence == nil ||
			measurement.ObservedSequence == nil ||
			*measurement.ExpectedSequence == 0 ||
			*measurement.ObservedSequence == 0 ||
			*measurement.ExpectedSequence == *measurement.ObservedSequence {
			return ErrInvalid
		}
	case NodeTransportDigestMeasurement:
		if fields != 2 || measurement.ExpectedDigest == nil ||
			measurement.ObservedDigest == nil ||
			!validDigest(*measurement.ExpectedDigest) ||
			!validDigest(*measurement.ObservedDigest) ||
			*measurement.ExpectedDigest == *measurement.ObservedDigest {
			return ErrInvalid
		}
	case NodeTransportLimitMeasurement:
		if fields != 3 || measurement.Limit == nil || measurement.ObservedCount == nil ||
			measurement.WindowMilliseconds == nil ||
			*measurement.Limit == 0 ||
			*measurement.ObservedCount <= *measurement.Limit ||
			*measurement.WindowMilliseconds == 0 {
			return ErrInvalid
		}
	case NodeTransportProtocolVersionMeasurement:
		if fields != 2 || measurement.ObservedVersion == nil ||
			measurement.SupportedMaximum == nil ||
			*measurement.ObservedVersion == 0 ||
			*measurement.SupportedMaximum == 0 ||
			*measurement.ObservedVersion == *measurement.SupportedMaximum {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (evidence NodeTransportFactEvidence) Validate() error {
	if evidence.ByteCount == 0 || evidence.ByteCount > MaximumNodeTransportFactEvidenceByteCount ||
		!validDigest(evidence.ReferenceDigest) {
		return ErrInvalid
	}
	switch evidence.Kind {
	case NodeTransportTransportRecordEvidence, NodeTransportProtocolRecordEvidence,
		NodeTransportServiceHealthEvidence:
		return nil
	default:
		return ErrInvalid
	}
}

func (fact NodeTransportFact) requires(
	references []NodeTransportFactReferenceKind,
	measurement NodeTransportFactMeasurementKind,
	evidence NodeTransportFactEvidenceKind,
) error {
	if len(fact.References) != len(references) {
		return ErrInvalid
	}
	for index, kind := range references {
		if fact.References[index].Kind != kind {
			return ErrInvalid
		}
	}
	if measurement == "" {
		if fact.Measurement != nil {
			return ErrInvalid
		}
	} else if fact.Measurement == nil || fact.Measurement.Kind != measurement {
		return ErrInvalid
	}
	for _, item := range fact.Evidence {
		if item.Kind != evidence {
			return ErrInvalid
		}
	}
	return nil
}

func sortedUniqueFactReferences(values []NodeTransportFactReference) bool {
	return sort.SliceIsSorted(values, func(left, right int) bool {
		return factReferenceSortKey(values[left]) < factReferenceSortKey(values[right])
	}) && noAdjacentReferenceKeys(values)
}

func noAdjacentReferenceKeys(values []NodeTransportFactReference) bool {
	for index := 1; index < len(values); index++ {
		if factReferenceSortKey(values[index-1]) == factReferenceSortKey(values[index]) {
			return false
		}
	}
	return true
}

func factReferenceSortKey(value NodeTransportFactReference) string {
	key := string(value.Kind) + "\x00"
	if value.Component != nil {
		return key + *value.Component
	}
	if value.Identifier != nil {
		return key + value.Identifier.String()
	}
	if value.ReferenceDigest != nil {
		return key + *value.ReferenceDigest
	}
	return key
}

func sortedUniqueFactEvidence(values []NodeTransportFactEvidence) bool {
	return sort.SliceIsSorted(values, func(left, right int) bool {
		return factEvidenceSortKey(values[left]) < factEvidenceSortKey(values[right])
	}) && noAdjacentEvidenceKeys(values)
}

func noAdjacentEvidenceKeys(values []NodeTransportFactEvidence) bool {
	for index := 1; index < len(values); index++ {
		if factEvidenceSortKey(values[index-1]) == factEvidenceSortKey(values[index]) {
			return false
		}
	}
	return true
}

func factEvidenceSortKey(value NodeTransportFactEvidence) string {
	return string(value.Kind) + "\x00" + value.ReferenceDigest
}

func boolCount(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}

func (signer *DeploymentSigner) SignNodeTransportObservation(
	payload NodeTransportObservationPayload,
) (NodeTransportObservation, error) {
	if signer == nil || payload.Validate() != nil ||
		payload.DeploymentID != signer.DeploymentID() ||
		payload.SigningKeyFingerprint != signer.SigningKeyFingerprint() {
		return NodeTransportObservation{}, ErrInvalid
	}
	encoded, err := canonicalJSONWithLimit(
		payload,
		MaximumNodeTransportObservationPayloadByteCount,
	)
	if err != nil {
		return NodeTransportObservation{}, ErrInvalid
	}
	signature, err := signer.signRecord(NodeTransportObservationSignatureDomain, encoded)
	if err != nil {
		return NodeTransportObservation{}, err
	}
	return NodeTransportObservation{Payload: encoded, Signature: signature}, nil
}

// VerifiedPayload proves only canonical structure and cryptographic integrity
// under the key embedded in Signature. It does not authorize that key,
// deployment, service scope, authority manifest, recipient, or stream.
func (observation NodeTransportObservation) VerifiedPayload() (
	NodeTransportObservationPayload,
	error,
) {
	var payload NodeTransportObservationPayload
	if len(observation.Payload) == 0 ||
		len(observation.Payload) > MaximumNodeTransportObservationPayloadByteCount ||
		verifyCanonicalRecord(
			observation.Payload,
			observation.Signature,
			NodeTransportObservationSignatureDomain,
			&payload,
		) != nil || payload.Validate() != nil ||
		payload.DeploymentID != observation.Signature.SignerID ||
		payload.SigningKeyFingerprint != observation.Signature.SigningKeyFingerprint {
		return NodeTransportObservationPayload{}, ErrInvalid
	}
	return payload, nil
}

// Authorize separately binds a self-verified record to an independently
// trusted service-authority manifest and its trust anchor. The historical
// manifest supplied here must have been resolved by exact manifest digest;
// using an embedded or current deployment key by itself is not authorization.
func (observation NodeTransportObservation) Authorize(
	manifest Manifest,
	anchor TrustAnchor,
) (NodeTransportObservationPayload, error) {
	payload, err := observation.VerifiedPayload()
	if err != nil {
		return NodeTransportObservationPayload{}, ErrInvalid
	}
	manifestPayload, err := manifest.Authorize(anchor, payload.CommittedAtMilliseconds)
	manifestDigest, digestErr := manifest.ReferenceDigest()
	if err != nil || digestErr != nil ||
		payload.Authority.Scope != manifestPayload.Scope ||
		payload.Authority.AuthorityRevision != manifestPayload.Revision ||
		payload.Authority.AuthorityManifestDigest != manifestDigest ||
		payload.DeploymentID != manifestPayload.ActiveDeployment.DeploymentID ||
		payload.SigningKeyFingerprint != manifestPayload.ActiveDeployment.SigningKeyFingerprint ||
		observation.Signature.SignerID != manifestPayload.ActiveDeployment.DeploymentID ||
		observation.Signature.PublicSigningKeyX963 != manifestPayload.ActiveDeployment.PublicSigningKeyX963 ||
		observation.Signature.SigningKeyFingerprint != manifestPayload.ActiveDeployment.SigningKeyFingerprint {
		return NodeTransportObservationPayload{}, ErrInvalid
	}
	return payload, nil
}

// ValidateRecipientBinding compares the signed delivery binding with an exact
// recipient identity and key known independently by the caller. This is not
// authority for that recipient key and does not prove ciphertext decryptability.
func (observation NodeTransportObservation) ValidateRecipientBinding(
	expected NodeTransportExpectedRecipient,
) error {
	payload, err := observation.VerifiedPayload()
	if err != nil || expected.DeviceID == uuid.Nil ||
		!validDigest(expected.AgreementKeyFingerprint) ||
		expected.RecipientAuthorityReference.Validate() != nil ||
		expected.EncryptionSuite != NodeTransportObservationEncryptionSuite ||
		payload.DeliveryProtection.DeliveryRecipientDeviceID != expected.DeviceID ||
		payload.DeliveryProtection.RecipientAgreementKeyFingerprint !=
			expected.AgreementKeyFingerprint ||
		!payload.DeliveryProtection.RecipientAuthorityReference.equals(
			expected.RecipientAuthorityReference,
		) ||
		payload.DeliveryProtection.EncryptionSuite != expected.EncryptionSuite {
		return ErrInvalid
	}
	return nil
}

func (observation NodeTransportObservation) ReferenceDigest() (string, error) {
	if _, err := observation.VerifiedPayload(); err != nil {
		return "", ErrInvalid
	}
	return signedReferenceDigest(
		NodeTransportObservationReferenceDomain,
		observation.Payload,
		observation.Signature,
	)
}

// ValidateSuccessor proves only signed stream continuity. It does not prove
// completeness or non-equivocation and does not authorize either record.
func (candidate NodeTransportObservation) ValidateSuccessor(
	predecessor NodeTransportObservation,
) (NodeTransportObservationPayload, error) {
	next, err := candidate.VerifiedPayload()
	if err != nil {
		return NodeTransportObservationPayload{}, ErrInvalid
	}
	current, err := predecessor.VerifiedPayload()
	if err != nil {
		return NodeTransportObservationPayload{}, ErrInvalid
	}
	digest, err := predecessor.ReferenceDigest()
	if err != nil || current.Sequence == math.MaxUint64 ||
		next.ServiceKind != current.ServiceKind ||
		next.DeploymentID != current.DeploymentID ||
		next.SigningKeyFingerprint != current.SigningKeyFingerprint ||
		next.StreamID != current.StreamID || next.Authority.Scope != current.Authority.Scope ||
		next.Sequence != current.Sequence+1 || next.PredecessorReferenceDigest == nil ||
		*next.PredecessorReferenceDigest != digest || next.ObservationID == current.ObservationID {
		return NodeTransportObservationPayload{}, ErrInvalid
	}
	return next, nil
}

// ValidateExactReplay admits only byte-identical reuse of one signed record.
// Re-signing the same payload produces a different record and is not a retry.
func (candidate NodeTransportObservation) ValidateExactReplay(
	original NodeTransportObservation,
) error {
	candidatePayload, err := candidate.VerifiedPayload()
	if err != nil {
		return ErrInvalid
	}
	originalPayload, err := original.VerifiedPayload()
	if err != nil || candidatePayload.ObservationID != originalPayload.ObservationID {
		return ErrInvalid
	}
	candidateBytes, err := canonicalJSON(candidate)
	if err != nil {
		return ErrInvalid
	}
	originalBytes, err := canonicalJSON(original)
	if err != nil || !bytes.Equal(candidateBytes, originalBytes) {
		return ErrInvalid
	}
	return nil
}

func DecodeNodeTransportObservation(input []byte) (NodeTransportObservation, error) {
	if len(input) == 0 || len(input) > MaximumNodeTransportObservationPayloadByteCount+4096 {
		return NodeTransportObservation{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var observation NodeTransportObservation
	if decoder.Decode(&observation) != nil {
		return NodeTransportObservation{}, ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return NodeTransportObservation{}, ErrInvalid
	}
	canonical, err := canonicalJSON(observation)
	if err != nil || !bytes.Equal(canonical, input) {
		return NodeTransportObservation{}, ErrInvalid
	}
	if _, err := observation.VerifiedPayload(); err != nil {
		return NodeTransportObservation{}, ErrInvalid
	}
	return observation, nil
}

// ProtectedObservationEnvelopeReferenceDigest binds the exact canonical bytes
// of the complete recipient-protected envelope, including its ephemeral key,
// nonce, authentication tag, and ciphertext. Encryption is client-owned and is
// intentionally not implemented by this transport-fact contract.
func ProtectedObservationEnvelopeReferenceDigest(canonicalEnvelope []byte) (string, error) {
	if len(canonicalEnvelope) == 0 ||
		len(canonicalEnvelope) > MaximumProtectedObservationEnvelopeByteCount {
		return "", ErrInvalid
	}
	digest := sha256Bytes(append(
		[]byte(NodeTransportProtectedEnvelopeReferenceDomain),
		canonicalEnvelope...,
	))
	return hex.EncodeToString(digest), nil
}

// RecipientPrincipalDeviceGrantRecordReferenceDigest identifies the exact
// canonical full signed principal-device-grant record bytes, including the
// payload and signature. This helper does not canonical-decode or authorize
// the grant; a later inbox must do both against independently trusted history.
func RecipientPrincipalDeviceGrantRecordReferenceDigest(
	canonicalSignedGrantRecord []byte,
) (string, error) {
	if len(canonicalSignedGrantRecord) == 0 ||
		len(canonicalSignedGrantRecord) > MaximumRecipientPrincipalDeviceGrantRecordByteCount {
		return "", ErrInvalid
	}
	digest := sha256Bytes(append(
		[]byte(NodeTransportRecipientPrincipalGrantReferenceDomain),
		canonicalSignedGrantRecord...,
	))
	return hex.EncodeToString(digest), nil
}

func isHex(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil
}

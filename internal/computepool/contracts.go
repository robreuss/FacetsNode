package computepool

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const (
	SchemaVersion               = 2
	WorkerCardSchemaVersion     = 1
	SignatureSchemaVersion      = 1
	MaximumResourceByteCount    = uint64(1 << 40)
	MaximumWallTimeMilliseconds = uint64(24 * 60 * 60 * 1_000)
	maximumDisplayNameBytes     = 512
	maximumDisplayNameRunes     = 128
	maximumIdentifierBytes      = 256
	maximumIdentifierCount      = 128
	maximumClaimValueBytes      = 1_024
	maximumCanonicalRecordBytes = 262_144
)

var ErrInvalid = errors.New("invalid Facets Compute Pool contract")

type ResourceCeiling struct {
	MaximumInputBytes           uint64 `json:"maximumInputBytes"`
	MaximumOutputBytes          uint64 `json:"maximumOutputBytes"`
	MaximumMemoryBytes          uint64 `json:"maximumMemoryBytes"`
	MaximumWallTimeMilliseconds uint64 `json:"maximumWallTimeMilliseconds"`
}

func (ceiling ResourceCeiling) Validate() error {
	if ceiling.MaximumInputBytes == 0 || ceiling.MaximumInputBytes > MaximumResourceByteCount ||
		ceiling.MaximumOutputBytes == 0 || ceiling.MaximumOutputBytes > MaximumResourceByteCount ||
		ceiling.MaximumMemoryBytes == 0 || ceiling.MaximumMemoryBytes > MaximumResourceByteCount ||
		ceiling.MaximumWallTimeMilliseconds == 0 ||
		ceiling.MaximumWallTimeMilliseconds > MaximumWallTimeMilliseconds {
		return ErrInvalid
	}
	return nil
}

type BudgetCeiling struct {
	MaximumCostMinorUnits uint64 `json:"maximumCostMinorUnits"`
	CurrencyIdentifier    string `json:"currencyIdentifier"`
}

func (ceiling BudgetCeiling) Validate() error {
	if ceiling.MaximumCostMinorUnits == 0 || !validIdentifier(ceiling.CurrencyIdentifier) {
		return ErrInvalid
	}
	return nil
}

type AuthorityTrustAnchor struct {
	Version               int                    `json:"version"`
	Scope                 serviceauthority.Scope `json:"scope"`
	SignerID              uuid.UUID              `json:"signerID"`
	PublicSigningKeyX963  string                 `json:"publicSigningKeyX963"`
	SigningKeyFingerprint string                 `json:"signingKeyFingerprint"`
}

func (anchor AuthorityTrustAnchor) Validate() error {
	publicKey, err := decodeBase64URL(anchor.PublicSigningKeyX963)
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKey)
	fingerprint := sha256.Sum256(publicKey)
	if anchor.Version != SignatureSchemaVersion || anchor.Scope.Validate() != nil ||
		anchor.Scope.Kind != serviceauthority.ScopeComputePool || anchor.SignerID == uuid.Nil ||
		err != nil || x == nil || y == nil ||
		hex.EncodeToString(fingerprint[:]) != anchor.SigningKeyFingerprint {
		return ErrInvalid
	}
	return nil
}

type AuthorityReference struct {
	Version                  int                  `json:"version"`
	PoolID                   uuid.UUID            `json:"poolID"`
	TrustAnchor              AuthorityTrustAnchor `json:"trustAnchor"`
	AcceptedManifestRevision uint64               `json:"acceptedManifestRevision"`
	AcceptedManifestDigest   string               `json:"acceptedManifestDigest"`
}

func (reference AuthorityReference) Validate() error {
	if reference.Version != SchemaVersion || reference.PoolID == uuid.Nil ||
		reference.AcceptedManifestRevision == 0 || !validSHA256Hex(reference.AcceptedManifestDigest) ||
		reference.TrustAnchor.Validate() != nil || reference.TrustAnchor.Scope.ScopeID != reference.PoolID {
		return ErrInvalid
	}
	return nil
}

type Pool struct {
	Version                 int       `json:"version"`
	PoolID                  uuid.UUID `json:"poolID"`
	OwnerAuthorityID        uuid.UUID `json:"ownerAuthorityID"`
	AuthorityRevision       uint64    `json:"authorityRevision"`
	AuthorityManifestDigest string    `json:"authorityManifestDigest"`
	DisplayName             string    `json:"displayName"`
	Enabled                 bool      `json:"enabled"`
	Revision                uint64    `json:"revision"`
	CreatedAtMilliseconds   int64     `json:"createdAtMilliseconds"`
	UpdatedAtMilliseconds   int64     `json:"updatedAtMilliseconds"`
}

func (pool Pool) Validate() error {
	if pool.Version != SchemaVersion || pool.PoolID == uuid.Nil || pool.OwnerAuthorityID == uuid.Nil ||
		pool.AuthorityRevision == 0 || pool.Revision == 0 ||
		!validSHA256Hex(pool.AuthorityManifestDigest) || !validDisplayName(pool.DisplayName) ||
		!validTimestamps(pool.CreatedAtMilliseconds, pool.UpdatedAtMilliseconds) {
		return ErrInvalid
	}
	return nil
}

type WorkerEnrollment struct {
	Version                 int       `json:"version"`
	EnrollmentID            uuid.UUID `json:"enrollmentID"`
	PoolID                  uuid.UUID `json:"poolID"`
	WorkerID                uuid.UUID `json:"workerID"`
	WorkerOwnerAuthorityID  uuid.UUID `json:"workerOwnerAuthorityID"`
	PublicSigningKeyEd25519 string    `json:"publicSigningKeyEd25519"`
	SigningKeyFingerprint   string    `json:"signingKeyFingerprint"`
	ConsentRevision         uint64    `json:"consentRevision"`
	Enabled                 bool      `json:"enabled"`
	Revision                uint64    `json:"revision"`
	CreatedAtMilliseconds   int64     `json:"createdAtMilliseconds"`
	UpdatedAtMilliseconds   int64     `json:"updatedAtMilliseconds"`
}

func (enrollment WorkerEnrollment) Validate() error {
	publicKey, err := decodeBase64URL(enrollment.PublicSigningKeyEd25519)
	fingerprint := sha256.Sum256(publicKey)
	if enrollment.Version != SchemaVersion || enrollment.EnrollmentID == uuid.Nil ||
		enrollment.PoolID == uuid.Nil || enrollment.WorkerID == uuid.Nil ||
		enrollment.WorkerOwnerAuthorityID == uuid.Nil || enrollment.ConsentRevision == 0 ||
		enrollment.Revision == 0 || err != nil || len(publicKey) != 32 ||
		hex.EncodeToString(fingerprint[:]) != enrollment.SigningKeyFingerprint ||
		!validTimestamps(enrollment.CreatedAtMilliseconds, enrollment.UpdatedAtMilliseconds) {
		return ErrInvalid
	}
	return nil
}

type PrivacyClass string

const (
	PrivacyPublic       PrivacyClass = "public"
	PrivacyPersonal     PrivacyClass = "personal"
	PrivacyConfidential PrivacyClass = "confidential"
	PrivacyRestricted   PrivacyClass = "restricted"
)

var privacyClasses = []PrivacyClass{PrivacyPublic, PrivacyPersonal, PrivacyConfidential, PrivacyRestricted}

func (value PrivacyClass) Valid() bool { return contains(privacyClasses, value) }

type PolicyControl string

const (
	ControlAllowed         PolicyControl = "allowed"
	ControlConsentRequired PolicyControl = "consent_required"
	ControlProhibited      PolicyControl = "prohibited"
)

func (value PolicyControl) Valid() bool {
	return value == ControlAllowed || value == ControlConsentRequired || value == ControlProhibited
}

type DisclosureAudience string

const (
	AudiencePrivateInvoker DisclosureAudience = "private_invoker"
	AudienceInvitedSpace   DisclosureAudience = "invited_space"
	AudiencePublic         DisclosureAudience = "public_audience"
)

func (value DisclosureAudience) Valid() bool {
	return value == AudiencePrivateInvoker || value == AudienceInvitedSpace || value == AudiencePublic
}

type PlaintextBoundary string

const (
	PlaintextBoundaryFacetsManagedLocalRuntime PlaintextBoundary = "facets_managed_local_runtime"
	PlaintextBoundarySeparateLocalProcess      PlaintextBoundary = "separate_local_process"
	PlaintextBoundaryPrivateInfrastructure     PlaintextBoundary = "private_infrastructure"
	PlaintextBoundaryExternalProvider          PlaintextBoundary = "external_provider"
)

func (value PlaintextBoundary) Valid() bool {
	return value == PlaintextBoundaryFacetsManagedLocalRuntime || value == PlaintextBoundarySeparateLocalProcess ||
		value == PlaintextBoundaryPrivateInfrastructure || value == PlaintextBoundaryExternalProvider
}

func (value PlaintextBoundary) rank() int {
	switch value {
	case PlaintextBoundaryFacetsManagedLocalRuntime:
		return 0
	case PlaintextBoundarySeparateLocalProcess:
		return 1
	case PlaintextBoundaryPrivateInfrastructure:
		return 2
	default:
		return 3
	}
}

type NetworkEgress string

const (
	NetworkEgressNone           NetworkEgress = "none"
	NetworkEgressTorNetwork     NetworkEgress = "tor_network"
	NetworkEgressDirectInternet NetworkEgress = "direct_internet"
)

func (value NetworkEgress) Valid() bool {
	return value == NetworkEgressNone || value == NetworkEgressTorNetwork || value == NetworkEgressDirectInternet
}

type RetentionMode string

const (
	RetentionNone                     RetentionMode = "none"
	RetentionTransientUntilCompletion RetentionMode = "transient_until_completion"
	RetentionEncryptedUntilDelivery   RetentionMode = "encrypted_until_delivery"
	RetentionDurationBound            RetentionMode = "duration_bound"
	RetentionProviderPolicy           RetentionMode = "provider_policy"
	RetentionUnknown                  RetentionMode = "unknown"
)

type RetentionPolicy struct {
	Mode                        RetentionMode `json:"mode"`
	MaximumDurationMilliseconds *uint64       `json:"maximumDurationMilliseconds,omitempty"`
}

func (policy RetentionPolicy) Validate() error {
	valid := policy.Mode == RetentionNone || policy.Mode == RetentionTransientUntilCompletion ||
		policy.Mode == RetentionEncryptedUntilDelivery || policy.Mode == RetentionDurationBound ||
		policy.Mode == RetentionProviderPolicy || policy.Mode == RetentionUnknown
	if !valid || (policy.Mode == RetentionDurationBound) != (policy.MaximumDurationMilliseconds != nil) ||
		policy.MaximumDurationMilliseconds != nil && *policy.MaximumDurationMilliseconds == 0 {
		return ErrInvalid
	}
	return nil
}

type TrainingUse string

const (
	TrainingProhibited     TrainingUse = "prohibited"
	TrainingProviderOptOut TrainingUse = "provider_opt_out"
	TrainingPermitted      TrainingUse = "permitted"
	TrainingUnknown        TrainingUse = "unknown"
)

func (value TrainingUse) Valid() bool {
	return value == TrainingProhibited || value == TrainingProviderOptOut || value == TrainingPermitted || value == TrainingUnknown
}

type ToolAccess string

const (
	ToolAccessNone           ToolAccess = "none"
	ToolAccessDeclaredSubset ToolAccess = "declared_subset"
	ToolAccessUnrestricted   ToolAccess = "unrestricted"
	ToolAccessUnknown        ToolAccess = "unknown"
)

func (value ToolAccess) Valid() bool {
	return value == ToolAccessNone || value == ToolAccessDeclaredSubset || value == ToolAccessUnrestricted || value == ToolAccessUnknown
}

type ResultPolicy string

const (
	ResultPrivateToInvoker     ResultPolicy = "private_to_invoker"
	ResultSharedImportAllowed  ResultPolicy = "shared_import_allowed"
	ResultSharedImportRequired ResultPolicy = "shared_import_required"
)

func (value ResultPolicy) Valid() bool {
	return value == ResultPrivateToInvoker || value == ResultSharedImportAllowed || value == ResultSharedImportRequired
}

type DataHandlingProfile struct {
	PlaintextBoundary   PlaintextBoundary `json:"plaintextBoundary"`
	NetworkEgress       NetworkEgress     `json:"networkEgress"`
	RequestRetention    RetentionPolicy   `json:"requestRetention"`
	ResultRetention     RetentionPolicy   `json:"resultRetention"`
	DiagnosticRetention RetentionPolicy   `json:"diagnosticRetention"`
	TrainingUse         TrainingUse       `json:"trainingUse"`
	ToolAccess          ToolAccess        `json:"toolAccess"`
	ProviderIdentifier  string            `json:"providerIdentifier"`
}

func (profile DataHandlingProfile) Validate() error {
	if !profile.PlaintextBoundary.Valid() || !profile.NetworkEgress.Valid() || profile.RequestRetention.Validate() != nil ||
		profile.ResultRetention.Validate() != nil || profile.DiagnosticRetention.Validate() != nil ||
		!profile.TrainingUse.Valid() || !profile.ToolAccess.Valid() || !validIdentifier(profile.ProviderIdentifier) ||
		profile.PlaintextBoundary == PlaintextBoundaryFacetsManagedLocalRuntime && profile.NetworkEgress != NetworkEgressNone ||
		profile.PlaintextBoundary == PlaintextBoundaryExternalProvider && profile.NetworkEgress == NetworkEgressNone {
		return ErrInvalid
	}
	return nil
}

type DataUseConstraint struct {
	PrivacyClass                        PrivacyClass       `json:"privacyClass"`
	Audience                            DisclosureAudience `json:"audience"`
	MaximumPlaintextBoundary            PlaintextBoundary  `json:"maximumPlaintextBoundary"`
	PermittedProviderIdentifiers        []string           `json:"permittedProviderIdentifiers"`
	PermittedNetworkEgress              []NetworkEgress    `json:"permittedNetworkEgress"`
	MaximumRequestRetentionMilliseconds *uint64            `json:"maximumRequestRetentionMilliseconds,omitempty"`
	PermittedTrainingUse                []TrainingUse      `json:"permittedTrainingUse"`
	PermittedToolAccess                 []ToolAccess       `json:"permittedToolAccess"`
	ResultPolicy                        ResultPolicy       `json:"resultPolicy"`
	OverrideControl                     PolicyControl      `json:"overrideControl"`
}

func (constraint DataUseConstraint) Validate() error {
	if !constraint.PrivacyClass.Valid() || !constraint.Audience.Valid() || !constraint.MaximumPlaintextBoundary.Valid() ||
		!validIdentifiers(constraint.PermittedProviderIdentifiers, true) ||
		!validSortedEnum(constraint.PermittedNetworkEgress, func(v NetworkEgress) bool { return v.Valid() }) ||
		!validSortedEnum(constraint.PermittedTrainingUse, func(v TrainingUse) bool { return v.Valid() }) ||
		!validSortedEnum(constraint.PermittedToolAccess, func(v ToolAccess) bool { return v.Valid() }) ||
		!constraint.ResultPolicy.Valid() || !constraint.OverrideControl.Valid() ||
		constraint.MaximumRequestRetentionMilliseconds != nil && *constraint.MaximumRequestRetentionMilliseconds == 0 {
		return ErrInvalid
	}
	return nil
}
func (constraint DataUseConstraint) Permits(profile DataHandlingProfile) bool {
	if profile.Validate() != nil || profile.PlaintextBoundary.rank() > constraint.MaximumPlaintextBoundary.rank() ||
		len(constraint.PermittedProviderIdentifiers) > 0 && !contains(constraint.PermittedProviderIdentifiers, profile.ProviderIdentifier) ||
		!contains(constraint.PermittedNetworkEgress, profile.NetworkEgress) ||
		!contains(constraint.PermittedTrainingUse, profile.TrainingUse) || !contains(constraint.PermittedToolAccess, profile.ToolAccess) {
		return false
	}
	if constraint.MaximumRequestRetentionMilliseconds == nil {
		return true
	}
	maximum := *constraint.MaximumRequestRetentionMilliseconds
	switch profile.RequestRetention.Mode {
	case RetentionNone, RetentionTransientUntilCompletion:
		return true
	case RetentionDurationBound:
		return profile.RequestRetention.MaximumDurationMilliseconds != nil && *profile.RequestRetention.MaximumDurationMilliseconds <= maximum
	default:
		return false
	}
}

type AssuranceEvidenceKind string

const (
	EvidenceFacetsEnforced           AssuranceEvidenceKind = "facets_enforced"
	EvidenceConfigurationVerified    AssuranceEvidenceKind = "configuration_verified"
	EvidenceRemotelyAttested         AssuranceEvidenceKind = "remotely_attested"
	EvidenceWorkerOperatorDeclared   AssuranceEvidenceKind = "worker_operator_declared"
	EvidenceExternalProviderDeclared AssuranceEvidenceKind = "external_provider_declared"
	EvidenceUnknown                  AssuranceEvidenceKind = "unknown"
)

func (value AssuranceEvidenceKind) Valid() bool {
	return value == EvidenceFacetsEnforced || value == EvidenceConfigurationVerified || value == EvidenceRemotelyAttested || value == EvidenceWorkerOperatorDeclared || value == EvidenceExternalProviderDeclared || value == EvidenceUnknown
}

var assuranceDimensions = []string{"diagnostic_retention", "execution_isolation", "network_egress", "plaintext_location", "provider_identity", "request_retention", "result_retention", "runtime_integrity", "tool_access", "training_use"}

type AssuranceClaim struct {
	DimensionIdentifier   string                `json:"dimensionIdentifier"`
	Value                 string                `json:"value"`
	EvidenceKind          AssuranceEvidenceKind `json:"evidenceKind"`
	IssuerIdentifier      string                `json:"issuerIdentifier"`
	EvidenceDigest        *string               `json:"evidenceDigest,omitempty"`
	ValidFromMilliseconds int64                 `json:"validFromMilliseconds"`
	ExpiresAtMilliseconds *int64                `json:"expiresAtMilliseconds,omitempty"`
	Revision              uint64                `json:"revision"`
}

func (claim AssuranceClaim) Validate() error {
	if !validIdentifier(claim.DimensionIdentifier) || !validClaimValue(claim.Value) || !claim.EvidenceKind.Valid() ||
		!validIdentifier(claim.IssuerIdentifier) || claim.EvidenceDigest != nil && !validSHA256Hex(*claim.EvidenceDigest) ||
		claim.ValidFromMilliseconds < 0 || claim.ExpiresAtMilliseconds != nil && *claim.ExpiresAtMilliseconds <= claim.ValidFromMilliseconds || claim.Revision == 0 {
		return ErrInvalid
	}
	return nil
}

type WorkerCard struct {
	Version                int              `json:"version"`
	WorkerCardID           uuid.UUID        `json:"workerCardID"`
	PoolID                 uuid.UUID        `json:"poolID"`
	WorkerEnrollmentID     uuid.UUID        `json:"workerEnrollmentID"`
	WorkerOwnerAuthorityID uuid.UUID        `json:"workerOwnerAuthorityID"`
	DisplayName            string           `json:"displayName"`
	RuntimeIdentifier      string           `json:"runtimeIdentifier"`
	BuildIdentifier        string           `json:"buildIdentifier"`
	Claims                 []AssuranceClaim `json:"claims"`
	Revision               uint64           `json:"revision"`
	CreatedAtMilliseconds  int64            `json:"createdAtMilliseconds"`
	UpdatedAtMilliseconds  int64            `json:"updatedAtMilliseconds"`
}

func (card WorkerCard) Validate() error {
	if card.Version != WorkerCardSchemaVersion || card.WorkerCardID == uuid.Nil || card.PoolID == uuid.Nil ||
		card.WorkerEnrollmentID == uuid.Nil || card.WorkerOwnerAuthorityID == uuid.Nil || !validDisplayName(card.DisplayName) ||
		!validIdentifier(card.RuntimeIdentifier) || !validIdentifier(card.BuildIdentifier) || card.Revision == 0 ||
		!validTimestamps(card.CreatedAtMilliseconds, card.UpdatedAtMilliseconds) || len(card.Claims) != len(assuranceDimensions) {
		return ErrInvalid
	}
	for index, claim := range card.Claims {
		if claim.Validate() != nil || claim.DimensionIdentifier != assuranceDimensions[index] {
			return ErrInvalid
		}
	}
	return nil
}
func (card WorkerCard) Digest() (string, error) { return canonicalDigest(card) }

type InteractionMode string

const (
	InteractionBatch           InteractionMode = "batch"
	InteractionStreamedRequest InteractionMode = "streamed_request"
	InteractionInteractive     InteractionMode = "interactive_session"
)

func (mode InteractionMode) Valid() bool {
	return mode == InteractionBatch || mode == InteractionStreamedRequest || mode == InteractionInteractive
}

type Offering struct {
	Version               int                 `json:"version"`
	OfferingID            uuid.UUID           `json:"offeringID"`
	PoolID                uuid.UUID           `json:"poolID"`
	WorkerEnrollmentID    uuid.UUID           `json:"workerEnrollmentID"`
	WorkerCardID          uuid.UUID           `json:"workerCardID"`
	WorkerCardRevision    uint64              `json:"workerCardRevision"`
	WorkerCardDigest      string              `json:"workerCardDigest"`
	ProviderIdentifier    string              `json:"providerIdentifier"`
	ModelIdentifiers      []string            `json:"modelIdentifiers"`
	AllowedOperations     []string            `json:"allowedOperations"`
	InteractionModes      []InteractionMode   `json:"interactionModes"`
	DataHandlingProfile   DataHandlingProfile `json:"dataHandlingProfile"`
	PricingRevision       uint64              `json:"pricingRevision"`
	ResourceCeiling       ResourceCeiling     `json:"resourceCeiling"`
	Enabled               bool                `json:"enabled"`
	Revision              uint64              `json:"revision"`
	CreatedAtMilliseconds int64               `json:"createdAtMilliseconds"`
	UpdatedAtMilliseconds int64               `json:"updatedAtMilliseconds"`
}

func (offering Offering) Validate() error {
	if offering.Version != SchemaVersion || offering.OfferingID == uuid.Nil || offering.PoolID == uuid.Nil || offering.WorkerEnrollmentID == uuid.Nil ||
		offering.WorkerCardID == uuid.Nil || offering.WorkerCardRevision == 0 || !validSHA256Hex(offering.WorkerCardDigest) ||
		offering.PricingRevision == 0 || offering.Revision == 0 || !validIdentifier(offering.ProviderIdentifier) ||
		!validIdentifiers(offering.ModelIdentifiers, false) || !validIdentifiers(offering.AllowedOperations, false) ||
		!validSortedEnum(offering.InteractionModes, func(v InteractionMode) bool { return v.Valid() }) ||
		offering.DataHandlingProfile.Validate() != nil || offering.DataHandlingProfile.ProviderIdentifier != offering.ProviderIdentifier ||
		offering.ResourceCeiling.Validate() != nil || !validTimestamps(offering.CreatedAtMilliseconds, offering.UpdatedAtMilliseconds) {
		return ErrInvalid
	}
	return nil
}

type SpaceBinding struct {
	Version                    int                 `json:"version"`
	BindingID                  uuid.UUID           `json:"bindingID"`
	SpaceID                    uuid.UUID           `json:"spaceID"`
	PoolAuthority              AuthorityReference  `json:"poolAuthority"`
	AllowedOperations          []string            `json:"allowedOperations"`
	EligiblePrincipalIDs       []uuid.UUID         `json:"eligiblePrincipalIDs"`
	EligibleRoleIdentifiers    []string            `json:"eligibleRoleIdentifiers"`
	AllowedProviderIdentifiers []string            `json:"allowedProviderIdentifiers"`
	ResourceCeiling            ResourceCeiling     `json:"resourceCeiling"`
	BudgetCeiling              BudgetCeiling       `json:"budgetCeiling"`
	PricingRevision            uint64              `json:"pricingRevision"`
	DataUseConstraints         []DataUseConstraint `json:"dataUseConstraints"`
	Revision                   uint64              `json:"revision"`
	SourceAuthorityRevision    uint64              `json:"sourceAuthorityRevision"`
	CreatedAtMilliseconds      int64               `json:"createdAtMilliseconds"`
	UpdatedAtMilliseconds      int64               `json:"updatedAtMilliseconds"`
}

func (binding SpaceBinding) Validate() error {
	if binding.Version != SchemaVersion || binding.BindingID == uuid.Nil || binding.SpaceID == uuid.Nil || binding.PricingRevision == 0 ||
		binding.Revision == 0 || binding.SourceAuthorityRevision == 0 || binding.PoolAuthority.Validate() != nil ||
		!validIdentifiers(binding.AllowedOperations, false) || !validUUIDs(binding.EligiblePrincipalIDs) ||
		!validIdentifiers(binding.EligibleRoleIdentifiers, true) || len(binding.EligiblePrincipalIDs) == 0 && len(binding.EligibleRoleIdentifiers) == 0 ||
		!validIdentifiers(binding.AllowedProviderIdentifiers, false) || binding.ResourceCeiling.Validate() != nil || binding.BudgetCeiling.Validate() != nil ||
		len(binding.DataUseConstraints) != len(privacyClasses) || !validTimestamps(binding.CreatedAtMilliseconds, binding.UpdatedAtMilliseconds) {
		return ErrInvalid
	}
	for index, constraint := range binding.DataUseConstraints {
		if constraint.Validate() != nil || constraint.PrivacyClass != privacyClasses[index] {
			return ErrInvalid
		}
	}
	return nil
}

func decodeBase64URL(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalid
	}
	return decoded, nil
}
func validDisplayName(value string) bool {
	trimmed := strings.TrimSpace(value)
	return utf8.ValidString(value) && value == trimmed && value != "" && len(value) <= maximumDisplayNameBytes && utf8.RuneCountInString(value) <= maximumDisplayNameRunes
}
func validIdentifier(value string) bool {
	trimmed := strings.TrimSpace(value)
	return utf8.ValidString(value) && value == trimmed && value != "" && len(value) <= maximumIdentifierBytes
}
func validClaimValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	return utf8.ValidString(value) && value == trimmed && value != "" && len(value) <= maximumClaimValueBytes
}
func validIdentifiers(values []string, optional bool) bool {
	if len(values) > maximumIdentifierCount || !sort.StringsAreSorted(values) || !optional && len(values) == 0 {
		return false
	}
	previous := ""
	for _, value := range values {
		if !validIdentifier(value) || value == previous {
			return false
		}
		previous = value
	}
	return true
}
func validUUIDs(values []uuid.UUID) bool {
	if len(values) > maximumIdentifierCount {
		return false
	}
	previous := ""
	for _, value := range values {
		current := value.String()
		if value == uuid.Nil || current <= previous {
			return false
		}
		previous = current
	}
	return true
}
func validSortedEnum[T ~string](values []T, valid func(T) bool) bool {
	if len(values) == 0 || len(values) > maximumIdentifierCount {
		return false
	}
	previous := ""
	for _, value := range values {
		current := string(value)
		if !valid(value) || current <= previous {
			return false
		}
		previous = current
	}
	return true
}
func contains[T comparable](values []T, target T) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func validTimestamps(created, updated int64) bool { return created >= 0 && updated >= created }
func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}
func canonicalJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(encoded, &generic); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(generic)
	if err != nil || len(canonical) > maximumCanonicalRecordBytes {
		return nil, ErrInvalid
	}
	return canonical, nil
}
func canonicalDigest(value any) (string, error) {
	encoded, err := canonicalJSON(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

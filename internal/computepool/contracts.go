package computepool

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const (
	SchemaVersion                          = 1
	MaximumResourceByteCount               = uint64(1 << 40)
	MaximumWallTimeMilliseconds            = uint64(24 * 60 * 60 * 1_000)
	maximumDisplayNameBytes                = 512
	maximumDisplayNameRunes                = 128
	maximumIdentifierBytes                 = 256
	maximumIdentifierCount                 = 128
	maximumContractBytes                   = 1_024
	PlaintextBoundaryLocalWorker           = PlaintextBoundary("local_worker")
	PlaintextBoundaryPrivateInfrastructure = PlaintextBoundary("private_infrastructure")
	PlaintextBoundaryExternalProvider      = PlaintextBoundary("external_provider")
	NetworkEgressNone                      = NetworkEgress("none")
	NetworkEgressDirectInternet            = NetworkEgress("direct_internet")
	NetworkEgressTorNetwork                = NetworkEgress("tor_network")
	ResultPrivateToInvoker                 = ResultPolicy("private_to_invoker")
	ResultSharedImportAllowed              = ResultPolicy("shared_import_allowed")
	ResultSharedImportRequired             = ResultPolicy("shared_import_required")
)

var ErrInvalid = errors.New("invalid Facets Compute Pool contract")

type ResourceCeiling struct {
	MaximumInputBytes           uint64 `json:"maximumInputBytes"`
	MaximumOutputBytes          uint64 `json:"maximumOutputBytes"`
	MaximumMemoryBytes          uint64 `json:"maximumMemoryBytes"`
	MaximumWallTimeMilliseconds uint64 `json:"maximumWallTimeMilliseconds"`
}

func (ceiling ResourceCeiling) Validate() error {
	if ceiling.MaximumInputBytes == 0 ||
		ceiling.MaximumInputBytes > MaximumResourceByteCount ||
		ceiling.MaximumOutputBytes == 0 ||
		ceiling.MaximumOutputBytes > MaximumResourceByteCount ||
		ceiling.MaximumMemoryBytes == 0 ||
		ceiling.MaximumMemoryBytes > MaximumResourceByteCount ||
		ceiling.MaximumWallTimeMilliseconds == 0 ||
		ceiling.MaximumWallTimeMilliseconds > MaximumWallTimeMilliseconds {
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
	if anchor.Version != SchemaVersion || anchor.Scope.Validate() != nil ||
		anchor.Scope.Kind != serviceauthority.ScopeComputePool ||
		anchor.SignerID == uuid.Nil || err != nil || x == nil || y == nil ||
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
		reference.AcceptedManifestRevision == 0 ||
		!validSHA256Hex(reference.AcceptedManifestDigest) ||
		reference.TrustAnchor.Validate() != nil ||
		reference.TrustAnchor.Scope.ScopeID != reference.PoolID {
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
	if pool.Version != SchemaVersion || pool.PoolID == uuid.Nil ||
		pool.OwnerAuthorityID == uuid.Nil || pool.AuthorityRevision == 0 ||
		pool.Revision == 0 || !validSHA256Hex(pool.AuthorityManifestDigest) ||
		!validDisplayName(pool.DisplayName) ||
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

type PlaintextBoundary string

func (boundary PlaintextBoundary) Valid() bool {
	return boundary == PlaintextBoundaryLocalWorker ||
		boundary == PlaintextBoundaryPrivateInfrastructure ||
		boundary == PlaintextBoundaryExternalProvider
}

type NetworkEgress string

func (egress NetworkEgress) Valid() bool {
	return egress == NetworkEgressNone || egress == NetworkEgressDirectInternet ||
		egress == NetworkEgressTorNetwork
}

type Offering struct {
	Version               int               `json:"version"`
	OfferingID            uuid.UUID         `json:"offeringID"`
	PoolID                uuid.UUID         `json:"poolID"`
	WorkerEnrollmentID    uuid.UUID         `json:"workerEnrollmentID"`
	ProviderIdentifier    string            `json:"providerIdentifier"`
	ModelIdentifiers      []string          `json:"modelIdentifiers"`
	AllowedOperations     []string          `json:"allowedOperations"`
	PlaintextBoundary     PlaintextBoundary `json:"plaintextBoundary"`
	NetworkEgress         NetworkEgress     `json:"networkEgress"`
	RetentionDeclaration  string            `json:"retentionDeclaration"`
	TrainingDeclaration   string            `json:"trainingDeclaration"`
	PricingRevision       uint64            `json:"pricingRevision"`
	ResourceCeiling       ResourceCeiling   `json:"resourceCeiling"`
	Enabled               bool              `json:"enabled"`
	Revision              uint64            `json:"revision"`
	CreatedAtMilliseconds int64             `json:"createdAtMilliseconds"`
	UpdatedAtMilliseconds int64             `json:"updatedAtMilliseconds"`
}

func (offering Offering) Validate() error {
	if offering.Version != SchemaVersion || offering.OfferingID == uuid.Nil ||
		offering.PoolID == uuid.Nil || offering.WorkerEnrollmentID == uuid.Nil ||
		offering.PricingRevision == 0 || offering.Revision == 0 ||
		!validIdentifier(offering.ProviderIdentifier) ||
		!validIdentifiers(offering.ModelIdentifiers, false) ||
		!validIdentifiers(offering.AllowedOperations, false) ||
		!offering.PlaintextBoundary.Valid() || !offering.NetworkEgress.Valid() ||
		!validContract(offering.RetentionDeclaration) ||
		!validContract(offering.TrainingDeclaration) ||
		offering.ResourceCeiling.Validate() != nil ||
		!validTimestamps(offering.CreatedAtMilliseconds, offering.UpdatedAtMilliseconds) {
		return ErrInvalid
	}
	return nil
}

type ResultPolicy string

func (policy ResultPolicy) Valid() bool {
	return policy == ResultPrivateToInvoker || policy == ResultSharedImportAllowed ||
		policy == ResultSharedImportRequired
}

type SpaceBinding struct {
	Version                    int                `json:"version"`
	BindingID                  uuid.UUID          `json:"bindingID"`
	SpaceID                    uuid.UUID          `json:"spaceID"`
	PoolAuthority              AuthorityReference `json:"poolAuthority"`
	AllowedOperations          []string           `json:"allowedOperations"`
	EligiblePrincipalIDs       []uuid.UUID        `json:"eligiblePrincipalIDs"`
	EligibleRoleIdentifiers    []string           `json:"eligibleRoleIdentifiers"`
	AllowedProviderIdentifiers []string           `json:"allowedProviderIdentifiers"`
	ResourceCeiling            ResourceCeiling    `json:"resourceCeiling"`
	PricingRevision            uint64             `json:"pricingRevision"`
	DataSensitivityContract    string             `json:"dataSensitivityContract"`
	ProcessingContract         string             `json:"processingContract"`
	BudgetContract             string             `json:"budgetContract"`
	ResultPolicy               ResultPolicy       `json:"resultPolicy"`
	Revision                   uint64             `json:"revision"`
	SourceAuthorityRevision    uint64             `json:"sourceAuthorityRevision"`
	CreatedAtMilliseconds      int64              `json:"createdAtMilliseconds"`
	UpdatedAtMilliseconds      int64              `json:"updatedAtMilliseconds"`
}

func (binding SpaceBinding) Validate() error {
	if binding.Version != SchemaVersion || binding.BindingID == uuid.Nil ||
		binding.SpaceID == uuid.Nil || binding.PricingRevision == 0 ||
		binding.Revision == 0 || binding.SourceAuthorityRevision == 0 ||
		binding.PoolAuthority.Validate() != nil ||
		!validIdentifiers(binding.AllowedOperations, false) ||
		!validUUIDs(binding.EligiblePrincipalIDs) ||
		!validIdentifiers(binding.EligibleRoleIdentifiers, true) ||
		len(binding.EligiblePrincipalIDs) == 0 && len(binding.EligibleRoleIdentifiers) == 0 ||
		!validIdentifiers(binding.AllowedProviderIdentifiers, false) ||
		binding.ResourceCeiling.Validate() != nil ||
		!validContract(binding.DataSensitivityContract) ||
		!validContract(binding.ProcessingContract) ||
		!validContract(binding.BudgetContract) || !binding.ResultPolicy.Valid() ||
		!validTimestamps(binding.CreatedAtMilliseconds, binding.UpdatedAtMilliseconds) {
		return ErrInvalid
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
	return utf8.ValidString(value) && value == trimmed && value != "" &&
		len(value) <= maximumDisplayNameBytes &&
		utf8.RuneCountInString(value) <= maximumDisplayNameRunes
}

func validIdentifier(value string) bool {
	trimmed := strings.TrimSpace(value)
	return utf8.ValidString(value) && value == trimmed && value != "" &&
		len(value) <= maximumIdentifierBytes
}

func validIdentifiers(values []string, optional bool) bool {
	if len(values) > maximumIdentifierCount || !sort.StringsAreSorted(values) ||
		!optional && len(values) == 0 {
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

func validContract(value string) bool {
	trimmed := strings.TrimSpace(value)
	return utf8.ValidString(value) && value == trimmed && value != "" &&
		len(value) <= maximumContractBytes
}

func validTimestamps(created, updated int64) bool {
	return created >= 0 && updated >= created
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

package sharedspaces

import (
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

const (
	MaximumComputePoolDisplayNameBytes = 512
	MaximumComputePoolDisplayNameRunes = 128
	MaximumComputeOperationCount       = 64
	MaximumComputeOperationBytes       = 128
	MaximumComputeContractBytes        = 256
	MaximumComputeInputBytes           = uint64(1 << 40)
	MaximumComputeOutputBytes          = uint64(1 << 40)
	MaximumComputeMemoryBytes          = uint64(1 << 40)
	MaximumComputeWallTimeMilliseconds = uint64(24 * 60 * 60 * 1_000)
)

// ComputePool is the Space-owned recognition and availability record for a
// group of workers. It does not copy participant membership or authorize a
// worker; both are evaluated when a short-lived capability is issued.
type ComputePool struct {
	Version               int       `json:"version"`
	SpaceID               uuid.UUID `json:"spaceID"`
	PoolID                uuid.UUID `json:"poolID"`
	DisplayName           string    `json:"displayName"`
	Enabled               bool      `json:"enabled"`
	Revision              uint64    `json:"revision"`
	CreatedAtMilliseconds int64     `json:"createdAtMilliseconds"`
	UpdatedAtMilliseconds int64     `json:"updatedAtMilliseconds"`
}

func (p ComputePool) Validate() error {
	if p.Version != SchemaVersion || p.SpaceID == uuid.Nil || p.PoolID == uuid.Nil ||
		p.Revision == 0 || p.CreatedAtMilliseconds < 0 ||
		p.UpdatedAtMilliseconds < p.CreatedAtMilliseconds ||
		!validComputeDisplayName(p.DisplayName) {
		return NewProtocolError(CodeInvalidComputePool, "Shared Space compute pool fields are invalid")
	}
	return nil
}

// ComputeResourceCeiling bounds a capability before a Worker is selected.
// Workers may advertise tighter ceilings, but may never expand these values.
type ComputeResourceCeiling struct {
	MaximumInputBytes           uint64 `json:"maximumInputBytes"`
	MaximumOutputBytes          uint64 `json:"maximumOutputBytes"`
	MaximumMemoryBytes          uint64 `json:"maximumMemoryBytes"`
	MaximumWallTimeMilliseconds uint64 `json:"maximumWallTimeMilliseconds"`
}

func (c ComputeResourceCeiling) Validate() error {
	if c.MaximumInputBytes == 0 || c.MaximumInputBytes > MaximumComputeInputBytes ||
		c.MaximumOutputBytes == 0 || c.MaximumOutputBytes > MaximumComputeOutputBytes ||
		c.MaximumMemoryBytes == 0 || c.MaximumMemoryBytes > MaximumComputeMemoryBytes ||
		c.MaximumWallTimeMilliseconds == 0 ||
		c.MaximumWallTimeMilliseconds > MaximumComputeWallTimeMilliseconds {
		return NewProtocolError(CodeInvalidComputePool, "Shared Space compute resource ceiling is invalid")
	}
	return nil
}

// SpaceComputeBinding is the policy boundary between one Shared Space and one
// ComputePool. DataSensitivityContract and ProcessingContract are versioned
// identifiers whose human-readable disclosures are resolved by Facets; the
// server treats them as policy inputs rather than environmental claims.
type SpaceComputeBinding struct {
	Version                 int                    `json:"version"`
	SpaceID                 uuid.UUID              `json:"spaceID"`
	PoolID                  uuid.UUID              `json:"poolID"`
	AllowedOperations       []string               `json:"allowedOperations"`
	ResourceCeiling         ComputeResourceCeiling `json:"resourceCeiling"`
	PricingRevision         uint64                 `json:"pricingRevision"`
	DataSensitivityContract string                 `json:"dataSensitivityContract"`
	ProcessingContract      string                 `json:"processingContract"`
	Revision                uint64                 `json:"revision"`
	CreatedAtMilliseconds   int64                  `json:"createdAtMilliseconds"`
	UpdatedAtMilliseconds   int64                  `json:"updatedAtMilliseconds"`
}

func (b SpaceComputeBinding) Validate() error {
	if b.Version != SchemaVersion || b.SpaceID == uuid.Nil || b.PoolID == uuid.Nil ||
		b.PricingRevision == 0 || b.Revision == 0 ||
		b.CreatedAtMilliseconds < 0 || b.UpdatedAtMilliseconds < b.CreatedAtMilliseconds ||
		!validComputeContract(b.DataSensitivityContract) ||
		!validComputeContract(b.ProcessingContract) ||
		!validComputeOperations(b.AllowedOperations) {
		return NewProtocolError(CodeInvalidComputePool, "Shared Space compute binding fields are invalid")
	}
	return b.ResourceCeiling.Validate()
}

// ComputePoolChange is a complete, retry-safe replacement of one pool and its
// Space binding. Previous revisions are zero only when creating the pool.
type ComputePoolChange struct {
	Version                 int                    `json:"version"`
	RetryID                 uuid.UUID              `json:"retryID"`
	SpaceID                 uuid.UUID              `json:"spaceID"`
	PoolID                  uuid.UUID              `json:"poolID"`
	PreviousPoolRevision    uint64                 `json:"previousPoolRevision"`
	PreviousBindingRevision uint64                 `json:"previousBindingRevision"`
	DisplayName             string                 `json:"displayName"`
	Enabled                 bool                   `json:"enabled"`
	AllowedOperations       []string               `json:"allowedOperations"`
	ResourceCeiling         ComputeResourceCeiling `json:"resourceCeiling"`
	PricingRevision         uint64                 `json:"pricingRevision"`
	DataSensitivityContract string                 `json:"dataSensitivityContract"`
	ProcessingContract      string                 `json:"processingContract"`
	ChangedAtMilliseconds   int64                  `json:"changedAtMilliseconds"`
}

func (c ComputePoolChange) Validate() error {
	if c.Version != SchemaVersion || c.RetryID == uuid.Nil || c.SpaceID == uuid.Nil ||
		c.PoolID == uuid.Nil || c.PreviousPoolRevision != c.PreviousBindingRevision ||
		c.PricingRevision == 0 || c.ChangedAtMilliseconds < 0 ||
		!validComputeDisplayName(c.DisplayName) ||
		!validComputeContract(c.DataSensitivityContract) ||
		!validComputeContract(c.ProcessingContract) ||
		!validComputeOperations(c.AllowedOperations) {
		return NewProtocolError(CodeInvalidComputePool, "Shared Space compute pool change fields are invalid")
	}
	return c.ResourceCeiling.Validate()
}

type ComputePoolChangeResult struct {
	Acceptance relay.Acceptance    `json:"acceptance"`
	RetryID    uuid.UUID           `json:"retryID"`
	Pool       ComputePool         `json:"pool"`
	Binding    SpaceComputeBinding `json:"binding"`
}

func (r ComputePoolChangeResult) Validate() error {
	if (r.Acceptance != relay.AcceptanceAccepted && r.Acceptance != relay.AcceptanceDuplicate) ||
		r.RetryID == uuid.Nil {
		return NewProtocolError(CodeInvalidComputePool, "Shared Space compute pool result fields are invalid")
	}
	if err := r.Pool.Validate(); err != nil {
		return err
	}
	if err := r.Binding.Validate(); err != nil {
		return err
	}
	if r.Pool.SpaceID != r.Binding.SpaceID || r.Pool.PoolID != r.Binding.PoolID ||
		r.Pool.Revision != r.Binding.Revision ||
		r.Pool.CreatedAtMilliseconds != r.Binding.CreatedAtMilliseconds ||
		r.Pool.UpdatedAtMilliseconds != r.Binding.UpdatedAtMilliseconds {
		return NewProtocolError(CodeInvalidComputePool, "Shared Space compute pool and binding are inconsistent")
	}
	return nil
}

func validComputeDisplayName(value string) bool {
	trimmed := strings.TrimSpace(value)
	return utf8.ValidString(value) && trimmed == value && trimmed != "" &&
		len(value) <= MaximumComputePoolDisplayNameBytes &&
		utf8.RuneCountInString(value) <= MaximumComputePoolDisplayNameRunes
}

func validComputeContract(value string) bool {
	trimmed := strings.TrimSpace(value)
	return utf8.ValidString(value) && trimmed == value && trimmed != "" &&
		len(value) <= MaximumComputeContractBytes
}

func validComputeOperations(values []string) bool {
	if len(values) == 0 || len(values) > MaximumComputeOperationCount || !sort.StringsAreSorted(values) {
		return false
	}
	previous := ""
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if !utf8.ValidString(value) || trimmed == "" || trimmed != value ||
			len(value) > MaximumComputeOperationBytes || value == previous {
			return false
		}
		previous = value
	}
	return true
}

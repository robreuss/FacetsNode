package relay

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
)

const (
	DefaultMaximumDomainCountPerTenant  = 256
	DefaultMaximumMessageCountPerTenant = 1_000_000
	DefaultMaximumMessageBytesPerTenant = int64(1 * 1_024 * 1_024 * 1_024 * 1_024)
	DefaultMaximumBlobCountPerTenant    = 1_000_000
	DefaultMaximumBlobBytesPerTenant    = int64(1 * 1_024 * 1_024 * 1_024 * 1_024)
)

var tenantAuthorizationDomain = []byte("Facets replica relay tenant provisioning v1\x00")

type TenantCredential struct {
	TenantID uuid.UUID
	Token    string
}

func TenantAuthorizationDigest(credential TenantCredential) (string, error) {
	if credential.TenantID == uuid.Nil {
		return "", fmt.Errorf("tenant scope is invalid")
	}
	if err := validateToken(credential.Token); err != nil {
		return "", err
	}
	return scopedDigest(
		tenantAuthorizationDomain,
		credential.TenantID.String(),
		credential.Token,
	), nil
}

type TenantRegistration struct {
	Version                          int       `json:"version"`
	RetryID                          uuid.UUID `json:"retryID"`
	TenantID                         uuid.UUID `json:"tenantID"`
	AuthorizationDigest              string    `json:"authorizationDigest"`
	CreatedAtMilliseconds            int64     `json:"createdAtMilliseconds"`
	MaximumDomainCount               int       `json:"maximumDomainCount"`
	MaximumAggregateMessageCount     int       `json:"maximumAggregateMessageCount"`
	MaximumAggregateMessageByteCount int64     `json:"maximumAggregateMessageByteCount"`
	MaximumAggregateBlobCount        int       `json:"maximumAggregateBlobCount"`
	MaximumAggregateBlobByteCount    int64     `json:"maximumAggregateBlobByteCount"`
}

func (r TenantRegistration) Validate() error {
	if r.Version != SchemaVersion || r.RetryID == uuid.Nil ||
		r.TenantID == uuid.Nil || !validDigest(r.AuthorizationDigest) ||
		r.CreatedAtMilliseconds < 0 || r.MaximumDomainCount <= 0 ||
		r.MaximumAggregateMessageCount <= 0 ||
		r.MaximumAggregateMessageByteCount <= 0 ||
		r.MaximumAggregateBlobCount <= 0 ||
		r.MaximumAggregateBlobByteCount <= 0 {
		return protocolError(CodeInvalidTenant, "tenant fields are invalid")
	}
	return nil
}

func (r TenantRegistration) Authorize(credential TenantCredential) error {
	if credential.TenantID != r.TenantID {
		return protocolError(CodeWrongScope, "tenant credential belongs to another tenant")
	}
	digest, err := TenantAuthorizationDigest(credential)
	if err != nil || !constantTimeDigestEqual(digest, r.AuthorizationDigest) {
		return protocolError(CodeUnauthorized, "tenant credential is invalid")
	}
	return nil
}

type SubscriptionStatus string

const (
	SubscriptionActive              SubscriptionStatus = "active"
	SubscriptionRebootstrapRequired SubscriptionStatus = "rebootstrap_required"
	SubscriptionRevoked             SubscriptionStatus = "revoked"
)

func (s SubscriptionStatus) Valid() bool {
	return s == SubscriptionActive || s == SubscriptionRebootstrapRequired ||
		s == SubscriptionRevoked
}

type Subscription struct {
	Version               int                `json:"version"`
	TenantID              uuid.UUID          `json:"tenantID"`
	DomainID              uuid.UUID          `json:"domainID"`
	SubscriptionID        uuid.UUID          `json:"subscriptionID"`
	Status                SubscriptionStatus `json:"status"`
	StartCursor           *string            `json:"startCursor,omitempty"`
	CreatedAtMilliseconds int64              `json:"createdAtMilliseconds"`
	UpdatedAtMilliseconds int64              `json:"updatedAtMilliseconds"`
}

type SubscriptionCreateRequest struct {
	RetryID               uuid.UUID `json:"retryID"`
	SubscriptionID        uuid.UUID `json:"subscriptionID"`
	CreatedAtMilliseconds int64     `json:"createdAtMilliseconds"`
}

func (r SubscriptionCreateRequest) Validate() error {
	if r.RetryID == uuid.Nil || r.SubscriptionID == uuid.Nil ||
		r.CreatedAtMilliseconds < 0 {
		return protocolError(CodeInvalidSubscription, "subscription creation is invalid")
	}
	return nil
}

type SubscriptionCreateResponse struct {
	Acceptance   Acceptance   `json:"acceptance"`
	RetryID      uuid.UUID    `json:"retryID"`
	Subscription Subscription `json:"subscription"`
}

type SubscriptionStatusChangeRequest struct {
	RetryID               uuid.UUID          `json:"retryID"`
	Status                SubscriptionStatus `json:"status"`
	ChangedAtMilliseconds int64              `json:"changedAtMilliseconds"`
}

func (r SubscriptionStatusChangeRequest) Validate() error {
	if r.RetryID == uuid.Nil || !r.Status.Valid() || r.Status == SubscriptionActive ||
		r.ChangedAtMilliseconds < 0 {
		return protocolError(CodeInvalidSubscription, "subscription status change is invalid")
	}
	return nil
}

type SubscriptionStatusChangeResponse struct {
	Acceptance   Acceptance   `json:"acceptance"`
	RetryID      uuid.UUID    `json:"retryID"`
	Subscription Subscription `json:"subscription"`
}

// SubscriptionRebootstrapRequest lets an enrolled member fence only its own
// replica and restart at the relay's latest opaque checkpoint boundary.  The
// relay selects the cursor; it never inspects the checkpoint payload.
type SubscriptionRebootstrapRequest struct {
	RetryID                 uuid.UUID `json:"retryID"`
	RequestedAtMilliseconds int64     `json:"requestedAtMilliseconds"`
}

func (r SubscriptionRebootstrapRequest) Validate() error {
	if r.RetryID == uuid.Nil || r.RequestedAtMilliseconds < 0 {
		return protocolError(CodeInvalidSubscription, "subscription rebootstrap request is invalid")
	}
	return nil
}

type SubscriptionRebootstrapResponse struct {
	Acceptance   Acceptance   `json:"acceptance"`
	RetryID      uuid.UUID    `json:"retryID"`
	Subscription Subscription `json:"subscription"`
}

// SubscriptionRebootstrapCompletion is accepted only after the member has
// durably acknowledged every relay message in the checkpoint-tail interval.
// The cursor is opaque to the client, but sequence-backed to the relay so it
// can establish delivery completeness without parsing FEF content.
type SubscriptionRebootstrapCompletion struct {
	RetryID                 uuid.UUID `json:"retryID"`
	CompletedThroughCursor  string    `json:"completedThroughCursor"`
	CompletedAtMilliseconds int64     `json:"completedAtMilliseconds"`
}

func (r SubscriptionRebootstrapCompletion) Validate() error {
	if r.RetryID == uuid.Nil || r.CompletedAtMilliseconds < 0 {
		return protocolError(CodeInvalidSubscription, "subscription rebootstrap completion is invalid")
	}
	if err := ValidateOpaqueCursor(r.CompletedThroughCursor); err != nil {
		return protocolError(CodeInvalidCursor, "rebootstrap completion cursor is invalid")
	}
	return nil
}

type SubscriptionRebootstrapCompletionResponse struct {
	Acceptance   Acceptance   `json:"acceptance"`
	RetryID      uuid.UUID    `json:"retryID"`
	Subscription Subscription `json:"subscription"`
}

// TenantMembershipRevocation is an internal, tenant-authorized operation used
// by products such as Device Sync to fence one logical client from every relay
// domain it can reach. It intentionally carries only opaque relay identifiers.
// The operation is atomic: every listed member and subscription is revoked, or
// none of them are.
type TenantMembershipRevocation struct {
	Version               int                              `json:"version"`
	RetryID               uuid.UUID                        `json:"retryID"`
	RevokedAtMilliseconds int64                            `json:"revokedAtMilliseconds"`
	Memberships           []TenantMembershipRevocationItem `json:"memberships"`
}

type TenantMembershipRevocationItem struct {
	DomainID       uuid.UUID `json:"domainID"`
	SubscriptionID uuid.UUID `json:"subscriptionID"`
	MemberID       uuid.UUID `json:"memberID"`
}

func (r TenantMembershipRevocation) Validate() error {
	if r.Version != SchemaVersion || r.RetryID == uuid.Nil ||
		r.RevokedAtMilliseconds < 0 || len(r.Memberships) == 0 {
		return protocolError(CodeInvalidMember, "tenant membership revocation is invalid")
	}
	seenDomains := make(map[uuid.UUID]struct{}, len(r.Memberships))
	for _, item := range r.Memberships {
		if item.DomainID == uuid.Nil || item.SubscriptionID == uuid.Nil || item.MemberID == uuid.Nil {
			return protocolError(CodeInvalidMember, "tenant membership revocation target is invalid")
		}
		if _, duplicate := seenDomains[item.DomainID]; duplicate {
			return protocolError(CodeInvalidMember, "tenant membership revocation repeats a domain")
		}
		seenDomains[item.DomainID] = struct{}{}
	}
	return nil
}

type TenantMembershipRevocationResult struct {
	Acceptance            Acceptance                       `json:"acceptance"`
	RetryID               uuid.UUID                        `json:"retryID"`
	RevokedAtMilliseconds int64                            `json:"revokedAtMilliseconds"`
	Memberships           []TenantMembershipRevocationItem `json:"memberships"`
}

type DomainQuota struct {
	MaximumMessageCount     int   `json:"maximumMessageCount"`
	MaximumMessageByteCount int64 `json:"maximumMessageByteCount"`
	MaximumBlobCount        int   `json:"maximumBlobCount"`
	MaximumBlobByteCount    int64 `json:"maximumBlobByteCount"`
}

type DomainStatus struct {
	TenantID                    uuid.UUID   `json:"tenantID"`
	DomainID                    uuid.UUID   `json:"domainID"`
	MessageCount                int64       `json:"messageCount"`
	MessageByteCount            int64       `json:"messageByteCount"`
	BlobCount                   int64       `json:"blobCount"`
	BlobByteCount               int64       `json:"blobByteCount"`
	ReservedBlobCount           int64       `json:"reservedBlobCount"`
	ReservedBlobByteCount       int64       `json:"reservedBlobByteCount"`
	ActiveSubscriptionCount     int64       `json:"activeSubscriptionCount"`
	OldestUncollectedCursor     *string     `json:"oldestUncollectedCursor"`
	LatestActivatedCheckpointID *uuid.UUID  `json:"latestActivatedCheckpointID"`
	Quota                       DomainQuota `json:"quota"`
}

type TenantQuota struct {
	MaximumDomainCount               int   `json:"maximumDomainCount"`
	MaximumAggregateMessageCount     int   `json:"maximumAggregateMessageCount"`
	MaximumAggregateMessageByteCount int64 `json:"maximumAggregateMessageByteCount"`
	MaximumAggregateBlobCount        int   `json:"maximumAggregateBlobCount"`
	MaximumAggregateBlobByteCount    int64 `json:"maximumAggregateBlobByteCount"`
}

type TenantStatus struct {
	TenantID                  uuid.UUID   `json:"tenantID"`
	DomainCount               int64       `json:"domainCount"`
	AggregateMessageCount     int64       `json:"aggregateMessageCount"`
	AggregateMessageByteCount int64       `json:"aggregateMessageByteCount"`
	AggregateBlobCount        int64       `json:"aggregateBlobCount"`
	AggregateBlobByteCount    int64       `json:"aggregateBlobByteCount"`
	ReservedBlobCount         int64       `json:"reservedBlobCount"`
	ReservedBlobByteCount     int64       `json:"reservedBlobByteCount"`
	Quota                     TenantQuota `json:"quota"`
}

type SubscriptionMemberRegistration struct {
	SubscriptionID     uuid.UUID          `json:"subscriptionID"`
	MemberRegistration MemberRegistration `json:"memberRegistration"`
}

type SubscriptionMemberAdmission struct {
	SubscriptionID uuid.UUID       `json:"subscriptionID"`
	Admission      MemberAdmission `json:"admission"`
}

type SubscriptionAdmissionClaimResult struct {
	Acceptance Acceptance                     `json:"acceptance"`
	Member     SubscriptionMemberRegistration `json:"member"`
}

type SubscriptionAdmissionCreateResult struct {
	Acceptance Acceptance                  `json:"acceptance"`
	Admission  SubscriptionMemberAdmission `json:"admission"`
}

func (s Subscription) Validate() error {
	if s.Version != SchemaVersion || s.TenantID == uuid.Nil ||
		s.DomainID == uuid.Nil || s.SubscriptionID == uuid.Nil ||
		!s.Status.Valid() || s.CreatedAtMilliseconds < 0 ||
		s.UpdatedAtMilliseconds < s.CreatedAtMilliseconds {
		return protocolError(CodeInvalidSubscription, "subscription fields are invalid")
	}
	if s.StartCursor != nil {
		if err := ValidateOpaqueCursor(*s.StartCursor); err != nil {
			return protocolError(CodeInvalidSubscription, "subscription start cursor is invalid")
		}
	}
	return nil
}

func (s Subscription) ActiveForDelivery() bool {
	return s.Status == SubscriptionActive
}

type DomainProvisioning struct {
	Version                   int
	RetryID                   uuid.UUID
	Registration              DomainRegistration
	Subscription              Subscription
	InitialMember             MemberRegistration
	AdministrationPlainDigest string
	InitialMemberPlainDigest  string
}

func (p DomainProvisioning) Validate() error {
	if p.Version != SchemaVersion || p.RetryID == uuid.Nil {
		return protocolError(CodeInvalidDomain, "domain provisioning fields are invalid")
	}
	if err := p.Registration.Validate(); err != nil {
		return err
	}
	if err := p.Subscription.Validate(); err != nil {
		return err
	}
	if err := p.InitialMember.Validate(); err != nil {
		return err
	}
	if p.Subscription.TenantID != p.Registration.TenantID ||
		p.Subscription.DomainID != p.Registration.DomainID ||
		p.InitialMember.TenantID != p.Registration.TenantID ||
		p.InitialMember.DomainID != p.Registration.DomainID ||
		p.Subscription.Status != SubscriptionActive ||
		p.Subscription.CreatedAtMilliseconds != p.Registration.CreatedAtMilliseconds ||
		p.InitialMember.CreatedAtMilliseconds < p.Registration.CreatedAtMilliseconds {
		return protocolError(CodeWrongScope, "initial domain authority has inconsistent scope")
	}
	return nil
}

type DomainProvisioningResult struct {
	Acceptance                        Acceptance `json:"acceptance"`
	RetryID                           uuid.UUID  `json:"retryID"`
	TenantID                          uuid.UUID  `json:"tenantID"`
	DomainID                          uuid.UUID  `json:"domainID"`
	SubscriptionID                    uuid.UUID  `json:"subscriptionID"`
	MemberID                          uuid.UUID  `json:"memberID"`
	AdministrationAuthorizationDigest string     `json:"administrationAuthorizationDigest"`
	MemberAuthorizationDigest         string     `json:"memberAuthorizationDigest"`
}

type TenantProvisioningResult struct {
	Acceptance                            Acceptance               `json:"acceptance"`
	RetryID                               uuid.UUID                `json:"retryID"`
	TenantProvisioningAuthorizationDigest string                   `json:"tenantProvisioningAuthorizationDigest"`
	InitialDomain                         DomainProvisioningResult `json:"initialDomain"`
}

type TenantCredentialRotation struct {
	Version                        int       `json:"version"`
	RotationID                     uuid.UUID `json:"rotationID"`
	TenantID                       uuid.UUID `json:"tenantID"`
	ReplacementAuthorizationDigest string    `json:"replacementAuthorizationDigest"`
	RotatedAtMilliseconds          int64     `json:"rotatedAtMilliseconds"`
}

func (r TenantCredentialRotation) Validate() error {
	if r.Version != SchemaVersion || r.RotationID == uuid.Nil ||
		r.TenantID == uuid.Nil || !validDigest(r.ReplacementAuthorizationDigest) ||
		r.RotatedAtMilliseconds < 0 {
		return protocolError(CodeInvalidCredentialRotation, "tenant credential rotation is invalid")
	}
	return nil
}

type TenantCredentialRotationResult struct {
	Acceptance            Acceptance `json:"acceptance"`
	RotationID            uuid.UUID  `json:"rotationID"`
	TenantID              uuid.UUID  `json:"tenantID"`
	AuthorizationDigest   string     `json:"authorizationDigest"`
	RotatedAtMilliseconds int64      `json:"rotatedAtMilliseconds"`
}

func digestEqual(left, right string) bool {
	leftBytes, leftErr := hex.DecodeString(left)
	rightBytes, rightErr := hex.DecodeString(right)
	return leftErr == nil && rightErr == nil && len(leftBytes) == sha256.Size &&
		subtle.ConstantTimeCompare(leftBytes, rightBytes) == 1
}

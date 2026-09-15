package devicesync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

var (
	ErrObjectScopeConflict = errors.New("Spaces Sync object scope consent conflicts with retained state")
	ErrObjectScopeNotFound = errors.New("Spaces Sync object scope consent is unavailable")
)

// ObjectScopeConsent is ONE service's consent, not a bilateral link or storage
// permit. A future adapter must validate the full common intent and the Backup
// owner's independent consent. None of these IDs is authority by itself.
type ObjectScopeConsent struct {
	BindingID        uuid.UUID `json:"bindingID"`
	ContentEpoch     uint64    `json:"contentEpoch"`
	ContentScopeID   uuid.UUID `json:"contentScopeID"`
	DomainID         uuid.UUID `json:"domainID"`
	LedgerID         uuid.UUID `json:"ledgerID"`
	LinkID           uuid.UUID `json:"linkID"`
	LinkIntentDigest string    `json:"linkIntentDigest"`
	PoolID           uuid.UUID `json:"poolID"`
	PrincipalID      uuid.UUID `json:"principalID"`
	SpaceID          uuid.UUID `json:"spaceID"`
	Version          int       `json:"version"`
}

func (c ObjectScopeConsent) Validate() error {
	if c.Version != 1 || c.BindingID == uuid.Nil || c.ContentEpoch == 0 || c.ContentScopeID == uuid.Nil ||
		c.DomainID == uuid.Nil || c.LedgerID == uuid.Nil || c.LinkID == uuid.Nil || !validDigest(c.LinkIntentDigest) || c.LinkIntentDigest != strings.ToLower(c.LinkIntentDigest) ||
		c.PoolID == uuid.Nil || c.PrincipalID == uuid.Nil || c.SpaceID == uuid.Nil {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func (c ObjectScopeConsent) ReferenceDigest() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("Facets sync object scope consent reference v1\x00"), body...))
	return hex.EncodeToString(digest[:]), nil
}

// Mutations retain the exact operation body for retry. Withdrawing consent is
// terminal; it neither revokes participant credentials nor releases stored pins.
type ObjectScopeConsentMutation struct {
	Consent             ObjectScopeConsent `json:"consent"`
	ParticipantDeviceID uuid.UUID          `json:"participantDeviceID"`
	RetryID             uuid.UUID          `json:"retryID"`
	Withdraw            bool               `json:"withdraw"`
}

func (m ObjectScopeConsentMutation) Validate(credential SpaceSponsorCredential) error {
	if m.Consent.Validate() != nil || m.ParticipantDeviceID == uuid.Nil || m.RetryID == uuid.Nil ||
		credential.Administration.TenantID != m.Consent.PrincipalID || credential.Administration.DomainID != m.Consent.DomainID ||
		credential.Control.MemberID != m.ParticipantDeviceID || credential.Space.MemberID != m.ParticipantDeviceID {
		return serviceauthority.ErrInvalid
	}
	return nil
}

// Status is a point-in-time result, not continuing authorization. An exact
// acceptance retry after withdrawal returns Withdrawn=true, never reactivates.
type ObjectScopeConsentStatus struct {
	ReferenceDigest        string
	AcceptedAtMilliseconds int64
	Withdrawn              bool
}

// The store holds the durable deployment fence and current principal/Space/
// membership rows until Commit or Close. Commit revalidates authority at a NEW
// time after all lock waits. Close always rolls back an uncommitted mutation.
type ObjectScopeConsentTransaction interface {
	Commit(context.Context, serviceauthority.MutationAuthorization) (ObjectScopeConsentStatus, error)
	Close(context.Context) error
}

// Separate from the existing Store: no running route invokes this isolated seam.
type ObjectScopeConsentStore interface {
	BeginObjectScopeConsentMutation(context.Context, SpaceSponsorCredential, ObjectScopeConsentMutation,
		serviceauthority.MutationAuthorization) (ObjectScopeConsentTransaction, error)
}

type ObjectScopeConsentCustody struct {
	Store    ObjectScopeConsentStore
	Registry *serviceauthority.BindingRegistry
	Now      func() time.Time
}

const MaximumObjectScopeConsentDuration = 30 * time.Second

func (c *ObjectScopeConsentCustody) Apply(ctx context.Context, credential SpaceSponsorCredential,
	m ObjectScopeConsentMutation, binding serviceauthority.RequestBinding) (ObjectScopeConsentStatus, error) {
	if c == nil || c.Store == nil || c.Registry == nil || c.Now == nil || ctx == nil || m.Validate(credential) != nil ||
		binding.Scope != (serviceauthority.Scope{Kind: serviceauthority.ScopeDeviceSync, ScopeID: m.Consent.PrincipalID}) ||
		binding.TrafficClass != serviceauthority.TrafficControl {
		return ObjectScopeConsentStatus{}, serviceauthority.ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, MaximumObjectScopeConsentDuration)
	defer cancel()
	lease, err := c.Registry.AcquireMutationLease(bounded, binding.Scope)
	if err != nil {
		return ObjectScopeConsentStatus{}, err
	}
	defer lease.Release()
	authorization, err := c.Registry.AuthorizeMutationAt(binding, c.Now())
	if err != nil {
		return ObjectScopeConsentStatus{}, err
	}
	tx, err := c.Store.BeginObjectScopeConsentMutation(bounded, credential, m, authorization)
	if err != nil {
		return ObjectScopeConsentStatus{}, err
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = tx.Close(cleanup)
	}()
	if err := bounded.Err(); err != nil {
		return ObjectScopeConsentStatus{}, err
	}
	authorization, err = c.Registry.AuthorizeMutationAt(binding, c.Now())
	if err != nil {
		return ObjectScopeConsentStatus{}, err
	}
	return tx.Commit(bounded, authorization)
}

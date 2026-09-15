package backupcustody

import (
	"encoding/json"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const objectScopeConsentReferenceDomain = "Facets backup object scope consent reference v1\x00"

// ObjectScopeConsent is the Backup owner's half of a proposed resource link.
// It is NOT Sync authority, a verified bilateral link, or a storage permit.
// The full link intent and current authority must be checked before any effect.
type ObjectScopeConsent struct {
	AccountID        uuid.UUID `json:"accountID"`
	BackupSetID      uuid.UUID `json:"backupSetID"`
	BindingID        uuid.UUID `json:"bindingID"`
	ContentEpoch     uint64    `json:"contentEpoch"`
	ContentScopeID   uuid.UUID `json:"contentScopeID"`
	LedgerID         uuid.UUID `json:"ledgerID"`
	LinkID           uuid.UUID `json:"linkID"`
	LinkIntentDigest string    `json:"linkIntentDigest"`
	PoolID           uuid.UUID `json:"poolID"`
	TargetID         uuid.UUID `json:"targetID"`
	Version          int       `json:"version"`
}

func (consent ObjectScopeConsent) Validate() error {
	if consent.Version != 1 || consent.AccountID == uuid.Nil || consent.BackupSetID == uuid.Nil ||
		consent.BindingID == uuid.Nil || consent.ContentEpoch == 0 || consent.ContentScopeID == uuid.Nil ||
		consent.LedgerID == uuid.Nil || consent.LinkID == uuid.Nil || !validHexDigest(consent.LinkIntentDigest) ||
		consent.PoolID == uuid.Nil || consent.TargetID == uuid.Nil {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func (consent ObjectScopeConsent) ReferenceDigest() (string, error) {
	if consent.Validate() != nil {
		return "", serviceauthority.ErrInvalid
	}
	encoded, err := json.Marshal(consent)
	if err != nil {
		return "", serviceauthority.ErrInvalid
	}
	return hexDigest(append([]byte(objectScopeConsentReferenceDomain), encoded...)), nil
}

// AcceptedObjectScopeConsent is a derived control-log projection, not a bearer.
// Retaining this value after its source transaction cannot establish currentness.
type AcceptedObjectScopeConsent struct {
	Consent         ObjectScopeConsent
	ReferenceDigest string
	Revoked         bool
}

func cloneObjectScopeConsents(source map[string]AcceptedObjectScopeConsent) map[string]AcceptedObjectScopeConsent {
	result := make(map[string]AcceptedObjectScopeConsent, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func insertObjectScopeConsent(consents map[string]AcceptedObjectScopeConsent, consent ObjectScopeConsent) error {
	reference, err := consent.ReferenceDigest()
	if err != nil {
		return err
	}
	for _, prior := range consents {
		if prior.ReferenceDigest == reference || prior.Consent.BindingID == consent.BindingID ||
			prior.Consent.LinkID == consent.LinkID || prior.Consent.LinkIntentDigest == consent.LinkIntentDigest {
			return serviceauthority.ErrInvalid
		}
	}
	consents[reference] = AcceptedObjectScopeConsent{Consent: consent, ReferenceDigest: reference}
	return nil
}

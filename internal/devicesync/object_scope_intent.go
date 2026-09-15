package devicesync

import "github.com/robreuss/FacetsNode/internal/serviceauthority"

// NewObjectScopeConsent derives Sync's half from the entire common intent.
// It does NOT accept consent or verify Backup's independent owner authority.
func NewObjectScopeConsent(intent serviceauthority.CustodyLinkIntent) (ObjectScopeConsent, error) {
	digest, err := intent.ReferenceDigest()
	if err != nil {
		return ObjectScopeConsent{}, err
	}
	return ObjectScopeConsent{PrincipalID: intent.SyncPrincipalID, SpaceID: intent.SyncSpaceID, DomainID: intent.SyncDomainID,
		BindingID: intent.SyncBindingID, ContentEpoch: intent.ContentEpoch, ContentScopeID: intent.ContentScopeID, LedgerID: intent.LedgerID,
		LinkID: intent.LinkID, LinkIntentDigest: digest, PoolID: intent.PoolID, Version: 1}, nil
}

func (c ObjectScopeConsent) ValidateIntent(intent serviceauthority.CustodyLinkIntent) error {
	expected, err := NewObjectScopeConsent(intent)
	if err != nil || c != expected {
		return serviceauthority.ErrInvalid
	}
	return nil
}

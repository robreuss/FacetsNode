package backupcustody

import "github.com/robreuss/FacetsNode/internal/serviceauthority"

// NewObjectScopeConsent derives Backup's half from the entire common intent.
// It does NOT sign/accept consent or verify the Sync participant's authority.
func NewObjectScopeConsent(intent serviceauthority.CustodyLinkIntent) (ObjectScopeConsent, error) {
	digest, err := intent.ReferenceDigest()
	if err != nil {
		return ObjectScopeConsent{}, err
	}
	return ObjectScopeConsent{AccountID: intent.BackupAccountID, BackupSetID: intent.BackupSetID, BindingID: intent.BackupBindingID,
		ContentEpoch: intent.ContentEpoch, ContentScopeID: intent.ContentScopeID, LedgerID: intent.LedgerID, LinkID: intent.LinkID,
		LinkIntentDigest: digest, PoolID: intent.PoolID, TargetID: intent.BackupTargetID, Version: 1}, nil
}

func (c ObjectScopeConsent) ValidateIntent(intent serviceauthority.CustodyLinkIntent) error {
	expected, err := NewObjectScopeConsent(intent)
	if err != nil || c != expected {
		return serviceauthority.ErrInvalid
	}
	return nil
}

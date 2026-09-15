package serviceauthority

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/google/uuid"
)

const MaximumCustodyLinkIntentBytes = 4096

// CustodyLinkIntent commits the FULL proposed compatible resource association.
// It is public metadata, not a grant, proof of common ownership or an activated
// link. Each service must independently verify current consent for this exact
// intent; the receiver must independently pin PoolID/LedgerID. Neither service
// receives the other's credentials, signing keys, manifests or plaintext.
type CustodyLinkIntent struct {
	BackupAccountID uuid.UUID `json:"backupAccountID"`
	BackupBindingID uuid.UUID `json:"backupBindingID"`
	BackupSetID     uuid.UUID `json:"backupSetID"`
	BackupTargetID  uuid.UUID `json:"backupTargetID"`
	ContentEpoch    uint64    `json:"contentEpoch"`
	ContentScopeID  uuid.UUID `json:"contentScopeID"`
	LedgerID        uuid.UUID `json:"ledgerID"`
	LinkID          uuid.UUID `json:"linkID"`
	PoolID          uuid.UUID `json:"poolID"`
	SyncBindingID   uuid.UUID `json:"syncBindingID"`
	SyncDomainID    uuid.UUID `json:"syncDomainID"`
	SyncPrincipalID uuid.UUID `json:"syncPrincipalID"`
	SyncSpaceID     uuid.UUID `json:"syncSpaceID"`
	Version         int       `json:"version"`
}

func (i CustodyLinkIntent) Validate() error {
	if i.Version != 1 || i.ContentEpoch == 0 || i.BackupBindingID == i.SyncBindingID {
		return ErrInvalid
	}
	for _, id := range []uuid.UUID{i.BackupAccountID, i.BackupBindingID, i.BackupSetID, i.BackupTargetID,
		i.ContentScopeID, i.LedgerID, i.LinkID, i.PoolID, i.SyncBindingID, i.SyncDomainID, i.SyncPrincipalID, i.SyncSpaceID} {
		if id == uuid.Nil {
			return ErrInvalid
		}
	}
	// The content scope is an opaque random identity, not a public account or
	// resource identifier reused as a cross-service correlation label.
	for _, id := range []uuid.UUID{i.BackupAccountID, i.BackupSetID, i.BackupTargetID, i.SyncDomainID, i.SyncPrincipalID, i.SyncSpaceID} {
		if i.ContentScopeID == id {
			return ErrInvalid
		}
	}
	return nil
}

func (i CustodyLinkIntent) ReferenceDigest() (string, error) {
	if err := i.Validate(); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(i)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("Facets immutable custody link intent v1\x00"), canonical...))
	return hex.EncodeToString(digest[:]), nil
}

// Equality with re-encoded bytes rejects unknown/duplicate fields, whitespace,
// alternate UUID spellings, floats, omitted fields and trailing input. This
// decoder does not authenticate a sender or turn an intent into a resource link.
func DecodeCustodyLinkIntent(data []byte) (CustodyLinkIntent, error) {
	var intent CustodyLinkIntent
	if len(data) == 0 || len(data) > MaximumCustodyLinkIntentBytes {
		return intent, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&intent) != nil || intent.Validate() != nil {
		return CustodyLinkIntent{}, ErrInvalid
	}
	canonical, err := json.Marshal(intent)
	if err != nil || !bytes.Equal(canonical, data) {
		return CustodyLinkIntent{}, ErrInvalid
	}
	return intent, nil
}

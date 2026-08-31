package backupcustody

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

// This file defines portable, content-blind account-control and credential
// records only. They are not custody/retention receipts, are not wired to a
// service handler or store in this checkpoint, and carry no Recovery Root
// coordinates or raw bearer secret.
const (
	CredentialAuthorityVersion                                   = 1
	CredentialAuthoritySignatureAlgorithm                        = "Ed25519"
	MaximumCredentialAuthorityPayloadByteCount                   = 64 * 1024
	MaximumCredentialAuthorityRecordByteCount                    = 80 * 1024
	controlKeyIDDomain                                           = "Facets backup custody account control key ID v1\x00"
	controlAnchorPossessionSignatureDomain                       = "Facets backup custody account control possession v1\x00"
	controlAnchorReferenceDomain                                 = "Facets backup custody account control anchor reference v1\x00"
	controlCommandAuthoritySignatureDomain                       = "Facets backup custody account control command authority v1\x00"
	controlCommandNewPossessionSignatureDomain                   = "Facets backup custody account control command new possession v1\x00"
	controlCommandReferenceDomain                                = "Facets backup custody account control command reference v1\x00"
	credentialGrantReferenceDomain                               = "Facets backup custody credential grant reference v1\x00"
	CreateTargetWithInitialGrant               ControlEffectKind = "create_target_with_initial_grant"
	GrantCredential                            ControlEffectKind = "grant"
	SupersedeCredential                        ControlEffectKind = "supersede"
	RevokeCredential                           ControlEffectKind = "revoke"
	RotateControlKey                           ControlEffectKind = "rotate_control_key"
)

// ControlPossessionAnchor proves only possession of one opaque account-control
// key. It carries no Recovery Root coordinates and is not authority until an
// owner-controlled store pins its exact reference as the initial account head.
type ControlPossessionAnchorUnsigned struct {
	AccountID             uuid.UUID `json:"accountID"`
	Algorithm             string    `json:"algorithm"`
	ControlGeneration     uint64    `json:"controlGeneration"`
	ControlKeyID          uuid.UUID `json:"controlKeyID"`
	PublicSigningKey      string    `json:"publicSigningKey"`
	SigningKeyFingerprint string    `json:"signingKeyFingerprint"`
	Version               int       `json:"version"`
}

func (value ControlPossessionAnchorUnsigned) Validate() error {
	key, err := decodeBase64URL(value.PublicSigningKey, ed25519.PublicKeySize)
	if value.Version != CredentialAuthorityVersion || value.AccountID == uuid.Nil ||
		value.Algorithm != CredentialAuthoritySignatureAlgorithm || value.ControlGeneration == 0 ||
		value.ControlKeyID == uuid.Nil || err != nil || !validHexDigest(value.SigningKeyFingerprint) ||
		value.SigningKeyFingerprint != hexDigest(key) || value.ControlKeyID != controlKeyID(key) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

type ControlPossessionAnchor struct {
	PossessionSignature string                          `json:"possessionSignature"`
	Unsigned            ControlPossessionAnchorUnsigned `json:"unsigned"`
}

func (anchor ControlPossessionAnchor) VerifyPossession() error {
	if anchor.Unsigned.Validate() != nil {
		return serviceauthority.ErrInvalid
	}
	key, _ := decodeBase64URL(anchor.Unsigned.PublicSigningKey, ed25519.PublicKeySize)
	signature, err := decodeBase64URL(anchor.PossessionSignature, ed25519.SignatureSize)
	encoded, encodeErr := json.Marshal(anchor.Unsigned)
	if err != nil || encodeErr != nil || !ed25519.Verify(
		ed25519.PublicKey(key),
		append([]byte(controlAnchorPossessionSignatureDomain), encoded...),
		signature,
	) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func (anchor ControlPossessionAnchor) CanonicalJSON() ([]byte, error) {
	if anchor.VerifyPossession() != nil {
		return nil, serviceauthority.ErrInvalid
	}
	encoded, err := json.Marshal(anchor)
	if err != nil || len(encoded) > MaximumCredentialAuthorityRecordByteCount {
		return nil, serviceauthority.ErrInvalid
	}
	return encoded, nil
}

func (anchor ControlPossessionAnchor) ReferenceDigest() (string, error) {
	encoded, err := anchor.CanonicalJSON()
	if err != nil {
		return "", serviceauthority.ErrInvalid
	}
	return hexDigest(append([]byte(controlAnchorReferenceDomain), encoded...)), nil
}

func DecodeControlPossessionAnchor(input []byte) (ControlPossessionAnchor, error) {
	var value ControlPossessionAnchor
	if decodeCredentialAuthorityCanonical(input, &value, MaximumCredentialAuthorityRecordByteCount) != nil ||
		value.VerifyPossession() != nil {
		return value, serviceauthority.ErrInvalid
	}
	return value, nil
}

type CredentialGrant struct {
	AuthorizationDigest string                    `json:"authorizationDigest"`
	Credential          TargetCredentialReference `json:"credential"`
	Version             int                       `json:"version"`
}

func (grant CredentialGrant) Validate() error {
	if grant.Version != CredentialAuthorityVersion || grant.Credential.Validate() != nil ||
		!validHexDigest(grant.AuthorizationDigest) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func (grant CredentialGrant) ReferenceDigest() (string, error) {
	if grant.Validate() != nil {
		return "", serviceauthority.ErrInvalid
	}
	encoded, err := json.Marshal(grant)
	if err != nil {
		return "", serviceauthority.ErrInvalid
	}
	return hexDigest(append([]byte(credentialGrantReferenceDomain), encoded...)), nil
}

type ControlEffectKind string

type ControlEffect struct {
	BackupSetID               *uuid.UUID               `json:"backupSetID,omitempty"`
	ControlAnchor             *ControlPossessionAnchor `json:"controlAnchor,omitempty"`
	Grant                     *CredentialGrant         `json:"grant,omitempty"`
	Kind                      ControlEffectKind        `json:"kind"`
	PriorGrantReferenceDigest *string                  `json:"priorGrantReferenceDigest,omitempty"`
	TargetID                  *uuid.UUID               `json:"targetID,omitempty"`
}

func (effect ControlEffect) Validate() error {
	switch effect.Kind {
	case CreateTargetWithInitialGrant:
		if effect.TargetID == nil || *effect.TargetID == uuid.Nil || effect.BackupSetID == nil ||
			*effect.BackupSetID == uuid.Nil || effect.Grant == nil || effect.Grant.Validate() != nil ||
			effect.Grant.Credential.TargetID != *effect.TargetID ||
			effect.Grant.Credential.BackupSetID != *effect.BackupSetID ||
			effect.PriorGrantReferenceDigest != nil || effect.ControlAnchor != nil {
			return serviceauthority.ErrInvalid
		}
	case GrantCredential:
		if effect.Grant == nil || effect.Grant.Validate() != nil || effect.TargetID != nil ||
			effect.BackupSetID != nil || effect.PriorGrantReferenceDigest != nil || effect.ControlAnchor != nil {
			return serviceauthority.ErrInvalid
		}
	case SupersedeCredential:
		if effect.Grant == nil || effect.Grant.Validate() != nil || effect.PriorGrantReferenceDigest == nil ||
			!validHexDigest(*effect.PriorGrantReferenceDigest) || effect.TargetID != nil ||
			effect.BackupSetID != nil || effect.ControlAnchor != nil {
			return serviceauthority.ErrInvalid
		}
	case RevokeCredential:
		if effect.PriorGrantReferenceDigest == nil || !validHexDigest(*effect.PriorGrantReferenceDigest) ||
			effect.Grant != nil || effect.TargetID != nil || effect.BackupSetID != nil || effect.ControlAnchor != nil {
			return serviceauthority.ErrInvalid
		}
	case RotateControlKey:
		if effect.ControlAnchor == nil || effect.ControlAnchor.VerifyPossession() != nil || effect.Grant != nil ||
			effect.TargetID != nil || effect.BackupSetID != nil || effect.PriorGrantReferenceDigest != nil {
			return serviceauthority.ErrInvalid
		}
	default:
		return serviceauthority.ErrInvalid
	}
	return nil
}

type ControlCommandPayload struct {
	AccountID                  uuid.UUID     `json:"accountID"`
	CommandID                  uuid.UUID     `json:"commandID"`
	ControlGeneration          uint64        `json:"controlGeneration"`
	ControlKeyID               uuid.UUID     `json:"controlKeyID"`
	Effect                     ControlEffect `json:"effect"`
	PredecessorReferenceDigest string        `json:"predecessorReferenceDigest"`
	Sequence                   uint64        `json:"sequence"`
	Version                    int           `json:"version"`
}

func (payload ControlCommandPayload) Validate() error {
	if payload.Version != CredentialAuthorityVersion || payload.AccountID == uuid.Nil || payload.CommandID == uuid.Nil ||
		payload.ControlGeneration == 0 || payload.ControlKeyID == uuid.Nil || payload.Sequence == 0 ||
		!validHexDigest(payload.PredecessorReferenceDigest) || payload.Effect.Validate() != nil ||
		(payload.Effect.Grant != nil && payload.Effect.Grant.Credential.AccountID != payload.AccountID) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

type SignedControlCommand struct {
	AuthoritySignature     string  `json:"authoritySignature"`
	NewPossessionSignature *string `json:"newPossessionSignature,omitempty"`
	Payload                []byte  `json:"payload"`
}

func (record SignedControlCommand) DecodedPayload() (ControlCommandPayload, error) {
	var payload ControlCommandPayload
	if decodeCredentialAuthorityCanonical(record.Payload, &payload, MaximumCredentialAuthorityPayloadByteCount) != nil ||
		payload.Validate() != nil || !validBase64URLBytes(record.AuthoritySignature, ed25519.SignatureSize) ||
		(record.NewPossessionSignature != nil && !validBase64URLBytes(*record.NewPossessionSignature, ed25519.SignatureSize)) ||
		(payload.Effect.Kind == RotateControlKey) != (record.NewPossessionSignature != nil) {
		return payload, serviceauthority.ErrInvalid
	}
	return payload, nil
}

func (record SignedControlCommand) Verify(current ControlPossessionAnchor) (ControlCommandPayload, error) {
	payload, err := record.DecodedPayload()
	if err != nil || current.VerifyPossession() != nil || payload.AccountID != current.Unsigned.AccountID ||
		payload.ControlGeneration != current.Unsigned.ControlGeneration || payload.ControlKeyID != current.Unsigned.ControlKeyID {
		return payload, serviceauthority.ErrInvalid
	}
	if verifyEd25519(current.Unsigned.PublicSigningKey, record.AuthoritySignature,
		append([]byte(controlCommandAuthoritySignatureDomain), record.Payload...)) != nil {
		return payload, serviceauthority.ErrInvalid
	}
	if payload.Effect.Kind == RotateControlKey {
		next := payload.Effect.ControlAnchor
		if next == nil || current.Unsigned.ControlGeneration == ^uint64(0) ||
			next.Unsigned.AccountID != payload.AccountID || next.Unsigned.ControlGeneration != current.Unsigned.ControlGeneration+1 ||
			next.Unsigned.ControlKeyID == current.Unsigned.ControlKeyID || next.VerifyPossession() != nil ||
			record.NewPossessionSignature == nil || verifyEd25519(next.Unsigned.PublicSigningKey,
			*record.NewPossessionSignature,
			append([]byte(controlCommandNewPossessionSignatureDomain), record.Payload...)) != nil {
			return payload, serviceauthority.ErrInvalid
		}
	}
	return payload, nil
}

func (record SignedControlCommand) CanonicalJSON() ([]byte, error) {
	if _, err := record.DecodedPayload(); err != nil {
		return nil, serviceauthority.ErrInvalid
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > MaximumCredentialAuthorityRecordByteCount {
		return nil, serviceauthority.ErrInvalid
	}
	return encoded, nil
}

func (record SignedControlCommand) ReferenceDigest() (string, error) {
	encoded, err := record.CanonicalJSON()
	if err != nil {
		return "", serviceauthority.ErrInvalid
	}
	return hexDigest(append([]byte(controlCommandReferenceDomain), encoded...)), nil
}

func DecodeSignedControlCommand(input []byte) (SignedControlCommand, error) {
	var value SignedControlCommand
	if decodeCredentialAuthorityCanonical(input, &value, MaximumCredentialAuthorityRecordByteCount) != nil {
		return value, serviceauthority.ErrInvalid
	}
	if _, err := value.DecodedPayload(); err != nil {
		return value, serviceauthority.ErrInvalid
	}
	return value, nil
}

type AcceptedGrantStatus string

const (
	GrantActive     AcceptedGrantStatus = "active"
	GrantSuperseded AcceptedGrantStatus = "superseded"
	GrantRevoked    AcceptedGrantStatus = "revoked"
)

type AcceptedGrant struct {
	Grant                      CredentialGrant
	ReferenceDigest            string
	Status                     AcceptedGrantStatus
	ReplacementReferenceDigest *string
}

type AcceptedControlHead struct {
	AccountID         uuid.UUID
	Sequence          uint64
	ControlGeneration uint64
	ControlKeyID      uuid.UUID
	ReferenceDigest   string
}

// CredentialAuthorityState applies records only in explicit durable commit
// order. Client timestamps have no authority here. Exact replay is idempotent
// only for the current tail; historical lookup belongs to the later durable
// store rather than this CAS reducer.
type CredentialAuthorityState struct {
	PinnedInitialAnchor ControlPossessionAnchor
	CurrentAnchor       ControlPossessionAnchor
	Head                AcceptedControlHead
	Targets             map[uuid.UUID]uuid.UUID
	Grants              map[string]AcceptedGrant
	Records             []SignedControlCommand
}

func NewCredentialAuthorityState(externallyPinnedInitialAnchor ControlPossessionAnchor) (CredentialAuthorityState, error) {
	if externallyPinnedInitialAnchor.VerifyPossession() != nil ||
		externallyPinnedInitialAnchor.Unsigned.ControlGeneration != 1 {
		return CredentialAuthorityState{}, serviceauthority.ErrInvalid
	}
	reference, err := externallyPinnedInitialAnchor.ReferenceDigest()
	if err != nil {
		return CredentialAuthorityState{}, serviceauthority.ErrInvalid
	}
	return CredentialAuthorityState{
		PinnedInitialAnchor: externallyPinnedInitialAnchor,
		CurrentAnchor:       externallyPinnedInitialAnchor,
		Head: AcceptedControlHead{
			AccountID:         externallyPinnedInitialAnchor.Unsigned.AccountID,
			ControlGeneration: externallyPinnedInitialAnchor.Unsigned.ControlGeneration,
			ControlKeyID:      externallyPinnedInitialAnchor.Unsigned.ControlKeyID,
			ReferenceDigest:   reference,
		},
		Targets: make(map[uuid.UUID]uuid.UUID), Grants: make(map[string]AcceptedGrant),
	}, nil
}

func (state *CredentialAuthorityState) Apply(record SignedControlCommand) error {
	if state == nil || state.CurrentAnchor.VerifyPossession() != nil {
		return serviceauthority.ErrInvalid
	}
	if len(state.Records) > 0 {
		lastBytes, _ := state.Records[len(state.Records)-1].CanonicalJSON()
		candidateBytes, _ := record.CanonicalJSON()
		if len(lastBytes) > 0 && bytes.Equal(lastBytes, candidateBytes) {
			return nil
		}
	}
	payload, err := record.Verify(state.CurrentAnchor)
	if err != nil || payload.AccountID != state.Head.AccountID || state.Head.Sequence == ^uint64(0) ||
		payload.Sequence != state.Head.Sequence+1 || payload.PredecessorReferenceDigest != state.Head.ReferenceDigest {
		return serviceauthority.ErrInvalid
	}
	acceptedControlKeyIDs := map[uuid.UUID]struct{}{
		state.PinnedInitialAnchor.Unsigned.ControlKeyID: {},
	}
	for _, accepted := range state.Records {
		acceptedPayload, decodeErr := accepted.DecodedPayload()
		if decodeErr != nil || acceptedPayload.CommandID == payload.CommandID {
			return serviceauthority.ErrInvalid
		}
		if acceptedPayload.Effect.ControlAnchor != nil {
			acceptedControlKeyIDs[acceptedPayload.Effect.ControlAnchor.Unsigned.ControlKeyID] = struct{}{}
		}
	}
	nextTargets := cloneTargets(state.Targets)
	nextGrants := cloneGrants(state.Grants)
	nextAnchor := state.CurrentAnchor
	switch payload.Effect.Kind {
	case CreateTargetWithInitialGrant:
		targetID, backupSetID, grant := *payload.Effect.TargetID, *payload.Effect.BackupSetID, *payload.Effect.Grant
		if _, exists := nextTargets[targetID]; exists || targetSetExists(nextTargets, backupSetID) ||
			insertGrant(nextGrants, grant) != nil {
			return serviceauthority.ErrInvalid
		}
		nextTargets[targetID] = backupSetID
	case GrantCredential:
		grant := *payload.Effect.Grant
		if nextTargets[grant.Credential.TargetID] != grant.Credential.BackupSetID || insertGrant(nextGrants, grant) != nil {
			return serviceauthority.ErrInvalid
		}
	case SupersedeCredential:
		prior, grant := *payload.Effect.PriorGrantReferenceDigest, *payload.Effect.Grant
		existing, exists := nextGrants[prior]
		if !exists || existing.Status != GrantActive || nextTargets[grant.Credential.TargetID] != grant.Credential.BackupSetID ||
			existing.Grant.Credential.TargetID != grant.Credential.TargetID ||
			existing.Grant.Credential.BackupSetID != grant.Credential.BackupSetID || insertGrant(nextGrants, grant) != nil {
			return serviceauthority.ErrInvalid
		}
		replacement, _ := grant.ReferenceDigest()
		existing.Status = GrantSuperseded
		existing.ReplacementReferenceDigest = &replacement
		nextGrants[prior] = existing
	case RevokeCredential:
		prior := *payload.Effect.PriorGrantReferenceDigest
		existing, exists := nextGrants[prior]
		if !exists || existing.Status != GrantActive {
			return serviceauthority.ErrInvalid
		}
		existing.Status = GrantRevoked
		existing.ReplacementReferenceDigest = nil
		nextGrants[prior] = existing
	case RotateControlKey:
		if _, reused := acceptedControlKeyIDs[payload.Effect.ControlAnchor.Unsigned.ControlKeyID]; reused {
			return serviceauthority.ErrInvalid
		}
		nextAnchor = *payload.Effect.ControlAnchor
	default:
		return serviceauthority.ErrInvalid
	}
	reference, err := record.ReferenceDigest()
	if err != nil {
		return serviceauthority.ErrInvalid
	}
	state.Targets = nextTargets
	state.Grants = nextGrants
	state.CurrentAnchor = nextAnchor
	state.Head = AcceptedControlHead{
		AccountID: payload.AccountID, Sequence: payload.Sequence,
		ControlGeneration: nextAnchor.Unsigned.ControlGeneration,
		ControlKeyID:      nextAnchor.Unsigned.ControlKeyID, ReferenceDigest: reference,
	}
	state.Records = append(state.Records, record)
	return nil
}

func (state *CredentialAuthorityState) ApplyAll(records []SignedControlCommand) error {
	for _, record := range records {
		if err := state.Apply(record); err != nil {
			return err
		}
	}
	return nil
}

func (state CredentialAuthorityState) ActiveGrant(credentialID uuid.UUID) (AcceptedGrant, bool) {
	for _, grant := range state.Grants {
		if grant.Grant.Credential.CredentialID == credentialID && grant.Status == GrantActive {
			return grant, true
		}
	}
	return AcceptedGrant{}, false
}

func insertGrant(grants map[string]AcceptedGrant, grant CredentialGrant) error {
	reference, err := grant.ReferenceDigest()
	if err != nil {
		return serviceauthority.ErrInvalid
	}
	if _, exists := grants[reference]; exists {
		return serviceauthority.ErrInvalid
	}
	for _, existing := range grants {
		if existing.Grant.Credential.CredentialID == grant.Credential.CredentialID {
			return serviceauthority.ErrInvalid
		}
	}
	grants[reference] = AcceptedGrant{Grant: grant, ReferenceDigest: reference, Status: GrantActive}
	return nil
}

func cloneTargets(source map[uuid.UUID]uuid.UUID) map[uuid.UUID]uuid.UUID {
	result := make(map[uuid.UUID]uuid.UUID, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func targetSetExists(targets map[uuid.UUID]uuid.UUID, backupSetID uuid.UUID) bool {
	for _, candidate := range targets {
		if candidate == backupSetID {
			return true
		}
	}
	return false
}

func cloneGrants(source map[string]AcceptedGrant) map[string]AcceptedGrant {
	result := make(map[string]AcceptedGrant, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func verifyEd25519(publicKey, signature string, message []byte) error {
	key, keyErr := decodeBase64URL(publicKey, ed25519.PublicKeySize)
	sig, sigErr := decodeBase64URL(signature, ed25519.SignatureSize)
	if keyErr != nil || sigErr != nil || !ed25519.Verify(ed25519.PublicKey(key), message, sig) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func decodeBase64URL(value string, count int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != count || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, serviceauthority.ErrInvalid
	}
	return decoded, nil
}

func validBase64URLBytes(value string, count int) bool {
	_, err := decodeBase64URL(value, count)
	return err == nil
}

func hexDigest(input []byte) string {
	digest := sha256.Sum256(input)
	return hex.EncodeToString(digest[:])
}

func controlKeyID(publicKey []byte) uuid.UUID {
	digest := sha256.Sum256(append([]byte(controlKeyIDDomain), publicKey...))
	value := append([]byte(nil), digest[:16]...)
	value[6] = (value[6] & 0x0f) | 0x50
	value[8] = (value[8] & 0x3f) | 0x80
	result, _ := uuid.FromBytes(value)
	return result
}

func decodeCredentialAuthorityCanonical(input []byte, target any, maximum int) error {
	if len(input) == 0 || len(input) > maximum {
		return serviceauthority.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return serviceauthority.ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return serviceauthority.ErrInvalid
	}
	encoded, err := json.Marshal(target)
	if err != nil || !bytes.Equal(encoded, input) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

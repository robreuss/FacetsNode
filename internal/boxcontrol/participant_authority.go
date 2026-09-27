package boxcontrol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

// This is a pure admission boundary, not an HTTP enrollment route. In
// particular, a discovery ConnectionGrant cannot create either record below.
// The operational store must pin the owner-approved Box-scoped root and exact device
// grant before calling Authorize, and consume challenges durably at admission.
// V1 accepts only initial generation-1 grants. Chained device rotation needs
// a complete signed-history reducer on both platforms before this gate widens.
const boxParticipantCapability = "facets.box.participate"

var (
	ErrParticipantAuthority = errors.New("BOX-PARTICIPANT-AUTHORITY: Box participant or device authority is invalid; re-enroll this device with the Box")
	ErrParticipantReplay    = errors.New("BOX-PARTICIPANT-REPLAY: Box participant proof was already used; request a new challenge")
)

const (
	principalRootDomain                    = "Facets principal trust root v1\x00"
	principalDeviceDomain                  = "Facets principal device grant v1\x00"
	principalRevocationDomain              = "Facets principal device revocation v1\x00"
	participantProofDomain                 = "Facets Box participant proof v1\x00"
	maximumParticipantProofAgeMilliseconds = int64(2 * 60 * 1000)
)

type BoxParticipantAnchor struct {
	BoxID                  uuid.UUID `json:"boxID"`
	ParticipantID          uuid.UUID `json:"participantID"`
	BoxScopedPrincipalID   uuid.UUID `json:"boxScopedPrincipalID"`
	RootKeyFingerprint     string    `json:"rootKeyFingerprint"`
	ApprovedAtMilliseconds int64     `json:"approvedAtMilliseconds"`
	RevokedAtMilliseconds  int64     `json:"revokedAtMilliseconds"`
}

type BoxParticipantDevice struct {
	ParticipantID            uuid.UUID `json:"participantID"`
	DeviceID                 uuid.UUID `json:"deviceID"`
	GrantID                  uuid.UUID `json:"grantID"`
	DeviceGeneration         uint64    `json:"deviceGeneration"`
	SigningKeyFingerprint    string    `json:"signingKeyFingerprint"`
	RevokedThroughGeneration uint64    `json:"revokedThroughGeneration"`
}

// Human-facing, Box-local projection. It is neither a Principal credential
// nor a grant, and deliberately has no Space or canonical Persona identifier.
type BoxParticipantPresentation struct {
	ParticipantID uuid.UUID `json:"participantID"`
	DisplayName   string    `json:"displayName"`
	Revision      uint64    `json:"revision"`
}

func (presentation BoxParticipantPresentation) Validate() error {
	if presentation.ParticipantID == uuid.Nil || presentation.Revision == 0 ||
		!utf8.ValidString(presentation.DisplayName) ||
		presentation.DisplayName == "" || len(presentation.DisplayName) > 128 ||
		normalizedDisplayName(presentation.DisplayName) != presentation.DisplayName ||
		strings.IndexFunc(presentation.DisplayName, unicode.IsControl) >= 0 {
		return ErrParticipantAuthority
	}
	return nil
}

type BoxSignedPrincipalRecord struct {
	Payload   []byte `json:"payload"`
	Signature struct {
		Algorithm             string `json:"algorithm"`
		SigningKeyFingerprint string `json:"signingKeyFingerprint"`
		Signature             string `json:"signature"`
	} `json:"signature"`
}

type BoxParticipantProofPayload struct {
	Version               int       `json:"version"`
	BoxID                 uuid.UUID `json:"boxID"`
	ParticipantID         uuid.UUID `json:"participantID"`
	BoxScopedPrincipalID  uuid.UUID `json:"boxScopedPrincipalID"`
	DeviceID              uuid.UUID `json:"deviceID"`
	GrantID               uuid.UUID `json:"grantID"`
	DeviceGeneration      uint64    `json:"deviceGeneration"`
	ChallengeID           uuid.UUID `json:"challengeID"`
	IssuedAtMilliseconds  int64     `json:"issuedAtMilliseconds"`
	ExpiresAtMilliseconds int64     `json:"expiresAtMilliseconds"`
}

type BoxSignedParticipantProof struct {
	Payload   []byte `json:"payload"`
	Signature string `json:"signature"`
}

type boxPrincipalRoot struct {
	Version                   int       `json:"version"`
	PrincipalID               uuid.UUID `json:"principalID"`
	PrincipalKind             string    `json:"principalKind"`
	RootPublicSigningKeyX963  string    `json:"rootPublicSigningKeyX963"`
	RootSigningKeyFingerprint string    `json:"rootSigningKeyFingerprint"`
	RootKeyGeneration         uint64    `json:"rootKeyGeneration"`
	CreatedAtMilliseconds     int64     `json:"createdAtMilliseconds"`
}

type boxPrincipalDeviceGrant struct {
	Version                    int        `json:"version"`
	ID                         uuid.UUID  `json:"id"`
	PrincipalID                uuid.UUID  `json:"principalID"`
	DeviceID                   uuid.UUID  `json:"deviceID"`
	DeviceGeneration           uint64     `json:"deviceGeneration"`
	DeviceName                 string     `json:"deviceName"`
	SigningPublicKeyX963       string     `json:"signingPublicKeyX963"`
	SigningKeyFingerprint      string     `json:"signingKeyFingerprint"`
	KeyAgreementPublicKeyX963  string     `json:"keyAgreementPublicKeyX963"`
	KeyAgreementKeyFingerprint string     `json:"keyAgreementKeyFingerprint"`
	Capabilities               []string   `json:"capabilities"`
	IssuedAtMilliseconds       int64      `json:"issuedAtMilliseconds"`
	NotBeforeMilliseconds      int64      `json:"notBeforeMilliseconds"`
	ExpiresAtMilliseconds      int64      `json:"expiresAtMilliseconds"`
	SupersedesGrantID          *uuid.UUID `json:"supersedesGrantID,omitempty"`
}

type boxPrincipalDeviceRevocation struct {
	Version                  int       `json:"version"`
	ID                       uuid.UUID `json:"id"`
	PrincipalID              uuid.UUID `json:"principalID"`
	DeviceID                 uuid.UUID `json:"deviceID"`
	RevokedThroughGeneration uint64    `json:"revokedThroughGeneration"`
	IssuedAtMilliseconds     int64     `json:"issuedAtMilliseconds"`
	Reason                   string    `json:"reason"`
}

// The Box controller store atomically consumes an issued challenge bound to
// these exact identities and expiry, durably across a Box restart. The
// participant enrollment and proof HTTP routes are not installed yet.
type BoxParticipantChallengeStore interface {
	ConsumeParticipantChallenge(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, int64) (bool, error)
}

type BoxParticipantProofVerifier struct {
	challenges BoxParticipantChallengeStore
}

func NewBoxParticipantProofVerifier(challenges BoxParticipantChallengeStore) (*BoxParticipantProofVerifier, error) {
	if challenges == nil {
		return nil, ErrParticipantAuthority
	}
	return &BoxParticipantProofVerifier{challenges: challenges}, nil
}

func (verifier *BoxParticipantProofVerifier) Authorize(
	ctx context.Context,
	anchor BoxParticipantAnchor,
	device BoxParticipantDevice,
	rootRecord BoxSignedPrincipalRecord,
	grantRecord BoxSignedPrincipalRecord,
	revocations []BoxSignedPrincipalRecord,
	proof BoxSignedParticipantProof,
	expectedChallengeID uuid.UUID,
	nowMilliseconds int64,
) error {
	if verifier == nil || verifier.challenges == nil {
		return ErrParticipantAuthority
	}
	if err := verifyBoxParticipantProof(anchor, device, rootRecord, grantRecord,
		revocations, proof, expectedChallengeID, nowMilliseconds); err != nil {
		return err
	}
	consumed, err := verifier.challenges.ConsumeParticipantChallenge(ctx, anchor.BoxID,
		anchor.ParticipantID, device.DeviceID, expectedChallengeID, nowMilliseconds)
	if err != nil {
		return err
	}
	if !consumed {
		return ErrParticipantReplay
	}
	return nil
}

func verifyBoxParticipantProof(
	anchor BoxParticipantAnchor,
	device BoxParticipantDevice,
	rootRecord BoxSignedPrincipalRecord,
	grantRecord BoxSignedPrincipalRecord,
	revocations []BoxSignedPrincipalRecord,
	proof BoxSignedParticipantProof,
	expectedChallengeID uuid.UUID,
	nowMilliseconds int64,
) error {
	if anchor.BoxID == uuid.Nil || anchor.ParticipantID == uuid.Nil ||
		anchor.BoxScopedPrincipalID == uuid.Nil || expectedChallengeID == uuid.Nil ||
		anchor.ApprovedAtMilliseconds <= 0 || anchor.ApprovedAtMilliseconds > nowMilliseconds ||
		(anchor.RevokedAtMilliseconds > 0 && anchor.RevokedAtMilliseconds <= nowMilliseconds) ||
		device.ParticipantID != anchor.ParticipantID || device.DeviceID == uuid.Nil ||
		device.GrantID == uuid.Nil || device.DeviceGeneration != 1 ||
		device.RevokedThroughGeneration >= device.DeviceGeneration {
		return ErrParticipantAuthority
	}
	var root boxPrincipalRoot
	if strictParticipantJSON(rootRecord.Payload, &root) != nil ||
		root.Version != 1 || root.PrincipalID != anchor.BoxScopedPrincipalID ||
		root.RootKeyGeneration != 1 || root.CreatedAtMilliseconds < 0 ||
		root.RootSigningKeyFingerprint != anchor.RootKeyFingerprint {
		return ErrParticipantAuthority
	}
	rootKey, err := participantPublicKey(root.RootPublicSigningKeyX963, root.RootSigningKeyFingerprint)
	if err != nil || verifyPrincipalRecord(rootRecord, rootKey, root.RootSigningKeyFingerprint, principalRootDomain) != nil {
		return ErrParticipantAuthority
	}
	var grant boxPrincipalDeviceGrant
	if strictParticipantJSON(grantRecord.Payload, &grant) != nil ||
		grant.Version != 1 || grant.PrincipalID != root.PrincipalID ||
		grant.ID != device.GrantID || grant.DeviceID != device.DeviceID ||
		grant.DeviceGeneration != device.DeviceGeneration ||
		grant.SupersedesGrantID != nil ||
		grant.SigningKeyFingerprint != device.SigningKeyFingerprint ||
		grant.IssuedAtMilliseconds < root.CreatedAtMilliseconds ||
		grant.NotBeforeMilliseconds < grant.IssuedAtMilliseconds ||
		grant.ExpiresAtMilliseconds <= grant.NotBeforeMilliseconds ||
		(nowMilliseconds < grant.NotBeforeMilliseconds || nowMilliseconds >= grant.ExpiresAtMilliseconds) ||
		!hasParticipantCapability(grant.Capabilities) ||
		verifyPrincipalRecord(grantRecord, rootKey, root.RootSigningKeyFingerprint, principalDeviceDomain) != nil {
		return ErrParticipantAuthority
	}
	deviceKey, err := participantPublicKey(grant.SigningPublicKeyX963, grant.SigningKeyFingerprint)
	if err != nil {
		return ErrParticipantAuthority
	}
	if _, err := participantPublicKey(grant.KeyAgreementPublicKeyX963, grant.KeyAgreementKeyFingerprint); err != nil {
		return ErrParticipantAuthority
	}
	for _, record := range revocations {
		var revocation boxPrincipalDeviceRevocation
		if strictParticipantJSON(record.Payload, &revocation) != nil ||
			revocation.Version != 1 || revocation.PrincipalID != root.PrincipalID ||
			verifyPrincipalRecord(record, rootKey, root.RootSigningKeyFingerprint, principalRevocationDomain) != nil {
			return ErrParticipantAuthority
		}
		if revocation.DeviceID == device.DeviceID &&
			revocation.IssuedAtMilliseconds <= nowMilliseconds &&
			revocation.RevokedThroughGeneration >= device.DeviceGeneration {
			return ErrParticipantAuthority
		}
	}
	var payload BoxParticipantProofPayload
	if strictParticipantJSON(proof.Payload, &payload) != nil || payload.Version != 1 ||
		!canonicalParticipantProof(proof.Payload) ||
		payload.BoxID != anchor.BoxID || payload.ParticipantID != anchor.ParticipantID ||
		payload.BoxScopedPrincipalID != anchor.BoxScopedPrincipalID || payload.DeviceID != device.DeviceID ||
		payload.GrantID != device.GrantID || payload.DeviceGeneration != device.DeviceGeneration ||
		payload.ChallengeID != expectedChallengeID ||
		payload.IssuedAtMilliseconds < grant.NotBeforeMilliseconds ||
		payload.IssuedAtMilliseconds > nowMilliseconds ||
		payload.ExpiresAtMilliseconds <= nowMilliseconds ||
		payload.ExpiresAtMilliseconds-payload.IssuedAtMilliseconds > maximumParticipantProofAgeMilliseconds ||
		verifyParticipantSignature(proof.Signature, deviceKey, participantProofDomain, proof.Payload) != nil {
		return ErrParticipantAuthority
	}
	return nil
}

func canonicalParticipantProof(data []byte) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil || object == nil {
		return false
	}
	encoded, err := json.Marshal(object)
	return err == nil && bytes.Equal(data, encoded)
}

func hasParticipantCapability(capabilities []string) bool {
	for _, capability := range capabilities {
		if capability == boxParticipantCapability {
			return true
		}
	}
	return false
}

func verifyPrincipalRecord(record BoxSignedPrincipalRecord, key *ecdsa.PublicKey, fingerprint, domain string) error {
	if record.Signature.Algorithm != "ES256" || record.Signature.SigningKeyFingerprint != fingerprint {
		return ErrParticipantAuthority
	}
	return verifyParticipantSignature(record.Signature.Signature, key, domain, record.Payload)
}

func verifyParticipantSignature(encoded string, key *ecdsa.PublicKey, domain string, payload []byte) error {
	signature, err := participantBase64URL(encoded)
	if err != nil || len(signature) != 64 || len(payload) == 0 || len(payload) > 65_536 {
		return ErrParticipantAuthority
	}
	hash := sha256.Sum256(append([]byte(domain), payload...))
	if !ecdsa.Verify(key, hash[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return ErrParticipantAuthority
	}
	return nil
}

func participantPublicKey(encoded, fingerprint string) (*ecdsa.PublicKey, error) {
	bytes, err := participantBase64URL(encoded)
	if err != nil || len(bytes) != 65 || !validParticipantFingerprint(fingerprint) {
		return nil, ErrParticipantAuthority
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), bytes)
	if x == nil || y == nil {
		return nil, ErrParticipantAuthority
	}
	hash := sha256.Sum256(bytes)
	if hex.EncodeToString(hash[:]) != fingerprint {
		return nil, ErrParticipantAuthority
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

func validParticipantFingerprint(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func participantBase64URL(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrParticipantAuthority
	}
	return decoded, nil
}

func strictParticipantJSON(data []byte, target any) error {
	if len(data) == 0 || len(data) > 65_536 {
		return ErrParticipantAuthority
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrParticipantAuthority
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return ErrParticipantAuthority
	}
	return nil
}

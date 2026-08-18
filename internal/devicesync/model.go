package devicesync

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

const (
	SchemaVersion                        = 1
	MinimumAdmissionLifetimeMilliseconds = int64(5 * 60 * 1_000)
	MaximumAdmissionLifetimeMilliseconds = int64(7 * 24 * 60 * 60 * 1_000)
)

var admissionAuthorizationDomain = []byte("Facets Device Sync account admission v1\x00")

type AdmissionCredential struct {
	AdmissionID uuid.UUID
	Token       string
}

func AdmissionAuthorizationDigest(credential AdmissionCredential) (string, error) {
	if credential.AdmissionID == uuid.Nil {
		return "", fmt.Errorf("admission scope is invalid")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(credential.Token)
	if err != nil || len(decoded) != 32 ||
		base64.RawURLEncoding.EncodeToString(decoded) != credential.Token {
		return "", fmt.Errorf("admission token must be 32-byte unpadded base64url")
	}
	hash := sha256.New()
	_, _ = hash.Write(admissionAuthorizationDomain)
	_, _ = hash.Write([]byte(credential.AdmissionID.String()))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(credential.Token))
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type AccountAdmission struct {
	Version               int        `json:"version"`
	RetryID               uuid.UUID  `json:"retryID"`
	AdmissionID           uuid.UUID  `json:"admissionID"`
	AuthorizationDigest   string     `json:"authorizationDigest"`
	CreatedAtMilliseconds int64      `json:"createdAtMilliseconds"`
	ExpiresAtMilliseconds int64      `json:"expiresAtMilliseconds"`
	ClaimedAtMilliseconds *int64     `json:"claimedAtMilliseconds,omitempty"`
	ClaimedPrincipalID    *uuid.UUID `json:"claimedPrincipalID,omitempty"`
}

func (a AccountAdmission) Validate() error {
	if a.Version != SchemaVersion || a.RetryID == uuid.Nil || a.AdmissionID == uuid.Nil ||
		!validDigest(a.AuthorizationDigest) || a.CreatedAtMilliseconds < 0 ||
		a.ExpiresAtMilliseconds-a.CreatedAtMilliseconds < MinimumAdmissionLifetimeMilliseconds ||
		a.ExpiresAtMilliseconds-a.CreatedAtMilliseconds > MaximumAdmissionLifetimeMilliseconds {
		return NewProtocolError(CodeInvalidAdmission, "account admission fields are invalid")
	}
	if (a.ClaimedAtMilliseconds == nil) != (a.ClaimedPrincipalID == nil) {
		return NewProtocolError(CodeInvalidAdmission, "account admission claim state is incomplete")
	}
	if a.ClaimedAtMilliseconds != nil &&
		(*a.ClaimedAtMilliseconds < a.CreatedAtMilliseconds ||
			*a.ClaimedAtMilliseconds >= a.ExpiresAtMilliseconds ||
			*a.ClaimedPrincipalID == uuid.Nil) {
		return NewProtocolError(CodeInvalidAdmission, "account admission claim state is invalid")
	}
	return nil
}

func (a AccountAdmission) VerifyCredential(credential AdmissionCredential) error {
	if credential.AdmissionID != a.AdmissionID {
		return NewProtocolError(CodeWrongScope, "account admission credential has another scope")
	}
	digest, err := AdmissionAuthorizationDigest(credential)
	if err != nil || !digestEqual(digest, a.AuthorizationDigest) {
		return NewProtocolError(CodeUnauthorized, "account admission credential is invalid")
	}
	return nil
}

func (a AccountAdmission) RequireActive(nowMilliseconds int64) error {
	if a.ClaimedAtMilliseconds != nil {
		return NewProtocolError(CodeAdmissionClaimed, "account admission was already claimed")
	}
	if nowMilliseconds < a.CreatedAtMilliseconds || nowMilliseconds >= a.ExpiresAtMilliseconds {
		return NewProtocolError(CodeAdmissionExpired, "account admission is not active")
	}
	return nil
}

type AdmissionCreateResult struct {
	Acceptance relay.Acceptance `json:"acceptance"`
	Admission  AccountAdmission `json:"admission"`
}

type PrincipalProvisioning struct {
	Version               int                      `json:"version"`
	RetryID               uuid.UUID                `json:"retryID"`
	PrincipalID           uuid.UUID                `json:"principalID"`
	InitialDeviceID       uuid.UUID                `json:"initialDeviceID"`
	Tenant                relay.TenantRegistration `json:"tenant"`
	ControlDomain         relay.DomainProvisioning `json:"controlDomain"`
	CreatedAtMilliseconds int64                    `json:"createdAtMilliseconds"`
}

func (p PrincipalProvisioning) Validate() error {
	if p.Version != SchemaVersion || p.RetryID == uuid.Nil || p.PrincipalID == uuid.Nil ||
		p.InitialDeviceID == uuid.Nil || p.CreatedAtMilliseconds < 0 {
		return NewProtocolError(CodeInvalidPrincipal, "principal provisioning fields are invalid")
	}
	if err := p.Tenant.Validate(); err != nil {
		return err
	}
	if err := p.ControlDomain.Validate(); err != nil {
		return err
	}
	if p.PrincipalID != p.Tenant.TenantID ||
		p.PrincipalID != p.ControlDomain.Registration.TenantID ||
		p.InitialDeviceID != p.ControlDomain.InitialMember.MemberID ||
		p.CreatedAtMilliseconds != p.Tenant.CreatedAtMilliseconds ||
		p.CreatedAtMilliseconds != p.ControlDomain.Registration.CreatedAtMilliseconds {
		return NewProtocolError(CodeWrongScope, "principal, tenant, control domain, and initial device scopes differ")
	}
	return nil
}

type PrincipalProvisioningResult struct {
	Acceptance            relay.Acceptance               `json:"acceptance"`
	RetryID               uuid.UUID                      `json:"retryID"`
	PrincipalID           uuid.UUID                      `json:"principalID"`
	DeviceID              uuid.UUID                      `json:"deviceID"`
	Relay                 relay.TenantProvisioningResult `json:"relay"`
	CreatedAtMilliseconds int64                          `json:"createdAtMilliseconds"`
}

func resultFor(provisioning PrincipalProvisioning, relayResult relay.TenantProvisioningResult, acceptance relay.Acceptance) PrincipalProvisioningResult {
	return PrincipalProvisioningResult{
		Acceptance: acceptance, RetryID: provisioning.RetryID,
		PrincipalID: provisioning.PrincipalID, DeviceID: provisioning.InitialDeviceID,
		Relay: relayResult, CreatedAtMilliseconds: provisioning.CreatedAtMilliseconds,
	}
}

// DeviceAdmission binds a generic relay admission to exactly one Device Sync
// principal and device. It grants transport membership only; content trust and
// key material must still arrive through the encrypted principal control
// channel from an already trusted device.
type DeviceAdmission struct {
	Version               int                   `json:"version"`
	RetryID               uuid.UUID             `json:"retryID"`
	PrincipalID           uuid.UUID             `json:"principalID"`
	DeviceID              uuid.UUID             `json:"deviceID"`
	SubscriptionID        uuid.UUID             `json:"subscriptionID"`
	RelayAdmission        relay.MemberAdmission `json:"relayAdmission"`
	CreatedAtMilliseconds int64                 `json:"createdAtMilliseconds"`
}

func (a DeviceAdmission) Validate() error {
	if a.Version != SchemaVersion || a.RetryID == uuid.Nil ||
		a.PrincipalID == uuid.Nil || a.DeviceID == uuid.Nil ||
		a.SubscriptionID == uuid.Nil || a.CreatedAtMilliseconds < 0 {
		return NewProtocolError(CodeInvalidAdmission, "device admission fields are invalid")
	}
	if err := a.RelayAdmission.Validate(); err != nil {
		return err
	}
	if a.PrincipalID != a.RelayAdmission.TenantID ||
		a.CreatedAtMilliseconds != a.RelayAdmission.CreatedAtMilliseconds ||
		a.RelayAdmission.RevokedAtMilliseconds != nil ||
		a.RelayAdmission.ClaimedAtMilliseconds != nil ||
		a.RelayAdmission.ClaimedMemberID != nil {
		return NewProtocolError(CodeWrongScope, "device admission and relay scopes differ")
	}
	return nil
}

type DeviceAdmissionCreateResult struct {
	Acceptance relay.Acceptance `json:"acceptance"`
	Admission  DeviceAdmission  `json:"admission"`
}

type DeviceAdmissionCredential struct {
	PrincipalID uuid.UUID
	AdmissionID uuid.UUID
	Token       string
}

type DeviceAdmissionClaim struct {
	Version               int                        `json:"version"`
	PrincipalID           uuid.UUID                  `json:"principalID"`
	DeviceID              uuid.UUID                  `json:"deviceID"`
	RelayClaim            relay.MemberAdmissionClaim `json:"relayClaim"`
	ClaimedAtMilliseconds int64                      `json:"claimedAtMilliseconds"`
}

func (c DeviceAdmissionClaim) Validate() error {
	if c.Version != SchemaVersion || c.PrincipalID == uuid.Nil ||
		c.DeviceID == uuid.Nil || c.ClaimedAtMilliseconds < 0 {
		return NewProtocolError(CodeInvalidAdmission, "device admission claim fields are invalid")
	}
	if err := c.RelayClaim.Validate(); err != nil {
		return err
	}
	if c.DeviceID != c.RelayClaim.MemberID {
		return NewProtocolError(CodeWrongScope, "device and relay member scopes differ")
	}
	return nil
}

type DeviceAdmissionClaimResult struct {
	Acceptance  relay.Acceptance                     `json:"acceptance"`
	PrincipalID uuid.UUID                            `json:"principalID"`
	DeviceID    uuid.UUID                            `json:"deviceID"`
	Member      relay.SubscriptionMemberRegistration `json:"member"`
}

// SpaceProvisioning binds one opaque Facets Space identifier to one isolated
// relay domain. The service never receives a Space name, content key, FEF
// graph, or plaintext content.
type SpaceProvisioning struct {
	Version               int                      `json:"version"`
	RetryID               uuid.UUID                `json:"retryID"`
	PrincipalID           uuid.UUID                `json:"principalID"`
	SpaceID               uuid.UUID                `json:"spaceID"`
	InitialDeviceID       uuid.UUID                `json:"initialDeviceID"`
	Domain                relay.DomainProvisioning `json:"domain"`
	CreatedAtMilliseconds int64                    `json:"createdAtMilliseconds"`
}

func (p SpaceProvisioning) Validate() error {
	if p.Version != SchemaVersion || p.RetryID == uuid.Nil ||
		p.PrincipalID == uuid.Nil || p.SpaceID == uuid.Nil ||
		p.InitialDeviceID == uuid.Nil || p.CreatedAtMilliseconds < 0 {
		return NewProtocolError(CodeInvalidSpace, "Device Sync Space fields are invalid")
	}
	if err := p.Domain.Validate(); err != nil {
		return err
	}
	if p.PrincipalID != p.Domain.Registration.TenantID ||
		p.InitialDeviceID != p.Domain.InitialMember.MemberID ||
		p.CreatedAtMilliseconds != p.Domain.Registration.CreatedAtMilliseconds {
		return NewProtocolError(CodeWrongScope, "Device Sync Space and relay scopes differ")
	}
	return nil
}

type SpaceProvisioningResult struct {
	Acceptance  relay.Acceptance               `json:"acceptance"`
	PrincipalID uuid.UUID                      `json:"principalID"`
	SpaceID     uuid.UUID                      `json:"spaceID"`
	Domain      relay.DomainProvisioningResult `json:"domain"`
}

// SpaceDeviceAdmission binds one already enrolled Device Sync device to one
// opaque Space relay domain. It grants transport membership only. The server
// does not grant Space content trust, distribute content keys, or interpret
// the encrypted payloads carried by the domain.
type SpaceDeviceAdmission struct {
	Version               int                   `json:"version"`
	RetryID               uuid.UUID             `json:"retryID"`
	PrincipalID           uuid.UUID             `json:"principalID"`
	SpaceID               uuid.UUID             `json:"spaceID"`
	DeviceID              uuid.UUID             `json:"deviceID"`
	SubscriptionID        uuid.UUID             `json:"subscriptionID"`
	RelayAdmission        relay.MemberAdmission `json:"relayAdmission"`
	CreatedAtMilliseconds int64                 `json:"createdAtMilliseconds"`
}

func (a SpaceDeviceAdmission) Validate() error {
	if a.Version != SchemaVersion || a.RetryID == uuid.Nil ||
		a.PrincipalID == uuid.Nil || a.SpaceID == uuid.Nil ||
		a.DeviceID == uuid.Nil || a.SubscriptionID == uuid.Nil ||
		a.CreatedAtMilliseconds < 0 {
		return NewProtocolError(CodeInvalidAdmission, "Space device admission fields are invalid")
	}
	if err := a.RelayAdmission.Validate(); err != nil {
		return err
	}
	if a.PrincipalID != a.RelayAdmission.TenantID ||
		a.CreatedAtMilliseconds != a.RelayAdmission.CreatedAtMilliseconds ||
		a.RelayAdmission.RevokedAtMilliseconds != nil ||
		a.RelayAdmission.ClaimedAtMilliseconds != nil ||
		a.RelayAdmission.ClaimedMemberID != nil {
		return NewProtocolError(CodeWrongScope, "Space device admission and relay scopes differ")
	}
	return nil
}

type SpaceDeviceAdmissionCreateResult struct {
	Acceptance relay.Acceptance     `json:"acceptance"`
	Admission  SpaceDeviceAdmission `json:"admission"`
}

type SpaceDeviceAdmissionCredential struct {
	PrincipalID uuid.UUID
	SpaceID     uuid.UUID
	AdmissionID uuid.UUID
	Token       string
}

type SpaceDeviceAdmissionClaim struct {
	Version               int                        `json:"version"`
	PrincipalID           uuid.UUID                  `json:"principalID"`
	SpaceID               uuid.UUID                  `json:"spaceID"`
	DeviceID              uuid.UUID                  `json:"deviceID"`
	RelayClaim            relay.MemberAdmissionClaim `json:"relayClaim"`
	ClaimedAtMilliseconds int64                      `json:"claimedAtMilliseconds"`
}

func (c SpaceDeviceAdmissionClaim) Validate() error {
	if c.Version != SchemaVersion || c.PrincipalID == uuid.Nil ||
		c.SpaceID == uuid.Nil || c.DeviceID == uuid.Nil ||
		c.ClaimedAtMilliseconds < 0 {
		return NewProtocolError(CodeInvalidAdmission, "Space device admission claim fields are invalid")
	}
	if err := c.RelayClaim.Validate(); err != nil {
		return err
	}
	if c.DeviceID != c.RelayClaim.MemberID {
		return NewProtocolError(CodeWrongScope, "Space device and relay member scopes differ")
	}
	return nil
}

type SpaceDeviceAdmissionClaimResult struct {
	Acceptance  relay.Acceptance                     `json:"acceptance"`
	PrincipalID uuid.UUID                            `json:"principalID"`
	SpaceID     uuid.UUID                            `json:"spaceID"`
	DeviceID    uuid.UUID                            `json:"deviceID"`
	Member      relay.SubscriptionMemberRegistration `json:"member"`
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func digestEqual(left, right string) bool {
	leftBytes, leftErr := hex.DecodeString(left)
	rightBytes, rightErr := hex.DecodeString(right)
	return leftErr == nil && rightErr == nil && len(leftBytes) == sha256.Size &&
		subtle.ConstantTimeCompare(leftBytes, rightBytes) == 1
}

package devicesync

import (
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

const MaximumDiscoveryProfiles = 256

type DiscoveryProfile struct {
	Version             int       `json:"version"`
	PrincipalID         uuid.UUID `json:"principalID"`
	SetDiscriminator    string    `json:"setDiscriminator"`
	DisplayName         string    `json:"displayName"`
	Revision            uint64    `json:"revision"`
	UpdatedMilliseconds int64     `json:"updatedAtMilliseconds"`
}

func (profile DiscoveryProfile) Validate() error {
	name := strings.TrimSpace(profile.DisplayName)
	if profile.Version != SchemaVersion || profile.PrincipalID == uuid.Nil ||
		name == "" || name != profile.DisplayName || utf8.RuneCountInString(name) > 128 ||
		len([]byte(name)) > 256 || profile.Revision == 0 || profile.Revision > uint64(^uint64(0)>>1) || profile.UpdatedMilliseconds < 0 ||
		len(profile.SetDiscriminator) != 32 {
		return NewProtocolError(CodeInvalidPrincipal, "Device Sync discovery profile is invalid")
	}
	for _, value := range []byte(profile.SetDiscriminator) {
		if !((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f')) {
			return NewProtocolError(CodeInvalidPrincipal, "Device Sync discovery profile is invalid")
		}
	}
	return nil
}

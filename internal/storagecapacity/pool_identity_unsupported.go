//go:build !linux && !darwin

package storagecapacity

import (
	"errors"

	"github.com/google/uuid"
)

const (
	PoolIdentityVersion  = 1
	PoolIdentityFileName = ".facets-storage-capacity-pool-v1"
)

var (
	ErrPoolIdentityUnavailable = errors.New("storage pool identity is unavailable")
	ErrPoolIdentityConflict    = errors.New("storage pool identity conflicts with the configured pool")
)

type PhysicalPoolIdentity struct {
	Version int       `json:"version"`
	PoolID  uuid.UUID `json:"poolID"`
}

func (PhysicalPoolIdentity) Validate() error { return ErrPoolIdentityUnavailable }

func CreatePhysicalPoolIdentity(string, uuid.UUID) (PhysicalPoolIdentity, error) {
	return PhysicalPoolIdentity{}, ErrPoolIdentityUnavailable
}

func LoadPhysicalPoolIdentity(string) (PhysicalPoolIdentity, error) {
	return PhysicalPoolIdentity{}, ErrPoolIdentityUnavailable
}

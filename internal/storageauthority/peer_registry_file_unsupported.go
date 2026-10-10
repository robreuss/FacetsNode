//go:build !unix

package storageauthority

func LoadCapacityPeerRegistry(string) (*CapacityPeerRegistry, error) {
	return nil, ErrInvalid
}

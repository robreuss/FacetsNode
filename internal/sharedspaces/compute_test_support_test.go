package sharedspaces_test

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computepool"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func testComputePoolAuthority(poolID uuid.UUID) computepool.AuthorityReference {
	x, y := elliptic.P256().ScalarBaseMult(bytes.Repeat([]byte{0x71}, 32))
	publicKey := elliptic.Marshal(elliptic.P256(), x, y)
	fingerprint := sha256.Sum256(publicKey)
	return computepool.AuthorityReference{
		Version: computepool.SchemaVersion,
		PoolID:  poolID,
		TrustAnchor: computepool.AuthorityTrustAnchor{
			Version: computepool.SignatureSchemaVersion,
			Scope: serviceauthority.Scope{
				Kind: serviceauthority.ScopeComputePool, ScopeID: poolID,
			},
			SignerID:              uuid.MustParse("77777777-7777-4777-8777-777777777777"),
			PublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(publicKey),
			SigningKeyFingerprint: hex.EncodeToString(fingerprint[:]),
		},
		AcceptedManifestRevision: 3,
		AcceptedManifestDigest:   hex.EncodeToString(bytes.Repeat([]byte{0x72}, 32)),
	}
}

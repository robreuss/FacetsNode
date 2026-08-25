package serviceauthority

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBulkTransferGrantRequiresExactCurrentAuthorityAndRoute(t *testing.T) {
	scope := Scope{
		Kind:    ScopeDeviceSync,
		ScopeID: uuid.MustParse("61000000-0000-0000-0000-000000000001"),
	}
	deploymentID := uuid.MustParse("63000000-0000-0000-0000-000000000001")
	routeID := uuid.MustParse("62000000-0000-0000-0000-000000000001")
	digest := repeatHex("1")
	current := testCurrentBinding(t, 1, digest, deploymentID)
	registry := NewBindingRegistry()
	if err := registry.Activate(scope, current); err != nil {
		t.Fatal(err)
	}
	binding := RequestBinding{
		Scope:             scope,
		AuthorityRevision: 1,
		AuthorityDigest:   digest,
		DeploymentID:      deploymentID,
		RouteID:           routeID,
		TrafficClass:      TrafficBulk,
	}
	payload := BulkGrantPayload{
		AuthorityManifestDigest: digest,
		DeploymentID:            deploymentID,
		Direction:               BulkUpload,
		ExpiresAtMilliseconds:   2_000,
		GrantID:                 uuid.MustParse("65000000-0000-0000-0000-000000000001"),
		MaximumByteCount:        1_048_576,
		NotBeforeMilliseconds:   1_000,
		ResourceID:              "66000000-0000-0000-0000-000000000001",
		RouteID:                 routeID,
		Scope:                   scope,
		Version:                 SchemaVersion,
	}
	header := make(http.Header)
	header.Set(HeaderBulkResourceID, payload.ResourceID)
	header.Set(HeaderBulkDirection, string(payload.Direction))
	header.Set(HeaderBulkTransferGrant, testSignedBulkGrantHeader(t, payload))

	if accepted, err := registry.AuthorizeBulkTransfer(binding, header, time.UnixMilli(1_500)); err != nil || accepted != payload {
		t.Fatalf("current exact grant rejected: payload=%+v err=%v", accepted, err)
	}

	rejections := []struct {
		name    string
		binding RequestBinding
		header  http.Header
		now     time.Time
	}{
		{
			name: "wrong resource", binding: binding,
			header: clonedHeaderWith(header, HeaderBulkResourceID, "different-resource"),
			now:    time.UnixMilli(1_500),
		},
		{
			name: "wrong direction", binding: binding,
			header: clonedHeaderWith(header, HeaderBulkDirection, string(BulkDownload)),
			now:    time.UnixMilli(1_500),
		},
		{
			name: "wrong route",
			binding: func() RequestBinding {
				changed := binding
				changed.RouteID = uuid.MustParse("62000000-0000-0000-0000-000000000002")
				return changed
			}(),
			header: header.Clone(), now: time.UnixMilli(1_500),
		},
		{
			name: "not yet valid", binding: binding,
			header: header.Clone(), now: time.UnixMilli(999),
		},
		{
			name: "expired", binding: binding,
			header: header.Clone(), now: time.UnixMilli(2_000),
		},
		{
			name: "tampered envelope", binding: binding,
			header: clonedHeaderWith(
				header,
				HeaderBulkTransferGrant,
				header.Get(HeaderBulkTransferGrant)[:len(header.Get(HeaderBulkTransferGrant))-1]+"A",
			),
			now: time.UnixMilli(1_500),
		},
		{
			name: "duplicate grant header", binding: binding,
			header: func() http.Header {
				changed := header.Clone()
				changed.Add(HeaderBulkTransferGrant, header.Get(HeaderBulkTransferGrant))
				return changed
			}(),
			now: time.UnixMilli(1_500),
		},
	}
	for _, test := range rejections {
		t.Run(test.name, func(t *testing.T) {
			if _, err := registry.AuthorizeBulkTransfer(test.binding, test.header, test.now); err == nil {
				t.Fatal("invalid bulk transfer grant accepted")
			}
		})
	}
}

func testSignedBulkGrantHeader(t *testing.T, payload BulkGrantPayload) string {
	t.Helper()
	privateScalar := make([]byte, 32)
	privateScalar[31] = 1
	curve := elliptic.P256()
	d := new(big.Int).SetBytes(privateScalar)
	x, y := curve.ScalarBaseMult(privateScalar)
	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(append([]byte(bulkGrantSignatureDomain), encodedPayload...))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(curve.Params().N), 1)) > 0 {
		s.Sub(curve.Params().N, s)
	}
	rawSignature := make([]byte, 64)
	r.FillBytes(rawSignature[:32])
	s.FillBytes(rawSignature[32:])
	publicKey := elliptic.Marshal(curve, x, y)
	fingerprint := sha256.Sum256(publicKey)
	grant := BulkTransferGrant{
		Payload: encodedPayload,
		Signature: Signature{
			Algorithm:             "ES256",
			PublicSigningKeyX963:  base64.RawURLEncoding.EncodeToString(publicKey),
			Signature:             base64.RawURLEncoding.EncodeToString(rawSignature),
			SignerID:              uuid.MustParse("64000000-0000-0000-0000-000000000001"),
			SigningKeyFingerprint: hex.EncodeToString(fingerprint[:]),
		},
	}
	encodedGrant, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encodedGrant)
}

func clonedHeaderWith(source http.Header, name string, value string) http.Header {
	result := source.Clone()
	result.Set(name, value)
	return result
}

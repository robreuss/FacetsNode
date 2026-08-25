package devicesync

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"testing"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestInitialServiceAuthorityBindingSeparatesExactRetryFromFreshClaim(t *testing.T) {
	contents, err := os.ReadFile(
		"../serviceauthority/testdata/service-migration-portable-v2.json",
	)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		AuthorityAnchor  serviceauthority.TrustAnchor `json:"authorityAnchor"`
		RollbackEvidence struct {
			ActivationEvidence struct {
				Preparation struct {
					CurrentManifest serviceauthority.Manifest `json:"currentManifest"`
				} `json:"preparation"`
			} `json:"activationEvidence"`
		} `json:"rollbackEvidence"`
	}
	if err := json.Unmarshal(contents, &fixture); err != nil {
		t.Fatal(err)
	}
	manifest := fixture.RollbackEvidence.ActivationEvidence.Preparation.CurrentManifest
	payload, err := manifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	validUntil := int64(1_500)
	payload.ValidUntilMilliseconds = &validUntil
	manifest = fixtureDeviceSyncAuthorityManifest(
		t, payload, fixture.AuthorityAnchor,
	)
	signer := fixtureDeviceSyncDeploymentSigner(t, payload.ActiveDeployment)
	offer, err := signer.SignDeploymentOffer(serviceauthority.DeploymentOfferPayload{
		Deployment: payload.ActiveDeployment, ExpiresAtMilliseconds: 2_000,
		IssuedAtMilliseconds: 900, TransportPolicy: payload.TransportPolicy,
		Version: serviceauthority.SchemaVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	enrollment := serviceauthority.InitialEnrollment{
		Anchor: fixture.AuthorityAnchor, DeploymentOffer: offer,
		Manifest: manifest, Version: serviceauthority.SchemaVersion,
	}
	first, err := NewInitialServiceAuthorityBinding(
		enrollment, signer, payload.Scope, 1_100,
	)
	if err != nil || first.RequireFreshClaimAt(1_100) != nil {
		t.Fatalf("fresh binding=%+v err=%v", first, err)
	}
	if err := first.RequireFreshClaimAt(1_600); !errors.Is(
		err, serviceauthority.ErrInvalid,
	) {
		t.Fatalf("expired finite Manifest accepted while offer remained current: %v", err)
	}
	retry, err := NewInitialServiceAuthorityBinding(
		enrollment, signer, payload.Scope, 2_100,
	)
	if err != nil {
		t.Fatalf("expired-offer-and-Manifest exact retry binding: %v", err)
	}
	if retry.ValidatedAtMilliseconds() == first.ValidatedAtMilliseconds() ||
		!InitialServiceAuthorityBindingsEqual(first, retry) {
		t.Fatal("request validation time changed exact authority identity")
	}
	if err := retry.RequireFreshClaimAt(2_100); !errors.Is(
		err, serviceauthority.ErrInvalid,
	) {
		t.Fatalf("expired offer and Manifest accepted for an unclaimed admission: %v", err)
	}
}

func fixtureDeviceSyncAuthorityManifest(
	t *testing.T,
	payload serviceauthority.ManifestPayload,
	anchor serviceauthority.TrustAnchor,
) serviceauthority.Manifest {
	t.Helper()
	key := fixtureDeviceSyncAuthorityPrivateKey(t, anchor)
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(append(
		[]byte("Facets service authority manifest v1\x00"), encoded...,
	))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	halfOrder := new(big.Int).Rsh(
		new(big.Int).Set(elliptic.P256().Params().N), 1,
	)
	if s.Cmp(halfOrder) > 0 {
		s.Sub(elliptic.P256().Params().N, s)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	return serviceauthority.Manifest{
		Payload: encoded,
		Signature: serviceauthority.Signature{
			Algorithm:             "ES256",
			PublicSigningKeyX963:  anchor.PublicSigningKeyX963,
			Signature:             base64.RawURLEncoding.EncodeToString(raw),
			SignerID:              anchor.SignerID,
			SigningKeyFingerprint: anchor.SigningKeyFingerprint,
		},
	}
}

func fixtureDeviceSyncAuthorityPrivateKey(
	t *testing.T,
	anchor serviceauthority.TrustAnchor,
) *ecdsa.PrivateKey {
	t.Helper()
	for candidate := 1; candidate <= 255; candidate++ {
		scalar := make([]byte, 32)
		scalar[31] = byte(candidate)
		d := new(big.Int).SetBytes(scalar)
		x, y := elliptic.P256().ScalarBaseMult(scalar)
		if d.Sign() <= 0 || x == nil || y == nil {
			continue
		}
		public := elliptic.Marshal(elliptic.P256(), x, y)
		if base64.RawURLEncoding.EncodeToString(public) == anchor.PublicSigningKeyX963 {
			return &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: elliptic.P256(), X: x, Y: y,
				},
				D: d,
			}
		}
	}
	t.Fatal("fixture authority private key was not found")
	return nil
}

func fixtureDeviceSyncDeploymentSigner(
	t *testing.T,
	descriptor serviceauthority.DeploymentDescriptor,
) *serviceauthority.DeploymentSigner {
	t.Helper()
	for candidate := 1; candidate <= 255; candidate++ {
		scalar := make([]byte, 32)
		scalar[31] = byte(candidate)
		signer, err := serviceauthority.NewDeploymentSigner(
			descriptor.DeploymentID, scalar,
		)
		if err == nil && signer.PublicSigningKeyX963() ==
			descriptor.PublicSigningKeyX963 &&
			signer.SigningKeyFingerprint() == descriptor.SigningKeyFingerprint {
			return signer
		}
	}
	t.Fatal("fixture deployment signer was not found")
	return nil
}

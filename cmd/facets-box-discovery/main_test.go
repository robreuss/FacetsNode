package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/boxcontrol"
)

func TestAdvertisementContainsOnlySignedPublicBoxMetadata(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	boxID := uuid.New()
	payload := boxcontrol.PublicManifestPayload{
		Version: boxcontrol.SchemaVersion, BoxID: boxID, DisplayName: "Rob's Home Box",
		Claimed: true, PublicKey: base64.RawURLEncoding.EncodeToString(public),
		Services: []boxcontrol.ServiceDescriptor{{Kind: "device-sync", Endpoint: "https://box.example:8443/facetsbox/device-sync"}},
	}
	payloadBytes, _ := json.Marshal(payload)
	envelope, _ := json.Marshal(boxcontrol.SignedPublicManifest{
		Payload:   base64.RawURLEncoding.EncodeToString(payloadBytes),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, payloadBytes)),
	})

	result, err := advertisementFromManifest(envelope, "https://box.example:8443/facetsbox")
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(public)
	for _, expected := range []string{
		"v=1", "boxID=" + boxID.String(), "name=Rob's Home Box",
		"url=https://box.example:8443/facetsbox", "key=" + hex.EncodeToString(fingerprint[:]),
		"claimed=true", "service0=device-sync",
	} {
		if !slices.Contains(result.txt, expected) {
			t.Fatalf("missing TXT field %q in %#v", expected, result.txt)
		}
	}
	joined := strings.Join(result.txt, "\n")
	for _, forbidden := range []string{"password", "grant", "group", "token", "endpoint="} {
		if strings.Contains(strings.ToLower(joined), forbidden) {
			t.Fatalf("advertisement contains private field %q: %s", forbidden, joined)
		}
	}
	if result.port != 8443 || !strings.HasSuffix(result.instance, boxID.String()[:8]) {
		t.Fatalf("unexpected advertisement: %+v", result)
	}
}

func TestAdvertisementRejectsTampering(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	payload := boxcontrol.PublicManifestPayload{
		Version: boxcontrol.SchemaVersion, BoxID: uuid.New(), DisplayName: "Home Box",
		PublicKey: base64.RawURLEncoding.EncodeToString(public),
		Services:  []boxcontrol.ServiceDescriptor{{Kind: "device-sync", Endpoint: "https://box.example:8443/facetsbox/device-sync"}},
	}
	payloadBytes, _ := json.Marshal(payload)
	signature := ed25519.Sign(private, payloadBytes)
	payload.DisplayName = "Attacker Box"
	tampered, _ := json.Marshal(payload)
	envelope, _ := json.Marshal(boxcontrol.SignedPublicManifest{
		Payload:   base64.RawURLEncoding.EncodeToString(tampered),
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	})
	if _, err := advertisementFromManifest(envelope, "https://box.example:8443/facetsbox"); err == nil {
		t.Fatal("tampered manifest accepted")
	}
}

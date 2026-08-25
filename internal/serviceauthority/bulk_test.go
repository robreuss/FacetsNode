package serviceauthority

import (
	"encoding/base64"
	"encoding/json"
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
	seed := make([]byte, 32)
	seed[31] = 2
	signer, err := NewDeploymentSigner(deploymentID, seed)
	if err != nil {
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
	header.Set(HeaderBulkTransferGrant, testSignedBulkGrantHeader(t, payload, signer))

	if accepted, err := registry.AuthorizeBulkTransfer(binding, header, time.UnixMilli(1_500), signer); err != nil || accepted != payload {
		t.Fatalf("current exact grant rejected: payload=%+v err=%v", accepted, err)
	}

	rejections := []struct {
		name    string
		binding RequestBinding
		header  http.Header
		now     time.Time
	}{
		{
			name: "stale authority digest",
			binding: func() RequestBinding {
				changed := binding
				changed.AuthorityDigest = repeatHex("2")
				return changed
			}(),
			header: header.Clone(), now: time.UnixMilli(1_500),
		},
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
			if _, err := registry.AuthorizeBulkTransfer(test.binding, test.header, test.now, signer); err == nil {
				t.Fatal("invalid bulk transfer grant accepted")
			}
		})
	}
}

func TestBulkTransferGrantRejectsWrongDeploymentSignerAndExcessLifetime(t *testing.T) {
	deploymentID := uuid.MustParse("63000000-0000-0000-0000-000000000001")
	seed := make([]byte, 32)
	seed[31] = 2
	signer, err := NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	payload := BulkGrantPayload{
		AuthorityManifestDigest: repeatHex("1"),
		DeploymentID:            deploymentID,
		Direction:               BulkDownload,
		ExpiresAtMilliseconds:   301_000,
		GrantID:                 uuid.MustParse("65000000-0000-0000-0000-000000000001"),
		MaximumByteCount:        0,
		NotBeforeMilliseconds:   1_000,
		ResourceID:              repeatHex("2"),
		RouteID:                 uuid.MustParse("62000000-0000-0000-0000-000000000001"),
		Scope: Scope{
			Kind:    ScopeDeviceSync,
			ScopeID: uuid.MustParse("61000000-0000-0000-0000-000000000001"),
		},
		Version: SchemaVersion,
	}
	grant, err := signer.SignBulkTransferGrant(payload)
	if err != nil {
		t.Fatal(err)
	}

	attackerSeed := make([]byte, 32)
	attackerSeed[31] = 3
	attacker, err := NewDeploymentSigner(deploymentID, attackerSeed)
	if err != nil {
		t.Fatal(err)
	}
	if verifyBulkTransferGrant(grant, payload, attacker) == nil {
		t.Fatal("grant accepted against another deployment key")
	}

	payload.ExpiresAtMilliseconds++
	if payload.Validate() == nil {
		t.Fatal("grant lifetime above five minutes accepted")
	}
	payload.ExpiresAtMilliseconds = 301_000
	payload.DeploymentID = uuid.New()
	if _, err := signer.SignBulkTransferGrant(payload); err == nil {
		t.Fatal("deployment signer signed a grant for another deployment")
	}
}

func testSignedBulkGrantHeader(
	t *testing.T,
	payload BulkGrantPayload,
	signer *DeploymentSigner,
) string {
	t.Helper()
	grant, err := signer.SignBulkTransferGrant(payload)
	if err != nil {
		t.Fatal(err)
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

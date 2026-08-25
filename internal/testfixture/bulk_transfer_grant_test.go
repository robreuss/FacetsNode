package testfixture_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/testfixture"
)

func TestBulkTransferGrantPortableFixture(t *testing.T) {
	fixture, err := testfixture.LoadBulkTransferGrantFixture()
	if err != nil {
		t.Fatal(err)
	}
	if fixture.Format != "facets.bulk-transfer-grant-fixture.v1" {
		t.Fatalf("format=%q", fixture.Format)
	}
	_, payload, err := serviceauthority.ParseBulkTransferGrantHeader(fixture.GrantHeader)
	if err != nil || payload != fixture.Expected {
		t.Fatalf("portable payload=%+v expected=%+v err=%v", payload, fixture.Expected, err)
	}
	registry := serviceauthority.NewBindingRegistry()
	current := serviceauthority.CurrentBinding{
		Revision:     fixture.AuthorityRevision,
		Digest:       fixture.Expected.AuthorityManifestDigest,
		DeploymentID: fixture.Expected.DeploymentID,
	}
	if err := registry.Activate(fixture.Expected.Scope, current); err != nil {
		t.Fatal(err)
	}
	binding := serviceauthority.RequestBinding{
		Scope:             fixture.Expected.Scope,
		AuthorityRevision: fixture.AuthorityRevision,
		AuthorityDigest:   fixture.Expected.AuthorityManifestDigest,
		DeploymentID:      fixture.Expected.DeploymentID,
		RouteID:           fixture.Expected.RouteID,
		TrafficClass:      serviceauthority.TrafficBulk,
	}
	header := make(http.Header)
	header.Set(serviceauthority.HeaderBulkTransferGrant, fixture.GrantHeader)
	header.Set(serviceauthority.HeaderBulkResourceID, fixture.Expected.ResourceID)
	header.Set(serviceauthority.HeaderBulkDirection, string(fixture.Expected.Direction))
	seed := make([]byte, 32)
	seed[31] = 2
	signer, err := serviceauthority.NewDeploymentSigner(fixture.Expected.DeploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.AuthorizeBulkTransfer(binding, http.MethodPost, header, time.UnixMilli(1_500), signer); err != nil {
		t.Fatalf("portable grant signature rejected: %v", err)
	}
}

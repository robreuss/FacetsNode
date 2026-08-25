package serviceauthority

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCurrentBindingIdentitiesFiltersSortsAndDefensivelyCopies(t *testing.T) {
	registry := NewBindingRegistry()
	firstScope := Scope{
		Kind:    ScopeDeviceSync,
		ScopeID: uuid.MustParse("10000000-0000-0000-0000-000000000001"),
	}
	secondScope := Scope{
		Kind:    ScopeDeviceSync,
		ScopeID: uuid.MustParse("20000000-0000-0000-0000-000000000002"),
	}
	otherScope := Scope{
		Kind:    ScopeSharedSpace,
		ScopeID: uuid.MustParse("30000000-0000-0000-0000-000000000003"),
	}
	for scope, binding := range map[Scope]CurrentBinding{
		secondScope: {
			Revision: 2, Digest: digestForBindingSnapshotTest("2"),
			DeploymentID: uuid.MustParse("40000000-0000-0000-0000-000000000004"),
		},
		firstScope: {
			Revision: 1, Digest: digestForBindingSnapshotTest("1"),
			DeploymentID: uuid.MustParse("50000000-0000-0000-0000-000000000005"),
		},
		otherScope: {
			Revision: 1, Digest: digestForBindingSnapshotTest("3"),
			DeploymentID: uuid.MustParse("60000000-0000-0000-0000-000000000006"),
		},
	} {
		if err := registry.Activate(scope, binding); err != nil {
			t.Fatal(err)
		}
	}

	identities, err := registry.CurrentBindingIdentities(ScopeDeviceSync)
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 2 || identities[0].Scope != firstScope ||
		identities[1].Scope != secondScope {
		t.Fatalf("unexpected sorted identities: %+v", identities)
	}
	identities[0].Digest = digestForBindingSnapshotTest("f")
	reloaded, err := registry.CurrentBindingIdentities(ScopeDeviceSync)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded[0].Digest != digestForBindingSnapshotTest("1") {
		t.Fatal("returned identity aliases registry state")
	}
}

func TestCurrentBindingIdentitiesAtRejectsExpiredPersistentAuthority(t *testing.T) {
	fixture := newBootstrapFixture(t)
	validUntil := int64(2_000)
	manifest := fixture.signedManifestUntil(t, fixture.policy, &validUntil)
	digest, err := manifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	registry := NewBindingRegistry()
	registry.expectedDeploymentID = fixture.descriptor.DeploymentID
	if err := registry.Activate(fixture.scope, CurrentBinding{
		Revision: 1, Digest: digest,
		DeploymentID: fixture.descriptor.DeploymentID,
		Manifest:     &manifest,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.CurrentBindingIdentitiesAt(
		ScopeDeviceSync,
		time.UnixMilli(1_999),
	); err != nil {
		t.Fatalf("current Manifest readiness rejected: %v", err)
	}
	if _, err := registry.CurrentBindingIdentitiesAt(
		ScopeDeviceSync,
		time.UnixMilli(2_000),
	); !errors.Is(err, ErrBindingUnavailable) {
		t.Fatalf("expired Manifest readiness error=%v", err)
	}
}

func TestCurrentBindingIdentitiesFailsWhenRegistryIsClosed(t *testing.T) {
	registry := NewBindingRegistry()
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.CurrentBindingIdentities(ScopeDeviceSync); !errors.Is(
		err, ErrBindingUnavailable,
	) {
		t.Fatalf("closed registry error=%v", err)
	}
}

func digestForBindingSnapshotTest(character string) string {
	value := ""
	for len(value) < 64 {
		value += character
	}
	return value[:64]
}

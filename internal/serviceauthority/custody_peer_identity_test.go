package serviceauthority

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCustodyPeerIdentityRequiresCurrentPersistentScopedRegistry(t *testing.T) {
	for _, kind := range []ScopeKind{ScopeDeviceSync, ScopeBackupCustody} {
		f := newCustodyPeerFixture(t, kind, CustodyReserveObject)
		identity, err := f.receiver.CurrentCustodyPeerIdentityAt(f.binding.Scope, f.now)
		if err != nil || identity.Scope != f.binding.Scope || identity.Revision != f.binding.AuthorityRevision || identity.Digest != f.binding.AuthorityDigest || identity.DeploymentID != f.binding.DeploymentID || identity.WriteFenced {
			t.Fatal("wrong projection", err)
		}
		identity.Digest = "changed copy"
		if again, err := f.receiver.CurrentCustodyPeerIdentityAt(f.binding.Scope, f.now); err != nil || again.Digest != f.binding.AuthorityDigest {
			t.Fatal("mutable projection", err)
		}
		for _, scope := range []Scope{{Kind: kind, ScopeID: uuid.New()}, {Kind: ScopeComputePool, ScopeID: f.binding.Scope.ScopeID}, {}} {
			if _, err := f.receiver.CurrentCustodyPeerIdentityAt(scope, f.now); err == nil {
				t.Fatal("wrong scope accepted")
			}
		}
		if _, err := f.receiver.CurrentCustodyPeerIdentityAt(f.binding.Scope, time.UnixMilli(999)); err == nil {
			t.Fatal("not-yet-valid authority accepted")
		}
		bare := &BindingRegistry{bindings: map[Scope]CurrentBinding{f.binding.Scope: {Revision: 1, Digest: f.binding.AuthorityDigest, DeploymentID: f.binding.DeploymentID}}}
		if _, err := bare.CurrentCustodyPeerIdentityAt(f.binding.Scope, f.now); err == nil {
			t.Fatal("bare registry accepted")
		}
		if err := f.receiver.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := f.receiver.CurrentCustodyPeerIdentityAt(f.binding.Scope, f.now); err == nil {
			t.Fatal("closed registry accepted")
		}
	}
	var registry *BindingRegistry
	if _, err := registry.CurrentCustodyPeerIdentityAt(Scope{}, time.Now()); err == nil {
		t.Fatal("nil registry")
	}
}

func TestCustodyPeerIdentityReportsRealMigrationFence(t *testing.T) {
	f := decodeMigrationPortableFixture(t)
	a := f.RollbackEvidence.ActivationEvidence
	initial := a.Preparation.CurrentManifest
	payload, err := initial.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := initial.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := newMigrationRegistry(t, payload.ActiveDeployment.DeploymentID)
	if err := registry.Activate(payload.Scope, CurrentBinding{Revision: payload.Revision, Digest: digest, DeploymentID: payload.ActiveDeployment.DeploymentID, Manifest: &initial}); err != nil {
		t.Fatal(err)
	}
	if err := registry.ApplyMigrationPreparation(a.Preparation, f.AuthorityAnchor, 2200); err != nil {
		t.Fatal(err)
	}
	before, err := registry.CurrentCustodyPeerIdentityAt(payload.Scope, time.UnixMilli(2500))
	if err != nil || before.WriteFenced {
		t.Fatal("unexpected pre-drain state", err)
	}
	snapshot, err := a.Snapshot.VerifiedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = registry.StageMigrationWriteFence(a.Preparation.PreparationManifest, snapshot, f.AuthorityAnchor, 2500); err != nil {
		t.Fatal(err)
	}
	after, err := registry.CurrentCustodyPeerIdentityAt(payload.Scope, time.UnixMilli(2500))
	if err != nil || !after.WriteFenced || after.Revision != before.Revision || after.Digest != before.Digest {
		t.Fatal("real fence not projected", err)
	}
}

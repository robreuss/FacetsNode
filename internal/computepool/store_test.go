package computepool

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestMemoryStoreKeepsPoolWorkerAndOfferingAuthoritySeparate(t *testing.T) {
	var fixture portableFixture
	decodeStrict(t, portableContractFixture, &fixture)
	store := NewMemoryStore()
	ctx := context.Background()

	if err := store.CreatePool(ctx, fixture.Pool); err != nil {
		t.Fatal(err)
	}
	for index := range fixture.WorkerEnrollments {
		if err := store.PutWorkerEnrollment(ctx, 0, fixture.WorkerEnrollments[index]); err != nil {
			t.Fatal(err)
		}
		if err := store.PutWorkerCard(ctx, 0, fixture.WorkerCards[index]); err != nil {
			t.Fatal(err)
		}
		if err := store.PutOffering(ctx, 0, fixture.Offerings[index]); err != nil {
			t.Fatal(err)
		}
	}
	status, err := store.GetPoolStatus(ctx, fixture.Pool.PoolID)
	if err != nil || status.Validate() != nil || len(status.WorkerEnrollments) != 3 ||
		len(status.WorkerCards) != 3 || len(status.Offerings) != 3 {
		t.Fatalf("Compute Pool status=%+v error=%v", status, err)
	}
	if status.Pool.OwnerAuthorityID == status.WorkerEnrollments[0].WorkerOwnerAuthorityID ||
		status.WorkerCards[0].Card.WorkerOwnerAuthorityID != status.WorkerEnrollments[0].WorkerOwnerAuthorityID {
		t.Fatal("Pool ownership silently became Worker ownership")
	}
}

func TestMemoryStoreRejectsRollbackAndCrossPoolOffering(t *testing.T) {
	var fixture portableFixture
	decodeStrict(t, portableContractFixture, &fixture)
	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.CreatePool(ctx, fixture.Pool); err != nil {
		t.Fatal(err)
	}
	if err := store.PutWorkerEnrollment(ctx, 0, fixture.WorkerEnrollments[0]); err != nil {
		t.Fatal(err)
	}
	tamperedCard := fixture.WorkerCards[0]
	tamperedCard.Signature.Signature = strings.Repeat("A", len(tamperedCard.Signature.Signature))
	if err := store.PutWorkerCard(ctx, 0, tamperedCard); err == nil {
		t.Fatal("tampered signed Worker Card was persisted")
	}
	if err := store.PutWorkerCard(ctx, 0, fixture.WorkerCards[0]); err != nil {
		t.Fatal(err)
	}

	stalePool := fixture.Pool
	stalePool.Revision = 3
	stalePool.UpdatedAtMilliseconds = 2_000
	if err := store.UpdatePool(ctx, 2, stalePool); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale Pool revision accepted: %v", err)
	}
	conflictingManifest := fixture.Pool
	conflictingManifest.Revision = 2
	conflictingManifest.UpdatedAtMilliseconds++
	conflictingManifest.AuthorityManifestDigest = strings.Repeat("ab", 32)
	if err := store.UpdatePool(ctx, 1, conflictingManifest); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting manifest at one authority revision accepted: %v", err)
	}

	crossPoolOffering := fixture.Offerings[0]
	crossPoolOffering.PoolID = fixture.Binding.SpaceID
	if err := store.PutOffering(ctx, 0, crossPoolOffering); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-Pool offering accepted: %v", err)
	}
}

func TestDeletingPoolCleansOnlyPoolOwnedRecords(t *testing.T) {
	var fixture portableFixture
	decodeStrict(t, portableContractFixture, &fixture)
	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.CreatePool(ctx, fixture.Pool); err != nil {
		t.Fatal(err)
	}
	if err := store.PutWorkerEnrollment(ctx, 0, fixture.WorkerEnrollments[0]); err != nil {
		t.Fatal(err)
	}
	if err := store.PutWorkerCard(ctx, 0, fixture.WorkerCards[0]); err != nil {
		t.Fatal(err)
	}
	if err := store.PutOffering(ctx, 0, fixture.Offerings[0]); err != nil {
		t.Fatal(err)
	}
	if err := store.DeletePool(ctx, fixture.Pool.PoolID, fixture.Pool.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetPoolStatus(ctx, fixture.Pool.PoolID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted Pool remained available: %v", err)
	}
	if fixture.Binding.PoolAuthority.PoolID != fixture.Pool.PoolID {
		t.Fatal("test fixture lost external Space binding reference")
	}
}

package objectcustodyledger

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/robreuss/FacetsNode/internal/objectcustodyfiles"
	"github.com/robreuss/FacetsNode/internal/objectcustodywire"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

func committedPublication(t *testing.T, f *fixtureContext, binding Binding, references ...objectcustodywire.Reference) Publication {
	t.Helper()
	ctx := context.Background()
	p, err := f.l.BeginPublication(ctx, pub(binding, int64(len(references))))
	if err != nil {
		t.Fatal(err)
	}
	if len(references) != 0 {
		if err = f.l.AddPins(ctx, p.BindingID, p.ID, references); err != nil {
			t.Fatal(err)
		}
	}
	p, err = f.l.Prepare(ctx, p.BindingID, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	p, err = f.l.Confirm(ctx, p.BindingID, p.ID, p.RootDigest, p.InventoryDigest, hashLabel(p.ID.String()))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLeaseExactReplayPinnedReadsAndTerminalClose(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r, wire := object(f.binding, 32)
	mustPut(t, f, r, wire)
	p := committedPublication(t, f, f.binding, r)
	before, err := databaseNow(ctx, f.pool)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := f.l.AcquireLease(ctx, p, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	after, err := databaseNow(ctx, f.pool)
	if err != nil {
		t.Fatal(err)
	}
	if lease.Revision != 1 || lease.Closed || lease.ExpiresAtMilliseconds < before+RestoreLeaseLifetime.Milliseconds() || lease.ExpiresAtMilliseconds > after+RestoreLeaseLifetime.Milliseconds() {
		t.Fatal("lease is not database-timed for the fixed lifetime")
	}
	if retry, err := f.l.AcquireLease(ctx, p, lease.ID); err != nil || retry != lease {
		t.Fatalf("acquire retry: %v", err)
	}
	if got, err := f.l.ReadLeased(ctx, p.BindingID, p.ID, lease.ID, r); err != nil || !bytes.Equal(got, wire) {
		t.Fatalf("leased read: %v", err)
	}
	renewID := uuid.New()
	renewed, err := f.l.RenewLease(ctx, p.BindingID, p.ID, lease.ID, renewID, lease.Revision)
	if err != nil || renewed.Revision != 2 || renewed.ExpiresAtMilliseconds < lease.ExpiresAtMilliseconds {
		t.Fatalf("renew: %v", err)
	}
	if retry, err := f.l.RenewLease(ctx, p.BindingID, p.ID, lease.ID, renewID, lease.Revision); err != nil || retry != renewed {
		t.Fatalf("renew retry: %v", err)
	}
	if _, err := f.l.CloseLease(ctx, p.BindingID, p.ID, lease.ID, renewID, lease.Revision); !errors.Is(err, ErrConflict) {
		t.Fatal("operation ID was reused for a different kind")
	}
	if _, err := f.l.RenewLease(ctx, p.BindingID, p.ID, lease.ID, renewID, renewed.Revision); !errors.Is(err, ErrConflict) {
		t.Fatal("operation ID was reused for another revision")
	}
	if _, err := f.l.RenewLease(ctx, p.BindingID, p.ID, lease.ID, uuid.New(), lease.Revision); !errors.Is(err, ErrConflict) {
		t.Fatal("stale revision renewed")
	}
	closeID := uuid.New()
	closed, err := f.l.CloseLease(ctx, p.BindingID, p.ID, lease.ID, closeID, renewed.Revision)
	if err != nil || !closed.Closed || closed.Revision != 3 {
		t.Fatalf("close: %v", err)
	}
	if retry, err := f.l.CloseLease(ctx, p.BindingID, p.ID, lease.ID, closeID, renewed.Revision); err != nil || retry != closed {
		t.Fatalf("close retry: %v", err)
	}
	// Historical operation receipts remain exact but grant no current access.
	if retry, err := f.l.AcquireLease(ctx, p, lease.ID); err != nil || retry != lease {
		t.Fatalf("historical acquire: %v", err)
	}
	if retry, err := f.l.RenewLease(ctx, p.BindingID, p.ID, lease.ID, renewID, lease.Revision); err != nil || retry != renewed {
		t.Fatalf("historical renew: %v", err)
	}
	if current, err := f.l.Lease(ctx, p.BindingID, p.ID, lease.ID); err != nil || current != closed {
		t.Fatalf("replay revived closed lease: %v", err)
	}
	if _, err := f.l.ReadLeased(ctx, p.BindingID, p.ID, lease.ID, r); !errors.Is(err, ErrConflict) {
		t.Fatal("closed lease read")
	}
	if _, err := f.l.RenewLease(ctx, p.BindingID, p.ID, lease.ID, uuid.New(), closed.Revision); !errors.Is(err, ErrConflict) {
		t.Fatal("closed lease renewed")
	}
}

func TestRetirementKeepsIndependentBackupAndRunningRestore(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r, wire := object(f.binding, 16)
	mustPut(t, f, r, wire)
	p := committedPublication(t, f, f.binding, r)
	backup := f.binding
	backup.ID, backup.ServiceKind, backup.ServiceScopeID, backup.ResourceID = uuid.New(), "backup_custody", uuid.New(), uuid.New()
	if err := f.l.RegisterBinding(ctx, backup); err != nil {
		t.Fatal(err)
	}
	b := committedPublication(t, f, backup, r)
	lease, err := f.l.AcquireLease(ctx, p, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	decision := hashLabel("authorized retirement fixture")
	retired, err := f.l.Retire(ctx, p, decision)
	if err != nil || retired.State != "retired" || retired.RetirementDigest != decision {
		t.Fatalf("retire: %v", err)
	}
	if retry, err := f.l.Retire(ctx, p, decision); err != nil || retry != retired {
		t.Fatalf("retirement retry: %v", err)
	}
	if _, err := f.l.Retire(ctx, p, hashLabel("different decision")); !errors.Is(err, ErrConflict) {
		t.Fatal("retirement decision replaced")
	}
	if obligations, err := f.l.Retention(ctx, r); err != nil || obligations != (RetentionObligations{Publications: 1, ActiveRestoreLeases: 1}) {
		t.Fatalf("independent obligations: %+v %v", obligations, err)
	}
	if _, err := f.l.AcquireLease(ctx, p, uuid.New()); !errors.Is(err, ErrConflict) {
		t.Fatal("new restore started after retirement")
	}
	if retry, err := f.l.AcquireLease(ctx, p, lease.ID); err != nil || retry != lease {
		t.Fatalf("accepted acquisition retry after retirement: %v", err)
	}
	renewed, err := f.l.RenewLease(ctx, p.BindingID, p.ID, lease.ID, uuid.New(), lease.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.l.ReadLeased(ctx, p.BindingID, p.ID, lease.ID, r); err != nil || !bytes.Equal(got, wire) {
		t.Fatalf("in-progress restore lost bytes: %v", err)
	}
	if err := f.l.AddPins(ctx, p.BindingID, p.ID, []objectcustodywire.Reference{r}); !errors.Is(err, ErrConflict) {
		t.Fatal("pin replay reactivated retirement")
	}
	if _, err := f.l.Prepare(ctx, p.BindingID, p.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("prepare reactivated retirement")
	}
	if _, err := f.l.Confirm(ctx, p.BindingID, p.ID, p.RootDigest, p.InventoryDigest, p.ReceiptDigest); !errors.Is(err, ErrConflict) {
		t.Fatal("confirm reactivated retirement")
	}
	start := p
	start.State, start.InventoryDigest, start.ReceiptDigest = "", "", ""
	if _, err := f.l.BeginPublication(ctx, start); !errors.Is(err, ErrConflict) {
		t.Fatal("begin reactivated retirement")
	}
	if _, err := f.l.CloseLease(ctx, p.BindingID, p.ID, lease.ID, uuid.New(), renewed.Revision); err != nil {
		t.Fatal(err)
	}
	if obligations, err := f.l.Retention(ctx, r); err != nil || obligations != (RetentionObligations{Publications: 1}) {
		t.Fatalf("backup protection removed: %+v %v", obligations, err)
	}
	if _, err := f.l.Retire(ctx, b, hashLabel("backup policy fixture")); err != nil {
		t.Fatal(err)
	}
	if obligations, err := f.l.Retention(ctx, r); err != nil || obligations != (RetentionObligations{}) {
		t.Fatalf("all obligations ended: %+v %v", obligations, err)
	}
	// This packet only changes durable obligations. It does not delete bytes.
	assertWire(t, f.l, f.binding, r, wire)
}

func TestLeaseAndRetirementRejectWrongScopeRootAndUnpinnedObject(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r, wire := object(f.binding, 0)
	mustPut(t, f, r, wire)
	p := committedPublication(t, f, f.binding, r)
	for _, field := range []string{"binding", "publication", "root", "inventory", "receipt", "count"} {
		t.Run(field, func(t *testing.T) {
			wrong := p
			switch field {
			case "binding":
				wrong.BindingID = uuid.New()
			case "publication":
				wrong.ID = uuid.New()
			case "root":
				wrong.RootDigest = hashLabel("different root")
			case "inventory":
				wrong.InventoryDigest = hashLabel("different inventory")
			case "receipt":
				wrong.ReceiptDigest = hashLabel("different receipt")
			case "count":
				wrong.ObjectCount++
			}
			if _, err := f.l.AcquireLease(ctx, wrong, uuid.New()); err == nil {
				t.Fatal("wrong publication accepted")
			}
			if _, err := f.l.Retire(ctx, wrong, hashLabel("decision")); err == nil {
				t.Fatal("wrong retirement accepted")
			}
		})
	}
	lease, err := f.l.AcquireLease(ctx, p, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	unpinned, otherWire := object(f.binding, 1)
	mustPut(t, f, unpinned, otherWire)
	if _, err := f.l.ReadLeased(ctx, p.BindingID, p.ID, lease.ID, unpinned); err == nil {
		t.Fatal("unpinned object read")
	}
	wrong := r
	wrong.Header.ContentEpoch++
	if _, err := f.l.ReadLeased(ctx, p.BindingID, p.ID, lease.ID, wrong); err == nil {
		t.Fatal("wrong epoch read")
	}
	if _, err := f.l.ReadLeased(ctx, uuid.New(), p.ID, lease.ID, r); err == nil {
		t.Fatal("wrong binding read")
	}
	if _, err := f.l.ReadLeased(ctx, p.BindingID, uuid.New(), lease.ID, r); err == nil {
		t.Fatal("wrong publication read")
	}
	pending, err := f.l.BeginPublication(ctx, pub(f.binding, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.AcquireLease(ctx, pending, uuid.New()); err == nil {
		t.Fatal("open publication leased")
	}
	if _, err := f.l.Retire(ctx, pending, hashLabel("decision")); err == nil {
		t.Fatal("open publication retired")
	}
	pending, err = f.l.Prepare(ctx, pending.BindingID, pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.AcquireLease(ctx, pending, uuid.New()); err == nil {
		t.Fatal("prepared uncertain publication leased")
	}
	if _, err := f.l.Retire(ctx, pending, hashLabel("decision")); err == nil {
		t.Fatal("prepared uncertain publication retired")
	}
}

func TestExpiredLeaseCannotRenewOrReadButCanClose(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r, wire := object(f.binding, 0)
	mustPut(t, f, r, wire)
	p := committedPublication(t, f, f.binding, r)
	lease, err := f.l.AcquireLease(ctx, p, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	// Alter only a disposable fixture row; never change machine clocks.
	if _, err := f.pool.Exec(ctx, `UPDATE immutable_custody_leases SET expires_at_milliseconds=1 WHERE lease_id=$1`, lease.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE immutable_custody_lease_operations SET result_expires_at_milliseconds=1 WHERE lease_id=$1`, lease.ID); err != nil {
		t.Fatal(err)
	}
	lease.ExpiresAtMilliseconds = 1
	if _, err := f.l.ReadLeased(ctx, p.BindingID, p.ID, lease.ID, r); !errors.Is(err, ErrConflict) {
		t.Fatal("expired read accepted")
	}
	if _, err := f.l.RenewLease(ctx, p.BindingID, p.ID, lease.ID, uuid.New(), 1); !errors.Is(err, ErrConflict) {
		t.Fatal("expired lease renewed")
	}
	if prior, err := f.l.AcquireLease(ctx, p, lease.ID); err != nil || prior != lease {
		t.Fatalf("replay receipt changed: %v", err)
	}
	if current, err := f.l.Lease(ctx, p.BindingID, p.ID, lease.ID); err != nil || current.ExpiresAtMilliseconds != 1 {
		t.Fatalf("retry extended expiry: %v", err)
	}
	if obligations, err := f.l.Retention(ctx, r); err != nil || obligations.ActiveRestoreLeases != 0 {
		t.Fatalf("expired lease remains active: %v", err)
	}
	if closed, err := f.l.CloseLease(ctx, p.BindingID, p.ID, lease.ID, uuid.New(), 1); err != nil || !closed.Closed {
		t.Fatalf("expiry cleanup: %v", err)
	}
}

func TestPressureAllowsReplayLeasedReadCloseAndRetirement(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r, wire := object(f.binding, 0)
	mustPut(t, f, r, wire)
	p := committedPublication(t, f, f.binding, r)
	lease, err := f.l.AcquireLease(ctx, p, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	f.provider.set(0, storagecapacity.ErrUnavailable)
	if _, err := f.l.AcquireLease(ctx, p, uuid.New()); err == nil {
		t.Fatal("new lease without capacity")
	}
	if _, err := f.l.RenewLease(ctx, p.BindingID, p.ID, lease.ID, uuid.New(), 1); err == nil {
		t.Fatal("renewal without capacity")
	}
	if retry, err := f.l.AcquireLease(ctx, p, lease.ID); err != nil || retry != lease {
		t.Fatalf("replay under pressure: %v", err)
	}
	if got, err := f.l.ReadLeased(ctx, p.BindingID, p.ID, lease.ID, r); err != nil || !bytes.Equal(got, wire) {
		t.Fatalf("read under pressure: %v", err)
	}
	if _, err := f.l.Retire(ctx, p, hashLabel("retirement fixture")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.CloseLease(ctx, p.BindingID, p.ID, lease.ID, uuid.New(), 1); err != nil {
		t.Fatal(err)
	}
}

func TestLeaseAndRetirementReopenLostResponseAtomicity(t *testing.T) {
	for _, point := range []string{"before_database_commit", "after_database_commit"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			p := committedPublication(t, f, f.binding)
			leaseID := uuid.New()
			f.l.fault = func(current string) error {
				if current == point {
					return errors.New("injected ledger outcome")
				}
				return nil
			}
			original, err := f.l.AcquireLease(ctx, p, leaseID)
			if err == nil {
				t.Fatal("fault not reached")
			}
			var leases, operations int64
			if err := f.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM immutable_custody_leases),(SELECT count(*) FROM immutable_custody_lease_operations)`).Scan(&leases, &operations); err != nil {
				t.Fatal(err)
			}
			want := int64(0)
			if point == "after_database_commit" {
				want = 1
			}
			if leases != want || operations != want {
				t.Fatal("lease and receipt commit diverged")
			}
			if err := f.files.Close(); err != nil {
				t.Fatal(err)
			}
			files, err := objectcustodyfiles.Open(f.path)
			if err != nil {
				t.Fatal(err)
			}
			defer files.Close()
			reopened, err := Open(ctx, f.pool, f.l.poolID, files, f.provider)
			if err != nil {
				t.Fatal(err)
			}
			retried, err := reopened.AcquireLease(ctx, p, leaseID)
			if err != nil || (want == 1 && retried != original) {
				t.Fatalf("reopened acquisition: %v", err)
			}
			renewID := uuid.New()
			reopened.fault = func(current string) error {
				if current == point {
					return errors.New("injected outcome")
				}
				return nil
			}
			renewed, err := reopened.RenewLease(ctx, p.BindingID, p.ID, leaseID, renewID, 1)
			if err == nil {
				t.Fatal("renew fault not reached")
			}
			reopened.fault = nil
			again, err := reopened.RenewLease(ctx, p.BindingID, p.ID, leaseID, renewID, 1)
			if err != nil || (want == 1 && again != renewed) {
				t.Fatalf("renew exact recovery: %v", err)
			}
			decision := hashLabel("retirement lost response")
			reopened.fault = func(current string) error {
				if current == point {
					return errors.New("injected outcome")
				}
				return nil
			}
			_, err = reopened.Retire(ctx, p, decision)
			if err == nil {
				t.Fatal("retire fault not reached")
			}
			reopened.fault = nil
			if retired, err := reopened.Retire(ctx, p, decision); err != nil || retired.State != "retired" {
				t.Fatalf("retire exact recovery: %v", err)
			}
		})
	}
}

func secondLedger(t *testing.T, f *fixtureContext) *Ledger {
	t.Helper()
	pool, err := pgxpool.NewWithConfig(context.Background(), f.pool.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	l, err := Open(context.Background(), pool, f.l.poolID, f.files, f.provider)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestRetirementVersusLeaseAcquisitionAcrossConnections(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r, wire := object(f.binding, 0)
	mustPut(t, f, r, wire)
	p := committedPublication(t, f, f.binding, r)
	other := secondLedger(t, f)
	start := make(chan struct{})
	accepted := make(chan RestoreLease, 16)
	failures := make(chan error, 17)
	var group sync.WaitGroup
	for range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			lease, err := other.AcquireLease(ctx, p, uuid.New())
			if err == nil {
				accepted <- lease
			} else if !errors.Is(err, ErrConflict) {
				failures <- err
			}
		}()
	}
	group.Add(1)
	go func() {
		defer group.Done()
		<-start
		if _, err := f.l.Retire(ctx, p, hashLabel("race retirement")); err != nil {
			failures <- err
		}
	}()
	close(start)
	group.Wait()
	close(accepted)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	var count int64
	for lease := range accepted {
		count++
		if _, err := other.RenewLease(ctx, p.BindingID, p.ID, lease.ID, uuid.New(), 1); err != nil {
			t.Fatal(err)
		}
		if got, err := f.l.ReadLeased(ctx, p.BindingID, p.ID, lease.ID, r); err != nil || !bytes.Equal(got, wire) {
			t.Fatalf("accepted restore lost custody: %v", err)
		}
	}
	if obligations, err := f.l.Retention(ctx, r); err != nil || obligations.Publications != 0 || obligations.ActiveRestoreLeases != count {
		t.Fatalf("race obligations: %+v %v", obligations, err)
	}
	if _, err := f.l.AcquireLease(ctx, p, uuid.New()); !errors.Is(err, ErrConflict) {
		t.Fatal("post-retirement acquisition")
	}
}

func TestConcurrentRenewalAndCloseHaveOneRevisionWinner(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	p := committedPublication(t, f, f.binding)
	lease, err := f.l.AcquireLease(ctx, p, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	other := secondLedger(t, f)
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		_, err := f.l.RenewLease(ctx, p.BindingID, p.ID, lease.ID, uuid.New(), 1)
		results <- err
	}()
	go func() {
		<-start
		_, err := other.CloseLease(ctx, p.BindingID, p.ID, lease.ID, uuid.New(), 1)
		results <- err
	}()
	close(start)
	winners := 0
	for range 2 {
		err := <-results
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatal("concurrent operations did not have one winner")
	}
	if current, err := other.Lease(ctx, p.BindingID, p.ID, lease.ID); err != nil || current.Revision != 2 {
		t.Fatalf("revision conflict: %v", err)
	}
}

func TestRetentionIncludesPendingUploadAndRejectsCorruptState(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r, _ := object(f.binding, 1)
	if err := f.l.Reserve(ctx, f.binding.ID, r); err != nil {
		t.Fatal(err)
	}
	if obligations, err := f.l.Retention(ctx, r); err != nil || obligations != (RetentionObligations{PendingUpload: true}) {
		t.Fatalf("pending upload lost: %+v %v", obligations, err)
	}
	p := committedPublication(t, f, f.binding)
	lease, err := f.l.AcquireLease(ctx, p, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	// Valid SQL strings can still be invalid canonical digests; fail closed.
	if _, err := f.pool.Exec(ctx, `ALTER TABLE immutable_custody_publications DROP CONSTRAINT immutable_custody_publications_receipt_digest_check`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE immutable_custody_publications SET receipt_digest=$1 WHERE publication_id=$2`, strings.Repeat("A", 64), p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.RenewLease(ctx, p.BindingID, p.ID, lease.ID, uuid.New(), 1); err == nil {
		t.Fatal("corrupt publication renewed")
	}
	if _, err := f.l.Retire(ctx, p, hashLabel("decision")); err == nil {
		t.Fatal("corrupt publication retired")
	}
}

func TestLeaseCurrentRowMustMatchItsDurableOperation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r, wire := object(f.binding, 0)
	mustPut(t, f, r, wire)
	p := committedPublication(t, f, f.binding, r)
	lease, err := f.l.AcquireLease(ctx, p, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	closed, err := f.l.CloseLease(ctx, p.BindingID, p.ID, lease.ID, uuid.New(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE immutable_custody_leases SET closed=false WHERE lease_id=$1`, lease.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.ReadLeased(ctx, p.BindingID, p.ID, lease.ID, r); !errors.Is(err, ErrInvalid) {
		t.Fatal("corrupt row revived closed lease")
	}
	if _, err := f.l.RenewLease(ctx, p.BindingID, p.ID, lease.ID, uuid.New(), closed.Revision); !errors.Is(err, ErrInvalid) {
		t.Fatal("corrupt row renewed lease")
	}
	if _, err := f.l.AcquireLease(ctx, p, lease.ID); !errors.Is(err, ErrInvalid) {
		t.Fatal("corrupt current row ignored by acquire replay")
	}
	if _, err := f.pool.Exec(ctx, `UPDATE immutable_custody_leases SET revision=1,closed=false,expires_at_milliseconds=$2 WHERE lease_id=$1`, lease.ID, lease.ExpiresAtMilliseconds); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.ReadLeased(ctx, p.BindingID, p.ID, lease.ID, r); !errors.Is(err, ErrInvalid) {
		t.Fatal("old current row ignored newer closed receipt")
	}
}

func runRetentionCrashAction(t *testing.T, ledger *Ledger, bindingID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	readID := func(key string) uuid.UUID {
		id, err := uuid.Parse(os.Getenv(key))
		if err != nil || id == uuid.Nil {
			t.Fatal("invalid retention fixture identity")
		}
		return id
	}
	publicationID := readID("FACETS_CUSTODY_LEDGER_CRASH_PUBLICATION")
	leaseID := readID("FACETS_CUSTODY_LEDGER_CRASH_LEASE")
	operationID := readID("FACETS_CUSTODY_LEDGER_CRASH_OPERATION")
	p, err := ledger.Publication(ctx, bindingID, publicationID)
	if err != nil {
		t.Fatal(err)
	}
	switch os.Getenv("FACETS_CUSTODY_LEDGER_CRASH_ACTION") {
	case "acquire":
		_, _ = ledger.AcquireLease(ctx, p, leaseID)
	case "renew":
		_, _ = ledger.RenewLease(ctx, bindingID, publicationID, leaseID, operationID, 1)
	case "close":
		_, _ = ledger.CloseLease(ctx, bindingID, publicationID, leaseID, operationID, 1)
	case "retire":
		_, _ = ledger.Retire(ctx, p, hashLabel("retention process crash decision"))
	default:
		t.Fatal("invalid retention fixture action")
	}
	t.Fatal("expected abrupt process termination")
}

func TestSIGKILLAcrossRestoreLeaseAndRetirementCommits(t *testing.T) {
	for _, action := range []string{"acquire", "renew", "close", "retire"} {
		for _, point := range []string{"before_database_commit", "after_database_commit"} {
			t.Run(action+"/"+point, func(t *testing.T) {
				f := newFixture(t)
				ctx := context.Background()
				r, wire := object(f.binding, 7)
				mustPut(t, f, r, wire)
				p := committedPublication(t, f, f.binding, r)
				leaseID, operationID := uuid.New(), uuid.New()
				if action != "acquire" {
					if _, err := f.l.AcquireLease(ctx, p, leaseID); err != nil {
						t.Fatal(err)
					}
				}
				if err := f.files.Close(); err != nil {
					t.Fatal(err)
				}
				command := exec.Command(os.Args[0], "-test.run=^TestLedgerAbruptProcessHelper$")
				command.Env = append(os.Environ(), "FACETS_CUSTODY_LEDGER_CRASH_HELPER=1",
					"FACETS_CUSTODY_LEDGER_CRASH_SCHEMA="+f.pool.Config().ConnConfig.RuntimeParams["search_path"],
					"FACETS_CUSTODY_LEDGER_CRASH_ROOT="+f.path, "FACETS_CUSTODY_LEDGER_CRASH_POOL="+f.l.poolID.String(),
					"FACETS_CUSTODY_LEDGER_CRASH_BINDING="+f.binding.ID.String(), "FACETS_CUSTODY_LEDGER_CRASH_POINT="+point,
					"FACETS_CUSTODY_LEDGER_CRASH_ACTION="+action, "FACETS_CUSTODY_LEDGER_CRASH_PUBLICATION="+p.ID.String(),
					"FACETS_CUSTODY_LEDGER_CRASH_LEASE="+leaseID.String(), "FACETS_CUSTODY_LEDGER_CRASH_OPERATION="+operationID.String())
				err := command.Run()
				var failure *exec.ExitError
				if !errors.As(err, &failure) || failure.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
					t.Fatalf("expected SIGKILL: %v", err)
				}
				f.files, err = objectcustodyfiles.Open(f.path)
				if err != nil {
					t.Fatal(err)
				}
				defer f.files.Close()
				f.l, err = Open(ctx, f.pool, f.l.poolID, f.files, f.provider)
				if err != nil {
					t.Fatal(err)
				}
				beforeRetry, beforeErr := f.l.Lease(ctx, p.BindingID, p.ID, leaseID)
				if action == "acquire" && point == "before_database_commit" {
					if !errors.Is(beforeErr, pgx.ErrNoRows) {
						t.Fatal("uncommitted lease survived")
					}
				} else if beforeErr != nil {
					t.Fatal(beforeErr)
				}
				var afterRetry RestoreLease
				switch action {
				case "acquire":
					afterRetry, err = f.l.AcquireLease(ctx, p, leaseID)
				case "renew":
					afterRetry, err = f.l.RenewLease(ctx, p.BindingID, p.ID, leaseID, operationID, 1)
				case "close":
					afterRetry, err = f.l.CloseLease(ctx, p.BindingID, p.ID, leaseID, operationID, 1)
				case "retire":
					prior, priorErr := f.l.Publication(ctx, p.BindingID, p.ID)
					if priorErr != nil || (prior.State == "retired") != (point == "after_database_commit") {
						t.Fatalf("retirement commit boundary: point=%s state=%s error=%v", point, prior.State, priorErr)
					}
					_, err = f.l.Retire(ctx, p, hashLabel("retention process crash decision"))
					afterRetry = beforeRetry
				}
				if err != nil {
					t.Fatal(err)
				}
				if point == "after_database_commit" && afterRetry != beforeRetry {
					t.Fatal("lost-response retry changed durable lease outcome")
				}
				if action == "close" {
					if !afterRetry.Closed {
						t.Fatal("close did not remain terminal")
					}
					if _, err := f.l.ReadLeased(ctx, p.BindingID, p.ID, leaseID, r); !errors.Is(err, ErrConflict) {
						t.Fatal("closed lease read after crash")
					}
				} else if got, err := f.l.ReadLeased(ctx, p.BindingID, p.ID, leaseID, r); err != nil || !bytes.Equal(got, wire) {
					t.Fatalf("restore lost after crash: %v", err)
				}
			})
		}
	}
}

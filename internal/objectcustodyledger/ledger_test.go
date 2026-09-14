package objectcustodyledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/robreuss/FacetsNode/internal/objectcustodyfiles"
	"github.com/robreuss/FacetsNode/internal/objectcustodywire"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

type testCapacity struct {
	mu        sync.Mutex
	available int64
	failure   error
	calls     int
	failAt    int
}

func (c *testCapacity) Snapshot(ctx context.Context) (storagecapacity.Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if err := ctx.Err(); err != nil {
		return storagecapacity.Snapshot{}, err
	}
	if c.failure != nil {
		return storagecapacity.Snapshot{}, c.failure
	}
	available := c.available
	if c.failAt > 0 && c.calls >= c.failAt {
		available = 0
	}
	return storagecapacity.Snapshot{TotalBytes: 100 << 30, AvailableBytes: available}, nil
}
func (c *testCapacity) set(available int64, failure error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.available = available
	c.failure = failure
	c.failAt = 0
	c.calls = 0
}

type fixtureContext struct {
	l        *Ledger
	files    *objectcustodyfiles.Store
	pool     *pgxpool.Pool
	provider *testCapacity
	path     string
	binding  Binding
}

func newFixture(t *testing.T) *fixtureContext {
	t.Helper()
	ctx := context.Background()
	url := os.Getenv("FACETS_OBJECT_CUSTODY_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("FACETS_OBJECT_CUSTODY_TEST_DATABASE_URL is not set; requires disposable database")
	}
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal("connect disposable database")
	}
	var database string
	if admin.QueryRow(ctx, `SELECT current_database()`).Scan(&database) != nil || database != "facets_immutable_custody_tests" {
		admin.Close()
		t.Fatal("test database name must be facets_immutable_custody_tests")
	}
	schemaName := "object_custody_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schemaName}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		t.Fatal("create disposable schema")
	}
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schemaName
	config.MaxConns = 16
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE")
		admin.Close()
	})
	parent := t.TempDir()
	if err = os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "custody")
	files, err := objectcustodyfiles.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = files.Close() })
	poolID := uuid.New()
	if err = Initialize(ctx, pool, poolID); err != nil {
		t.Fatal(err)
	}
	provider := &testCapacity{available: 90 << 30}
	l, err := Open(ctx, pool, poolID, files, provider)
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{ID: uuid.New(), ServiceKind: "device_sync", ServiceScopeID: uuid.New(), ResourceID: uuid.New(), ContentScopeID: uuid.New(), ContentEpoch: 7}
	if err = l.RegisterBinding(ctx, binding); err != nil {
		t.Fatal(err)
	}
	return &fixtureContext{l: l, files: files, pool: pool, provider: provider, path: path, binding: binding}
}

func object(binding Binding, size int) (objectcustodywire.Reference, []byte) {
	header := objectcustodywire.Header{ScopeID: binding.ContentScopeID, ContentEpoch: binding.ContentEpoch, IncarnationID: uuid.New(), PlaintextBytes: uint64(size)}
	wire, _ := header.Encode()
	wire = append(wire, bytes.Repeat([]byte{0x63}, size+28)...)
	r, err := objectcustodywire.Inspect(wire)
	if err != nil {
		panic(err)
	}
	return r, wire
}

func hashLabel(label string) string {
	digest := sha256.Sum256([]byte(label))
	return hex.EncodeToString(digest[:])
}
func pub(binding Binding, count int64) Publication {
	return Publication{BindingID: binding.ID, ID: uuid.New(), RootDigest: hashLabel(uuid.NewString()), ObjectCount: count}
}

func mustPut(t *testing.T, f *fixtureContext, r objectcustodywire.Reference, wire []byte) {
	t.Helper()
	if err := f.l.Put(context.Background(), f.binding.ID, r, wire); err != nil {
		t.Fatal(err)
	}
}
func outstanding(t *testing.T, f *fixtureContext) int64 {
	t.Helper()
	value, err := reservations(context.Background(), f.pool)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func assertWire(t *testing.T, l *Ledger, b Binding, r objectcustodywire.Reference, wire []byte) {
	t.Helper()
	data, err := l.Read(context.Background(), b.ID, r)
	if err != nil || !bytes.Equal(data, wire) {
		t.Fatalf("retained read: %v", err)
	}
}

func TestDedicatedSchemaAndExactBinding(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if err := Initialize(ctx, f.pool, uuid.New()); err == nil {
		t.Fatal("existing schema adopted")
	}
	if _, err := Open(ctx, f.pool, uuid.New(), f.files, f.provider); err == nil {
		t.Fatal("wrong pool adopted")
	}
	if _, err := Open(ctx, f.pool, f.l.poolID, f.files, nil); err == nil {
		t.Fatal("missing capacity provider")
	}
	if err := f.l.RegisterBinding(ctx, f.binding); err != nil {
		t.Fatal(err)
	}
	other := f.binding
	other.ContentEpoch++
	if err := f.l.RegisterBinding(ctx, other); !errors.Is(err, ErrConflict) {
		t.Fatalf("binding rewrite: %v", err)
	}
	other.ID = uuid.New()
	other.ServiceKind = "compute_pool"
	if err := f.l.RegisterBinding(ctx, other); err == nil {
		t.Fatal("unrelated service accepted")
	}
	other.ServiceKind = "backup_custody"
	other.ContentEpoch = ^uint64(0)
	if err := f.l.RegisterBinding(ctx, other); err != nil {
		t.Fatal(err)
	}
	r, w := object(other, 0)
	if err := f.l.Put(ctx, other.ID, r, w); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `CREATE TABLE unexpected(value integer)`); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, f.pool, f.l.poolID, f.files, f.provider); err == nil {
		t.Fatal("unexpected schema accepted")
	}
}

func TestDurableReservationAndExactSharedPayloadReuse(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r, wire := object(f.binding, 3*65536+19)
	if err := f.l.Reserve(ctx, f.binding.ID, r); err != nil {
		t.Fatal(err)
	}
	expected, _ := storagecapacity.UploadReservation(int64(len(wire)), 0, 0)
	if got := outstanding(t, f); got != expected {
		t.Fatalf("reservation=%d expected=%d", got, expected)
	}
	if err := f.l.Reserve(ctx, f.binding.ID, r); err != nil {
		t.Fatal(err)
	}
	if got := outstanding(t, f); got != expected {
		t.Fatal("duplicate reservation")
	}
	mustPut(t, f, r, wire)
	if got := outstanding(t, f); got != 0 {
		t.Fatalf("remaining reservation=%d", got)
	}
	first, _ := os.Stat(filepath.Join(f.path, "objects", r.CiphertextID))
	backup := f.binding
	backup.ID = uuid.New()
	backup.ServiceKind = "backup_custody"
	backup.ServiceScopeID = uuid.New()
	backup.ResourceID = uuid.New()
	if err := f.l.RegisterBinding(ctx, backup); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := f.l.Put(ctx, backup.ID, r, wire); err != nil {
			t.Fatal(err)
		}
	}
	assertWire(t, f.l, backup, r, wire)
	after, _ := os.Stat(filepath.Join(f.path, "objects", r.CiphertextID))
	if !os.SameFile(first, after) {
		t.Fatal("unchanged service reuse copied/replaced bytes")
	}
	entries, _ := os.ReadDir(filepath.Join(f.path, "objects"))
	if len(entries) != 1 {
		t.Fatal("duplicate physical payload")
	}
	var count int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM immutable_custody_objects`).Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate metadata object")
	}
}

func TestConcurrentPoolReservationsAcrossConnections(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	secondPool, err := pgxpool.NewWithConfig(ctx, f.pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer secondPool.Close()
	second, err := Open(ctx, secondPool, f.l.poolID, f.files, f.provider)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := object(f.binding, 100000)
	reservation, _ := storagecapacity.UploadReservation(wireBytes(r), 0, 0)
	f.provider.set((10<<30)+2*reservation, nil)
	var accepted atomic.Int32
	var group sync.WaitGroup
	failures := make(chan error, 16)
	for i := range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			ledger := f.l
			if i%2 == 1 {
				ledger = second
			}
			candidate, _ := object(f.binding, 100000)
			if err := ledger.Reserve(ctx, f.binding.ID, candidate); err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, storagecapacity.ErrPressure) {
				failures <- err
			}
		}()
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	if accepted.Load() != 2 || outstanding(t, f) != 2*reservation {
		t.Fatalf("over/under admission: %d", accepted.Load())
	}
}

func TestLowStoragePausePartialWriteAndRecovery(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r, wire := object(f.binding, 4*65536)
	if err := f.l.Reserve(ctx, f.binding.ID, r); err != nil {
		t.Fatal(err)
	}
	f.provider.mu.Lock()
	f.provider.calls = 0
	f.provider.failAt = 3
	f.provider.mu.Unlock()
	err := f.l.Put(ctx, f.binding.ID, r, wire)
	if !errors.Is(err, storagecapacity.ErrPressure) {
		t.Fatalf("storage pause: %v", err)
	}
	info, err := os.Stat(filepath.Join(f.path, "staging", r.CiphertextID))
	if err != nil || info.Size() != 2*65536 {
		t.Fatalf("bounded prefix size: %v", err)
	}
	if outstanding(t, f) == 0 {
		t.Fatal("paused reservation lost")
	}
	f.provider.set(90<<30, nil)
	mustPut(t, f, r, wire)
	assertWire(t, f.l, f.binding, r, wire)
	if outstanding(t, f) != 0 {
		t.Fatal("successful reservation retained")
	}
	// Physical probe failure blocks new writes, not an already retained read.
	f.provider.set(0, storagecapacity.ErrUnavailable)
	assertWire(t, f.l, f.binding, r, wire)
	if err := f.l.Put(ctx, f.binding.ID, r, wire); err != nil {
		t.Fatalf("exact retained retry failed: %v", err)
	}
	other, otherWire := object(f.binding, 1)
	if err := f.l.Put(ctx, f.binding.ID, other, otherWire); !errors.Is(err, storagecapacity.ErrUnavailable) {
		t.Fatalf("unknown capacity admitted: %v", err)
	}
}

func TestLostFileAndDatabaseCompletionReconcile(t *testing.T) {
	for _, point := range []string{"after_file_custody", "before_database_commit", "after_database_commit"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			r, wire := object(f.binding, 65537)
			if err := f.l.Reserve(ctx, f.binding.ID, r); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected ledger completion failure")
			f.l.fault = func(current string) error {
				if current == point {
					return injected
				}
				return nil
			}
			if err := f.l.Put(ctx, f.binding.ID, r, wire); !errors.Is(err, injected) {
				t.Fatalf("fault not observed: %v", err)
			}
			f.l.fault = nil
			first, err := os.Stat(filepath.Join(f.path, "objects", r.CiphertextID))
			if err != nil {
				t.Fatal(err)
			}
			f.l, err = Open(ctx, f.pool, f.l.poolID, f.files, f.provider)
			if err != nil {
				t.Fatal(err)
			}
			mustPut(t, f, r, wire)
			assertWire(t, f.l, f.binding, r, wire)
			after, _ := os.Stat(filepath.Join(f.path, "objects", r.CiphertextID))
			if !os.SameFile(first, after) || outstanding(t, f) != 0 {
				t.Fatal("exact completion not reconciled")
			}
		})
	}
}

func TestCrossScopeAndCorruptedStateFailClosed(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r, wire := object(f.binding, 128)
	other := f.binding
	other.ID = uuid.New()
	other.ContentScopeID = uuid.New()
	if err := f.l.RegisterBinding(ctx, other); err != nil {
		t.Fatal(err)
	}
	if err := f.l.Put(ctx, other.ID, r, wire); err == nil {
		t.Fatal("cross scope upload")
	}
	if err := f.l.Put(ctx, uuid.New(), r, wire); err == nil {
		t.Fatal("unknown binding upload")
	}
	mustPut(t, f, r, wire)
	if _, err := f.l.Read(ctx, other.ID, r); err == nil {
		t.Fatal("cross scope read")
	}
	changed := r.Header
	changed.ContentEpoch++
	header, _ := changed.Encode()
	if _, err := f.pool.Exec(ctx, `UPDATE immutable_custody_objects SET wire_header=$2 WHERE ciphertext_id=$1`, r.CiphertextID, header); err != nil {
		t.Fatal(err)
	}
	if err := f.l.Put(ctx, f.binding.ID, r, wire); err == nil {
		t.Fatal("corrupted header reused")
	}
	if _, err := f.l.Read(ctx, f.binding.ID, r); err == nil {
		t.Fatal("corrupted header read")
	}
}

func TestPreparedAndIndependentServicePinsSurviveReopen(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r, wire := object(f.binding, 65537)
	mustPut(t, f, r, wire)
	backup := f.binding
	backup.ID = uuid.New()
	backup.ServiceKind = "backup_custody"
	backup.ResourceID = uuid.New()
	if err := f.l.RegisterBinding(ctx, backup); err != nil {
		t.Fatal(err)
	}
	var prepared []Publication
	for _, binding := range []Binding{f.binding, backup} {
		requested := pub(binding, 1)
		p, err := f.l.BeginPublication(ctx, requested)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.l.Confirm(ctx, p.BindingID, p.ID, p.RootDigest, hashLabel("fake inventory"), hashLabel("receipt")); !errors.Is(err, ErrIncomplete) {
			t.Fatalf("unprepared commit: %v", err)
		}
		if err := f.l.AddPins(ctx, p.BindingID, p.ID, []objectcustodywire.Reference{r, r}); err != nil {
			t.Fatal(err)
		}
		p, err = f.l.Prepare(ctx, p.BindingID, p.ID)
		if err != nil || p.State != "prepared" {
			t.Fatalf("prepare: %v", err)
		}
		if retry, err := f.l.BeginPublication(ctx, requested); err != nil || retry != p {
			t.Fatalf("begin retry differs: %v", err)
		}
		prepared = append(prepared, p)
	}
	var err error
	f.l, err = Open(ctx, f.pool, f.l.poolID, f.files, f.provider)
	if err != nil {
		t.Fatal(err)
	}
	first := prepared[0]
	committed, err := f.l.Confirm(ctx, first.BindingID, first.ID, first.RootDigest, first.InventoryDigest, hashLabel("sync receipt"))
	if err != nil || committed.State != "committed" {
		t.Fatal(err)
	}
	if retry, err := f.l.Confirm(ctx, first.BindingID, first.ID, first.RootDigest, first.InventoryDigest, hashLabel("sync receipt")); err != nil || retry != committed {
		t.Fatalf("confirmation retry: %v", err)
	}
	if _, err := f.l.Confirm(ctx, first.BindingID, first.ID, first.RootDigest, first.InventoryDigest, hashLabel("different receipt")); !errors.Is(err, ErrConflict) {
		t.Fatalf("receipt collision: %v", err)
	}
	second, err := f.l.Publication(ctx, backup.ID, prepared[1].ID)
	if err != nil || second != prepared[1] {
		t.Fatalf("other service pin changed: %v", err)
	}
	var count int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM immutable_custody_pins WHERE ciphertext_id=$1`, r.CiphertextID).Scan(&count); err != nil || count != 2 {
		t.Fatalf("independent pins: %v", err)
	}
	if err := f.l.AddPins(ctx, first.BindingID, first.ID, []objectcustodywire.Reference{r}); err != nil {
		t.Fatal(err)
	}
}

func TestClosureCountScopeAndBatchFailuresAreAtomic(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r, wire := object(f.binding, 128)
	mustPut(t, f, r, wire)
	p, err := f.l.BeginPublication(ctx, pub(f.binding, 2))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.l.AddPins(ctx, p.BindingID, p.ID, []objectcustodywire.Reference{r}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.Prepare(ctx, p.BindingID, p.ID); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("missing closure accepted: %v", err)
	}
	pending, pendingWire := object(f.binding, 129)
	if err := f.l.Reserve(ctx, f.binding.ID, pending); err != nil {
		t.Fatal(err)
	}
	if err := f.l.AddPins(ctx, p.BindingID, p.ID, []objectcustodywire.Reference{pending}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.Prepare(ctx, p.BindingID, p.ID); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("reserved object accepted: %v", err)
	}
	mustPut(t, f, pending, pendingWire)
	prepared, err := f.l.Prepare(ctx, p.BindingID, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.Confirm(ctx, p.BindingID, p.ID, hashLabel("wrong root"), prepared.InventoryDigest, hashLabel("receipt")); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong root confirmation: %v", err)
	}
	if err := f.l.AddPins(ctx, p.BindingID, p.ID, make([]objectcustodywire.Reference, 257)); err == nil {
		t.Fatal("oversized batch accepted")
	}
	third, thirdWire := object(f.binding, 130)
	mustPut(t, f, third, thirdWire)
	if err := f.l.AddPins(ctx, p.BindingID, p.ID, []objectcustodywire.Reference{third}); err == nil {
		t.Fatal("prepared inventory modified")
	}
	newPub, err := f.l.BeginPublication(ctx, pub(f.binding, 2))
	if err != nil {
		t.Fatal(err)
	}
	wrong := third
	wrong.Header.ContentEpoch++
	if err := f.l.AddPins(ctx, newPub.BindingID, newPub.ID, []objectcustodywire.Reference{r, wrong}); err == nil {
		t.Fatal("wrong scope batch accepted")
	}
	var count int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM immutable_custody_pins WHERE binding_id=$1 AND publication_id=$2`, newPub.BindingID, newPub.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("partial failed batch committed")
	}
}

func TestMetadataBatchCapacityAccountsForWholeBatch(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r, w := object(f.binding, 0)
	mustPut(t, f, r, w)
	other, ow := object(f.binding, 1)
	mustPut(t, f, other, ow)
	p, err := f.l.BeginPublication(ctx, pub(f.binding, 2))
	if err != nil {
		t.Fatal(err)
	}
	f.provider.set((10<<30)+storagecapacity.MutationMetadataAllowance, nil)
	if err = f.l.AddPins(ctx, p.BindingID, p.ID, []objectcustodywire.Reference{r, other}); !errors.Is(err, storagecapacity.ErrPressure) {
		t.Fatalf("undercharged batch: %v", err)
	}
	var count int
	if err = f.pool.QueryRow(ctx, `SELECT count(*) FROM immutable_custody_pins`).Scan(&count); err != nil || count != 0 {
		t.Fatal("partial metadata transaction")
	}
	f.provider.set(90<<30, nil)
	if err = f.l.AddPins(ctx, p.BindingID, p.ID, []objectcustodywire.Reference{r, other}); err != nil {
		t.Fatal(err)
	}
}

func TestCorruptRetainedFilesCannotPrepareOrBeSilentlyReplaced(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			r, w := object(f.binding, 128)
			mustPut(t, f, r, w)
			p, err := f.l.BeginPublication(ctx, pub(f.binding, 1))
			if err != nil {
				t.Fatal(err)
			}
			if err = f.l.AddPins(ctx, p.BindingID, p.ID, []objectcustodywire.Reference{r}); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.path, "objects", r.CiphertextID)
			if kind == "missing" {
				if err = os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else {
				if err = os.Chmod(path, 0o600); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err = os.Chmod(path, 0o400); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = f.l.Prepare(ctx, p.BindingID, p.ID); err == nil {
				t.Fatal("missing/corrupt closure prepared")
			}
			if err = f.l.Put(ctx, f.binding.ID, r, w); err == nil {
				t.Fatal("live retained promise silently recreated")
			}
			current, err := f.l.Publication(ctx, p.BindingID, p.ID)
			if err != nil || current.State != "open" {
				t.Fatal("failed preparation advanced")
			}
		})
	}
}

func TestPublicationCommitFaultsAndEmptyClosure(t *testing.T) {
	for _, point := range []string{"before_database_commit", "after_database_commit"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			requested := pub(f.binding, 0)
			p, err := f.l.BeginPublication(ctx, requested)
			if err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected publication failure")
			f.l.fault = func(current string) error {
				if current == point {
					return injected
				}
				return nil
			}
			if _, err = f.l.Prepare(ctx, p.BindingID, p.ID); !errors.Is(err, injected) {
				t.Fatalf("prepare fault: %v", err)
			}
			f.l.fault = nil
			p, err = f.l.Prepare(ctx, p.BindingID, p.ID)
			if err != nil {
				t.Fatal(err)
			}
			f.l.fault = func(current string) error {
				if current == point {
					return injected
				}
				return nil
			}
			if _, err = f.l.Confirm(ctx, p.BindingID, p.ID, p.RootDigest, p.InventoryDigest, hashLabel("receipt")); !errors.Is(err, injected) {
				t.Fatalf("confirm fault: %v", err)
			}
			f.l.fault = nil
			committed, err := f.l.Confirm(ctx, p.BindingID, p.ID, p.RootDigest, p.InventoryDigest, hashLabel("receipt"))
			if err != nil || committed.State != "committed" {
				t.Fatal(err)
			}
		})
	}
}

func TestFinalPublicationRechecksCapacityWithoutLosingReadonlyStage(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r, wire := object(f.binding, 128)
	if err := f.l.Reserve(ctx, f.binding.ID, r); err != nil {
		t.Fatal(err)
	}
	f.provider.mu.Lock()
	f.provider.calls = 0
	f.provider.failAt = 2
	f.provider.mu.Unlock()
	if err := f.l.Put(ctx, f.binding.ID, r, wire); !errors.Is(err, storagecapacity.ErrPressure) {
		t.Fatalf("publication boundary: %v", err)
	}
	stage, err := os.Stat(filepath.Join(f.path, "staging", r.CiphertextID))
	if err != nil || stage.Size() != int64(len(wire)) || stage.Mode().Perm() != 0o400 {
		t.Fatal("verified stage lost")
	}
	if _, err := os.Stat(filepath.Join(f.path, "objects", r.CiphertextID)); !os.IsNotExist(err) {
		t.Fatal("publication crossed pressure boundary")
	}
	f.provider.set(90<<30, nil)
	mustPut(t, f, r, wire)
	assertWire(t, f.l, f.binding, r, wire)
}

func TestDuplicateConcurrentUploadsReserveAndPublishOneObject(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r, wire := object(f.binding, 2*65536+7)
	var group sync.WaitGroup
	failures := make(chan error, 16)
	for range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := f.l.Put(ctx, f.binding.ID, r, wire); err != nil {
				failures <- err
			}
		}()
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	if outstanding(t, f) != 0 {
		t.Fatal("duplicate upload reservation remains")
	}
	entries, err := os.ReadDir(filepath.Join(f.path, "objects"))
	if err != nil || len(entries) != 1 {
		t.Fatal("duplicate physical object")
	}
	assertWire(t, f.l, f.binding, r, wire)
}

func TestPrepareStreamsMultipleBatchesAndIsIndependentOfPinOrder(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	references := make([]objectcustodywire.Reference, 0, 257)
	for range 257 {
		r, wire := object(f.binding, 0)
		mustPut(t, f, r, wire)
		references = append(references, r)
	}
	p, err := f.l.BeginPublication(ctx, pub(f.binding, 257))
	if err != nil {
		t.Fatal(err)
	}
	// Send the final item first. Inventory hashing is canonical by ciphertext ID,
	// not request/batch order, and queries consume one bounded object at a time.
	if err = f.l.AddPins(ctx, p.BindingID, p.ID, references[256:]); err != nil {
		t.Fatal(err)
	}
	if err = f.l.AddPins(ctx, p.BindingID, p.ID, references[:256]); err != nil {
		t.Fatal(err)
	}
	prepared, err := f.l.Prepare(ctx, p.BindingID, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.l.AddPins(ctx, p.BindingID, p.ID, references[:256]); err != nil {
		t.Fatal(err)
	}
	if retry, err := f.l.Prepare(ctx, p.BindingID, p.ID); err != nil || retry != prepared {
		t.Fatalf("stable bounded inventory: %v", err)
	}
	var count int64
	if err = f.pool.QueryRow(ctx, `SELECT count(*) FROM immutable_custody_pins WHERE binding_id=$1 AND publication_id=$2`, p.BindingID, p.ID).Scan(&count); err != nil || count != 257 {
		t.Fatal("pin inventory changed")
	}
}

func TestLedgerAbruptProcessHelper(t *testing.T) {
	if os.Getenv("FACETS_CUSTODY_LEDGER_CRASH_HELPER") != "1" {
		return
	}
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(os.Getenv("FACETS_OBJECT_CUSTODY_TEST_DATABASE_URL"))
	if err != nil || config.ConnConfig.Database != "facets_immutable_custody_tests" {
		t.Fatal("requires disposable custody database")
	}
	schema := os.Getenv("FACETS_CUSTODY_LEDGER_CRASH_SCHEMA")
	if !strings.HasPrefix(schema, "object_custody_test_") {
		t.Fatal("requires disposable custody schema")
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	files, err := objectcustodyfiles.Open(os.Getenv("FACETS_CUSTODY_LEDGER_CRASH_ROOT"))
	if err != nil {
		t.Fatal(err)
	}
	poolID, err := uuid.Parse(os.Getenv("FACETS_CUSTODY_LEDGER_CRASH_POOL"))
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := Open(ctx, pool, poolID, files, &testCapacity{available: 90 << 30})
	if err != nil {
		t.Fatal(err)
	}
	bindingID, err := uuid.Parse(os.Getenv("FACETS_CUSTODY_LEDGER_CRASH_BINDING"))
	if err != nil {
		t.Fatal(err)
	}
	header, err := hex.DecodeString(os.Getenv("FACETS_CUSTODY_LEDGER_CRASH_HEADER"))
	if err != nil || len(header) != 54 {
		t.Fatal("invalid fixture header")
	}
	wire := append(header, bytes.Repeat([]byte{0x63}, 128+28)...)
	reference, err := objectcustodywire.Inspect(wire)
	if err != nil {
		t.Fatal(err)
	}
	point := os.Getenv("FACETS_CUSTODY_LEDGER_CRASH_POINT")
	ledger.fault = func(current string) error {
		if current == point {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
		return nil
	}
	_ = ledger.Put(ctx, bindingID, reference, wire)
	t.Fatal("expected process termination")
}

func TestSIGKILLAcrossFileAndDatabaseCommits(t *testing.T) {
	for _, point := range []string{"after_file_custody", "before_database_commit", "after_database_commit"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			reference, wire := object(f.binding, 128)
			if err := f.l.Reserve(ctx, f.binding.ID, reference); err != nil {
				t.Fatal(err)
			}
			header, _ := reference.Header.Encode()
			if err := f.files.Close(); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(os.Args[0], "-test.run=^TestLedgerAbruptProcessHelper$")
			command.Env = append(os.Environ(), "FACETS_CUSTODY_LEDGER_CRASH_HELPER=1",
				"FACETS_CUSTODY_LEDGER_CRASH_SCHEMA="+f.pool.Config().ConnConfig.RuntimeParams["search_path"],
				"FACETS_CUSTODY_LEDGER_CRASH_ROOT="+f.path, "FACETS_CUSTODY_LEDGER_CRASH_POOL="+f.l.poolID.String(),
				"FACETS_CUSTODY_LEDGER_CRASH_BINDING="+f.binding.ID.String(), "FACETS_CUSTODY_LEDGER_CRASH_HEADER="+hex.EncodeToString(header),
				"FACETS_CUSTODY_LEDGER_CRASH_POINT="+point)
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
			mustPut(t, f, reference, wire)
			assertWire(t, f.l, f.binding, reference, wire)
			if outstanding(t, f) != 0 {
				t.Fatal("crash left unresolved reservation after exact retry")
			}
		})
	}
}

func TestPublicationInventoryIndependentDigestFixture(t *testing.T) {
	var fixture struct {
		BindingID, PublicationID, ContentScopeID uuid.UUID
		ContentEpoch                             uint64
		RootDigest                               string
		CiphertextIDs                            []string
		InventoryDigest                          string
		CanonicalByteCount                       int
	}
	data, err := os.ReadFile("testdata/publication-inventory-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	p := Publication{BindingID: fixture.BindingID, ID: fixture.PublicationID, RootDigest: fixture.RootDigest, ObjectCount: int64(len(fixture.CiphertextIDs))}
	b := Binding{ContentScopeID: fixture.ContentScopeID, ContentEpoch: fixture.ContentEpoch}
	hasher := inventoryHasher(p, b)
	for _, id := range fixture.CiphertextIDs {
		raw, err := hex.DecodeString(id)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = hasher.Write(raw)
	}
	if hex.EncodeToString(hasher.Sum(nil)) != fixture.InventoryDigest {
		t.Fatal("independently computed fixture differs")
	}
	// The fixture was calculated independently with Python hashlib/UUID/struct,
	// not by dumping the production Go hasher's result.
	if fixture.CanonicalByteCount != 210 {
		t.Fatal("unexpected canonical fixture size")
	}
	for _, change := range []func(*Publication, *Binding){
		func(p *Publication, b *Binding) { p.BindingID = uuid.New() },
		func(p *Publication, b *Binding) { p.ID = uuid.New() },
		func(p *Publication, b *Binding) { p.RootDigest = hashLabel("substituted root") },
		func(p *Publication, b *Binding) { b.ContentEpoch++ },
		func(p *Publication, b *Binding) { b.ContentScopeID = uuid.New() },
		func(p *Publication, b *Binding) { p.ObjectCount++ },
	} {
		otherP, otherB := p, b
		change(&otherP, &otherB)
		changed := inventoryHasher(otherP, otherB)
		for _, id := range fixture.CiphertextIDs {
			raw, _ := hex.DecodeString(id)
			_, _ = changed.Write(raw)
		}
		if hex.EncodeToString(changed.Sum(nil)) == fixture.InventoryDigest {
			t.Fatal("substitution did not change commitment")
		}
	}
}

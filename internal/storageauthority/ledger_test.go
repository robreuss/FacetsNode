package storageauthority

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

type testCapacity struct {
	mu        sync.Mutex
	total     int64
	available int64
	failure   error
}

func (value *testCapacity) Snapshot(ctx context.Context) (storagecapacity.Snapshot, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return storagecapacity.Snapshot{}, err
	}
	if value.failure != nil {
		return storagecapacity.Snapshot{}, value.failure
	}
	return storagecapacity.Snapshot{TotalBytes: value.total, AvailableBytes: value.available}, nil
}

func (value *testCapacity) set(available int64, failure error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	value.available = available
	value.failure = failure
}

type fixture struct {
	ledger   *Ledger
	pool     *pgxpool.Pool
	provider *testCapacity
	poolID   uuid.UUID
}

func newFixture(t *testing.T, available int64) *fixture {
	t.Helper()
	ctx := context.Background()
	url := os.Getenv("FACETS_STORAGE_CAPACITY_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("FACETS_STORAGE_CAPACITY_TEST_DATABASE_URL is not set; requires disposable database")
	}
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal("connect disposable database")
	}
	var database string
	if admin.QueryRow(ctx, `SELECT current_database()`).Scan(&database) != nil || database != "facets_storage_capacity_tests" {
		admin.Close()
		t.Fatal("test database name must be facets_storage_capacity_tests")
	}
	schemaName := "storage_capacity_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schemaName}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		t.Fatal("create disposable schema")
	}
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schemaName
	config.MaxConns = 16
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE")
		admin.Close()
	})
	poolID := uuid.New()
	if err = Initialize(ctx, pool, poolID); err != nil {
		t.Fatal(err)
	}
	provider := &testCapacity{total: 100 << 30, available: available}
	ledger, err := Open(ctx, pool, poolID, provider)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{ledger: ledger, pool: pool, provider: provider, poolID: poolID}
}

func request(poolID uuid.UUID, ceiling, issuedAt, expiresAt int64) storagecapacity.ReservationRequest {
	return storagecapacity.ReservationRequest{
		ProtocolVersion:       storagecapacity.AuthorityProtocolVersion,
		PoolID:                poolID,
		ReservationID:         uuid.New(),
		OperationID:           uuid.New(),
		Service:               storagecapacity.ServiceBinding{Kind: storagecapacity.ServiceJobCustody, InstanceID: uuid.New()},
		ByteCeiling:           ceiling,
		IssuedAtMilliseconds:  issuedAt,
		ExpiresAtMilliseconds: expiresAt,
	}
}

func token(t *testing.T) string {
	t.Helper()
	value, err := storagecapacity.NewReservationToken()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestSchemaIsDedicatedAndContentBlind(t *testing.T) {
	lower := strings.ToLower(schema)
	for _, table := range []string{
		"storage_capacity_pool",
		"storage_capacity_reservations",
		"storage_capacity_operations",
		"storage_capacity_readiness",
		"storage_capacity_events",
	} {
		if strings.Count(lower, "create table "+table) != 1 {
			t.Fatalf("missing or duplicate table %s", table)
		}
	}
	if strings.Count(lower, "create table ") != ledgerTableCount {
		t.Fatalf("schema has %d tables, expected %d", strings.Count(lower, "create table "), ledgerTableCount)
	}
	for _, forbidden := range []string{
		"space_id", "object_id", "content_id", "account_id", "participant_id",
		"path text", "prompt text", "title text", "on delete cascade",
	} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("authority schema contains semantic/cascading field %q", forbidden)
		}
	}
}

func TestReadinessClassificationHysteresisAndTransitions(t *testing.T) {
	poolID := uuid.New()
	physical := storagecapacity.Snapshot{TotalBytes: 100 << 30, AvailableBytes: 10 << 30}
	pressure := buildReadiness(poolID, storagecapacity.ReadinessSnapshot{}, false, physical, nil, 0, 1_000)
	if pressure.State != storagecapacity.ReadinessStoragePressure || pressure.AdmissibleBytes != 0 {
		t.Fatalf("pressure=%+v", pressure)
	}
	pressure.Revision = 1
	event, ok := readinessTransition(storagecapacity.ReadinessSnapshot{}, false, pressure)
	event.Sequence = 1
	if !ok || event.Kind != storagecapacity.ReadinessEventPressure || event.Validate() != nil {
		t.Fatalf("pressure event=%+v ok=%v", event, ok)
	}

	physical.AvailableBytes = (10 << 30) + RecoveryHysteresisBytes - 1
	stillPressure := buildReadiness(poolID, pressure, true, physical, nil, 0, 1_100)
	if stillPressure.State != storagecapacity.ReadinessStoragePressure {
		t.Fatalf("pressure flapped early: %+v", stillPressure)
	}
	physical.AvailableBytes++
	recovered := buildReadiness(poolID, pressure, true, physical, nil, 0, 1_200)
	if recovered.State != storagecapacity.ReadinessReady || recovered.AdmissibleBytes != RecoveryHysteresisBytes {
		t.Fatalf("recovered=%+v", recovered)
	}
	recovered.Revision = 2
	event, ok = readinessTransition(pressure, true, recovered)
	event.Sequence = 2
	if !ok || event.Kind != storagecapacity.ReadinessEventRecovered || event.Validate() != nil {
		t.Fatalf("recovery event=%+v ok=%v", event, ok)
	}

	unavailable := buildReadiness(poolID, recovered, true, storagecapacity.Snapshot{}, storagecapacity.ErrUnavailable, 42, 1_300)
	if unavailable.State != storagecapacity.ReadinessCapacityUnavailable || unavailable.TotalBytes != 0 ||
		unavailable.AvailableBytes != 0 || unavailable.OperatingReserveBytes != 0 ||
		unavailable.AdmissibleBytes != 0 || unavailable.ReservedBytes != 42 {
		t.Fatalf("unavailable leaked stale capacity: %+v", unavailable)
	}
}

func TestDigestsBindEveryRequestAndDecisionFieldWithoutBearerDisclosure(t *testing.T) {
	base := request(uuid.New(), 4_096, 1_000, 2_000)
	baseDigest, err := digestRequest(base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*storagecapacity.ReservationRequest){
		func(value *storagecapacity.ReservationRequest) { value.ProtocolVersion++ },
		func(value *storagecapacity.ReservationRequest) { value.PoolID = uuid.New() },
		func(value *storagecapacity.ReservationRequest) { value.ReservationID = uuid.New() },
		func(value *storagecapacity.ReservationRequest) { value.OperationID = uuid.New() },
		func(value *storagecapacity.ReservationRequest) {
			value.Service.Kind = storagecapacity.ServiceBackupCustody
		},
		func(value *storagecapacity.ReservationRequest) { value.Service.InstanceID = uuid.New() },
		func(value *storagecapacity.ReservationRequest) { value.ByteCeiling++ },
		func(value *storagecapacity.ReservationRequest) { value.IssuedAtMilliseconds++ },
		func(value *storagecapacity.ReservationRequest) { value.ExpiresAtMilliseconds++ },
	}
	for index, mutate := range mutations {
		changed := base
		mutate(&changed)
		digest, err := digestRequest(changed)
		if err != nil || digest == baseDigest {
			t.Fatalf("request mutation %d was not bound: %q %v", index, digest, err)
		}
	}

	bearer := token(t)
	decision := storagecapacity.ReservationDecision{
		ProtocolVersion:        storagecapacity.AuthorityProtocolVersion,
		ReservationID:          base.ReservationID,
		OperationID:            uuid.New(),
		ExpectedRevision:       1,
		Kind:                   storagecapacity.DecisionCommit,
		ObservedAtMilliseconds: 1_500,
		BearerToken:            bearer,
	}
	digest, tokenDigest, err := digestDecision(decision)
	if err != nil || digest == "" || tokenDigest == bearer || strings.Contains(digest, bearer) {
		t.Fatalf("protected decision digest=%q tokenDigest=%q err=%v", digest, tokenDigest, err)
	}
	expected, err := storagecapacity.ReservationTokenDigest(bearer)
	if err != nil || tokenDigest != expected || !tokenMatches(expected, bearer) {
		t.Fatalf("token digest mismatch: %q %q %v", tokenDigest, expected, err)
	}
}

func TestDurableReservationRestartRetryAndTerminalFence(t *testing.T) {
	f := newFixture(t, 90<<30)
	ctx := context.Background()
	request := request(f.poolID, 1<<20, 1_000, 2_000)
	bearer := token(t)
	first, err := f.ledger.Reserve(ctx, request, bearer)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := f.ledger.Reserve(ctx, request, bearer)
	if err != nil || retry != first {
		t.Fatalf("exact retry=%+v err=%v", retry, err)
	}
	conflict := request
	conflict.ByteCeiling++
	if _, err = f.ledger.Reserve(ctx, conflict, bearer); !errors.Is(err, ErrConflict) {
		t.Fatalf("operation rewrite accepted: %v", err)
	}

	secondPool, err := pgxpool.NewWithConfig(ctx, f.pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer secondPool.Close()
	reopened, err := Open(ctx, secondPool, f.poolID, f.provider)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := reopened.Reservation(ctx, request.ReservationID)
	if err != nil || retained != first {
		t.Fatalf("restart record=%+v err=%v", retained, err)
	}
	if err = reopened.Recheck(ctx, request.ReservationID, first.Revision, bearer, 1_500); err != nil {
		t.Fatal(err)
	}
	if err = reopened.Recheck(ctx, request.ReservationID, first.Revision, token(t), 1_500); !errors.Is(err, ErrRejected) {
		t.Fatalf("wrong bearer accepted: %v", err)
	}

	decision := storagecapacity.ReservationDecision{
		ProtocolVersion:        storagecapacity.AuthorityProtocolVersion,
		ReservationID:          request.ReservationID,
		OperationID:            uuid.New(),
		ExpectedRevision:       first.Revision,
		Kind:                   storagecapacity.DecisionRelease,
		ObservedAtMilliseconds: 1_600,
		BearerToken:            bearer,
	}
	released, err := reopened.Decide(ctx, decision)
	if err != nil || released.State != storagecapacity.ReservationReleased || released.Revision != 2 {
		t.Fatalf("release=%+v err=%v", released, err)
	}
	retry, err = reopened.Decide(ctx, decision)
	if err != nil || retry != released {
		t.Fatalf("decision retry=%+v err=%v", retry, err)
	}
	decision.OperationID = uuid.New()
	decision.ExpectedRevision = released.Revision
	if _, err = reopened.Decide(ctx, decision); !errors.Is(err, ErrRejected) {
		t.Fatalf("terminal record changed: %v", err)
	}
}

func TestConcurrentReservationsSerializeAcrossAuthorityInstances(t *testing.T) {
	f := newFixture(t, (10<<30)+100)
	ctx := context.Background()
	secondPool, err := pgxpool.NewWithConfig(ctx, f.pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer secondPool.Close()
	second, err := Open(ctx, secondPool, f.poolID, f.provider)
	if err != nil {
		t.Fatal(err)
	}
	ledgers := []*Ledger{f.ledger, second}
	tokens := []string{token(t), token(t)}
	var accepted atomic.Int32
	failures := make(chan error, len(ledgers))
	var group sync.WaitGroup
	for index, ledger := range ledgers {
		bearer := tokens[index]
		group.Add(1)
		go func() {
			defer group.Done()
			_, reserveErr := ledger.Reserve(ctx, request(f.poolID, 80, int64(1_000+index), 2_000), bearer)
			if reserveErr == nil {
				accepted.Add(1)
			} else if !errors.Is(reserveErr, storagecapacity.ErrPressure) {
				failures <- reserveErr
			}
		}()
	}
	group.Wait()
	close(failures)
	for failure := range failures {
		t.Fatal(failure)
	}
	if accepted.Load() != 1 {
		t.Fatalf("physical pool over/under admitted %d reservations", accepted.Load())
	}
}

func TestCapacityFailureExpiryAndDedicatedSchemaFailClosed(t *testing.T) {
	f := newFixture(t, 90<<30)
	ctx := context.Background()
	firstRequest := request(f.poolID, 1<<20, 1_000, 1_100)
	firstToken := token(t)
	first, err := f.ledger.Reserve(ctx, firstRequest, firstToken)
	if err != nil {
		t.Fatal(err)
	}
	f.provider.set(0, storagecapacity.ErrUnavailable)
	if err = f.ledger.Recheck(ctx, first.ReservationID, first.Revision, firstToken, 1_050); !errors.Is(err, storagecapacity.ErrUnavailable) {
		t.Fatalf("unknown capacity admitted: %v", err)
	}
	f.provider.set(90<<30, nil)
	expired, err := f.ledger.ReconcileExpired(ctx, 1_100, 32)
	if err != nil || len(expired) != 1 || expired[0].State != storagecapacity.ReservationExpired {
		t.Fatalf("expired=%+v err=%v", expired, err)
	}
	again, err := f.ledger.ReconcileExpired(ctx, 1_100, 32)
	if err != nil || len(again) != 0 {
		t.Fatalf("duplicate expiry=%+v err=%v", again, err)
	}
	if _, err = f.ledger.Reservation(ctx, uuid.New()); !errors.Is(err, ErrRejected) {
		t.Fatalf("unknown reservation: %v", err)
	}
	if err = Initialize(ctx, f.pool, uuid.New()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong pool adopted: %v", err)
	}
	if _, err = f.pool.Exec(ctx, `CREATE TABLE unexpected(value integer)`); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(ctx, f.pool, f.poolID, f.provider); !errors.Is(err, ErrInvalid) {
		t.Fatalf("schema with unrelated table adopted: %v", err)
	}
}

func TestRevisionedReadinessAndDeduplicatedOwnerEvents(t *testing.T) {
	f := newFixture(t, 90<<30)
	ctx := context.Background()
	if _, err := f.ledger.Readiness(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unobserved readiness: %v", err)
	}
	ready, err := f.ledger.RefreshReadiness(ctx, 1_000)
	if err != nil || ready.State != storagecapacity.ReadinessReady || ready.Revision != 1 {
		t.Fatalf("ready=%+v err=%v", ready, err)
	}
	same, err := f.ledger.RefreshReadiness(ctx, 1_001)
	if err != nil || same.Revision != ready.Revision || same.ObservedAtMilliseconds != 1_001 {
		t.Fatalf("same=%+v err=%v", same, err)
	}
	coarse, err := f.ledger.CoarseReadiness(ctx)
	if err != nil || coarse.Revision != same.Revision || coarse.State != same.State {
		t.Fatalf("coarse=%+v err=%v", coarse, err)
	}

	reservationRequest := request(f.poolID, 1<<20, 1_010, 2_000)
	if _, err = f.ledger.Reserve(ctx, reservationRequest, token(t)); err != nil {
		t.Fatal(err)
	}
	f.provider.set(10<<30, nil)
	pressure, err := f.ledger.RefreshReadiness(ctx, 1_100)
	if err != nil || pressure.State != storagecapacity.ReadinessStoragePressure || pressure.Revision != 2 {
		t.Fatalf("pressure=%+v err=%v", pressure, err)
	}
	f.provider.set((10<<30)+RecoveryHysteresisBytes, nil)
	stillPressure, err := f.ledger.RefreshReadiness(ctx, 1_200)
	if err != nil || stillPressure.State != storagecapacity.ReadinessStoragePressure || stillPressure.Revision != 3 {
		t.Fatalf("hysteresis=%+v err=%v", stillPressure, err)
	}
	f.provider.set((10<<30)+RecoveryHysteresisBytes+(2<<20), nil)
	recovered, err := f.ledger.RefreshReadiness(ctx, 1_300)
	if err != nil || recovered.State != storagecapacity.ReadinessReady || recovered.Revision != 4 {
		t.Fatalf("recovered=%+v err=%v", recovered, err)
	}
	f.provider.set(0, storagecapacity.ErrUnavailable)
	unavailable, err := f.ledger.RefreshReadiness(ctx, 1_400)
	if err != nil || unavailable.State != storagecapacity.ReadinessCapacityUnavailable || unavailable.Revision != 5 ||
		unavailable.TotalBytes != 0 || unavailable.AvailableBytes != 0 || unavailable.AdmissibleBytes != 0 {
		t.Fatalf("unavailable=%+v err=%v", unavailable, err)
	}
	events, err := f.ledger.ReadinessEvents(ctx, 0, 32)
	if err != nil || len(events) != 3 ||
		events[0].Kind != storagecapacity.ReadinessEventPressure ||
		events[1].Kind != storagecapacity.ReadinessEventRecovered ||
		events[2].Kind != storagecapacity.ReadinessEventCapacityUnavailable {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	remaining, err := f.ledger.ReadinessEvents(ctx, events[1].Sequence, 32)
	if err != nil || len(remaining) != 1 || remaining[0] != events[2] {
		t.Fatalf("remaining=%+v err=%v", remaining, err)
	}
}

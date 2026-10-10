package jobcustody

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/robreuss/FacetsNode/internal/computequeue"
)

func TestCoordinatorStagesExactAdmissionThroughSharedCapacity(t *testing.T) {
	content, _ := temporaryContentStore(t)
	ledger := newMemoryLedger()
	capacity := &memoryCapacityAuthority{}
	fixture := newStagingFixture(t, []byte("opaque-protected-capsule-with-several-chunks"), 9)
	coordinator := &Coordinator{
		Ledger: ledger, Content: content, Capacity: capacity,
		Verifier: fixture.verifier, Clock: fixedJobCustodyClock{time.UnixMilli(1_800_000_000_010)},
	}

	handle, err := coordinator.Admit(
		context.Background(), fixture.envelopeBytes, fixture.header,
		fixture.signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := strings.ToLower(string(handle.Record().EnvelopeBytes))
	for _, field := range []string{
		"spaceid", "objectid", "prompt", "modelid", "credential", "result", "label", "path",
	} {
		if strings.Contains(forbidden, `"`+field+`"`) {
			t.Fatalf("Box-visible admission leaked %s", field)
		}
	}

	for index := int64(0); index < fixture.header.ProtectedObject.ChunkCount; index++ {
		offset := index * fixture.header.ProtectedObject.ChunkByteCount
		end := min(offset+fixture.header.ProtectedObject.ChunkByteCount, int64(len(fixture.protectedBytes)))
		chunk := fixture.protectedBytes[offset:end]
		next, err := coordinator.AppendChunk(
			context.Background(), handle, index, chunk, digestBytes(chunk),
		)
		if err != nil || next != end {
			t.Fatalf("chunk %d next=%d err=%v", index, next, err)
		}
	}
	reservations := capacity.snapshot()
	if len(reservations) != int(fixture.header.ProtectedObject.ChunkCount) {
		t.Fatalf("capacity reservations=%d", len(reservations))
	}
	for _, reservation := range reservations {
		if !reservation.rechecked || !reservation.committed || reservation.released {
			t.Fatalf("incomplete capacity lifecycle: %+v", reservation)
		}
	}

	firstChunk := fixture.protectedBytes[:fixture.header.ProtectedObject.ChunkByteCount]
	if next, err := coordinator.AppendChunk(
		context.Background(), handle, 0, firstChunk, digestBytes(firstChunk),
	); err != nil || next != fixture.header.ProtectedObject.ChunkByteCount {
		t.Fatalf("exact replay next=%d err=%v", next, err)
	}
	if len(capacity.snapshot()) != len(reservations) {
		t.Fatal("exact chunk replay reserved physical capacity twice")
	}

	retained, err := coordinator.Finalize(context.Background(), handle)
	if err != nil {
		t.Fatal(err)
	}
	if retained.State != AdmissionRetained || retained.CommittedBytes != int64(len(fixture.protectedBytes)) {
		t.Fatalf("retained record=%+v", retained)
	}
	if retry, err := coordinator.Finalize(context.Background(), handle); err != nil || retry.ObjectPath != retained.ObjectPath {
		t.Fatalf("finalization retry=%+v err=%v", retry, err)
	}

	coordinator.Clock = fixedJobCustodyClock{time.UnixMilli(1_800_000_300_000)}
	reopened, err := coordinator.Admit(
		context.Background(), fixture.envelopeBytes, fixture.header,
		fixture.signer,
	)
	if err != nil || reopened.Record().State != AdmissionRetained {
		t.Fatalf("historical exact admission retry=%+v err=%v", reopened.Record(), err)
	}
}

func TestCoordinatorReleasesCapacityBeforeLedgerCommitAndReconcilesRetry(t *testing.T) {
	content, _ := temporaryContentStore(t)
	ledger := newMemoryLedger()
	ledger.failAppendCommitOnce = true
	capacity := &memoryCapacityAuthority{}
	fixture := newStagingFixture(t, []byte("single-opaque-chunk"), 64)
	coordinator := &Coordinator{
		Ledger: ledger, Content: content, Capacity: capacity,
		Verifier: fixture.verifier, Clock: fixedJobCustodyClock{time.UnixMilli(1_800_000_000_010)},
	}
	handle, err := coordinator.Admit(
		context.Background(), fixture.envelopeBytes, fixture.header,
		fixture.signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	digest := digestBytes(fixture.protectedBytes)
	if _, err := coordinator.AppendChunk(context.Background(), handle, 0, fixture.protectedBytes, digest); err == nil {
		t.Fatal("injected ledger commit failure did not surface")
	}
	first := capacity.snapshot()
	if len(first) != 1 || !first[0].rechecked || first[0].committed || !first[0].released {
		t.Fatalf("failed append capacity lifecycle=%+v", first)
	}
	if next, err := coordinator.AppendChunk(context.Background(), handle, 0, fixture.protectedBytes, digest); err != nil || next != int64(len(fixture.protectedBytes)) {
		t.Fatalf("retry next=%d err=%v", next, err)
	}
	all := capacity.snapshot()
	if len(all) != 2 || !all[1].committed || all[1].released {
		t.Fatalf("retry capacity lifecycle=%+v", all)
	}
	if _, err := coordinator.Finalize(context.Background(), handle); err != nil {
		t.Fatal(err)
	}
}

func TestCoordinatorRejectsConflictingAdmissionAndChunkGeometry(t *testing.T) {
	content, _ := temporaryContentStore(t)
	ledger := newMemoryLedger()
	capacity := &memoryCapacityAuthority{}
	fixture := newStagingFixture(t, []byte("opaque-protected-capsule"), 8)
	coordinator := &Coordinator{
		Ledger: ledger, Content: content, Capacity: capacity,
		Verifier: fixture.verifier, Clock: fixedJobCustodyClock{time.UnixMilli(1_800_000_000_010)},
	}
	handle, err := coordinator.Admit(
		context.Background(), fixture.envelopeBytes, fixture.header,
		fixture.signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.AppendChunk(
		context.Background(), handle, 0, fixture.protectedBytes[:7],
		digestBytes(fixture.protectedBytes[:7]),
	); err == nil {
		t.Fatal("accepted a short non-final chunk")
	}
	if len(capacity.snapshot()) != 0 {
		t.Fatal("invalid chunk geometry reached capacity authority")
	}

	changedHeader, err := computequeue.NewJobCustodyAdmissionHeader(
		fixture.header.CapsuleID,
		fixture.header.AssignmentID,
		fixture.header.RouteRecipientWorkerID,
		fixture.header.RouteRecipientKeyFingerprint,
		fixture.header.ProtectedObject,
		fixture.header.NotBeforeAt,
		fixture.header.ExpiresAt,
		fixture.header.RetentionUntil+1,
	)
	if err != nil {
		t.Fatal(err)
	}
	changedBytes := signAdmission(t, fixture.privateKey, fixture.signer, changedHeader)
	if _, err := coordinator.Admit(
		context.Background(), changedBytes, changedHeader,
		fixture.signer,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting capsule admission error=%v", err)
	}
}

type fixedJobCustodyClock struct{ value time.Time }

func (clock fixedJobCustodyClock) Now() time.Time { return clock.value }

type stagingFixture struct {
	privateKey     *ecdsa.PrivateKey
	signer         computequeue.ReceiptSignerBinding
	verifier       *computequeue.JobCustodyP256AdmissionVerifier
	header         computequeue.JobCustodyAdmissionHeader
	envelopeBytes  []byte
	protectedBytes []byte
}

func newStagingFixture(t *testing.T, protectedBytes []byte, chunkBytes int64) stagingFixture {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := computequeue.ReceiptSignerBinding{
		SignerID: "source.device.fixture", SigningKeyID: "source.key.fixture",
		SigningKeyRevision: 7,
		SignatureProfileID: computequeue.JobCustodyP256AdmissionSignatureProfile,
	}
	public := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)
	key, err := computequeue.NewJobCustodyP256AdmissionVerificationKey(signer, public)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := computequeue.NewJobCustodyP256AdmissionVerifier(
		[]computequeue.JobCustodyP256AdmissionVerificationKey{key},
	)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := protectedDescriptor(t, protectedBytes, chunkBytes)
	header, err := computequeue.NewJobCustodyAdmissionHeader(
		"11111111-1111-4111-8111-111111111111",
		"22222222-2222-4222-8222-222222222222",
		"33333333-3333-4333-8333-333333333333",
		computequeue.SHA256Digest("fixture-worker-key", "key"),
		descriptor,
		1_800_000_000_000,
		1_800_000_100_000,
		1_800_000_200_000,
	)
	if err != nil {
		t.Fatal(err)
	}
	return stagingFixture{
		privateKey: privateKey, signer: signer, verifier: verifier,
		header: header, envelopeBytes: signAdmission(t, privateKey, signer, header),
		protectedBytes: bytes.Clone(protectedBytes),
	}
}

func signAdmission(
	t *testing.T,
	privateKey *ecdsa.PrivateKey,
	signer computequeue.ReceiptSignerBinding,
	header computequeue.JobCustodyAdmissionHeader,
) []byte {
	t.Helper()
	payload, err := computequeue.JobCustodyAdmissionSigningPayloadDigest(header, signer)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(payload))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	fillScalar(raw[:32], r)
	fillScalar(raw[32:], s)
	envelope, err := computequeue.NewJobCustodySignedAdmissionEnvelope(
		header,
		signer.SignatureProfileID,
		computequeue.SignatureValue(base64.RawURLEncoding.EncodeToString(raw)),
	)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := computequeue.EncodeJobCustodyAdmissionCanonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func fillScalar(destination []byte, value *big.Int) { value.FillBytes(destination) }

func digestBytes(value []byte) computequeue.Digest {
	digest := sha256.Sum256(value)
	return computequeue.Digest(fmt.Sprintf("%x", digest[:]))
}

type memoryCapacityAuthority struct {
	mu     sync.Mutex
	leases []*memoryCapacityLease
}

func (authority *memoryCapacityAuthority) Reserve(
	_ context.Context,
	byteCeiling int64,
) (CapacityReservation, error) {
	if byteCeiling <= 0 {
		return nil, ErrInvalid
	}
	lease := &memoryCapacityLease{byteCeiling: byteCeiling}
	authority.mu.Lock()
	authority.leases = append(authority.leases, lease)
	authority.mu.Unlock()
	return lease, nil
}

type memoryCapacitySnapshot struct {
	byteCeiling int64
	rechecked   bool
	committed   bool
	released    bool
}

func (authority *memoryCapacityAuthority) snapshot() []memoryCapacitySnapshot {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	result := make([]memoryCapacitySnapshot, len(authority.leases))
	for index, lease := range authority.leases {
		lease.mu.Lock()
		result[index] = memoryCapacitySnapshot{
			byteCeiling: lease.byteCeiling,
			rechecked:   lease.rechecked,
			committed:   lease.committed,
			released:    lease.released,
		}
		lease.mu.Unlock()
	}
	return result
}

type memoryCapacityLease struct {
	mu          sync.Mutex
	byteCeiling int64
	rechecked   bool
	committed   bool
	released    bool
}

func (lease *memoryCapacityLease) Recheck(context.Context) error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.committed || lease.released {
		return ErrConflict
	}
	lease.rechecked = true
	return nil
}

func (lease *memoryCapacityLease) Commit(context.Context) error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if !lease.rechecked || lease.committed || lease.released {
		return ErrConflict
	}
	lease.committed = true
	return nil
}

func (lease *memoryCapacityLease) Release(context.Context) error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.committed {
		return ErrConflict
	}
	lease.released = true
	return nil
}

type memoryLedger struct {
	mu                   sync.Mutex
	records              map[computequeue.JobCapsuleID]AdmissionRecord
	idempotency          map[computequeue.Digest]computequeue.JobCapsuleID
	chunks               map[computequeue.JobCapsuleID]map[int64]AppendRequest
	failAppendCommitOnce bool
}

func newMemoryLedger() *memoryLedger {
	return &memoryLedger{
		records:     make(map[computequeue.JobCapsuleID]AdmissionRecord),
		idempotency: make(map[computequeue.Digest]computequeue.JobCapsuleID),
		chunks:      make(map[computequeue.JobCapsuleID]map[int64]AppendRequest),
	}
}

func (ledger *memoryLedger) ReserveAdmission(
	_ context.Context,
	candidate AdmissionRecord,
) (AdmissionRecord, bool, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if current, exists := ledger.records[candidate.Header.CapsuleID]; exists {
		if !sameAdmissionIdentity(current, candidate) {
			return AdmissionRecord{}, false, ErrConflict
		}
		return cloneAdmission(current), false, nil
	}
	if owner, exists := ledger.idempotency[candidate.Header.IdempotencyKey]; exists && owner != candidate.Header.CapsuleID {
		return AdmissionRecord{}, false, ErrConflict
	}
	ledger.records[candidate.Header.CapsuleID] = cloneAdmission(candidate)
	ledger.idempotency[candidate.Header.IdempotencyKey] = candidate.Header.CapsuleID
	ledger.chunks[candidate.Header.CapsuleID] = make(map[int64]AppendRequest)
	return cloneAdmission(candidate), true, nil
}

func (ledger *memoryLedger) LoadAdmission(
	_ context.Context,
	capsuleID computequeue.JobCapsuleID,
) (AdmissionRecord, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	record, exists := ledger.records[capsuleID]
	if !exists {
		return AdmissionRecord{}, ErrMissing
	}
	return cloneAdmission(record), nil
}

func (ledger *memoryLedger) BeginAppend(
	_ context.Context,
	request AppendRequest,
) (AppendLease, error) {
	ledger.mu.Lock()
	record, exists := ledger.records[request.CapsuleID]
	if !exists || record.State != AdmissionStaging {
		ledger.mu.Unlock()
		return nil, ErrMissing
	}
	if existing, exists := ledger.chunks[request.CapsuleID][request.ChunkIndex]; exists {
		if existing != request {
			ledger.mu.Unlock()
			return nil, ErrConflict
		}
		next := existing.Offset + existing.ByteCount
		return &memoryAppendLease{ledger: ledger, request: request, record: cloneAdmission(record), existing: &next}, nil
	}
	if record.CommittedBytes != request.Offset {
		ledger.mu.Unlock()
		return nil, ErrConflict
	}
	return &memoryAppendLease{ledger: ledger, request: request, record: cloneAdmission(record)}, nil
}

func (ledger *memoryLedger) BeginFinalization(
	_ context.Context,
	capsuleID computequeue.JobCapsuleID,
) (FinalizationLease, error) {
	ledger.mu.Lock()
	record, exists := ledger.records[capsuleID]
	if !exists {
		ledger.mu.Unlock()
		return nil, ErrMissing
	}
	return &memoryFinalizationLease{ledger: ledger, record: cloneAdmission(record)}, nil
}

type memoryAppendLease struct {
	ledger   *memoryLedger
	request  AppendRequest
	record   AdmissionRecord
	existing *int64
	closed   bool
}

func (lease *memoryAppendLease) Admission() AdmissionRecord { return cloneAdmission(lease.record) }
func (lease *memoryAppendLease) ExistingNextOffset() *int64 {
	if lease.existing == nil {
		return nil
	}
	value := *lease.existing
	return &value
}
func (lease *memoryAppendLease) Commit(_ context.Context, next int64) error {
	if lease.closed || lease.existing != nil || next != lease.request.Offset+lease.request.ByteCount {
		return ErrConflict
	}
	lease.closed = true
	defer lease.ledger.mu.Unlock()
	if lease.ledger.failAppendCommitOnce {
		lease.ledger.failAppendCommitOnce = false
		return ErrUnavailable
	}
	record := lease.ledger.records[lease.request.CapsuleID]
	record.CommittedBytes = next
	record.UpdatedAtMillis++
	lease.ledger.records[lease.request.CapsuleID] = record
	lease.ledger.chunks[lease.request.CapsuleID][lease.request.ChunkIndex] = lease.request
	return nil
}
func (lease *memoryAppendLease) Abort(context.Context) error {
	if lease.closed {
		return nil
	}
	lease.closed = true
	lease.ledger.mu.Unlock()
	return nil
}

type memoryFinalizationLease struct {
	ledger *memoryLedger
	record AdmissionRecord
	closed bool
}

func (lease *memoryFinalizationLease) Admission() AdmissionRecord {
	return cloneAdmission(lease.record)
}
func (lease *memoryFinalizationLease) Commit(
	_ context.Context,
	objectPath string,
) (AdmissionRecord, error) {
	if lease.closed {
		return AdmissionRecord{}, ErrConflict
	}
	lease.closed = true
	defer lease.ledger.mu.Unlock()
	record := lease.ledger.records[lease.record.Header.CapsuleID]
	record.State = AdmissionRetained
	record.ObjectPath = objectPath
	record.UpdatedAtMillis++
	lease.ledger.records[lease.record.Header.CapsuleID] = record
	return cloneAdmission(record), nil
}
func (lease *memoryFinalizationLease) Abort(context.Context) error {
	if lease.closed {
		return nil
	}
	lease.closed = true
	lease.ledger.mu.Unlock()
	return nil
}

func cloneAdmission(record AdmissionRecord) AdmissionRecord {
	record.EnvelopeBytes = bytes.Clone(record.EnvelopeBytes)
	return record
}

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

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestCoordinatorStagesExactAdmissionThroughSharedCapacity(t *testing.T) {
	content, _ := temporaryContentStore(t)
	ledger := newMemoryLedger()
	capacity := &memoryCapacityAuthority{}
	fixture := newStagingFixture(t, []byte("opaque-protected-capsule-with-several-chunks"), 9)
	coordinator := &Coordinator{
		Ledger: ledger, Content: content, Capacity: capacity,
		Verifier: fixture.verifier, ReceiptSigner: testJobCustodyReceiptSigner(t),
		Clock: fixedJobCustodyClock{time.UnixMilli(1_800_000_000_010)},
	}

	handle, err := coordinator.AdmitAuthorized(
		context.Background(), fixture.envelopeBytes,
		fixture.authorization(),
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
	receipt, err := serviceauthority.DecodeJobCustodyReceipt(retained.CustodyReceiptBytes)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := receipt.VerifiedPayload()
	if err != nil || payload.CapsuleID.String() != string(fixture.header.CapsuleID) ||
		payload.AssignmentID.String() != string(fixture.header.AssignmentID) ||
		payload.ProtectedObjectSHA256 != string(fixture.header.ProtectedObject.SHA256) ||
		payload.AdmissionPermitDigest != string(handle.Record().AdmissionPermitDigest) {
		t.Fatalf("custody receipt payload=%+v err=%v", payload, err)
	}
	if retry, err := coordinator.Finalize(context.Background(), handle); err != nil || retry.ObjectPath != retained.ObjectPath {
		t.Fatalf("finalization retry=%+v err=%v", retry, err)
	} else if !bytes.Equal(retry.CustodyReceiptBytes, retained.CustodyReceiptBytes) {
		t.Fatal("exact finalization replay returned different signed receipt bytes")
	}

	coordinator.Clock = fixedJobCustodyClock{time.UnixMilli(1_800_000_300_000)}
	reopened, err := coordinator.AdmitAuthorized(
		context.Background(), fixture.envelopeBytes,
		fixture.authorization(),
	)
	if err != nil || reopened.Record().State != AdmissionRetained {
		t.Fatalf("historical exact admission retry=%+v err=%v", reopened.Record(), err)
	}
}

func TestAdmissionExpiryCoordinatorExpiresRetainedInputAndEndedClaimAfterUnlink(t *testing.T) {
	content, _ := temporaryContentStore(t)
	ledger := newMemoryLedger()
	fixture := newStagingFixture(t, []byte("opaque-retained-input-for-expiry"), 64)
	clock := fixedJobCustodyClock{time.UnixMilli(1_800_000_000_010)}
	signer := testJobCustodyReceiptSigner(t)
	coordinator := &Coordinator{
		Ledger: ledger, Content: content, Capacity: &memoryCapacityAuthority{},
		Verifier: fixture.verifier, ReceiptSigner: signer, Clock: clock,
	}
	handle, err := coordinator.AdmitAuthorized(
		t.Context(), fixture.envelopeBytes, fixture.authorization(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.AppendChunk(
		t.Context(), handle, 0, fixture.protectedBytes, digestBytes(fixture.protectedBytes),
	); err != nil {
		t.Fatal(err)
	}
	retained, err := coordinator.Finalize(t.Context(), handle)
	if err != nil {
		t.Fatal(err)
	}
	claimCoordinator := &WorkerClaimCoordinator{Ledger: ledger, Content: content, Clock: clock}
	claim, err := claimCoordinator.Claim(
		t.Context(), verifiedWorkerClaimAuthorization(t, fixture, retained.Header.RetentionUntil),
	)
	if err != nil {
		t.Fatal(err)
	}
	claimCoordinator.Clock = fixedJobCustodyClock{
		time.UnixMilli(int64(retained.Header.RetentionUntil)),
	}
	if _, err := claimCoordinator.ReadChunk(claim, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expired in-memory claim handle remained readable: %v", err)
	}
	expiry := &AdmissionExpiryCoordinator{
		Ledger: ledger, Content: content, ReceiptSigner: signer,
		Clock: fixedJobCustodyClock{time.UnixMilli(int64(retained.Header.RetentionUntil))},
	}
	ledger.mu.Lock()
	ledger.failAdmissionExpiryFinalizeOnce = true
	ledger.mu.Unlock()
	if completed, err := expiry.ReconcileExpiredAdmissions(t.Context(), 16); !errors.Is(err, ErrUnavailable) || completed != 0 {
		t.Fatalf("injected input expiry completed=%d err=%v", completed, err)
	}
	pending, err := ledger.LoadAdmission(t.Context(), retained.Header.CapsuleID)
	if err != nil || pending.State != AdmissionExpiryPending ||
		pending.ExpiryStartedAt != retained.Header.RetentionUntil {
		t.Fatalf("pending input expiry=%+v err=%v", pending, err)
	}
	endedClaim, _, err := ledger.LoadWorkerClaim(t.Context(), claim.Record().ClaimID)
	if err != nil || endedClaim.State != WorkerClaimExpired {
		t.Fatalf("ended claim=%+v err=%v", endedClaim, err)
	}
	if _, err := content.OpenObject(retained.Header.CapsuleID, retained.Header.ProtectedObject); !errors.Is(err, ErrMissing) {
		t.Fatalf("input expiry intent did not unlink retained input: %v", err)
	}
	if completed, err := expiry.ReconcileExpiredAdmissions(t.Context(), 16); err != nil || completed != 1 {
		t.Fatalf("input expiry resume completed=%d err=%v", completed, err)
	}
	expired, err := ledger.LoadAdmission(t.Context(), retained.Header.CapsuleID)
	if err != nil || expired.State != AdmissionExpired || expired.ObjectPath != "" ||
		len(expired.CustodyReceiptBytes) == 0 || len(expired.ExpiryReceiptBytes) == 0 {
		t.Fatalf("expired input=%+v err=%v", expired, err)
	}
	receipt, err := serviceauthority.DecodeJobCustodyExpiryReceipt(expired.ExpiryReceiptBytes)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := receipt.VerifiedPayload()
	if err != nil || payload.CapsuleID.String() != string(retained.Header.CapsuleID) ||
		payload.RetentionUntilMilliseconds != int64(retained.Header.RetentionUntil) {
		t.Fatalf("input expiry receipt=%+v err=%v", payload, err)
	}
}

func TestAdmissionExpiryCoordinatorExpiresPartialStagingAndResumesAfterUnlink(t *testing.T) {
	content, _ := temporaryContentStore(t)
	ledger := newMemoryLedger()
	fixture := newStagingFixture(t, []byte("opaque-partial-input-that-never-finishes"), 8)
	clock := fixedJobCustodyClock{time.UnixMilli(1_800_000_000_010)}
	signer := testJobCustodyReceiptSigner(t)
	coordinator := &Coordinator{
		Ledger: ledger, Content: content, Capacity: &memoryCapacityAuthority{},
		Verifier: fixture.verifier, ReceiptSigner: signer, Clock: clock,
	}
	handle, err := coordinator.AdmitAuthorized(
		t.Context(), fixture.envelopeBytes, fixture.authorization(),
	)
	if err != nil {
		t.Fatal(err)
	}
	firstChunk := fixture.protectedBytes[:8]
	if _, err := coordinator.AppendChunk(
		t.Context(), handle, 0, firstChunk, digestBytes(firstChunk),
	); err != nil {
		t.Fatal(err)
	}
	staged, err := ledger.LoadAdmission(t.Context(), fixture.header.CapsuleID)
	if err != nil || staged.CommittedBytes != int64(len(firstChunk)) {
		t.Fatalf("partial input=%+v err=%v", staged, err)
	}
	expiry := &AdmissionExpiryCoordinator{
		Ledger: ledger, Content: content, ReceiptSigner: signer,
		Clock: fixedJobCustodyClock{time.UnixMilli(int64(staged.Header.RetentionUntil))},
	}
	ledger.mu.Lock()
	ledger.failAdmissionExpiryFinalizeOnce = true
	ledger.mu.Unlock()
	if completed, err := expiry.ReconcileExpiredAdmissions(t.Context(), 16); !errors.Is(err, ErrUnavailable) || completed != 0 {
		t.Fatalf("injected staging expiry completed=%d err=%v", completed, err)
	}
	pending, err := ledger.LoadAdmission(t.Context(), staged.Header.CapsuleID)
	if err != nil || pending.State != AdmissionStagingExpiryPending ||
		pending.CommittedBytes != int64(len(firstChunk)) {
		t.Fatalf("pending staging expiry=%+v err=%v", pending, err)
	}
	name, err := capsuleName(staged.Header.CapsuleID)
	if err != nil {
		t.Fatal(err)
	}
	partial, err := openRegular(content.staging, name, 1, 0o600, 0o400)
	if partial != nil {
		_ = partial.Close()
	}
	if !errors.Is(err, ErrMissing) {
		t.Fatalf("input staging expiry did not unlink partial bytes: %v", err)
	}
	if completed, err := expiry.ReconcileExpiredAdmissions(t.Context(), 16); err != nil || completed != 1 {
		t.Fatalf("input staging expiry resume completed=%d err=%v", completed, err)
	}
	expired, err := ledger.LoadAdmission(t.Context(), staged.Header.CapsuleID)
	if err != nil || expired.State != AdmissionExpired || len(expired.CustodyReceiptBytes) != 0 ||
		len(expired.ExpiryReceiptBytes) == 0 {
		t.Fatalf("expired staging input=%+v err=%v", expired, err)
	}
	receipt, err := serviceauthority.DecodeJobCustodyStagingExpiryReceipt(
		expired.ExpiryReceiptBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := receipt.VerifiedPayload()
	if err != nil || payload.CommittedBytes != int64(len(firstChunk)) ||
		payload.ProtectedObjectByteCount != int64(len(fixture.protectedBytes)) {
		t.Fatalf("input staging expiry receipt=%+v err=%v", payload, err)
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
		Verifier: fixture.verifier, ReceiptSigner: testJobCustodyReceiptSigner(t),
		Clock: fixedJobCustodyClock{time.UnixMilli(1_800_000_000_010)},
	}
	handle, err := coordinator.AdmitAuthorized(
		context.Background(), fixture.envelopeBytes,
		fixture.authorization(),
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
		Verifier: fixture.verifier, ReceiptSigner: testJobCustodyReceiptSigner(t),
		Clock: fixedJobCustodyClock{time.UnixMilli(1_800_000_000_010)},
	}
	handle, err := coordinator.AdmitAuthorized(
		context.Background(), fixture.envelopeBytes,
		fixture.authorization(),
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
	if _, err := coordinator.AdmitAuthorized(
		context.Background(), changedBytes,
		testAdmissionAuthorization(changedHeader, fixture.signer),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting capsule admission error=%v", err)
	}
}

func TestCoordinatorRejectsSelfConsistentReceiptFromSubstitutedDeploymentKey(t *testing.T) {
	content, _ := temporaryContentStore(t)
	ledger := newMemoryLedger()
	fixture := newStagingFixture(t, []byte("opaque-protected-capsule"), 64)
	coordinator := &Coordinator{
		Ledger: ledger, Content: content, Capacity: &memoryCapacityAuthority{},
		Verifier: fixture.verifier, ReceiptSigner: testJobCustodyReceiptSigner(t),
		Clock: fixedJobCustodyClock{time.UnixMilli(1_800_000_000_010)},
	}
	handle, err := coordinator.AdmitAuthorized(
		context.Background(), fixture.envelopeBytes, fixture.authorization(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.AppendChunk(
		context.Background(), handle, 0, fixture.protectedBytes,
		digestBytes(fixture.protectedBytes),
	); err != nil {
		t.Fatal(err)
	}
	retained, err := coordinator.Finalize(context.Background(), handle)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := serviceauthority.DecodeJobCustodyReceipt(retained.CustodyReceiptBytes)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := receipt.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	attackerSeed := bytes.Repeat([]byte{0}, 32)
	attackerSeed[31] = 9
	attacker, err := serviceauthority.NewDeploymentSigner(payload.DeploymentID, attackerSeed)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := attacker.SignJobCustodyReceipt(payload)
	if err != nil {
		t.Fatal(err)
	}
	forgedBytes, err := forged.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	ledger.mu.Lock()
	forgedRecord := ledger.records[fixture.header.CapsuleID]
	forgedRecord.CustodyReceiptBytes = forgedBytes
	ledger.records[fixture.header.CapsuleID] = forgedRecord
	ledger.mu.Unlock()
	if _, err := coordinator.AdmitAuthorized(
		context.Background(), fixture.envelopeBytes, fixture.authorization(),
	); err == nil {
		t.Fatal("receipt signed by substituted deployment key reopened custody")
	}
}

type fixedJobCustodyClock struct{ value time.Time }

func (clock fixedJobCustodyClock) Now() time.Time { return clock.value }

func testJobCustodyReceiptSigner(t *testing.T) *serviceauthority.DeploymentSigner {
	t.Helper()
	seed := bytes.Repeat([]byte{0}, 32)
	seed[31] = 7
	signer, err := serviceauthority.NewDeploymentSigner(
		uuid.MustParse("8b000000-0000-0000-0000-000000000001"), seed,
	)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

type stagingFixture struct {
	privateKey     *ecdsa.PrivateKey
	signer         computequeue.ReceiptSignerBinding
	verifier       *computequeue.JobCustodyP256AdmissionVerifier
	header         computequeue.JobCustodyAdmissionHeader
	envelopeBytes  []byte
	protectedBytes []byte
}

func (fixture stagingFixture) authorization() AdmissionAuthorization {
	return testAdmissionAuthorization(fixture.header, fixture.signer)
}

func testAdmissionAuthorization(
	header computequeue.JobCustodyAdmissionHeader,
	signer computequeue.ReceiptSignerBinding,
) AdmissionAuthorization {
	return AdmissionAuthorization{
		header: header, expectedSigner: signer,
		permitDigest: computequeue.SHA256Digest(
			"job-custody-staging-tests",
			string(header.CapsuleID),
			string(header.IdempotencyKey),
		),
		authorityID: uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
		requesterAuthorityDigest: computequeue.SHA256Digest(
			"job-custody-staging-tests", "requester-authority",
		),
		workerCapabilitiesDigest: computequeue.SHA256Digest(
			"job-custody-staging-tests", "worker-capabilities",
		),
	}
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
	mu                              sync.Mutex
	records                         map[computequeue.JobCapsuleID]AdmissionRecord
	idempotency                     map[computequeue.Digest]computequeue.JobCapsuleID
	chunks                          map[computequeue.JobCapsuleID]map[int64]AppendRequest
	claims                          map[uuid.UUID]WorkerClaimRecord
	results                         map[computequeue.JobCapsuleID]ResultRecord
	resultIdempotency               map[computequeue.Digest]computequeue.JobCapsuleID
	resultChunks                    map[computequeue.JobCapsuleID]map[int64]AppendRequest
	failAppendCommitOnce            bool
	failAdmissionExpiryFinalizeOnce bool
	failResultReleaseFinalizeOnce   bool
	failResultExpiryFinalizeOnce    bool
}

func newMemoryLedger() *memoryLedger {
	return &memoryLedger{
		records:           make(map[computequeue.JobCapsuleID]AdmissionRecord),
		idempotency:       make(map[computequeue.Digest]computequeue.JobCapsuleID),
		chunks:            make(map[computequeue.JobCapsuleID]map[int64]AppendRequest),
		claims:            make(map[uuid.UUID]WorkerClaimRecord),
		results:           make(map[computequeue.JobCapsuleID]ResultRecord),
		resultIdempotency: make(map[computequeue.Digest]computequeue.JobCapsuleID),
		resultChunks:      make(map[computequeue.JobCapsuleID]map[int64]AppendRequest),
	}
}

func (ledger *memoryLedger) ClaimNext(
	_ context.Context,
	authorization WorkerClaimAuthorization,
) (WorkerClaimRecord, AdmissionRecord, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	payload := authorization.Payload()
	if existing, present := ledger.claims[payload.ClaimID]; present {
		admission := ledger.records[existing.CapsuleID]
		if !sameMemoryWorkerClaimAuthorization(existing, admission, authorization) {
			return WorkerClaimRecord{}, AdmissionRecord{}, ErrConflict
		}
		return existing, cloneAdmission(admission), nil
	}
	for capsuleID, admission := range ledger.records {
		if admission.State != AdmissionRetained || admission.RouteAuthorityID != payload.AuthorityID ||
			admission.Header.RouteRecipientWorkerID != payload.RouteRecipientWorkerID ||
			admission.Header.RouteRecipientKeyFingerprint != payload.RouteRecipientKeyFingerprint ||
			admission.WorkerCapabilitiesDigest != payload.WorkerCapabilitiesDigest ||
			payload.ExpiresAt > admission.Header.RetentionUntil {
			continue
		}
		active := false
		for _, claim := range ledger.claims {
			if claim.CapsuleID == capsuleID && claim.State == WorkerClaimClaimed {
				active = true
				break
			}
		}
		if active {
			continue
		}
		record := WorkerClaimRecord{
			ClaimID: payload.ClaimID, CapsuleID: capsuleID,
			RouteAuthorityID:             payload.AuthorityID,
			RouteRecipientWorkerID:       payload.RouteRecipientWorkerID,
			RouteRecipientKeyFingerprint: payload.RouteRecipientKeyFingerprint,
			WorkerCapabilitiesDigest:     payload.WorkerCapabilitiesDigest,
			WorkerOwnerAuthorityDigest:   payload.WorkerOwnerAuthorityDigest,
			ClaimPermitDigest:            authorization.PermitDigest(),
			ClaimedAt:                    payload.IssuedAt, LeaseExpiresAt: payload.ExpiresAt,
			State: WorkerClaimClaimed, UpdatedAtMillis: int64(payload.IssuedAt),
		}
		ledger.claims[payload.ClaimID] = record
		return record, cloneAdmission(admission), nil
	}
	return WorkerClaimRecord{}, AdmissionRecord{}, ErrNoWork
}

func (ledger *memoryLedger) RenewClaim(
	_ context.Context,
	authorization WorkerClaimAuthorization,
) (WorkerClaimRecord, AdmissionRecord, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	payload := authorization.Payload()
	record, present := ledger.claims[payload.ClaimID]
	if !present {
		return WorkerClaimRecord{}, AdmissionRecord{}, ErrMissing
	}
	admission := ledger.records[record.CapsuleID]
	if sameMemoryWorkerClaimAuthorization(record, admission, authorization) {
		return record, cloneAdmission(admission), nil
	}
	if record.State != WorkerClaimClaimed || record.RouteAuthorityID != payload.AuthorityID ||
		record.RouteRecipientWorkerID != payload.RouteRecipientWorkerID ||
		record.RouteRecipientKeyFingerprint != payload.RouteRecipientKeyFingerprint ||
		record.WorkerCapabilitiesDigest != payload.WorkerCapabilitiesDigest ||
		record.WorkerOwnerAuthorityDigest != payload.WorkerOwnerAuthorityDigest ||
		payload.ExpiresAt <= record.LeaseExpiresAt || payload.ExpiresAt > admission.Header.RetentionUntil {
		return WorkerClaimRecord{}, AdmissionRecord{}, ErrConflict
	}
	record.ClaimPermitDigest = authorization.PermitDigest()
	record.LeaseExpiresAt = payload.ExpiresAt
	record.UpdatedAtMillis++
	ledger.claims[payload.ClaimID] = record
	return record, cloneAdmission(admission), nil
}

func (ledger *memoryLedger) LoadWorkerClaim(
	_ context.Context,
	claimID uuid.UUID,
) (WorkerClaimRecord, AdmissionRecord, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	record, present := ledger.claims[claimID]
	if !present {
		return WorkerClaimRecord{}, AdmissionRecord{}, ErrMissing
	}
	admission, present := ledger.records[record.CapsuleID]
	if !present {
		return WorkerClaimRecord{}, AdmissionRecord{}, ErrMissing
	}
	return record, cloneAdmission(admission), nil
}

func sameMemoryWorkerClaimAuthorization(
	record WorkerClaimRecord,
	admission AdmissionRecord,
	authorization WorkerClaimAuthorization,
) bool {
	payload := authorization.Payload()
	return record.CapsuleID == admission.Header.CapsuleID &&
		record.RouteAuthorityID == admission.RouteAuthorityID &&
		record.WorkerCapabilitiesDigest == admission.WorkerCapabilitiesDigest &&
		record.ClaimID == payload.ClaimID && record.RouteAuthorityID == payload.AuthorityID &&
		record.RouteRecipientWorkerID == payload.RouteRecipientWorkerID &&
		record.RouteRecipientKeyFingerprint == payload.RouteRecipientKeyFingerprint &&
		record.WorkerCapabilitiesDigest == payload.WorkerCapabilitiesDigest &&
		record.WorkerOwnerAuthorityDigest == payload.WorkerOwnerAuthorityDigest &&
		record.ClaimPermitDigest == authorization.PermitDigest() &&
		record.LeaseExpiresAt == payload.ExpiresAt
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

func (ledger *memoryLedger) ListAdmissionExpiryCandidates(
	_ context.Context,
	now computequeue.Timestamp,
	limit int,
) ([]AdmissionRecord, error) {
	if limit <= 0 || limit > MaximumAdmissionExpiryBatchSize {
		return nil, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	records := make([]AdmissionRecord, 0, limit)
	for _, record := range ledger.records {
		if record.State == AdmissionStagingExpiryPending || record.State == AdmissionExpiryPending ||
			((record.State == AdmissionStaging || record.State == AdmissionRetained) &&
				record.Header.RetentionUntil <= now) {
			records = append(records, cloneAdmission(record))
			if len(records) == limit {
				break
			}
		}
	}
	return records, nil
}

func (ledger *memoryLedger) RequestAdmissionExpiry(
	_ context.Context,
	capsuleID computequeue.JobCapsuleID,
	startedAt computequeue.Timestamp,
) (AdmissionRecord, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	record, exists := ledger.records[capsuleID]
	if !exists {
		return AdmissionRecord{}, ErrMissing
	}
	if record.State == AdmissionStagingExpiryPending || record.State == AdmissionExpiryPending ||
		record.State == AdmissionExpired {
		return cloneAdmission(record), nil
	}
	if (record.State != AdmissionStaging && record.State != AdmissionRetained) ||
		startedAt < record.Header.RetentionUntil ||
		startedAt < computequeue.Timestamp(record.UpdatedAtMillis) {
		return AdmissionRecord{}, ErrConflict
	}
	for claimID, claim := range ledger.claims {
		if claim.CapsuleID != capsuleID || claim.State != WorkerClaimClaimed {
			continue
		}
		if claim.LeaseExpiresAt > startedAt {
			return AdmissionRecord{}, ErrConflict
		}
		claim.State = WorkerClaimExpired
		claim.UpdatedAtMillis = int64(startedAt)
		ledger.claims[claimID] = claim
	}
	if record.State == AdmissionStaging {
		record.State = AdmissionStagingExpiryPending
	} else {
		record.State = AdmissionExpiryPending
	}
	record.ExpiryStartedAt = startedAt
	record.UpdatedAtMillis = int64(startedAt)
	ledger.records[capsuleID] = record
	return cloneAdmission(record), nil
}

func (ledger *memoryLedger) FinalizeAdmissionExpiry(
	_ context.Context,
	capsuleID computequeue.JobCapsuleID,
	receiptBytes []byte,
	expiredAt int64,
) (AdmissionRecord, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	record, exists := ledger.records[capsuleID]
	if !exists {
		return AdmissionRecord{}, ErrMissing
	}
	if record.State == AdmissionExpired {
		return cloneAdmission(record), nil
	}
	if (record.State != AdmissionStagingExpiryPending && record.State != AdmissionExpiryPending) ||
		len(receiptBytes) == 0 || expiredAt < record.UpdatedAtMillis ||
		expiredAt < int64(record.Header.RetentionUntil) {
		return AdmissionRecord{}, ErrConflict
	}
	if ledger.failAdmissionExpiryFinalizeOnce {
		ledger.failAdmissionExpiryFinalizeOnce = false
		return AdmissionRecord{}, ErrUnavailable
	}
	record.State = AdmissionExpired
	record.ObjectPath = ""
	record.ExpiryReceiptBytes = bytes.Clone(receiptBytes)
	record.UpdatedAtMillis = expiredAt
	ledger.records[capsuleID] = record
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
	receiptBytes []byte,
	committedAt int64,
) (AdmissionRecord, error) {
	if lease.closed || len(receiptBytes) == 0 || committedAt < lease.record.UpdatedAtMillis {
		return AdmissionRecord{}, ErrConflict
	}
	lease.closed = true
	defer lease.ledger.mu.Unlock()
	record := lease.ledger.records[lease.record.Header.CapsuleID]
	record.State = AdmissionRetained
	record.ObjectPath = objectPath
	record.CustodyReceiptBytes = bytes.Clone(receiptBytes)
	record.UpdatedAtMillis = committedAt
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
	record.CustodyReceiptBytes = bytes.Clone(record.CustodyReceiptBytes)
	record.ExpiryReceiptBytes = bytes.Clone(record.ExpiryReceiptBytes)
	return record
}

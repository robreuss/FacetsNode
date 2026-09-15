package objectcustodyledger

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

// Install a real root-signed successor only in the receiver. The independent
// sender registry deliberately stays old to exercise a stale second process.
func advancePeerReceiver(t *testing.T, f peerFixture) (serviceauthority.RequestBinding, serviceauthority.Manifest) {
	t.Helper()
	payload, err := f.manifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := f.manifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	payload.PredecessorManifestDigest = &digest
	payload.Revision++
	payload.Transition = serviceauthority.TransitionPolicyUpdate
	payload.IssuedAtMilliseconds++
	payload.ValidFromMilliseconds++
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(append([]byte("Facets service authority manifest v1\x00"), encoded...))
	r, s, err := ecdsa.Sign(rand.Reader, f.authorityKey, h[:])
	if err != nil {
		t.Fatal(err)
	}
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(f.authorityKey.Params().N), 1)) > 0 {
		s.Sub(f.authorityKey.Params().N, s)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	next := serviceauthority.Manifest{Payload: encoded, Signature: f.manifest.Signature}
	next.Signature.Signature = base64.RawURLEncoding.EncodeToString(raw)
	if err = f.receiver.ApplyServiceAuthoritySuccessor(f.manifest, next, f.anchor, time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	result := f.source
	result.AuthorityRevision = payload.Revision
	result.AuthorityDigest, err = next.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	return result, next
}

func TestPeerFenceSignedSuccessorRejectsStaleProcessForEveryOperation(t *testing.T) {
	for _, kind := range []serviceauthority.ScopeKind{serviceauthority.ScopeDeviceSync, serviceauthority.ScopeBackupCustody} {
		t.Run(string(kind), func(t *testing.T) {
			f := newPeerFixtureKind(t, kind)
			ctx := context.Background()
			c := f.issue(t)
			proof := f.sign(t, c)
			if _, err := f.verify(proof, f.body); err != nil {
				t.Fatal(err)
			}
			next, manifest := advancePeerReceiver(t, f)
			if err := f.f.l.ReconcilePeerAuthority(ctx, f.receiver, next.Scope); err != nil {
				t.Fatal(err)
			}
			if _, err := f.f.l.VerifyPeerChallenge(ctx, f.sender, f.f.binding.ID, f.intent.OperationID, proof, f.body); err == nil {
				t.Fatal("stale registry replayed consumed request through advanced durable fence")
			}
			for _, operation := range []serviceauthority.CustodyPeerOperation{serviceauthority.CustodyReserveObject, serviceauthority.CustodyPutObject, serviceauthority.CustodyReadObject, serviceauthority.CustodyBeginPublication, serviceauthority.CustodyAddPins, serviceauthority.CustodyPreparePublication, serviceauthority.CustodyConfirmPublication, serviceauthority.CustodyAcquireLease, serviceauthority.CustodyRenewLease, serviceauthority.CustodyCloseLease, serviceauthority.CustodyRetirePublication} {
				intent, source := f.intent, f.source
				intent.Operation, intent.OperationID = operation, uuid.New()
				if operation == serviceauthority.CustodyPutObject || operation == serviceauthority.CustodyReadObject {
					source.TrafficClass = serviceauthority.TrafficBulk
				}
				if _, err := f.f.l.IssuePeerChallenge(ctx, source, intent); err == nil {
					t.Fatalf("new stale operation accepted: %s", operation)
				}
			}
			if err := f.f.l.ReconcilePeerAuthority(ctx, f.sender, f.source.Scope); !errors.Is(err, ErrConflict) {
				t.Fatalf("registry rollback: %v", err)
			}
			if err := f.f.l.ReconcilePeerAuthority(ctx, f.receiver, next.Scope); err != nil {
				t.Fatal("exact current retry", err)
			}
			if err := f.sender.ApplyServiceAuthoritySuccessor(f.manifest, manifest, f.anchor, time.Now().UnixMilli()); err != nil {
				t.Fatal(err)
			}
			f.source = next
			reissued := f.issue(t)
			if reissued.Consumed || reissued.Payload.Request.Challenge == c.Payload.Request.Challenge {
				t.Fatal("successor did not rotate freshness")
			}
			if _, err := f.verify(f.sign(t, reissued), f.body); err != nil {
				t.Fatal("new current request rejected", err)
			}
			if objects := outstanding(t, f.f); objects != 0 {
				t.Fatal("authority reconciliation created ciphertext")
			}
		})
	}
}

func TestPeerFenceAdvanceRules(t *testing.T) {
	f := newPeerAuthorityFixture(t, Binding{ID: uuid.New(), ServiceKind: "device_sync", ServiceScopeID: uuid.New(), ResourceID: uuid.New(), ContentScopeID: uuid.New(), ContentEpoch: 1}, uuid.New(), uuid.New())
	prior, err := f.receiver.CurrentCustodyPeerIdentityAt(f.source.Scope, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"rollback", "digest", "deployment", "scope", "zero"} {
		next := prior
		switch change {
		case "rollback":
			prior.Revision = 2
			next.Revision = 1
		case "digest":
			next.Digest = hashLabel("different")
		case "deployment":
			next.DeploymentID = uuid.New()
		case "scope":
			next.Scope.ScopeID = uuid.New()
		case "zero":
			next.Revision = 0
		}
		if err := validatePeerAuthorityAdvance(prior, next); err == nil {
			t.Fatal("accepted", change)
		}
		prior.Revision = 1
	}
	fenced := prior
	fenced.WriteFenced = true
	if err := validatePeerAuthorityAdvance(prior, fenced); err != nil {
		t.Fatal(err)
	}
	if err := validatePeerAuthorityAdvance(fenced, prior); err == nil {
		t.Fatal("same head cleared fence")
	}
	next := prior
	next.Revision = math.MaxUint64
	if err := validatePeerAuthorityAdvance(fenced, next); err != nil {
		t.Fatal("valid UInt64 maximum", err)
	}
}

func TestPeerFenceMissingCorruptFencedAndSeparateScope(t *testing.T) {
	for _, change := range []string{"missing", "overflow", "digest", "deployment", "fenced", "foreign_kind"} {
		t.Run(change, func(t *testing.T) {
			f := newPeerFixture(t)
			ctx := context.Background()
			c := f.issue(t)
			proof := f.sign(t, c)
			var err error
			switch change {
			case "missing":
				_, err = f.f.pool.Exec(ctx, `DELETE FROM immutable_custody_peer_authorities`)
			case "overflow":
				_, err = f.f.pool.Exec(ctx, `UPDATE immutable_custody_peer_authorities SET authority_revision='18446744073709551616'`)
			case "digest":
				_, err = f.f.pool.Exec(ctx, `UPDATE immutable_custody_peer_authorities SET manifest_digest=$1`, hashLabel("tampered"))
			case "deployment":
				_, err = f.f.pool.Exec(ctx, `UPDATE immutable_custody_peer_authorities SET deployment_id=$1`, uuid.New())
			case "fenced":
				_, err = f.f.pool.Exec(ctx, `UPDATE immutable_custody_peer_authorities SET write_fenced=true`)
			case "foreign_kind":
				_, err = f.f.pool.Exec(ctx, `UPDATE immutable_custody_peer_authorities SET service_kind='backup_custody'`)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.verify(proof, f.body); err == nil {
				t.Fatal("invalid durable authority accepted")
			}
			if _, err = f.f.l.IssuePeerChallenge(ctx, f.source, f.intent); err == nil {
				t.Fatal("invalid head issued challenge")
			}
			stored, err := loadPeerChallenge(ctx, f.f.pool, f.f.binding.ID, f.intent.OperationID)
			if err != nil || stored.Consumed {
				t.Fatal("rejection consumed request", err)
			}
			if change == "fenced" {
				// Synthetic database fence tests conservative denial independently
				// of the registry's migration fixture tested in serviceauthority.
				if err := f.f.l.ReconcilePeerAuthority(ctx, f.receiver, f.source.Scope); err == nil {
					t.Fatal("old registry cleared durable fence")
				}
				f.intent.Operation, f.intent.OperationID = serviceauthority.CustodyReadObject, uuid.New()
				f.source.TrafficClass = serviceauthority.TrafficBulk
				if _, err := f.verify(f.sign(t, f.issue(t)), f.body); err != nil {
					t.Fatal("current read denied by write-only fence", err)
				}
			}
		})
	}
}

func TestPeerFenceConcurrentReconcileAndRestart(t *testing.T) {
	f := newPeerFixture(t)
	ctx := context.Background()
	next, _ := advancePeerReceiver(t, f)
	otherPool, err := pgxpool.NewWithConfig(ctx, f.f.pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer otherPool.Close()
	other, err := Open(ctx, otherPool, f.f.l.poolID, f.f.files, f.f.provider)
	if err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 16)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			owner := f.f.l
			if i%2 != 0 {
				owner = other
			}
			errs <- owner.ReconcilePeerAuthority(ctx, f.receiver, next.Scope)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	stored, err := loadPeerAuthority(ctx, otherPool, next.Scope)
	if err != nil || stored.Revision != next.AuthorityRevision || stored.Digest != next.AuthorityDigest {
		t.Fatal("wrong shared head", err)
	}
	if err = other.ReconcilePeerAuthority(ctx, f.sender, f.source.Scope); !errors.Is(err, ErrConflict) {
		t.Fatal("reopened owner accepted rollback", err)
	}
	// A held pool row serializes a pending reconciliation; cancellation releases
	// its process lease and pooled connection rather than installing a head.
	lock, err := f.f.l.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	if err = other.ReconcilePeerAuthority(short, f.receiver, next.Scope); err == nil {
		t.Fatal("passed held pool fence")
	}
	cancel()
	_ = lock.Rollback(ctx)
	if err = other.ReconcilePeerAuthority(ctx, f.receiver, next.Scope); err != nil {
		t.Fatal("cancellation leaked lease", err)
	}
}

func TestPeerFenceCapacityAndCommitRecovery(t *testing.T) {
	for _, point := range []string{"before_database_commit", "after_database_commit"} {
		t.Run(point, func(t *testing.T) {
			f := newPeerFixture(t)
			ctx := context.Background()
			if _, err := f.f.pool.Exec(ctx, `DELETE FROM immutable_custody_peer_authorities`); err != nil {
				t.Fatal(err)
			}
			f.f.provider.set(0, nil)
			if err := f.f.l.ReconcilePeerAuthority(ctx, f.receiver, f.source.Scope); !errors.Is(err, storagecapacity.ErrPressure) {
				t.Fatal("bootstrap capacity", err)
			}
			f.f.provider.set(90<<30, nil)
			injected := errors.New("lost response")
			f.f.l.fault = func(at string) error {
				if at == point {
					return injected
				}
				return nil
			}
			if err := f.f.l.ReconcilePeerAuthority(ctx, f.receiver, f.source.Scope); !errors.Is(err, injected) {
				t.Fatal(err)
			}
			f.f.l.fault = nil
			_, err := loadPeerAuthority(ctx, f.f.pool, f.source.Scope)
			if point == "before_database_commit" && !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal("uncommitted head survived", err)
			}
			if point == "after_database_commit" && err != nil {
				t.Fatal("durable head lost", err)
			}
			if err := f.f.l.ReconcilePeerAuthority(ctx, f.receiver, f.source.Scope); err != nil {
				t.Fatal(err)
			}
			f.f.provider.set(0, nil)
			if err := f.f.l.ReconcilePeerAuthority(ctx, f.receiver, f.source.Scope); err != nil {
				t.Fatal("exact retry required more capacity", err)
			}
			next, _ := advancePeerReceiver(t, f)
			if err := f.f.l.ReconcilePeerAuthority(ctx, f.receiver, next.Scope); err != nil {
				t.Fatal("head advance required more capacity", err)
			}
		})
	}
}

func TestPeerFenceIndependentServicesSharingScopeUUID(t *testing.T) {
	f := newPeerFixture(t)
	ctx := context.Background()
	binding := f.f.binding
	binding.ID, binding.ServiceKind = uuid.New(), "backup_custody"
	if err := f.f.l.RegisterBinding(ctx, binding); err != nil {
		t.Fatal(err)
	}
	backup := newPeerAuthorityFixture(t, binding, f.f.l.poolID, f.f.l.ledgerID)
	backup.f = f.f
	if err := f.f.l.ReconcilePeerAuthority(ctx, backup.receiver, backup.source.Scope); err != nil {
		t.Fatal(err)
	}
	if _, err := f.f.pool.Exec(ctx, `UPDATE immutable_custody_peer_authorities SET write_fenced=true WHERE service_kind='device_sync'`); err != nil {
		t.Fatal(err)
	}
	c, err := f.f.l.IssuePeerChallenge(ctx, backup.source, backup.intent)
	if err != nil {
		t.Fatal("Sync fence blocked independent Backup", err)
	}
	if _, err := f.f.l.VerifyPeerChallenge(ctx, backup.receiver, binding.ID, backup.intent.OperationID, backup.sign(t, c), backup.body); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := f.f.pool.QueryRow(ctx, `SELECT count(*) FROM immutable_custody_peer_authorities WHERE service_scope_id=$1`, f.source.Scope.ScopeID).Scan(&count); err != nil || count != 2 {
		t.Fatal("services collided", err)
	}
}

func TestPeerFenceRechecksRegistryBeforeDurableCommit(t *testing.T) {
	f := newPeerFixture(t)
	ctx := context.Background()
	next, _ := advancePeerReceiver(t, f)
	closed := false
	f.f.l.fault = func(point string) error {
		if point == "peer_authority_staged" {
			closed = true
			return f.receiver.Close()
		}
		return nil
	}
	if err := f.f.l.ReconcilePeerAuthority(ctx, f.receiver, next.Scope); !errors.Is(err, ErrConflict) || !closed {
		t.Fatal("staged obsolete registry committed", err)
	}
	f.f.l.fault = nil
	head, err := loadPeerAuthority(ctx, f.f.pool, f.source.Scope)
	if err != nil || head.Revision != f.source.AuthorityRevision || head.Digest != f.source.AuthorityDigest {
		t.Fatal("unverified successor committed", err)
	}
	reopened, err := serviceauthority.LoadBindingRegistry(f.receiverPath, f.source.DeploymentID)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := f.f.l.ReconcilePeerAuthority(ctx, reopened, next.Scope); err != nil {
		t.Fatal("reopened current registry cannot finish", err)
	}
}

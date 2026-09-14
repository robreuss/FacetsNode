package objectcustodyledger

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

type peerFixture struct {
	f                *fixtureContext
	signer           *serviceauthority.DeploymentSigner
	sender, receiver *serviceauthority.BindingRegistry
	receiverPath     string
	source           serviceauthority.RequestBinding
	intent           serviceauthority.CustodyPeerRequest
	body             []byte
}

func newPeerFixture(t *testing.T) peerFixture {
	return newPeerFixtureKind(t, serviceauthority.ScopeDeviceSync)
}

func newPeerFixtureKind(t *testing.T, kind serviceauthority.ScopeKind) peerFixture {
	t.Helper()
	f := newFixture(t)
	if kind != serviceauthority.ScopeDeviceSync {
		f.binding.ID, f.binding.ServiceKind = uuid.New(), string(kind)
		if err := f.l.RegisterBinding(context.Background(), f.binding); err != nil {
			t.Fatal(err)
		}
	}
	seed := make([]byte, 32)
	seed[31] = 2
	signer, err := serviceauthority.NewDeploymentSigner(uuid.New(), seed)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pin := strings.Repeat("1", 64)
	route := serviceauthority.TransportRoute{Endpoint: "https://peer.invalid:8443", Kind: serviceauthority.RouteDirectHTTPS, NetworkScope: serviceauthority.NetworkTrustedLAN, RouteID: uuid.New(), ServerAuthentication: serviceauthority.ServerAuthentication{Kind: "pinned_spki_sha256", PinnedSPKISHA256: &pin}}
	scope := serviceauthority.Scope{Kind: kind, ScopeID: f.binding.ServiceScopeID}
	manifestPayload := serviceauthority.ManifestPayload{ActiveDeployment: serviceauthority.DeploymentDescriptor{CreatedAtMilliseconds: 900, DeploymentID: signer.DeploymentID(), PublicSigningKeyX963: signer.PublicSigningKeyX963(), SigningKeyFingerprint: signer.SigningKeyFingerprint(), Routes: []serviceauthority.TransportRoute{route}, Version: 1}, IssuedAtMilliseconds: 1000, PreparedDeployments: []serviceauthority.DeploymentDescriptor{}, Revision: 1, Scope: scope, Transition: serviceauthority.TransitionInitialActivation, TransportPolicy: serviceauthority.TransportPolicy{BulkRouteIDs: []uuid.UUID{route.RouteID}, ControlRouteIDs: []uuid.UUID{route.RouteID}, MessageRouteIDs: []uuid.UUID{route.RouteID}, Version: 1}, ValidFromMilliseconds: 1000, Version: 1}
	encoded, err := json.Marshal(manifestPayload)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(append([]byte("Facets service authority manifest v1\x00"), encoded...))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(key.Params().N), 1)) > 0 {
		s.Sub(key.Params().N, s)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	public := elliptic.Marshal(key.Curve, key.X, key.Y)
	pubHash := sha256.Sum256(public)
	manifest := serviceauthority.Manifest{Payload: encoded, Signature: serviceauthority.Signature{Algorithm: "ES256", PublicSigningKeyX963: base64.RawURLEncoding.EncodeToString(public), Signature: base64.RawURLEncoding.EncodeToString(raw), SignerID: uuid.New(), SigningKeyFingerprint: hex.EncodeToString(pubHash[:])}}
	digest, err := manifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	var registryPath string
	newRegistry := func() *serviceauthority.BindingRegistry {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "bindings.json")
		registryPath = path
		data, err := json.Marshal(serviceauthority.BindingFile{Bindings: []serviceauthority.BindingFileEntry{{DeploymentID: signer.DeploymentID(), Digest: digest, Manifest: &manifest, Revision: 1, Scope: scope}}, Version: 1})
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		registry, err := serviceauthority.LoadBindingRegistry(path, signer.DeploymentID())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = registry.Close() })
		return registry
	}
	body := []byte("bounded opaque request fixture")
	sender, receiver := newRegistry(), newRegistry()
	return peerFixture{f: f, signer: signer, sender: sender, receiver: receiver, receiverPath: registryPath, source: serviceauthority.RequestBinding{Scope: scope, AuthorityRevision: 1, AuthorityDigest: digest, DeploymentID: signer.DeploymentID(), RouteID: route.RouteID, TrafficClass: serviceauthority.TrafficControl}, body: body,
		intent: serviceauthority.CustodyPeerRequest{BodyByteCount: int64(len(body)), BodySHA256: hashLabel(string(body)), Operation: serviceauthority.CustodyReserveObject, OperationID: uuid.New(), Target: serviceauthority.CustodyPeerTarget{BindingID: f.binding.ID, ContentEpoch: f.binding.ContentEpoch, ContentScopeID: f.binding.ContentScopeID, LedgerID: f.l.ledgerID, PoolID: f.l.poolID}, Version: 1}}
}

func (f peerFixture) issue(t *testing.T) PeerChallenge {
	t.Helper()
	c, err := f.f.l.IssuePeerChallenge(context.Background(), f.source, f.intent)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func (f peerFixture) sign(t *testing.T, c PeerChallenge) serviceauthority.CustodyPeerProof {
	t.Helper()
	proof, err := f.sender.SignCustodyPeerRequestAt(f.signer, f.source, c.Payload.Request, f.body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return proof
}
func (f peerFixture) verify(proof serviceauthority.CustodyPeerProof, body []byte) (serviceauthority.VerifiedCustodyPeerRequest, error) {
	return f.f.l.VerifyPeerChallenge(context.Background(), f.receiver, f.intent.Target.BindingID, f.intent.OperationID, proof, body)
}

func TestPeerChallengeDurableExactIssuanceConsumptionAndReopen(t *testing.T) {
	f := newPeerFixture(t)
	ctx := context.Background()
	before, err := databaseNow(ctx, f.f.pool)
	if err != nil {
		t.Fatal(err)
	}
	c := f.issue(t)
	after, err := databaseNow(ctx, f.f.pool)
	if err != nil {
		t.Fatal(err)
	}
	if c.Consumed || c.IssuedAtMilliseconds < before || c.IssuedAtMilliseconds > after || c.ExpiresAtMilliseconds-c.IssuedAtMilliseconds != PeerChallengeLifetime.Milliseconds() {
		t.Fatal("not fixed database-timed lifetime")
	}
	if retry := f.issue(t); retry != c {
		t.Fatal("live issuance rotated challenge")
	}
	proof := f.sign(t, c)
	v, err := f.verify(proof, f.body)
	if err != nil || v.Request() != c.Payload.Request || v.Source() != f.source {
		t.Fatalf("verify: %v", err)
	}
	c.Consumed = true
	if retry := f.issue(t); retry != c {
		t.Fatal("consumed issuance changed intent/nonce")
	}
	reopened, err := Open(ctx, f.f.pool, f.f.l.poolID, f.f.files, f.f.provider)
	if err != nil {
		t.Fatal(err)
	}
	if retry, err := reopened.VerifyPeerChallenge(ctx, f.receiver, f.f.binding.ID, f.intent.OperationID, proof, f.body); err != nil || retry.Request() != v.Request() {
		t.Fatalf("reopened retry: %v", err)
	}
	if count := outstanding(t, f.f); count != 0 {
		t.Fatal("freshness state implicitly reserved an object")
	}
	var objects, pubs int
	if err = f.f.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM immutable_custody_objects),(SELECT count(*) FROM immutable_custody_publications)`).Scan(&objects, &pubs); err != nil || objects != 0 || pubs != 0 {
		t.Fatal("verification executed a storage effect")
	}
}

func TestPeerChallengeRejectsSubstitutionWithoutConsuming(t *testing.T) {
	f := newPeerFixture(t)
	c := f.issue(t)
	proof := f.sign(t, c)
	ctx := context.Background()
	if _, err := f.verify(proof, bytes.Repeat([]byte("X"), len(f.body))); err == nil {
		t.Fatal("wrong body accepted")
	}
	changed := proof
	changed.Payload = append(append([]byte(nil), proof.Payload...), '\n')
	if _, err := f.verify(changed, f.body); err == nil {
		t.Fatal("noncanonical proof accepted")
	}
	if _, err := f.f.l.VerifyPeerChallenge(ctx, f.receiver, uuid.New(), f.intent.OperationID, proof, f.body); err == nil {
		t.Fatal("different binding accepted")
	}
	if _, err := f.f.l.VerifyPeerChallenge(ctx, f.receiver, f.f.binding.ID, uuid.New(), proof, f.body); err == nil {
		t.Fatal("different operation accepted")
	}
	if _, err := f.f.l.VerifyPeerChallenge(ctx, nil, f.f.binding.ID, f.intent.OperationID, proof, f.body); err == nil {
		t.Fatal("unpinned registry accepted")
	}
	if current, err := loadPeerChallenge(ctx, f.f.pool, f.f.binding.ID, f.intent.OperationID); err != nil || current.Consumed {
		t.Fatal("rejection consumed challenge")
	}
	for _, field := range []string{"body", "operation", "scope", "epoch", "pool", "ledger", "source_scope", "source_kind", "source_revision", "source_digest", "nonce"} {
		t.Run(field, func(t *testing.T) {
			i, s := f.intent, f.source
			switch field {
			case "body":
				i.BodySHA256 = hashLabel("replacement")
			case "operation":
				i.Operation = serviceauthority.CustodyBeginPublication
			case "scope":
				i.Target.ContentScopeID = uuid.New()
			case "epoch":
				i.Target.ContentEpoch++
			case "pool":
				i.Target.PoolID = uuid.New()
			case "ledger":
				i.Target.LedgerID = uuid.New()
			case "source_scope":
				s.Scope.ScopeID = uuid.New()
			case "source_kind":
				s.Scope.Kind = serviceauthority.ScopeBackupCustody
			case "source_revision":
				s.AuthorityRevision = 0
			case "source_digest":
				s.AuthorityDigest = hashLabel("wrong-current")
			case "nonce":
				i.Challenge = c.Payload.Request.Challenge
			}
			if _, err := f.f.l.IssuePeerChallenge(ctx, s, i); err == nil {
				t.Fatal("immutable request reassigned")
			}
		})
	}
	if _, err := f.verify(proof, f.body); err != nil {
		t.Fatal(err)
	}
	if _, err := f.verify(proof, bytes.Repeat([]byte("Y"), len(f.body))); err == nil {
		t.Fatal("consumed flag bypassed body authentication")
	}
	if err := f.receiver.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.verify(proof, f.body); err == nil {
		t.Fatal("stale closed authority accepted")
	}
}

func TestPeerChallengeRejectsDifferentAuthenticatedSource(t *testing.T) {
	f, other := newPeerFixture(t), newPeerFixture(t)
	c := f.issue(t)
	// The other source genuinely signs, and its own independently pinned registry
	// validates it. It is still not the source captured in this receiver's row.
	proof, err := other.sender.SignCustodyPeerRequestAt(other.signer, other.source, c.Payload.Request, f.body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.f.l.VerifyPeerChallenge(context.Background(), other.receiver, f.f.binding.ID, f.intent.OperationID, proof, f.body); err == nil {
		t.Fatal("another correctly authenticated service substituted for challenged source")
	}
}

func TestPeerChallengeBackupUsesIndependentBindingAndAuthority(t *testing.T) {
	f := newPeerFixtureKind(t, serviceauthority.ScopeBackupCustody)
	c := f.issue(t)
	proof := f.sign(t, c)
	if v, err := f.verify(proof, f.body); err != nil || v.Source().Scope.Kind != serviceauthority.ScopeBackupCustody {
		t.Fatalf("independent backup proof: %v", err)
	}
}

func TestPeerChallengeSourceChangeRotatesAndPreventsRevisionRollback(t *testing.T) {
	f := newPeerFixture(t)
	c := f.issue(t)
	proof := f.sign(t, c)
	changed := f.source
	changed.AuthorityRevision++
	changed.AuthorityDigest = hashLabel("synthetic next authority head")
	next, err := f.f.l.IssuePeerChallenge(context.Background(), changed, f.intent)
	if err != nil || next.Payload.Request.Challenge == c.Payload.Request.Challenge {
		t.Fatal("source change did not rotate", err)
	}
	if _, err = f.verify(proof, f.body); err == nil {
		t.Fatal("superseded source proof accepted")
	}
	if _, err = f.f.l.IssuePeerChallenge(context.Background(), f.source, f.intent); err == nil {
		t.Fatal("source revision rollback accepted")
	}
	// Issuance accepts a trusted adapter input, not proof of a new authority.
	// The old pinned registry cannot sign or authorize the requested new head.
	if _, err = f.sender.SignCustodyPeerRequestAt(f.signer, changed, next.Payload.Request, f.body, time.Now()); err == nil {
		t.Fatal("unsigned new head acquired signing authority")
	}
}

func TestPeerChallengeBackwardClockFailsClosed(t *testing.T) {
	f := newPeerFixture(t)
	c := f.issue(t)
	proof := f.sign(t, c)
	_, err := f.f.pool.Exec(context.Background(), `UPDATE immutable_custody_peer_challenges SET issued_at_milliseconds=issued_at_milliseconds+3600000,expires_at_milliseconds=expires_at_milliseconds+3600000`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.verify(proof, f.body); err == nil {
		t.Fatal("not-yet-valid challenge accepted")
	}
	if _, err = f.f.l.IssuePeerChallenge(context.Background(), f.source, f.intent); err == nil {
		t.Fatal("future row silently replaced")
	}
}

func expirePeerChallenge(t *testing.T, f peerFixture) {
	t.Helper()
	// Only disposable rows move in time; no VM, host or PostgreSQL clock changes.
	_, err := f.f.pool.Exec(context.Background(), `UPDATE immutable_custody_peer_challenges SET issued_at_milliseconds=1000,expires_at_milliseconds=301000 WHERE binding_id=$1 AND operation_id=$2`, f.f.binding.ID, f.intent.OperationID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPeerChallengeExpiryReissueInvalidatesOldProofNotOperation(t *testing.T) {
	f := newPeerFixture(t)
	c := f.issue(t)
	proof := f.sign(t, c)
	if _, err := f.verify(proof, f.body); err != nil {
		t.Fatal(err)
	}
	expirePeerChallenge(t, f)
	if _, err := f.verify(proof, f.body); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired consumed proof: %v", err)
	}
	next := f.issue(t)
	if next.Consumed || next.Payload.Request.Challenge == c.Payload.Request.Challenge {
		t.Fatal("expired nonce reused")
	}
	if _, err := f.verify(proof, f.body); err == nil {
		t.Fatal("rotated nonce accepted")
	}
	if _, err := f.verify(f.sign(t, next), f.body); err != nil {
		t.Fatal(err)
	}
	other := f.intent
	other.BodySHA256 = hashLabel("different")
	if _, err := f.f.l.IssuePeerChallenge(context.Background(), f.source, other); err == nil {
		t.Fatal("consumed operation reassigned")
	}
}

func TestPeerChallengeConcurrentIssuanceAndConsumption(t *testing.T) {
	f := newPeerFixture(t)
	ctx := context.Background()
	other, err := Open(ctx, f.f.pool, f.f.l.poolID, f.f.files, f.f.provider)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan PeerChallenge, 16)
	errs := make(chan error, 32)
	var wg sync.WaitGroup
	for n := 0; n < 16; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			l := f.f.l
			if n%2 == 1 {
				l = other
			}
			c, err := l.IssuePeerChallenge(ctx, f.source, f.intent)
			results <- c
			errs <- err
		}(n)
	}
	wg.Wait()
	close(results)
	var first PeerChallenge
	for c := range results {
		if first.IssuedAtMilliseconds == 0 {
			first = c
		} else if first != c {
			t.Fatal("concurrent issuance produced rival nonces")
		}
	}
	for n := 0; n < 16; n++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	proof := f.sign(t, first)
	for n := 0; n < 16; n++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := f.verify(proof, f.body); errs <- err }()
	}
	wg.Wait()
	for n := 0; n < 16; n++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	current, err := loadPeerChallenge(ctx, f.f.pool, f.f.binding.ID, f.intent.OperationID)
	if err != nil || !current.Consumed || current.Payload != first.Payload {
		t.Fatal("concurrent consumption changed identity")
	}
}

func TestPeerChallengePendingBoundAndCapacity(t *testing.T) {
	f := newPeerFixture(t)
	ctx := context.Background()
	first := f.issue(t)
	for n := 1; n < MaximumPendingPeerChallenges; n++ {
		i := f.intent
		i.OperationID = uuid.New()
		if _, err := f.f.l.IssuePeerChallenge(ctx, f.source, i); err != nil {
			t.Fatal(err)
		}
	}
	i := f.intent
	i.OperationID = uuid.New()
	if _, err := f.f.l.IssuePeerChallenge(ctx, f.source, i); !errors.Is(err, ErrConflict) {
		t.Fatalf("pending budget: %v", err)
	}
	f.f.provider.set(0, nil)
	if retry := f.issue(t); retry != first {
		t.Fatal("live challenge retry required more capacity")
	}
	if _, err := f.verify(f.sign(t, first), f.body); err != nil {
		t.Fatal("consumption required capacity", err)
	}
	if _, err := f.f.l.IssuePeerChallenge(ctx, f.source, i); !errors.Is(err, storagecapacity.ErrPressure) {
		t.Fatalf("capacity: %v", err)
	}
	f.f.provider.set(90<<30, nil)
	if _, err := f.f.l.IssuePeerChallenge(ctx, f.source, i); err != nil {
		t.Fatal("consumed slot did not release pending budget", err)
	}
}

func TestPeerChallengeCommitInterruptionAndCorruptState(t *testing.T) {
	for _, operation := range []string{"issue", "consume"} {
		for _, point := range []string{"before_database_commit", "after_database_commit"} {
			t.Run(operation+"/"+point, func(t *testing.T) {
				f := newPeerFixture(t)
				ctx := context.Background()
				var proof serviceauthority.CustodyPeerProof
				if operation == "consume" {
					proof = f.sign(t, f.issue(t))
				}
				injected := errors.New("injected response loss")
				f.f.l.fault = func(at string) error {
					if at == point {
						return injected
					}
					return nil
				}
				if operation == "issue" {
					_, err := f.f.l.IssuePeerChallenge(ctx, f.source, f.intent)
					if !errors.Is(err, injected) {
						t.Fatal(err)
					}
				} else {
					_, err := f.verify(proof, f.body)
					if !errors.Is(err, injected) {
						t.Fatal(err)
					}
				}
				f.f.l.fault = nil
				current, err := loadPeerChallenge(ctx, f.f.pool, f.f.binding.ID, f.intent.OperationID)
				if operation == "issue" && point == "before_database_commit" {
					if err == nil {
						t.Fatal("failed issue committed")
					}
				} else if err != nil || current.Consumed != (operation == "consume" && point == "after_database_commit") {
					t.Fatal("wrong durable side of interruption", err)
				}
				c := f.issue(t)
				if operation == "issue" {
					proof = f.sign(t, c)
				}
				if _, err = f.verify(proof, f.body); err != nil {
					t.Fatal("exact recovery failed", err)
				}
			})
		}
	}
	for _, field := range []string{"json", "nonce", "intent"} {
		t.Run(field, func(t *testing.T) {
			f := newPeerFixture(t)
			c := f.issue(t)
			ctx := context.Background()
			proof := f.sign(t, c)
			switch field {
			case "json":
				_, _ = f.f.pool.Exec(ctx, `UPDATE immutable_custody_peer_challenges SET payload=payload||decode('0a','hex')`)
			case "nonce":
				_, _ = f.f.pool.Exec(ctx, `UPDATE immutable_custody_peer_challenges SET challenge=$1`, strings.Repeat("A", 43))
			case "intent":
				c.Payload.Request.OperationID = uuid.New()
				data, _ := json.Marshal(c.Payload)
				_, _ = f.f.pool.Exec(ctx, `UPDATE immutable_custody_peer_challenges SET payload=$1`, data)
			}
			if _, err := f.verify(proof, f.body); err == nil {
				t.Fatal("corrupt durable challenge accepted")
			}
			if _, err := f.f.l.IssuePeerChallenge(ctx, f.source, f.intent); err == nil {
				t.Fatal("corrupt challenge silently repaired")
			}
		})
	}
}

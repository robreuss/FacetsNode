package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	postgresstore "github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/rendezvous"
	"github.com/robreuss/FacetsNode/internal/testfixture"
)

type relayFetchSignalStore struct {
	relay.Store
	firstFetch chan struct{}
	once       sync.Once
}

func (s *relayFetchSignalStore) Fetch(
	ctx context.Context,
	credential relay.Credential,
	afterSequence uint64,
	limit int,
	nowMilliseconds int64,
) (relay.FetchResult, error) {
	result, err := s.Store.Fetch(ctx, credential, afterSequence, limit, nowMilliseconds)
	s.once.Do(func() { close(s.firstFetch) })
	return result, err
}

func TestPostgresRelayWakeCrossesInstancesAndMissedHintFallsBackToFetch(t *testing.T) {
	databaseURL := os.Getenv("FACETS_NODE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACETS_NODE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	poolA := openRelayWakePool(t, ctx, databaseURL)
	defer poolA.Close()
	poolB := openRelayWakePool(t, ctx, databaseURL)
	defer poolB.Close()
	if err := postgresstore.Migrate(ctx, poolA); err != nil {
		t.Fatal(err)
	}
	if _, err := poolA.Exec(ctx, `TRUNCATE relay_tenants CASCADE`); err != nil {
		t.Fatal(err)
	}

	storeA := postgresstore.NewRelayStore(poolA)
	storeB := &relayFetchSignalStore{
		Store:      postgresstore.NewRelayStore(poolB),
		firstFetch: make(chan struct{}),
	}
	operatorToken := relayTestToken(249)
	serverA, err := NewWithRelay(
		rendezvous.NewMemoryStore(), storeA, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)), operatorToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	serverB, err := NewWithRelay(
		rendezvous.NewMemoryStore(), storeB, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)), operatorToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	serverA.now = func() time.Time { return time.UnixMilli(1_500) }
	serverB.now = func() time.Time { return time.UnixMilli(1_500) }
	serverA.SetRelayWakeNotifier(postgresstore.NewRelayWakeNotifier(poolA))

	listener := postgresstore.NewRelayWakeListener(poolB)
	listenerContext, stopListener := context.WithCancel(ctx)
	listenerDone := make(chan struct{})
	listenerErrors := make(chan error, 8)
	go func() {
		defer close(listenerDone)
		listener.Run(listenerContext, serverB.ReceiveRelayWake, func(err error) {
			select {
			case listenerErrors <- err:
			default:
			}
		})
	}()
	defer func() {
		stopListener()
		<-listenerDone
	}()
	select {
	case <-listener.Ready():
	case err := <-listenerErrors:
		t.Fatalf("relay wake listener failed before readiness: %v", err)
	case <-ctx.Done():
		t.Fatal("relay wake listener did not become ready")
	}

	handlerA := serverA.Handler()
	handlerB := serverB.Handler()
	authority := provisionRelayTestAuthority(t, handlerA, operatorToken, 1_000, 252, 253)
	basePath := "/v1/relay/tenants/" + authority.Domain.TenantID.String() +
		"/domains/" + authority.Domain.DomainID.String()
	recipientSubscriptionID := uuid.New()
	createSubscription := performRelayJSON(
		t, handlerA, http.MethodPost, basePath+"/subscriptions",
		relay.SubscriptionCreateRequest{
			RetryID: uuid.New(), SubscriptionID: recipientSubscriptionID,
			CreatedAtMilliseconds: 1_100,
		},
		authority.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, createSubscription, http.StatusCreated)
	_ = createSubscription.Body.Close()
	createMember := performRelayJSON(
		t, handlerA, http.MethodPost, basePath+"/members",
		map[string]any{
			"subscriptionID": recipientSubscriptionID,
			"capabilities":   []string{"message_fetch"},
		},
		authority.AdministrationCredential.AuthorizationToken, uuid.Nil,
	)
	requireStatus(t, createMember, http.StatusCreated)
	var recipient struct {
		Member     relay.SubscriptionMemberRegistration `json:"member"`
		Credential relayMemberCredential                `json:"credential"`
	}
	if err := json.NewDecoder(createMember.Body).Decode(&recipient); err != nil {
		t.Fatal(err)
	}
	_ = createMember.Body.Close()

	remoteHint := serverB.relayWakeBroker.subscribe(authority.Domain.TenantID, authority.Domain.DomainID)
	wakeResponse := make(chan *http.Response, 1)
	go func() {
		request := httptest.NewRequest(
			http.MethodGet,
			basePath+"/messages/wake?waitMilliseconds=5000",
			nil,
		)
		request.Header.Set("Authorization", "Bearer "+recipient.Credential.AuthorizationToken)
		request.Header.Set("X-Facets-Member-ID", recipient.Member.MemberRegistration.MemberID.String())
		recorder := httptest.NewRecorder()
		handlerB.ServeHTTP(recorder, request)
		wakeResponse <- recorder.Result()
	}()
	select {
	case <-storeB.firstFetch:
	case <-ctx.Done():
		t.Fatal("instance B waiter did not perform its authoritative pre-wait fetch")
	}

	fixture, err := testfixture.LoadRelayCarrier()
	if err != nil {
		t.Fatal(err)
	}
	firstEnvelope := fixture.Envelope
	firstEnvelope.TenantID = authority.Domain.TenantID
	firstEnvelope.DomainID = authority.Domain.DomainID
	firstEnvelope.MessageID = uuid.New()
	firstEnvelope.PublisherMemberID = authority.Member.MemberID
	firstEnvelope.CreatedAtMilliseconds = 1_500
	firstPublish := performRelayJSON(
		t, handlerA, http.MethodPut,
		basePath+"/messages/"+firstEnvelope.MessageID.String(), firstEnvelope,
		authority.MemberCredential.AuthorizationToken, authority.Member.MemberID,
	)
	requireStatus(t, firstPublish, http.StatusCreated)
	_ = firstPublish.Body.Close()
	select {
	case <-remoteHint:
	case err := <-listenerErrors:
		t.Fatalf("instance B listener failed before cross-instance wake: %v", err)
	case <-ctx.Done():
		t.Fatal("publish through instance A did not feed instance B's local broker")
	}
	select {
	case response := <-wakeResponse:
		requireStatus(t, response, http.StatusOK)
		var body struct {
			Changed bool `json:"changed"`
		}
		if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if !body.Changed {
			t.Fatal("instance B waiter did not discover the committed message")
		}
	case <-ctx.Done():
		t.Fatal("instance B waiter did not return after cross-instance wake")
	}

	stopListener()
	select {
	case <-listenerDone:
	case <-ctx.Done():
		t.Fatal("relay wake listener did not stop cleanly")
	}
	missedHint := serverB.relayWakeBroker.subscribe(authority.Domain.TenantID, authority.Domain.DomainID)
	secondEnvelope := firstEnvelope
	secondEnvelope.MessageID = uuid.New()
	secondEnvelope.CreatedAtMilliseconds++
	secondPublish := performRelayJSON(
		t, handlerA, http.MethodPut,
		basePath+"/messages/"+secondEnvelope.MessageID.String(), secondEnvelope,
		authority.MemberCredential.AuthorizationToken, authority.Member.MemberID,
	)
	requireStatus(t, secondPublish, http.StatusCreated)
	_ = secondPublish.Body.Close()
	select {
	case <-missedHint:
		t.Fatal("stopped instance B listener unexpectedly received a wake hint")
	case <-time.After(50 * time.Millisecond):
	}
	fallback := performRelayJSON(
		t, handlerB, http.MethodGet,
		basePath+"/messages/wake?cursor="+relay.EncodeCursor(1)+"&waitMilliseconds=100",
		nil, recipient.Credential.AuthorizationToken,
		recipient.Member.MemberRegistration.MemberID,
	)
	requireStatus(t, fallback, http.StatusOK)
	_ = fallback.Body.Close()
}

func openRelayWakePool(
	t *testing.T,
	ctx context.Context,
	databaseURL string,
) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	return pool
}

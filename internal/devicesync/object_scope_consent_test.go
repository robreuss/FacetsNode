package devicesync

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func objectConsentFixture() (ObjectScopeConsentMutation, SpaceSponsorCredential) {
	m := ObjectScopeConsentMutation{Consent: ObjectScopeConsent{
		Version: 1, BindingID: uuid.New(), ContentEpoch: math.MaxUint64, ContentScopeID: uuid.New(), DomainID: uuid.New(),
		LedgerID: uuid.New(), LinkID: uuid.New(), LinkIntentDigest: strings.Repeat("a", 64), PoolID: uuid.New(), PrincipalID: uuid.New(), SpaceID: uuid.New(),
	}, ParticipantDeviceID: uuid.New(), RetryID: uuid.New()}
	c := SpaceSponsorCredential{Administration: relay.AdministrationCredential{TenantID: m.Consent.PrincipalID, DomainID: m.Consent.DomainID},
		Control: relay.Credential{MemberID: m.ParticipantDeviceID}, Space: relay.Credential{MemberID: m.ParticipantDeviceID}}
	return m, c
}

func TestObjectScopeConsentExactIdentity(t *testing.T) {
	m, credential := objectConsentFixture()
	if err := m.Validate(credential); err != nil {
		t.Fatal(err)
	}
	ref, err := m.Consent.ReferenceDigest()
	if err != nil || len(ref) != 64 {
		t.Fatal(ref, err)
	}
	body, _ := json.Marshal(m.Consent)
	var decoded ObjectScopeConsent
	if err := json.Unmarshal(body, &decoded); err != nil || decoded != m.Consent {
		t.Fatal("full UInt64 did not roundtrip", err)
	}
	for name, change := range map[string]func(*ObjectScopeConsent){
		"binding":   func(c *ObjectScopeConsent) { c.BindingID = uuid.New() },
		"epoch":     func(c *ObjectScopeConsent) { c.ContentEpoch-- },
		"scope":     func(c *ObjectScopeConsent) { c.ContentScopeID = uuid.New() },
		"domain":    func(c *ObjectScopeConsent) { c.DomainID = uuid.New() },
		"ledger":    func(c *ObjectScopeConsent) { c.LedgerID = uuid.New() },
		"link":      func(c *ObjectScopeConsent) { c.LinkID = uuid.New() },
		"intent":    func(c *ObjectScopeConsent) { c.LinkIntentDigest = strings.Repeat("b", 64) },
		"pool":      func(c *ObjectScopeConsent) { c.PoolID = uuid.New() },
		"principal": func(c *ObjectScopeConsent) { c.PrincipalID = uuid.New() },
		"space":     func(c *ObjectScopeConsent) { c.SpaceID = uuid.New() },
	} {
		t.Run(name, func(t *testing.T) {
			copy := m.Consent
			change(&copy)
			other, err := copy.ReferenceDigest()
			if err != nil || other == ref {
				t.Fatal("identity was not bound", err)
			}
		})
	}
	for _, change := range []func(*ObjectScopeConsent){
		func(c *ObjectScopeConsent) { c.Version++ }, func(c *ObjectScopeConsent) { c.ContentEpoch = 0 },
		func(c *ObjectScopeConsent) { c.BindingID = uuid.Nil }, func(c *ObjectScopeConsent) { c.ContentScopeID = uuid.Nil },
		func(c *ObjectScopeConsent) { c.DomainID = uuid.Nil }, func(c *ObjectScopeConsent) { c.LedgerID = uuid.Nil },
		func(c *ObjectScopeConsent) { c.LinkID = uuid.Nil }, func(c *ObjectScopeConsent) { c.PoolID = uuid.Nil },
		func(c *ObjectScopeConsent) { c.PrincipalID = uuid.Nil }, func(c *ObjectScopeConsent) { c.SpaceID = uuid.Nil },
		func(c *ObjectScopeConsent) { c.LinkIntentDigest = strings.Repeat("A", 64) },
		func(c *ObjectScopeConsent) { c.LinkIntentDigest = strings.Repeat("g", 64) },
	} {
		copy := m.Consent
		change(&copy)
		if copy.Validate() == nil {
			t.Fatal("malformed consent accepted")
		}
	}
}

type objectConsentFakeStore struct {
	begin func(context.Context, SpaceSponsorCredential, ObjectScopeConsentMutation, serviceauthority.MutationAuthorization) (ObjectScopeConsentTransaction, error)
}

func (s objectConsentFakeStore) BeginObjectScopeConsentMutation(ctx context.Context, c SpaceSponsorCredential, m ObjectScopeConsentMutation, a serviceauthority.MutationAuthorization) (ObjectScopeConsentTransaction, error) {
	return s.begin(ctx, c, m, a)
}

type objectConsentFakeTransaction struct {
	commit func(context.Context, serviceauthority.MutationAuthorization) (ObjectScopeConsentStatus, error)
	closed bool
}

func (s *objectConsentFakeTransaction) Commit(ctx context.Context, a serviceauthority.MutationAuthorization) (ObjectScopeConsentStatus, error) {
	return s.commit(ctx, a)
}
func (s *objectConsentFakeTransaction) Close(context.Context) error { s.closed = true; return nil }

func TestObjectScopeConsentCustodyRechecksAfterWaitAndCleansUp(t *testing.T) {
	for _, mode := range []string{"success", "begin-failure", "cancel-during-begin", "commit-failure", "invalid-binding"} {
		t.Run(mode, func(t *testing.T) {
			m, c := objectConsentFixture()
			registry := serviceauthority.NewBindingRegistry()
			scope := serviceauthority.Scope{Kind: serviceauthority.ScopeDeviceSync, ScopeID: m.Consent.PrincipalID}
			binding := serviceauthority.RequestBinding{Scope: scope, AuthorityRevision: 1, AuthorityDigest: strings.Repeat("a", 64), DeploymentID: uuid.New(), RouteID: uuid.New(), TrafficClass: serviceauthority.TrafficControl}
			if err := registry.Activate(scope, serviceauthority.CurrentBinding{Revision: 1, Digest: binding.AuthorityDigest, DeploymentID: binding.DeploymentID}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			now := int64(1000)
			began, committed := false, false
			tx := &objectConsentFakeTransaction{commit: func(ctx context.Context, a serviceauthority.MutationAuthorization) (ObjectScopeConsentStatus, error) {
				committed = true
				if a.AuthorizedAtMilliseconds() != 2000 {
					t.Fatal("pre-wait authority reused")
				}
				if mode == "commit-failure" {
					return ObjectScopeConsentStatus{}, serviceauthority.ErrInvalid
				}
				return ObjectScopeConsentStatus{ReferenceDigest: strings.Repeat("a", 64)}, nil
			}}
			store := objectConsentFakeStore{begin: func(ctx context.Context, _ SpaceSponsorCredential, _ ObjectScopeConsentMutation, a serviceauthority.MutationAuthorization) (ObjectScopeConsentTransaction, error) {
				began = true
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > MaximumObjectScopeConsentDuration {
					t.Fatal("unbounded operation")
				}
				if a.AuthorizedAtMilliseconds() != 1000 {
					t.Fatal("wrong initial time")
				}
				now = 2000
				if mode == "begin-failure" {
					return nil, serviceauthority.ErrInvalid
				}
				if mode == "cancel-during-begin" {
					cancel()
				}
				return tx, nil
			}}
			custody := ObjectScopeConsentCustody{Store: store, Registry: registry, Now: func() time.Time { return time.UnixMilli(now) }}
			if mode == "invalid-binding" {
				binding.TrafficClass = serviceauthority.TrafficBulk
			}
			_, err := custody.Apply(ctx, c, m, binding)
			if (mode == "success") != (err == nil) {
				t.Fatal("unexpected result", err)
			}
			if mode == "invalid-binding" && began {
				t.Fatal("invalid input reached store")
			}
			if mode == "cancel-during-begin" && (!errors.Is(err, context.Canceled) || committed) {
				t.Fatal("cancelled request committed", err)
			}
			if began && mode != "begin-failure" && !tx.closed {
				t.Fatal("transaction leaked")
			}
			// A subsequent migration drain must not be held by this operation.
			drainContext, drainCancel := context.WithTimeout(context.Background(), time.Second)
			defer drainCancel()
			lease, err := registry.AcquireMigrationDrain(drainContext, scope)
			if err != nil {
				t.Fatal(err)
			}
			lease.Release()
		})
	}
}

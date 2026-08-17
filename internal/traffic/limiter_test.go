package traffic

import (
	"testing"
	"time"
)

func TestLimiterRefillsAndReturnsIntegerRetryAfter(t *testing.T) {
	limiter := newLimiter(
		Limit{RequestsPerMinute: 60, Burst: 2}, time.Minute, 4,
	)
	key := Key{1}
	now := time.Unix(1_000, 0)
	for index := 0; index < 2; index++ {
		if allowed, retry := limiter.Allow(key, now); !allowed || retry != 0 {
			t.Fatalf("burst request %d allowed=%v retry=%d", index, allowed, retry)
		}
	}
	if allowed, retry := limiter.Allow(key, now); allowed || retry != 1 {
		t.Fatalf("exhausted request allowed=%v retry=%d", allowed, retry)
	}
	if allowed, retry := limiter.Allow(key, now.Add(500*time.Millisecond)); allowed || retry != 1 {
		t.Fatalf("half-refill request allowed=%v retry=%d", allowed, retry)
	}
	if allowed, retry := limiter.Allow(key, now.Add(time.Second)); !allowed || retry != 0 {
		t.Fatalf("refilled request allowed=%v retry=%d", allowed, retry)
	}
}

func TestLimiterEvictsLeastRecentlyUsedAndExpiresIdleEntries(t *testing.T) {
	limiter := newLimiter(
		Limit{RequestsPerMinute: 60, Burst: 1}, 10*time.Second, 2,
	)
	now := time.Unix(1_000, 0)
	first, second, third := Key{1}, Key{2}, Key{3}
	limiter.Allow(first, now)
	limiter.Allow(second, now)
	limiter.Allow(first, now.Add(time.Second))
	limiter.Allow(third, now.Add(2*time.Second))
	if limiter.entryCount() != 2 {
		t.Fatalf("entry count after LRU eviction=%d", limiter.entryCount())
	}
	if _, found := limiter.entries[second]; found {
		t.Fatal("least recently used entry was retained")
	}
	if _, found := limiter.entries[first]; !found {
		t.Fatal("recently used entry was evicted")
	}
	limiter.Allow(Key{4}, now.Add(20*time.Second))
	if limiter.entryCount() != 1 {
		t.Fatalf("entry count after TTL expiry=%d", limiter.entryCount())
	}
}

func TestLimitsRejectZeroAndValuesBeyondHardCaps(t *testing.T) {
	valid := DefaultLimits()
	for _, mutate := range []func(*Limit){
		func(limit *Limit) { limit.RequestsPerMinute = 0 },
		func(limit *Limit) { limit.RequestsPerMinute = MaximumRequestsPerMinute + 1 },
		func(limit *Limit) { limit.Burst = 0 },
		func(limit *Limit) { limit.Burst = MaximumBurst + 1 },
		func(limit *Limit) { limit.ConnectionRequestsPerMinute = 0 },
		func(limit *Limit) { limit.ConnectionRequestsPerMinute = MaximumRequestsPerMinute + 1 },
		func(limit *Limit) { limit.ConnectionBurst = 0 },
		func(limit *Limit) { limit.ConnectionBurst = MaximumBurst + 1 },
		func(limit *Limit) { limit.Concurrency = 0 },
		func(limit *Limit) { limit.Concurrency = MaximumConcurrency + 1 },
	} {
		candidate := valid
		limit := candidate[SurfaceRelayMessage]
		mutate(&limit)
		candidate[SurfaceRelayMessage] = limit
		if err := ValidateLimits(candidate); err == nil {
			t.Fatal("invalid traffic limit was accepted")
		}
	}
}

func TestLimiterClockRollbackDoesNotMintFutureRefill(t *testing.T) {
	limiter := newLimiter(
		Limit{RequestsPerMinute: 60, Burst: 1}, time.Minute, 4,
	)
	key := Key{9}
	now := time.Unix(1_000, 0)
	if allowed, _ := limiter.Allow(key, now); !allowed {
		t.Fatal("initial request was rejected")
	}
	if allowed, _ := limiter.Allow(key, now.Add(-time.Minute)); allowed {
		t.Fatal("clock rollback refilled the bucket")
	}
	if allowed, _ := limiter.Allow(key, now); allowed {
		t.Fatal("clock rollback moved lastSeen backward and minted refill")
	}
	if allowed, _ := limiter.Allow(key, now.Add(time.Second)); !allowed {
		t.Fatal("ordinary forward time did not refill the bucket")
	}
}

package traffic

import (
	"container/list"
	"math"
	"sync"
	"time"
)

const LimiterEntryTTL = 15 * time.Minute

type Key [32]byte

type limiterEntry struct {
	key      Key
	tokens   float64
	lastSeen time.Time
	element  *list.Element
}

type Limiter struct {
	mu                sync.Mutex
	requestsPerSecond float64
	burst             float64
	entryTTL          time.Duration
	maximumEntries    int
	entries           map[Key]*limiterEntry
	recency           *list.List
}

func NewLimiter(limit Limit) *Limiter {
	return newLimiter(limit, LimiterEntryTTL, MaximumLimiterEntries)
}

func newLimiter(limit Limit, entryTTL time.Duration, maximumEntries int) *Limiter {
	return &Limiter{
		requestsPerSecond: float64(limit.RequestsPerMinute) / 60,
		burst:             float64(limit.Burst),
		entryTTL:          entryTTL,
		maximumEntries:    maximumEntries,
		entries:           make(map[Key]*limiterEntry, maximumEntries),
		recency:           list.New(),
	}
}

// Allow consumes one token. retryAfterSeconds is a positive integer only when
// the request is rejected.
func (l *Limiter) Allow(key Key, now time.Time) (allowed bool, retryAfterSeconds int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expire(now)
	entry := l.entries[key]
	if entry == nil {
		if len(l.entries) >= l.maximumEntries {
			l.remove(l.recency.Back())
		}
		entry = &limiterEntry{key: key, tokens: l.burst, lastSeen: now}
		entry.element = l.recency.PushFront(entry)
		l.entries[key] = entry
	} else {
		elapsed := now.Sub(entry.lastSeen).Seconds()
		if elapsed > 0 {
			entry.tokens = math.Min(l.burst, entry.tokens+elapsed*l.requestsPerSecond)
			entry.lastSeen = now
		}
		l.recency.MoveToFront(entry.element)
	}
	if entry.tokens >= 1 {
		entry.tokens--
		return true, 0
	}
	seconds := int(math.Ceil((1 - entry.tokens) / l.requestsPerSecond))
	if seconds < 1 {
		seconds = 1
	}
	return false, seconds
}

func (l *Limiter) expire(now time.Time) {
	for element := l.recency.Back(); element != nil; element = l.recency.Back() {
		entry := element.Value.(*limiterEntry)
		if now.Sub(entry.lastSeen) < l.entryTTL {
			return
		}
		l.remove(element)
	}
}

func (l *Limiter) remove(element *list.Element) {
	if element == nil {
		return
	}
	entry := element.Value.(*limiterEntry)
	delete(l.entries, entry.key)
	l.recency.Remove(element)
}

func (l *Limiter) entryCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

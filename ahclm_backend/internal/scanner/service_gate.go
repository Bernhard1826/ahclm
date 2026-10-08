package scanner

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// serviceGate paces requests to one external evidence service and honors its
// rate limiting. After HTTP 429 it stops sending until the service's
// Retry-After or reset header (or a bounded exponential backoff) has passed,
// so the monitor does not turn a throttled service into a stream of failed
// lookups.
type serviceGate struct {
	name        string
	minInterval time.Duration

	mu        sync.Mutex
	next      time.Time // earliest time the next request may start
	coolUntil time.Time
	backoff   time.Duration

	cacheTTL time.Duration
	cache    map[string]gateEntry
	order    []string
	maxCache int
}

type gateEntry struct {
	at    time.Time
	ttl   time.Duration
	value interface{}
}

func newServiceGate(name string, minInterval, cacheTTL time.Duration, maxCache int) *serviceGate {
	return &serviceGate{name: name, minInterval: minInterval, cacheTTL: cacheTTL, cache: make(map[string]gateEntry), maxCache: maxCache}
}

// cached returns a stored result for key if it is still fresh.
func (g *serviceGate) cached(key string, now time.Time) (interface{}, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	entry, ok := g.cache[key]
	ttl := entry.ttl
	if ttl <= 0 {
		ttl = g.cacheTTL
	}
	if !ok || now.Sub(entry.at) > ttl {
		return nil, false
	}
	return entry.value, true
}

func (g *serviceGate) store(key string, value interface{}, now time.Time) {
	g.storeFor(key, value, now, 0)
}

// storeFor keeps a result for a specific time. Lookups by certificate
// fingerprint or serial describe one immutable certificate and can be kept
// longer than lookups by domain, which gain entries as new certificates issue.
func (g *serviceGate) storeFor(key string, value interface{}, now time.Time, ttl time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.cache[key]; !exists {
		g.order = append(g.order, key)
	}
	g.cache[key] = gateEntry{at: now, ttl: ttl, value: value}
	for len(g.order) > g.maxCache {
		delete(g.cache, g.order[0])
		g.order = g.order[1:]
	}
}

// reserve returns how long the caller must wait before sending, or an error
// while the service is cooling down after rate limiting.
func (g *serviceGate) reserve(now time.Time) (time.Duration, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.Before(g.coolUntil) {
		return 0, fmt.Errorf("%s lookup skipped: service rate-limited this monitor; next attempt after %s", g.name, g.coolUntil.UTC().Format(time.RFC3339))
	}
	start := now
	if g.next.After(start) {
		start = g.next
	}
	g.next = start.Add(g.minInterval)
	return start.Sub(now), nil
}

func (g *serviceGate) needsCooldownRefresh(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.backoff > 0 && now.Before(g.coolUntil)
}

func (g *serviceGate) clearCooldown() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.coolUntil = time.Time{}
	g.backoff = 0
}

func (g *serviceGate) setCooldown(until time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	// This method is for authoritative provider state (for example /v1/limits),
	// so it must replace any older local fallback deadline in either direction.
	g.coolUntil = until
	g.backoff = 0
}

// observe records the response status. 429 starts or extends a cooldown.
func (g *serviceGate) observe(resp *http.Response, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		if resp != nil && resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
			g.backoff = 0
		}
		return
	}
	wait := rateLimitWait(resp.Header, now)
	if wait <= 0 {
		if g.backoff == 0 {
			g.backoff = time.Minute
		} else if g.backoff < 5*time.Minute {
			g.backoff *= 2
			if g.backoff > 5*time.Minute {
				g.backoff = 5 * time.Minute
			}
		}
		wait = g.backoff
	}
	if until := now.Add(wait); until.After(g.coolUntil) {
		g.coolUntil = until
	}
}

// rateLimitWait accepts both Retry-After and the common reset headers. Reset
// values may be either a delta in seconds or an absolute Unix timestamp.
func rateLimitWait(header http.Header, now time.Time) time.Duration {
	if wait := retryAfter(headerValue(header, "Retry-After"), now); wait > 0 {
		return wait
	}
	for _, key := range []string{"RateLimit-Reset", "X-RateLimit-Reset"} {
		value := strings.TrimSpace(headerValue(header, key))
		seconds, err := strconv.ParseInt(value, 10, 64)
		if err != nil || seconds <= 0 {
			continue
		}
		if seconds > now.Unix() {
			return time.Unix(seconds, 0).Sub(now)
		}
		return time.Duration(seconds) * time.Second
	}
	return 0
}

func headerValue(header http.Header, key string) string {
	if value := header.Get(key); value != "" {
		return value
	}
	for name, values := range header {
		if strings.EqualFold(name, key) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func retryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil && at.After(now) {
		return at.Sub(now)
	}
	return 0
}

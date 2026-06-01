package auth

import (
	"net"
	"sync"
	"time"
)

// RateLimiter tracks authentication failures per IP and bans abusive sources.
type RateLimiter struct {
	mu          sync.Mutex
	failures    map[string]*failureRecord
	maxFailures int
	window      time.Duration
	banDuration time.Duration
	stopChan    chan struct{}
}

type failureRecord struct {
	count      int
	firstSeen  time.Time
	bannedTill time.Time
}

// NewRateLimiter creates a rate limiter that bans an IP for banDuration
// after maxFailures failed attempts within window.
func NewRateLimiter(maxFailures int, window, banDuration time.Duration) *RateLimiter {
	rl := &RateLimiter{
		failures:    make(map[string]*failureRecord),
		maxFailures: maxFailures,
		window:      window,
		banDuration: banDuration,
		stopChan:    make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

// Close stops the background cleanup goroutine and releases resources.
func (rl *RateLimiter) Close() {
	close(rl.stopChan)
}

// IsBanned reports whether the given remote address is currently banned.
func (rl *RateLimiter) IsBanned(addr net.Addr) bool {
	ip := extractIP(addr)
	if ip == "" {
		return false
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rec, ok := rl.failures[ip]
	if !ok {
		return false
	}
	return time.Now().Before(rec.bannedTill)
}

// RecordFailure increments the failure count for an IP. If the count exceeds
// maxFailures within window, the IP is banned for banDuration.
func (rl *RateLimiter) RecordFailure(addr net.Addr) {
	ip := extractIP(addr)
	if ip == "" {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	rec, ok := rl.failures[ip]

	// Reset window if record does not exist, or window expired and IP is not currently banned
	if !ok || (now.Sub(rec.firstSeen) > rl.window && now.After(rec.bannedTill)) {
		rl.failures[ip] = &failureRecord{count: 1, firstSeen: now}
		return
	}

	// Already banned: do nothing, let the ban expire naturally
	if now.Before(rec.bannedTill) {
		return
	}

	rec.count++
	if rec.count >= rl.maxFailures {
		rec.bannedTill = now.Add(rl.banDuration)
	}
}

// RecordSuccess clears the failure record for an IP on successful auth.
func (rl *RateLimiter) RecordSuccess(addr net.Addr) {
	ip := extractIP(addr)
	if ip == "" {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.failures, ip)
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for ip, rec := range rl.failures {
				// Only cleanup if window expired and IP is not actively banned
				if now.Sub(rec.firstSeen) > rl.window && now.After(rec.bannedTill) {
					delete(rl.failures, ip)
				}
			}
			rl.mu.Unlock()
		case <-rl.stopChan:
			return
		}
	}
}

func extractIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	return host
}

package server

import (
	"sync"
	"time"

	"github.com/user/dns-as-doh/internal/crypto"
)

// Security provides rate limiting and replay detection.
type Security struct {
	rateLimiter    *RateLimiter
	replayDetector *crypto.ReplayDetector
}

// NewSecurity creates a new security handler.
func NewSecurity(rateLimit int) *Security {
	return &Security{
		rateLimiter:    NewRateLimiter(rateLimit, time.Second),
		replayDetector: crypto.NewReplayDetector(crypto.ReplayWindow),
	}
}

// CheckRateLimit checks if the request is within rate limits.
func (s *Security) CheckRateLimit(ip string) bool {
	return s.rateLimiter.Allow(ip)
}

// CheckReplay checks if the nonce has been seen before.
func (s *Security) CheckReplay(nonce []byte) bool {
	return s.replayDetector.Check(nonce)
}

// RateLimiter implements a simple per-IP rate limiter.
type RateLimiter struct {
	limit    int
	window   time.Duration
	counters map[string]*counter
	mu       sync.RWMutex
}

type counter struct {
	count       int
	windowStart time.Time
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		limit:    limit,
		window:   window,
		counters: make(map[string]*counter),
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// Allow checks if a request from the given key should be allowed.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	c, ok := rl.counters[key]
	if !ok || now.Sub(c.windowStart) >= rl.window {
		// New window
		rl.counters[key] = &counter{
			count:       1,
			windowStart: now,
		}
		return true
	}

	// Existing window
	if c.count >= rl.limit {
		return false
	}

	c.count++
	return true
}

// cleanup removes old counters periodically.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.window * 2)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, c := range rl.counters {
			if now.Sub(c.windowStart) >= rl.window*2 {
				delete(rl.counters, key)
			}
		}
		rl.mu.Unlock()
	}
}

// InputValidator validates incoming DNS messages.
type InputValidator struct {
	maxQuerySize   int
	maxNameLength  int
	maxLabelLength int
	allowedQTypes  map[uint16]bool
}

// NewInputValidator creates a new input validator.
func NewInputValidator() *InputValidator {
	return &InputValidator{
		maxQuerySize:   4096,
		maxNameLength:  255,
		maxLabelLength: 63,
		allowedQTypes: map[uint16]bool{
			1:  true, // A
			28: true, // AAAA
			16: true, // TXT
		},
	}
}

// ValidateQuery validates an incoming DNS query.
func (v *InputValidator) ValidateQuery(data []byte) error {
	if len(data) > v.maxQuerySize {
		return &ValidationError{Message: "query too large"}
	}

	if len(data) < 12 {
		return &ValidationError{Message: "query too small"}
	}

	return nil
}

// ValidationError represents a validation error.
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

// ConnectionTracker tracks active connections for monitoring.
type ConnectionTracker struct {
	connections map[string]*ConnectionInfo
	mu          sync.RWMutex
}

// ConnectionInfo holds information about a connection.
type ConnectionInfo struct {
	IP         string
	FirstSeen  time.Time
	LastSeen   time.Time
	QueryCount int64
}

// NewConnectionTracker creates a new connection tracker.
func NewConnectionTracker() *ConnectionTracker {
	ct := &ConnectionTracker{
		connections: make(map[string]*ConnectionInfo),
	}

	// Start cleanup goroutine
	go ct.cleanup()

	return ct
}

// Track records a query from an IP.
func (ct *ConnectionTracker) Track(ip string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	now := time.Now()
	info, ok := ct.connections[ip]
	if !ok {
		ct.connections[ip] = &ConnectionInfo{
			IP:         ip,
			FirstSeen:  now,
			LastSeen:   now,
			QueryCount: 1,
		}
		return
	}

	info.LastSeen = now
	info.QueryCount++
}

// GetStats returns connection statistics.
func (ct *ConnectionTracker) GetStats() map[string]*ConnectionInfo {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	result := make(map[string]*ConnectionInfo)
	for k, v := range ct.connections {
		result[k] = &ConnectionInfo{
			IP:         v.IP,
			FirstSeen:  v.FirstSeen,
			LastSeen:   v.LastSeen,
			QueryCount: v.QueryCount,
		}
	}
	return result
}

// cleanup removes old connections periodically.
func (ct *ConnectionTracker) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		ct.mu.Lock()
		cutoff := time.Now().Add(-10 * time.Minute)
		for key, info := range ct.connections {
			if info.LastSeen.Before(cutoff) {
				delete(ct.connections, key)
			}
		}
		ct.mu.Unlock()
	}
}

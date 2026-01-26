package server

import (
	"testing"
	"time"
)

func TestNewSecurity(t *testing.T) {
	security := NewSecurity(100)
	if security == nil {
		t.Fatal("NewSecurity returned nil")
	}

	if security.rateLimiter == nil {
		t.Error("Rate limiter is nil")
	}

	if security.replayDetector == nil {
		t.Error("Replay detector is nil")
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(10, time.Second)

	ip := "192.168.1.1"

	// Should allow first 10 requests
	for i := 0; i < 10; i++ {
		if !rl.Allow(ip) {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 11th request should be denied
	if rl.Allow(ip) {
		t.Error("11th request should be denied")
	}

	// Different IP should be allowed
	if !rl.Allow("192.168.1.2") {
		t.Error("Different IP should be allowed")
	}
}

func TestRateLimiterWindow(t *testing.T) {
	rl := NewRateLimiter(5, 100*time.Millisecond)

	ip := "192.168.1.1"

	// Use up the limit
	for i := 0; i < 5; i++ {
		rl.Allow(ip)
	}

	// Should be denied
	if rl.Allow(ip) {
		t.Error("Should be denied after limit")
	}

	// Wait for window to reset
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again
	if !rl.Allow(ip) {
		t.Error("Should be allowed after window reset")
	}
}

func TestReplayDetector(t *testing.T) {
	security := NewSecurity(100)

	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

	// First check should not be replay
	if security.CheckReplay(nonce) {
		t.Error("First nonce should not be detected as replay")
	}

	// Second check should be replay
	if !security.CheckReplay(nonce) {
		t.Error("Second check should be detected as replay")
	}

	// Different nonce should not be replay
	nonce2 := []byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
	if security.CheckReplay(nonce2) {
		t.Error("Different nonce should not be detected as replay")
	}
}

func TestInputValidator(t *testing.T) {
	validator := NewInputValidator()

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid query",
			data:    make([]byte, 100),
			wantErr: false,
		},
		{
			name:    "too small",
			data:    make([]byte, 10),
			wantErr: true,
		},
		{
			name:    "too large",
			data:    make([]byte, 5000),
			wantErr: true,
		},
		{
			name:    "empty",
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateQuery(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateQuery() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConnectionTracker(t *testing.T) {
	ct := NewConnectionTracker()

	ip1 := "192.168.1.1"
	ip2 := "192.168.1.2"

	// Track some connections
	ct.Track(ip1)
	ct.Track(ip1)
	ct.Track(ip2)

	stats := ct.GetStats()
	if len(stats) != 2 {
		t.Errorf("Stats count: got %d, want 2", len(stats))
	}

	if stats[ip1].QueryCount != 2 {
		t.Errorf("IP1 query count: got %d, want 2", stats[ip1].QueryCount)
	}

	if stats[ip2].QueryCount != 1 {
		t.Errorf("IP2 query count: got %d, want 1", stats[ip2].QueryCount)
	}
}

func TestSecurityCheckRateLimit(t *testing.T) {
	security := NewSecurity(5)

	ip := "192.168.1.1"

	// Should allow first 5
	for i := 0; i < 5; i++ {
		if !security.CheckRateLimit(ip) {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 6th should be denied
	if security.CheckRateLimit(ip) {
		t.Error("6th request should be denied")
	}
}

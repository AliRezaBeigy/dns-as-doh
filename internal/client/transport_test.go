package client

import (
	"context"
	"testing"
	"time"
)

func TestNewTransport(t *testing.T) {
	resolvers := []string{"8.8.8.8:53", "1.1.1.1:53"}
	timeout := 2 * time.Second

	transport := NewTransport(resolvers, timeout)
	if transport == nil {
		t.Fatal("NewTransport returned nil")
	}

	if len(transport.resolvers) != len(resolvers) {
		t.Errorf("Resolver count: got %d, want %d", len(transport.resolvers), len(resolvers))
	}

	if transport.timeout != timeout {
		t.Errorf("Timeout: got %v, want %v", transport.timeout, timeout)
	}
}

func TestTransportGetStats(t *testing.T) {
	transport := NewTransport([]string{"8.8.8.8:53"}, time.Second)

	stats := transport.GetStats()
	if len(stats) != 1 {
		t.Errorf("Stats count: got %d, want 1", len(stats))
	}

	if stats["8.8.8.8:53"] == nil {
		t.Error("Stats for resolver not found")
	}
}

func TestAntiFingerprint(t *testing.T) {
	config := DefaultAntiFingerConfig()
	config.MinDelay = 0
	config.MaxDelay = 50 * time.Millisecond
	af := NewAntiFingerprinting(config)

	// Test random delay
	delay := af.GetRandomDelay()
	if delay < 0 || delay > 50*time.Millisecond {
		t.Errorf("Delay out of range: got %v", delay)
	}

	// Test random padding
	padding := af.GetRandomPadding(3, 8)
	if len(padding) < 3 || len(padding) > 8 {
		t.Errorf("Padding length out of range: got %d", len(padding))
	}
}

func TestRandomizeQueryType(t *testing.T) {
	types := make(map[uint16]int)
	for i := 0; i < 1000; i++ {
		qtype := RandomizeQueryType()
		types[qtype]++
	}

	// Should have some variation
	if len(types) < 2 {
		t.Error("Query types should vary")
	}
}

func TestObfuscateSize(t *testing.T) {
	data := []byte{1, 2, 3}
	obfuscated := ObfuscateSize(data, 10, 20)

	if len(obfuscated) < 10 || len(obfuscated) > 20 {
		t.Errorf("Obfuscated size out of range: got %d", len(obfuscated))
	}

	// Original data should be preserved at the beginning
	for i := range data {
		if obfuscated[i] != data[i] {
			t.Errorf("Original data not preserved at index %d", i)
		}
	}
}

func TestVaryTTL(t *testing.T) {
	baseTTL := uint32(300)
	ttl := VaryTTL(baseTTL)

	// Should be within ±20% of base
	minTTL := baseTTL - baseTTL/5
	maxTTL := baseTTL + baseTTL/5

	if ttl < minTTL || ttl > maxTTL {
		t.Errorf("TTL out of range: got %d, want [%d, %d]", ttl, minTTL, maxTTL)
	}
}

func TestVaryResponseDelay(t *testing.T) {
	delay := VaryResponseDelay()

	if delay < 10*time.Millisecond || delay > 100*time.Millisecond {
		t.Errorf("Delay out of range: got %v", delay)
	}
}

func TestRandomizePort(t *testing.T) {
	ports := make(map[int]bool)
	for i := 0; i < 100; i++ {
		port := RandomizePort()
		if port < 49152 || port > 65535 {
			t.Errorf("Port out of ephemeral range: got %d", port)
		}
		ports[port] = true
	}

	// Should have some variation
	if len(ports) < 10 {
		t.Error("Ports should vary")
	}
}

func TestTransportClose(t *testing.T) {
	transport := NewTransport([]string{"8.8.8.8:53"}, time.Second)

	// Should not panic
	transport.Close()
}

func TestTransportContextCancellation(t *testing.T) {
	transport := NewTransport([]string{"8.8.8.8:53"}, time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Query should fail quickly due to cancellation
	_, err := transport.Query(ctx, []byte{0x12, 0x34})
	if err == nil {
		t.Error("Expected error for cancelled context")
	}
}

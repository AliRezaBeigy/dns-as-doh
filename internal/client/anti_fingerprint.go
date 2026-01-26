package client

import (
	"crypto/rand"
	"time"
)

// Anti-fingerprinting constants
const (
	// Default timing randomization range
	DefaultMinDelay = 0
	DefaultMaxDelay = 50 * time.Millisecond

	// Query size randomization
	MinQueryPadding = 3
	MaxQueryPadding = 8
)

// AntiFingerprinting provides traffic analysis resistance features.
type AntiFingerprinting struct {
	minDelay time.Duration
	maxDelay time.Duration
	enabled  bool
	dummyGen *DummyQueryGenerator
}

// AntiFingerConfig holds anti-fingerprinting configuration.
type AntiFingerConfig struct {
	// Enabled enables anti-fingerprinting features
	Enabled bool

	// MinDelay is the minimum random delay
	MinDelay time.Duration

	// MaxDelay is the maximum random delay
	MaxDelay time.Duration

	// DummyDomains is a list of legitimate domains for dummy queries
	DummyDomains []string

	// DummyInterval is the interval between dummy queries
	DummyInterval time.Duration
}

// DefaultAntiFingerConfig returns the default anti-fingerprinting config.
func DefaultAntiFingerConfig() *AntiFingerConfig {
	return &AntiFingerConfig{
		Enabled:  true,
		MinDelay: DefaultMinDelay,
		MaxDelay: DefaultMaxDelay,
		DummyDomains: []string{
			"google.com",
			"microsoft.com",
			"apple.com",
			"amazon.com",
			"facebook.com",
			"twitter.com",
			"github.com",
			"cloudflare.com",
		},
		DummyInterval: 30 * time.Second,
	}
}

// NewAntiFingerprinting creates a new anti-fingerprinting handler.
func NewAntiFingerprinting(config *AntiFingerConfig) *AntiFingerprinting {
	af := &AntiFingerprinting{
		minDelay: config.MinDelay,
		maxDelay: config.MaxDelay,
		enabled:  config.Enabled,
	}
	return af
}

// GetRandomDelay returns a random delay for timing obfuscation.
func (af *AntiFingerprinting) GetRandomDelay() time.Duration {
	if !af.enabled || af.maxDelay <= af.minDelay {
		return 0
	}

	diff := af.maxDelay - af.minDelay
	randVal := randomUint64() % uint64(diff)
	return af.minDelay + time.Duration(randVal)
}

// GetRandomPadding returns random bytes for size obfuscation.
func (af *AntiFingerprinting) GetRandomPadding(min, max int) []byte {
	if !af.enabled || max <= min {
		return nil
	}

	var randByte [1]byte
	rand.Read(randByte[:])
	size := min + int(randByte[0])%(max-min+1)

	padding := make([]byte, size)
	rand.Read(padding)
	return padding
}

// randomUint64 generates a random uint64.
func randomUint64() uint64 {
	var buf [8]byte
	rand.Read(buf[:])
	return uint64(buf[0])<<56 | uint64(buf[1])<<48 |
		uint64(buf[2])<<40 | uint64(buf[3])<<32 |
		uint64(buf[4])<<24 | uint64(buf[5])<<16 |
		uint64(buf[6])<<8 | uint64(buf[7])
}

// RandomizeQueryType randomly selects a query type.
// This helps avoid patterns of always using TXT queries.
func RandomizeQueryType() uint16 {
	var buf [1]byte
	rand.Read(buf[:])

	// 80% TXT, 10% A, 10% AAAA
	switch {
	case buf[0] < 205: // ~80%
		return 16 // TXT
	case buf[0] < 230: // ~10%
		return 1 // A
	default: // ~10%
		return 28 // AAAA
	}
}

// ShouldSendDummy returns true if a dummy query should be sent.
func (af *AntiFingerprinting) ShouldSendDummy() bool {
	if !af.enabled {
		return false
	}

	var buf [1]byte
	rand.Read(buf[:])

	// 5% chance to send dummy
	return buf[0] < 13
}

// ObfuscateSize pads data to a random size within bounds.
func ObfuscateSize(data []byte, minSize, maxSize int) []byte {
	if len(data) >= maxSize {
		return data
	}

	targetSize := minSize
	if maxSize > minSize {
		var buf [1]byte
		rand.Read(buf[:])
		targetSize = minSize + int(buf[0])%(maxSize-minSize+1)
	}

	if len(data) >= targetSize {
		return data
	}

	result := make([]byte, targetSize)
	copy(result, data)
	// Fill rest with random data
	rand.Read(result[len(data):])
	return result
}

// VaryTTL returns a randomized TTL value within realistic bounds.
func VaryTTL(baseTTL uint32) uint32 {
	var buf [2]byte
	rand.Read(buf[:])

	// Vary by ±20%
	variance := (uint32(buf[0])<<8 | uint32(buf[1])) % (baseTTL / 5)
	if buf[0]&1 == 0 {
		return baseTTL + variance
	}
	if baseTTL > variance {
		return baseTTL - variance
	}
	return baseTTL
}

// VaryResponseDelay adds realistic response delay (10-100ms).
func VaryResponseDelay() time.Duration {
	var buf [1]byte
	rand.Read(buf[:])
	return 10*time.Millisecond + time.Duration(buf[0])*time.Millisecond*90/255
}

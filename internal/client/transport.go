package client

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AliRezaBeigy/dns-as-doh/internal/dns"
)

// Transport handles UDP DNS communication with parallel resolver support.
type Transport struct {
	resolvers []string
	timeout   time.Duration
	stats     map[string]*ResolverStats
	statsMu   sync.RWMutex
}

// ResolverStats tracks resolver performance.
type ResolverStats struct {
	Queries      uint64
	Successes    uint64
	Failures     uint64
	TotalLatency time.Duration
}

// NewTransport creates a new transport with the given resolvers.
func NewTransport(resolvers []string, timeout time.Duration) *Transport {
	t := &Transport{
		resolvers: resolvers,
		timeout:   timeout,
		stats:     make(map[string]*ResolverStats),
	}

	// Initialize stats for each resolver
	for _, r := range resolvers {
		t.stats[r] = &ResolverStats{}
	}

	return t
}

// Query sends a DNS query to all resolvers in parallel and returns the first valid response.
func (t *Transport) Query(ctx context.Context, query []byte) ([]byte, error) {
	if len(t.resolvers) == 0 {
		return nil, errors.New("no resolvers configured")
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()

	// Channel for results
	type result struct {
		data     []byte
		resolver string
		latency  time.Duration
		err      error
	}

	results := make(chan result, len(t.resolvers))
	var wg sync.WaitGroup

	// Send to all resolvers in parallel
	for _, resolver := range t.resolvers {
		wg.Add(1)
		go func(resolver string) {
			defer wg.Done()

			start := time.Now()
			data, err := t.queryResolver(ctx, resolver, query)
			latency := time.Since(start)

			select {
			case results <- result{data: data, resolver: resolver, latency: latency, err: err}:
			case <-ctx.Done():
			}
		}(resolver)
	}

	// Close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Wait for first valid response
	var lastErr error
	for r := range results {
		// Update stats
		t.updateStats(r.resolver, r.err == nil, r.latency)

		if r.err != nil {
			lastErr = r.err
			continue
		}

		// Got a valid response - cancel other queries
		cancel()

		return r.data, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("all resolvers failed")
}

// queryResolver sends a query to a single resolver.
func (t *Transport) queryResolver(ctx context.Context, resolver string, query []byte) ([]byte, error) {
	// Resolve address
	addr, err := net.ResolveUDPAddr("udp", resolver)
	if err != nil {
		return nil, fmt.Errorf("invalid resolver address: %w", err)
	}

	// Create UDP connection with random local port
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Set deadlines based on context
	deadline, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	}

	// Send query
	_, err = conn.Write(query)
	if err != nil {
		return nil, fmt.Errorf("failed to send query: %w", err)
	}

	// Read response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return buf[:n], nil
}

// updateStats updates resolver statistics.
func (t *Transport) updateStats(resolver string, success bool, latency time.Duration) {
	t.statsMu.Lock()
	defer t.statsMu.Unlock()

	stats, ok := t.stats[resolver]
	if !ok {
		return
	}

	atomic.AddUint64(&stats.Queries, 1)
	if success {
		atomic.AddUint64(&stats.Successes, 1)
		stats.TotalLatency += latency
	} else {
		atomic.AddUint64(&stats.Failures, 1)
	}
}

// GetStats returns resolver statistics.
func (t *Transport) GetStats() map[string]*ResolverStats {
	t.statsMu.RLock()
	defer t.statsMu.RUnlock()

	// Create a copy
	result := make(map[string]*ResolverStats)
	for k, v := range t.stats {
		result[k] = &ResolverStats{
			Queries:      atomic.LoadUint64(&v.Queries),
			Successes:    atomic.LoadUint64(&v.Successes),
			Failures:     atomic.LoadUint64(&v.Failures),
			TotalLatency: v.TotalLatency,
		}
	}
	return result
}

// Close closes the transport.
func (t *Transport) Close() {
	// Nothing to close for now
}

// AntiFingerprint provides anti-fingerprinting utilities.
type AntiFingerprint struct {
	minDelay time.Duration
	maxDelay time.Duration
}

// NewAntiFingerprint creates a new anti-fingerprinting helper.
func NewAntiFingerprint(minDelay, maxDelay time.Duration) *AntiFingerprint {
	return &AntiFingerprint{
		minDelay: minDelay,
		maxDelay: maxDelay,
	}
}

// RandomDelay returns a random delay within the configured range.
func (af *AntiFingerprint) RandomDelay() time.Duration {
	if af.maxDelay <= af.minDelay {
		return af.minDelay
	}

	var randBytes [8]byte
	rand.Read(randBytes[:])
	randVal := uint64(randBytes[0])<<56 | uint64(randBytes[1])<<48 |
		uint64(randBytes[2])<<40 | uint64(randBytes[3])<<32 |
		uint64(randBytes[4])<<24 | uint64(randBytes[5])<<16 |
		uint64(randBytes[6])<<8 | uint64(randBytes[7])

	diff := af.maxDelay - af.minDelay
	return af.minDelay + time.Duration(randVal%uint64(diff))
}

// ApplyDelay applies a random delay.
func (af *AntiFingerprint) ApplyDelay(ctx context.Context) error {
	delay := af.RandomDelay()
	select {
	case <-time.After(delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RandomizePort generates a random UDP source port.
func RandomizePort() int {
	var buf [2]byte
	rand.Read(buf[:])
	// Use ephemeral port range (49152-65535)
	port := int(buf[0])<<8 | int(buf[1])
	return 49152 + (port % 16384)
}

// DummyQueryGenerator periodically sends dummy queries to blend traffic.
type DummyQueryGenerator struct {
	domains   []string
	interval  time.Duration
	transport *Transport
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// NewDummyQueryGenerator creates a new dummy query generator.
func NewDummyQueryGenerator(domains []string, interval time.Duration, transport *Transport) *DummyQueryGenerator {
	ctx, cancel := context.WithCancel(context.Background())
	return &DummyQueryGenerator{
		domains:   domains,
		interval:  interval,
		transport: transport,
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start starts generating dummy queries.
func (dq *DummyQueryGenerator) Start() {
	dq.wg.Add(1)
	go dq.generateLoop()
}

// Stop stops generating dummy queries.
func (dq *DummyQueryGenerator) Stop() {
	dq.cancel()
	dq.wg.Wait()
}

// generateLoop generates periodic dummy queries.
func (dq *DummyQueryGenerator) generateLoop() {
	defer dq.wg.Done()

	ticker := time.NewTicker(dq.interval)
	defer ticker.Stop()

	af := NewAntiFingerprint(0, dq.interval/2)

	for {
		select {
		case <-dq.ctx.Done():
			return
		case <-ticker.C:
			// Add some jitter
			af.ApplyDelay(dq.ctx)

			// Generate a dummy query
			dq.sendDummyQuery()
		}
	}
}

// sendDummyQuery sends a dummy DNS query to a random domain.
func (dq *DummyQueryGenerator) sendDummyQuery() {
	if len(dq.domains) == 0 {
		return
	}

	// Select random domain
	var buf [1]byte
	rand.Read(buf[:])
	domain := dq.domains[int(buf[0])%len(dq.domains)]

	// Create a simple A query
	name, err := dns.ParseName(domain)
	if err != nil {
		return
	}

	query := dns.CreateQuery(name, dns.RRTypeA, dns.GenerateQueryID())
	query.AddEDNS0(4096)

	data, err := query.Marshal()
	if err != nil {
		return
	}

	// Send query (ignore response)
	ctx, cancel := context.WithTimeout(dq.ctx, time.Second)
	defer cancel()

	dq.transport.Query(ctx, data)
}

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/AliRezaBeigy/dns-as-doh/internal/dns"
)

// ResolverType represents the type of upstream resolver.
type ResolverType string

const (
	ResolverTypeUDP ResolverType = "udp"
	ResolverTypeDoH ResolverType = "doh"
	ResolverTypeDoT ResolverType = "dot"
)

// Resolver performs real DNS resolution.
type Resolver struct {
	upstream     string
	resolverType ResolverType
	timeout      time.Duration

	// For DoH
	httpClient *http.Client

	// For DoT
	tlsConfig *tls.Config
	dotPool   *connPool
}

// NewResolver creates a new resolver.
func NewResolver(upstream string, resolverType string) (*Resolver, error) {
	r := &Resolver{
		upstream:     upstream,
		resolverType: ResolverType(resolverType),
		timeout:      5 * time.Second,
	}

	switch r.resolverType {
	case ResolverTypeUDP:
		// Nothing special to initialize

	case ResolverTypeDoH:
		r.httpClient = &http.Client{
			Timeout: r.timeout,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     60 * time.Second,
			},
		}

	case ResolverTypeDoT:
		host, _, err := net.SplitHostPort(upstream)
		if err != nil {
			host = upstream
			r.upstream = host + ":853"
		}
		r.tlsConfig = &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		}
		r.dotPool = newConnPool(10, r.timeout)

	default:
		return nil, fmt.Errorf("unknown resolver type: %s", resolverType)
	}

	return r, nil
}

// Resolve performs DNS resolution.
func (r *Resolver) Resolve(ctx context.Context, query *dns.Message) (*dns.Message, error) {
	// Marshal query
	queryData, err := query.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	var respData []byte

	switch r.resolverType {
	case ResolverTypeUDP:
		respData, err = r.resolveUDP(ctx, queryData)
	case ResolverTypeDoH:
		respData, err = r.resolveDoH(ctx, queryData)
	case ResolverTypeDoT:
		respData, err = r.resolveDoT(ctx, queryData)
	default:
		err = fmt.Errorf("unknown resolver type: %s", r.resolverType)
	}

	if err != nil {
		return nil, err
	}

	// Parse response
	response, err := dns.ParseMessage(respData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Ensure response ID matches query
	response.ID = query.ID

	return response, nil
}

// resolveUDP resolves via UDP DNS.
func (r *Resolver) resolveUDP(ctx context.Context, query []byte) ([]byte, error) {
	// Create UDP connection
	conn, err := net.Dial("udp", r.upstream)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Set deadline from context
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(r.timeout))
	}

	// Send query
	_, err = conn.Write(query)
	if err != nil {
		return nil, fmt.Errorf("failed to send query: %w", err)
	}

	// Read response
	buf := make([]byte, dns.MaxEDNSSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return buf[:n], nil
}

// resolveDoH resolves via DNS over HTTPS.
func (r *Resolver) resolveDoH(ctx context.Context, query []byte) ([]byte, error) {
	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", r.upstream, bytes.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	// Send request
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH returned status: %d", resp.StatusCode)
	}

	// Read response
	respData, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxEDNSSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return respData, nil
}

// resolveDoT resolves via DNS over TLS.
func (r *Resolver) resolveDoT(ctx context.Context, query []byte) ([]byte, error) {
	// Get connection from pool or create new one
	conn, err := r.getDoTConnection()
	if err != nil {
		return nil, fmt.Errorf("failed to get DoT connection: %w", err)
	}

	// Set deadline from context
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(r.timeout))
	}

	// Send length-prefixed query (TCP DNS format)
	lenBuf := []byte{byte(len(query) >> 8), byte(len(query))}
	_, err = conn.Write(append(lenBuf, query...))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send query: %w", err)
	}

	// Read length-prefixed response
	respLenBuf := make([]byte, 2)
	_, err = io.ReadFull(conn, respLenBuf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read response length: %w", err)
	}

	respLen := int(respLenBuf[0])<<8 | int(respLenBuf[1])
	if respLen > dns.MaxEDNSSize {
		conn.Close()
		return nil, fmt.Errorf("response too large: %d", respLen)
	}

	respData := make([]byte, respLen)
	_, err = io.ReadFull(conn, respData)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Return connection to pool
	r.dotPool.put(conn)

	return respData, nil
}

// getDoTConnection gets a DoT connection from the pool or creates a new one.
func (r *Resolver) getDoTConnection() (net.Conn, error) {
	// Try to get from pool
	if conn := r.dotPool.get(); conn != nil {
		return conn, nil
	}

	// Create new connection
	dialer := &net.Dialer{Timeout: r.timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", r.upstream, r.tlsConfig)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// Close closes the resolver.
func (r *Resolver) Close() {
	if r.dotPool != nil {
		r.dotPool.close()
	}
}

// connPool is a simple connection pool.
type connPool struct {
	conns   []net.Conn
	mu      sync.Mutex
	maxSize int
	timeout time.Duration
}

func newConnPool(maxSize int, timeout time.Duration) *connPool {
	return &connPool{
		maxSize: maxSize,
		timeout: timeout,
	}
}

func (p *connPool) get() net.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.conns) == 0 {
		return nil
	}

	conn := p.conns[len(p.conns)-1]
	p.conns = p.conns[:len(p.conns)-1]
	return conn
}

func (p *connPool) put(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.conns) >= p.maxSize {
		conn.Close()
		return
	}

	p.conns = append(p.conns, conn)
}

func (p *connPool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range p.conns {
		conn.Close()
	}
	p.conns = nil
}

// ParseUpstreamConfig parses an upstream resolver configuration string.
// Formats:
// - "8.8.8.8:53" or "8.8.8.8" (UDP DNS)
// - "https://dns.google/dns-query" (DoH)
// - "dns.google:853" (DoT)
func ParseUpstreamConfig(config string) (upstream string, resolverType string, error error) {
	config = strings.TrimSpace(config)

	// Check for DoH
	if strings.HasPrefix(config, "https://") {
		return config, "doh", nil
	}

	// Check for DoT (explicit port 853)
	if strings.HasSuffix(config, ":853") {
		return config, "dot", nil
	}

	// Default to UDP
	if !strings.Contains(config, ":") {
		config = config + ":53"
	}
	return config, "udp", nil
}

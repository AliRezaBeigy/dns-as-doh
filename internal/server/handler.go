// Package server implements the DNS tunnel server.
package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/AliRezaBeigy/dns-as-doh/internal/crypto"
	"github.com/AliRezaBeigy/dns-as-doh/internal/dns"
)

// Config holds the server configuration.
type Config struct {
	// ListenAddr is the UDP address to listen on (default: :53)
	ListenAddr string

	// Domain is the domain this server is authoritative for
	Domain string

	// SharedSecret is the encryption key
	SharedSecret []byte

	// UpstreamResolver is the upstream DNS resolver for real queries
	// Can be UDP DNS (8.8.8.8:53), DoH URL, or DoT address
	UpstreamResolver string

	// UpstreamType is the type of upstream resolver (udp, doh, dot)
	UpstreamType string

	// MaxUDPSize is the maximum UDP payload size
	MaxUDPSize int

	// ResponseTTL is the TTL for responses
	ResponseTTL uint32

	// MaxConcurrent is the maximum concurrent queries
	MaxConcurrent int

	// RateLimit is the per-IP rate limit (queries per second)
	RateLimit int
}

// DefaultConfig returns a default server configuration.
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:       ":53",
		UpstreamResolver: "8.8.8.8:53",
		UpstreamType:     "udp",
		MaxUDPSize:       1232,
		ResponseTTL:      60,
		MaxConcurrent:    1000,
		RateLimit:        100,
	}
}

// Handler is the DNS tunnel server handler.
type Handler struct {
	config   *Config
	domain   dns.Name
	cipher   *crypto.Cipher
	resolver *Resolver
	security *Security
	conn     *net.UDPConn
	sem      chan struct{}
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewHandler creates a new server handler.
func NewHandler(config *Config) (*Handler, error) {
	// Parse domain
	domain, err := dns.ParseName(config.Domain)
	if err != nil {
		return nil, fmt.Errorf("invalid domain: %w", err)
	}

	// Create cipher (server side)
	cipher, err := crypto.NewCipher(config.SharedSecret, false) // isClient=false
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create resolver
	resolver, err := NewResolver(config.UpstreamResolver, config.UpstreamType)
	if err != nil {
		return nil, fmt.Errorf("failed to create resolver: %w", err)
	}

	// Create security handler
	security := NewSecurity(config.RateLimit)

	ctx, cancel := context.WithCancel(context.Background())

	h := &Handler{
		config:   config,
		domain:   domain,
		cipher:   cipher,
		resolver: resolver,
		security: security,
		sem:      make(chan struct{}, config.MaxConcurrent),
		ctx:      ctx,
		cancel:   cancel,
	}

	return h, nil
}

// Start starts the server handler.
func (h *Handler) Start() error {
	// Parse listen address
	addr, err := net.ResolveUDPAddr("udp", h.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}

	// Create UDP listener
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	h.conn = conn

	log.Printf("DNS server listening on %s", h.config.ListenAddr)
	log.Printf("Authoritative for domain: %s", h.domain.String())
	log.Printf("Upstream resolver: %s (%s)", h.config.UpstreamResolver, h.config.UpstreamType)

	// Start accept loop
	h.wg.Add(1)
	go h.acceptLoop()

	return nil
}

// Stop stops the server handler.
func (h *Handler) Stop() {
	h.cancel()
	if h.conn != nil {
		h.conn.Close()
	}
	h.resolver.Close()
	h.wg.Wait()
}

// acceptLoop accepts incoming DNS queries.
func (h *Handler) acceptLoop() {
	defer h.wg.Done()

	buf := make([]byte, dns.MaxEDNSSize)
	for {
		select {
		case <-h.ctx.Done():
			return
		default:
		}

		// Set read deadline
		_ = h.conn.SetReadDeadline(time.Now().Add(time.Second))

		n, addr, err := h.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if h.ctx.Err() != nil {
				return
			}
			log.Printf("read error: %v", err)
			continue
		}

		// Check rate limit
		if !h.security.CheckRateLimit(addr.IP.String()) {
			continue
		}

		// Copy the data
		data := make([]byte, n)
		copy(data, buf[:n])

		// Acquire semaphore
		select {
		case h.sem <- struct{}{}:
		case <-h.ctx.Done():
			return
		}

		// Handle query in goroutine
		h.wg.Add(1)
		go func(data []byte, addr *net.UDPAddr) {
			defer h.wg.Done()
			defer func() { <-h.sem }()

			h.handleQuery(data, addr)
		}(data, addr)
	}
}

// handleQuery handles a single DNS query.
func (h *Handler) handleQuery(data []byte, addr *net.UDPAddr) {
	// Parse DNS message
	query, err := dns.ParseMessage(data)
	if err != nil {
		log.Printf("failed to parse query from %s: %v", addr, err)
		return
	}

	// Must be a query
	if query.IsResponse() {
		return
	}

	// Validate query
	if err := dns.ValidateQuery(query, h.domain, uint16(h.config.MaxUDPSize)); err != nil {
		if err == dns.ErrNotAuthoritative {
			h.sendError(query, addr, dns.RcodeNameError)
		} else {
			h.sendError(query, addr, dns.RcodeFormatError)
		}
		return
	}

	// Process the tunnel query
	response, err := h.processTunnelQuery(h.ctx, query)
	if err != nil {
		log.Printf("tunnel query processing failed: %v", err)
		h.sendError(query, addr, dns.RcodeServerFail)
		return
	}

	// Add anti-fingerprinting delay
	time.Sleep(varyResponseDelay())

	// Send response
	respData, err := response.Marshal()
	if err != nil {
		log.Printf("failed to marshal response: %v", err)
		return
	}

	// Truncate if necessary
	if len(respData) > h.config.MaxUDPSize {
		respData = respData[:h.config.MaxUDPSize]
		respData[2] |= 0x02 // Set TC bit
	}

	_, _ = h.conn.WriteToUDP(respData, addr)
}

// processTunnelQuery processes a tunnel query and returns the response.
func (h *Handler) processTunnelQuery(ctx context.Context, query *dns.Message) (*dns.Message, error) {
	// Extract the encrypted payload from the query name
	clientID, encryptedPayload, err := dns.ExtractQueryPayload(query, h.domain)
	if err != nil {
		return nil, fmt.Errorf("failed to extract payload: %w", err)
	}

	_ = clientID // ClientID can be used for session tracking if needed

	// Decrypt the payload
	decryptedQuery, err := h.cipher.Decrypt(encryptedPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %w", err)
	}

	// Parse the original DNS query
	originalQuery, err := dns.ParseMessage(decryptedQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to parse original query: %w", err)
	}

	// Resolve the actual DNS query
	dnsResponse, err := h.resolver.Resolve(ctx, originalQuery)
	if err != nil {
		return nil, fmt.Errorf("upstream resolution failed: %w", err)
	}
	if dnsResponse == nil {
		return nil, fmt.Errorf("upstream resolver returned nil response")
	}

	// Marshal the DNS response
	responseData, err := dnsResponse.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal DNS response: %w", err)
	}

	// Encrypt the response
	encryptedResponse, err := h.cipher.EncryptWithoutTimestamp(responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt response: %w", err)
	}

	// Create the tunnel response
	ttl := varyTTL(h.config.ResponseTTL)
	response, err := dns.CreateTunnelResponse(query, h.domain, encryptedResponse, ttl)
	if err != nil {
		return nil, fmt.Errorf("failed to create tunnel response: %w", err)
	}

	return response, nil
}

// sendError sends a DNS error response.
func (h *Handler) sendError(query *dns.Message, addr *net.UDPAddr, rcode uint16) {
	if query == nil {
		return
	}
	resp := dns.CreateErrorResponse(query, h.domain, rcode)

	data, err := resp.Marshal()
	if err != nil {
		return
	}

	_, _ = h.conn.WriteToUDP(data, addr)
}

// varyTTL adds randomness to TTL.
func varyTTL(baseTTL uint32) uint32 {
	var buf [1]byte
	_, _ = crypto.GenerateKey() // Just to ensure random is initialized
	buf[0] = byte(time.Now().UnixNano())

	// Vary by ±30 seconds
	variance := uint32(buf[0]) % 60
	if buf[0]&1 == 0 && baseTTL > variance {
		return baseTTL - variance/2
	}
	return baseTTL + variance/2
}

// varyResponseDelay adds random delay (10-100ms).
func varyResponseDelay() time.Duration {
	var buf [1]byte
	buf[0] = byte(time.Now().UnixNano())
	return 10*time.Millisecond + time.Duration(buf[0])*90*time.Millisecond/255
}

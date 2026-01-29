// Package client implements the DNS tunnel client.
package client

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

// Config holds the client configuration.
type Config struct {
	// ListenAddr is the address to listen for DNS queries (default: 127.0.0.1:53)
	ListenAddr string

	// ServerDomain is the tunnel server domain (e.g., t.example.com)
	ServerDomain string

	// Resolvers is a list of public DNS resolvers to use
	Resolvers []string

	// SharedSecret is the encryption key
	SharedSecret []byte

	// Timeout is the timeout for DNS queries
	Timeout time.Duration

	// MaxConcurrent is the maximum number of concurrent queries
	MaxConcurrent int
}

// DefaultConfig returns a default configuration.
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:    "127.0.0.1:53",
		Timeout:       2 * time.Second,
		MaxConcurrent: 100,
		Resolvers: []string{
			"8.8.8.8:53",
			"1.1.1.1:53",
			"9.9.9.9:53",
		},
	}
}

// Resolver is the DNS tunnel client resolver.
type Resolver struct {
	config    *Config
	domain    dns.Name
	cipher    *crypto.Cipher
	clientID  dns.ClientID
	transport *Transport
	conn      *net.UDPConn
	sem       chan struct{}
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewResolver creates a new client resolver.
func NewResolver(config *Config) (*Resolver, error) {
	// Parse server domain
	domain, err := dns.ParseName(config.ServerDomain)
	if err != nil {
		return nil, fmt.Errorf("invalid server domain: %w", err)
	}

	// Create cipher
	cipher, err := crypto.NewCipher(config.SharedSecret, true) // isClient=true
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Generate client ID for this session
	clientID := dns.NewClientID()

	ctx, cancel := context.WithCancel(context.Background())

	r := &Resolver{
		config:   config,
		domain:   domain,
		cipher:   cipher,
		clientID: clientID,
		sem:      make(chan struct{}, config.MaxConcurrent),
		ctx:      ctx,
		cancel:   cancel,
	}

	// Create transport with parallel resolver support
	r.transport = NewTransport(config.Resolvers, config.Timeout)

	return r, nil
}

// Start starts the resolver and begins accepting DNS queries.
func (r *Resolver) Start() error {
	// Parse listen address
	addr, err := net.ResolveUDPAddr("udp", r.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}

	// Create UDP listener
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", r.config.ListenAddr, err)
	}
	r.conn = conn

	log.Printf("DNS resolver listening on %s", r.config.ListenAddr)
	log.Printf("Server domain: %s", r.domain.String())
	log.Printf("Using %d resolvers", len(r.config.Resolvers))

	// Start accepting queries
	r.wg.Add(1)
	go r.acceptLoop()

	return nil
}

// Stop stops the resolver.
func (r *Resolver) Stop() {
	r.cancel()
	if r.conn != nil {
		r.conn.Close()
	}
	r.transport.Close()
	r.wg.Wait()
}

// ListenAddr returns the address the resolver is listening on.
func (r *Resolver) ListenAddr() string {
	return r.config.ListenAddr
}

// acceptLoop accepts incoming DNS queries.
func (r *Resolver) acceptLoop() {
	defer r.wg.Done()

	buf := make([]byte, dns.MaxEDNSSize)
	for {
		select {
		case <-r.ctx.Done():
			return
		default:
		}

		// Set read deadline
		_ = r.conn.SetReadDeadline(time.Now().Add(time.Second))

		n, addr, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if r.ctx.Err() != nil {
				return
			}
			log.Printf("read error: %v", err)
			continue
		}

		// Copy the data
		data := make([]byte, n)
		copy(data, buf[:n])

		// Acquire semaphore
		select {
		case r.sem <- struct{}{}:
		case <-r.ctx.Done():
			return
		}

		// Handle query in goroutine
		r.wg.Add(1)
		go func(data []byte, addr *net.UDPAddr) {
			defer r.wg.Done()
			defer func() { <-r.sem }()

			r.handleQuery(data, addr)
		}(data, addr)
	}
}

// handleQuery handles a single DNS query.
func (r *Resolver) handleQuery(data []byte, addr *net.UDPAddr) {
	// Parse the incoming DNS query
	query, err := dns.ParseMessage(data)
	if err != nil {
		log.Printf("failed to parse query: %v", err)
		return
	}

	// Must be a query
	if query.IsResponse() {
		return
	}

	// Must have exactly one question
	if len(query.Question) != 1 {
		r.sendError(query, addr, dns.RcodeFormatError)
		return
	}

	// Process the query through the tunnel
	response, err := r.processTunneledQuery(r.ctx, query)
	if err != nil {
		log.Printf("tunnel query failed: %v", err)
		r.sendError(query, addr, dns.RcodeServerFail)
		return
	}

	// Send response
	respData, err := response.Marshal()
	if err != nil {
		log.Printf("failed to marshal response: %v", err)
		return
	}

	_, _ = r.conn.WriteToUDP(respData, addr)
}

// processTunneledQuery sends a DNS query through the tunnel.
func (r *Resolver) processTunneledQuery(ctx context.Context, query *dns.Message) (*dns.Message, error) {
	// Marshal the original query
	originalData, err := query.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	// Encrypt the query
	encryptedQuery, err := r.cipher.Encrypt(originalData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt query: %w", err)
	}

	// Encode into DNS name
	tunnelName, err := dns.EncodePayload(encryptedQuery, r.clientID, r.domain)
	if err != nil {
		return nil, fmt.Errorf("failed to encode payload: %w", err)
	}

	// Create tunnel query
	tunnelQuery := &dns.Message{
		ID:    dns.GenerateQueryID(),
		Flags: 0x0100, // RD=1
		Question: []dns.Question{
			{
				Name:  tunnelName,
				Type:  dns.RRTypeTXT,
				Class: dns.ClassIN,
			},
		},
	}
	tunnelQuery.AddEDNS0(4096)

	// Marshal tunnel query
	tunnelData, err := tunnelQuery.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tunnel query: %w", err)
	}

	// Send to resolvers and get response
	respData, err := r.transport.Query(ctx, tunnelData)
	if err != nil {
		return nil, fmt.Errorf("transport query failed: %w", err)
	}

	// Parse tunnel response
	tunnelResp, err := dns.ParseMessage(respData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tunnel response: %w", err)
	}

	// Check for errors
	if tunnelResp.Rcode() != dns.RcodeNoError {
		return nil, fmt.Errorf("tunnel response error: %d", tunnelResp.Rcode())
	}

	// Extract payload from TXT record
	payload, err := dns.ExtractResponsePayload(tunnelResp, r.domain)
	if err != nil {
		return nil, fmt.Errorf("failed to extract response payload: %w", err)
	}

	// Decrypt the response
	decryptedResp, err := r.cipher.DecryptWithoutTimestamp(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt response: %w", err)
	}

	// Parse the original DNS response
	response, err := dns.ParseMessage(decryptedResp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse decrypted response: %w", err)
	}

	// Update response ID to match original query
	response.ID = query.ID

	return response, nil
}

// sendError sends a DNS error response.
func (r *Resolver) sendError(query *dns.Message, addr *net.UDPAddr, rcode uint16) {
	resp := dns.CreateResponse(query)
	resp.SetRcode(rcode)

	data, err := resp.Marshal()
	if err != nil {
		return
	}

	_, _ = r.conn.WriteToUDP(data, addr)
}

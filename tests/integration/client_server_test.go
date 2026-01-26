package integration

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/AliRezaBeigy/dns-as-doh/internal/client"
	"github.com/AliRezaBeigy/dns-as-doh/internal/dns"
	"github.com/AliRezaBeigy/dns-as-doh/internal/server"
	"github.com/AliRezaBeigy/dns-as-doh/tests/helpers"
)

// TestEnvironment holds a complete test environment with client, server, and mock upstream.
type TestEnvironment struct {
	Client       *client.Resolver
	Server       *server.Handler
	MockUpstream *helpers.MockUpstreamDNS
	Cleanup      func()
}

// SetupTestEnvironment creates a complete test environment.
func SetupTestEnvironment(t *testing.T) *TestEnvironment {
	t.Helper()

	// Generate shared secret
	secret := helpers.GenerateTestKey()

	// Pick ports
	clientPort := helpers.PickPort(t)
	serverPort := helpers.PickPort(t)
	upstreamPort := helpers.PickPort(t)

	// Create mock upstream DNS
	mockUpstream := helpers.NewMockUpstreamDNS(t, upstreamPort)

	// Create server config
	serverConfig := &server.Config{
		ListenAddr:       net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort)),
		Domain:           "t.example.com",
		SharedSecret:     secret,
		UpstreamResolver: mockUpstream.Address(),
		UpstreamType:     "udp",
		MaxUDPSize:       1232,
		ResponseTTL:      60,
		MaxConcurrent:    100,
		RateLimit:        1000, // High limit for testing
	}

	// Create and start server handler
	serverHandler, err := server.NewHandler(serverConfig)
	if err != nil {
		mockUpstream.Close()
		t.Fatalf("Failed to create server handler: %v", err)
	}

	if err := serverHandler.Start(); err != nil {
		mockUpstream.Close()
		t.Fatalf("Failed to start server: %v", err)
	}

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)

	// Create client config
	clientConfig := &client.Config{
		ListenAddr:    net.JoinHostPort("127.0.0.1", strconv.Itoa(clientPort)),
		ServerDomain:  "t.example.com",
		Resolvers:     []string{net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort))},
		SharedSecret:  secret,
		Timeout:       5 * time.Second,
		MaxConcurrent: 100,
	}

	// Create and start client resolver
	clientResolver, err := client.NewResolver(clientConfig)
	if err != nil {
		serverHandler.Stop()
		mockUpstream.Close()
		t.Fatalf("Failed to create client resolver: %v", err)
	}

	if err := clientResolver.Start(); err != nil {
		serverHandler.Stop()
		mockUpstream.Close()
		t.Fatalf("Failed to start client: %v", err)
	}

	// Wait for client to be ready
	time.Sleep(100 * time.Millisecond)

	cleanup := func() {
		clientResolver.Stop()
		serverHandler.Stop()
		mockUpstream.Close()
	}

	return &TestEnvironment{
		Client:       clientResolver,
		Server:       serverHandler,
		MockUpstream: mockUpstream,
		Cleanup:      cleanup,
	}
}

// TestClientServerFullCommunication tests the complete client-server communication flow.
func TestClientServerFullCommunication(t *testing.T) {
	env := SetupTestEnvironment(t)
	defer env.Cleanup()

	// Create a DNS query
	query := dns.CreateQuery(
		helpers.MustParseName("example.com"),
		dns.RRTypeA,
		0x1234,
	)
	query.AddEDNS0(4096)

	// Send query to client and get response
	response, err := helpers.SendQuery(t, env.Client.ListenAddr(), query, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to send query: %v", err)
	}

	// Verify response
	if !response.IsResponse() {
		t.Error("Response should have QR=1")
	}

	if response.Rcode() != dns.RcodeNoError {
		t.Errorf("Response RCODE: got %d, want %d", response.Rcode(), dns.RcodeNoError)
	}

	if len(response.Answer) == 0 {
		t.Error("Response should have at least one answer")
	}

	// Verify answer
	if response.Answer[0].Type != dns.RRTypeA {
		t.Errorf("Answer type: got %d, want %d", response.Answer[0].Type, dns.RRTypeA)
	}
}

// TestClientServerRoundTrip tests multiple query types through the tunnel.
func TestClientServerRoundTrip(t *testing.T) {
	env := SetupTestEnvironment(t)
	defer env.Cleanup()

	tests := []struct {
		name    string
		qname   string
		qtype   uint16
		wantErr bool
	}{
		{
			name:    "A query",
			qname:   "example.com",
			qtype:   dns.RRTypeA,
			wantErr: false,
		},
		{
			name:    "AAAA query",
			qname:   "example.com",
			qtype:   dns.RRTypeAAAA,
			wantErr: false,
		},
		{
			name:    "TXT query",
			qname:   "example.com",
			qtype:   dns.RRTypeTXT,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create query
			query := dns.CreateQuery(
				helpers.MustParseName(tt.qname),
				tt.qtype,
				dns.GenerateQueryID(),
			)
			query.AddEDNS0(4096)

			// Send and receive
			response, err := helpers.SendQuery(t, env.Client.ListenAddr(), query, 5*time.Second)
			if (err != nil) != tt.wantErr {
				t.Errorf("SendQuery() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			// Verify response
			if response.Rcode() != dns.RcodeNoError {
				t.Errorf("Response RCODE: got %d, want %d", response.Rcode(), dns.RcodeNoError)
			}

			if len(response.Answer) == 0 {
				t.Error("Response should have at least one answer")
			}
		})
	}
}

// TestClientServerEncryption verifies that encryption works end-to-end.
func TestClientServerEncryption(t *testing.T) {
	// Test that encryption is working end-to-end
	secret := helpers.GenerateTestKey()

	clientPort := helpers.PickPort(t)
	serverPort := helpers.PickPort(t)
	upstreamPort := helpers.PickPort(t)

	mockUpstream := helpers.NewMockUpstreamDNS(t, upstreamPort)
	defer mockUpstream.Close()

	// Create server
	serverConfig := &server.Config{
		ListenAddr:       net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort)),
		Domain:           "t.example.com",
		SharedSecret:     secret,
		UpstreamResolver: mockUpstream.Address(),
		UpstreamType:     "udp",
		MaxUDPSize:       1232,
		ResponseTTL:      60,
		MaxConcurrent:    100,
		RateLimit:        1000,
	}

	serverHandler, err := server.NewHandler(serverConfig)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	serverHandler.Start()
	defer serverHandler.Stop()

	time.Sleep(100 * time.Millisecond)

	// Create client with matching key
	clientConfig := &client.Config{
		ListenAddr:    net.JoinHostPort("127.0.0.1", strconv.Itoa(clientPort)),
		ServerDomain:  "t.example.com",
		Resolvers:     []string{net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort))},
		SharedSecret:  secret,
		Timeout:       5 * time.Second,
		MaxConcurrent: 100,
	}

	clientResolver, err := client.NewResolver(clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	clientResolver.Start()
	defer clientResolver.Stop()

	time.Sleep(100 * time.Millisecond)

	// Send query
	query := dns.CreateQuery(helpers.MustParseName("example.com"), dns.RRTypeA, 0x1234)
	query.AddEDNS0(4096)

	response, err := helpers.SendQuery(t, clientResolver.ListenAddr(), query, 5*time.Second)
	if err != nil {
		t.Fatalf("Query with matching keys failed: %v", err)
	}

	if response.Rcode() != dns.RcodeNoError {
		t.Errorf("Response RCODE: got %d, want %d", response.Rcode(), dns.RcodeNoError)
	}
}

// TestClientServerMultipleQueries tests handling of multiple sequential queries.
func TestClientServerMultipleQueries(t *testing.T) {
	env := SetupTestEnvironment(t)
	defer env.Cleanup()

	// Send multiple queries
	queries := []*dns.Message{
		dns.CreateQuery(helpers.MustParseName("example.com"), dns.RRTypeA, 0x1001),
		dns.CreateQuery(helpers.MustParseName("google.com"), dns.RRTypeA, 0x1002),
		dns.CreateQuery(helpers.MustParseName("github.com"), dns.RRTypeA, 0x1003),
	}

	for _, q := range queries {
		q.AddEDNS0(4096)
	}

	// Send queries sequentially
	for i, query := range queries {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			response, err := helpers.SendQuery(t, env.Client.ListenAddr(), query, 5*time.Second)
			if err != nil {
				t.Errorf("Query %d failed: %v", i, err)
				return
			}

			if response.Rcode() != dns.RcodeNoError {
				t.Errorf("Query %d RCODE: got %d, want %d", i, response.Rcode(), dns.RcodeNoError)
			}
		})
	}
}

// TestClientServerErrorHandling tests error handling for invalid queries.
func TestClientServerErrorHandling(t *testing.T) {
	env := SetupTestEnvironment(t)
	defer env.Cleanup()

	// Test invalid query (no questions)
	query := &dns.Message{
		ID:    0x1234,
		Flags: 0x0100,
		// No questions
	}

	response, err := helpers.SendQuery(t, env.Client.ListenAddr(), query, time.Second)
	if err != nil {
		// Expected - client should return error or format error response
		return
	}

	if response != nil && response.Rcode() != dns.RcodeFormatError {
		t.Errorf("Error RCODE: got %d, want %d", response.Rcode(), dns.RcodeFormatError)
	}
}

// TestClientServerConcurrentQueries tests handling of concurrent queries.
func TestClientServerConcurrentQueries(t *testing.T) {
	env := SetupTestEnvironment(t)
	defer env.Cleanup()

	// Create multiple queries
	numQueries := 10
	queries := make([]*dns.Message, numQueries)
	for i := 0; i < numQueries; i++ {
		queries[i] = dns.CreateQuery(
			helpers.MustParseName("example.com"),
			dns.RRTypeA,
			uint16(0x2000+i),
		)
		queries[i].AddEDNS0(4096)
	}

	// Send queries concurrently
	type result struct {
		response *dns.Message
		err      error
		index    int
	}
	results := make(chan result, numQueries)

	for i, query := range queries {
		go func(idx int, q *dns.Message) {
			resp, err := helpers.SendQuery(t, env.Client.ListenAddr(), q, 5*time.Second)
			results <- result{response: resp, err: err, index: idx}
		}(i, query)
	}

	// Collect results
	responses := make(map[int]*dns.Message)
	errors := make(map[int]error)

	for i := 0; i < numQueries; i++ {
		res := <-results
		responses[res.index] = res.response
		if res.err != nil {
			errors[res.index] = res.err
		}
	}

	// Verify all succeeded
	for i := 0; i < numQueries; i++ {
		if err, ok := errors[i]; ok {
			t.Errorf("Query %d failed: %v", i, err)
		}
		if resp := responses[i]; resp == nil {
			t.Errorf("Query %d has nil response", i)
		} else if resp.Rcode() != dns.RcodeNoError {
			t.Errorf("Query %d RCODE: got %d, want %d", i, resp.Rcode(), dns.RcodeNoError)
		}
	}
}

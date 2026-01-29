// Package helpers provides shared testing utilities for all tests.
package helpers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/AliRezaBeigy/dns-as-doh/internal/crypto"
	"github.com/AliRezaBeigy/dns-as-doh/internal/dns"
)

// MustParseName parses a DNS name or panics.
func MustParseName(s string) dns.Name {
	n, err := dns.ParseName(s)
	if err != nil {
		panic(fmt.Sprintf("failed to parse name %q: %v", s, err))
	}
	return n
}

// MustDecodeHex decodes a hex string or panics.
func MustDecodeHex(s string) []byte {
	if s == "" {
		return []byte{}
	}
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("failed to decode hex %q: %v", s, err))
	}
	return data
}

// GenerateTestKey generates a test encryption key.
func GenerateTestKey() []byte {
	key, err := crypto.GenerateKey()
	if err != nil {
		panic(fmt.Sprintf("failed to generate key: %v", err))
	}
	return key
}

// RandomBytes generates random bytes of the specified length.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate random bytes: %v", err))
	}
	return b
}

// PickPort picks an available UDP port for testing.
func PickPort(t *testing.T) int {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer conn.Close()

	return conn.LocalAddr().(*net.UDPAddr).Port
}

// PickPortString picks an available UDP port and returns it as a string.
func PickPortString(t *testing.T) string {
	t.Helper()
	return strconv.Itoa(PickPort(t))
}

// WaitForCondition waits for a condition to become true within a timeout.
func WaitForCondition(condition func() bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		select {
		case <-ticker.C:
			continue
		case <-time.After(time.Until(deadline)):
			return false
		}
	}
	return false
}

// CreateTestDNSQuery creates a test DNS query message.
func CreateTestDNSQuery(name string, qtype uint16) *dns.Message {
	return dns.CreateQuery(MustParseName(name), qtype, dns.GenerateQueryID())
}

// CreateTestDNSResponse creates a test DNS response message.
func CreateTestDNSResponse(query *dns.Message, data []byte) *dns.Message {
	resp := dns.CreateResponse(query)
	if len(query.Question) > 0 {
		resp.Answer = []dns.RR{
			{
				Name:  query.Question[0].Name,
				Type:  query.Question[0].Type,
				Class: dns.ClassIN,
				TTL:   300,
				Data:  data,
			},
		}
	}
	return resp
}

// MockUpstreamDNS is a mock DNS server for testing.
type MockUpstreamDNS struct {
	conn   *net.UDPConn
	ctx    context.Context
	cancel context.CancelFunc
	port   int
}

// NewMockUpstreamDNS creates a new mock DNS server.
func NewMockUpstreamDNS(t *testing.T, port int) *MockUpstreamDNS {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("Failed to resolve address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	mock := &MockUpstreamDNS{
		conn:   conn,
		ctx:    ctx,
		cancel: cancel,
		port:   conn.LocalAddr().(*net.UDPAddr).Port,
	}

	// Start handler
	go mock.handleQueries()

	return mock
}

// Port returns the port the mock DNS is listening on.
func (m *MockUpstreamDNS) Port() int {
	return m.port
}

// Address returns the address the mock DNS is listening on.
func (m *MockUpstreamDNS) Address() string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(m.port))
}

func (m *MockUpstreamDNS) handleQueries() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		_ = m.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := m.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		// Parse query
		query, err := dns.ParseMessage(buf[:n])
		if err != nil {
			continue
		}

		// Create response
		response := dns.CreateResponse(query)
		if len(query.Question) > 0 {
			response.Answer = []dns.RR{
				{
					Name:  query.Question[0].Name,
					Type:  query.Question[0].Type,
					Class: dns.ClassIN,
					TTL:   300,
					Data:  []byte{192, 168, 1, 1}, // 192.168.1.1
				},
			}
		}

		// Send response
		respData, _ := response.Marshal()
		_, _ = m.conn.WriteToUDP(respData, addr)
	}
}

// Close stops the mock DNS server.
func (m *MockUpstreamDNS) Close() {
	m.cancel()
	if m.conn != nil {
		m.conn.Close()
	}
}

// SendQuery sends a DNS query and returns the response.
func SendQuery(t *testing.T, addr string, query *dns.Message, timeout time.Duration) (*dns.Message, error) {
	t.Helper()

	queryData, err := query.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(queryData); err != nil {
		return nil, fmt.Errorf("failed to write: %w", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %w", err)
	}

	return dns.ParseMessage(buf[:n])
}

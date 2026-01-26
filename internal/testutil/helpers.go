// Package testutil provides testing utilities.
package testutil

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/AliRezaBeigy/dns-as-doh/internal/crypto"
	"github.com/AliRezaBeigy/dns-as-doh/internal/dns"
)

// MustParseName parses a DNS name or panics.
func MustParseName(s string) dns.Name {
	n, err := dns.ParseName(s)
	if err != nil {
		panic(err)
	}
	return n
}

// MustDecodeHex decodes a hex string or panics.
func MustDecodeHex(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

// GenerateTestKey generates a test encryption key.
func GenerateTestKey() []byte {
	key, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	return key
}

// RandomBytes generates random bytes of the specified length.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// PickPort picks an available UDP port.
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

// WaitForCondition waits for a condition to become true.
func WaitForCondition(condition func() bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
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
	resp.Answer = []dns.RR{
		{
			Name:  query.Question[0].Name,
			Type:  dns.RRTypeA,
			Class: dns.ClassIN,
			TTL:   300,
			Data:  data,
		},
	}
	return resp
}

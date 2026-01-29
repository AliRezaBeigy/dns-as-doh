package server

import (
	"net"
	"testing"
	"time"
)

func TestParseUpstreamConfig(t *testing.T) {
	tests := []struct {
		name         string
		config       string
		wantUpstream string
		wantType     string
		wantErr      bool
	}{
		{
			name:         "UDP DNS with port",
			config:       "8.8.8.8:53",
			wantUpstream: "8.8.8.8:53",
			wantType:     "udp",
			wantErr:      false,
		},
		{
			name:         "UDP DNS without port",
			config:       "8.8.8.8",
			wantUpstream: "8.8.8.8:53",
			wantType:     "udp",
			wantErr:      false,
		},
		{
			name:         "DoH URL",
			config:       "https://dns.google/dns-query",
			wantUpstream: "https://dns.google/dns-query",
			wantType:     "doh",
			wantErr:      false,
		},
		{
			name:         "DoT with port",
			config:       "dns.google:853",
			wantUpstream: "dns.google:853",
			wantType:     "dot",
			wantErr:      false,
		},
		{
			name:         "DoT without port defaults to UDP",
			config:       "dns.google",
			wantUpstream: "dns.google:53",
			wantType:     "udp",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream, resolverType, err := ParseUpstreamConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseUpstreamConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			if upstream != tt.wantUpstream {
				t.Errorf("Upstream: got %q, want %q", upstream, tt.wantUpstream)
			}

			if resolverType != tt.wantType {
				t.Errorf("Type: got %q, want %q", resolverType, tt.wantType)
			}
		})
	}
}

func TestNewResolver(t *testing.T) {
	tests := []struct {
		name         string
		upstream     string
		resolverType string
		wantErr      bool
	}{
		{
			name:         "UDP resolver",
			upstream:     "8.8.8.8:53",
			resolverType: "udp",
			wantErr:      false,
		},
		{
			name:         "DoH resolver",
			upstream:     "https://dns.google/dns-query",
			resolverType: "doh",
			wantErr:      false,
		},
		{
			name:         "DoT resolver",
			upstream:     "dns.google:853",
			resolverType: "dot",
			wantErr:      false,
		},
		{
			name:         "invalid type",
			upstream:     "8.8.8.8:53",
			resolverType: "invalid",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver, err := NewResolver(tt.upstream, tt.resolverType)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewResolver() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			if resolver == nil {
				t.Error("Resolver is nil")
				return
			}

			if resolver.upstream != tt.upstream {
				t.Errorf("Upstream: got %q, want %q", resolver.upstream, tt.upstream)
			}

			resolver.Close()
		})
	}
}

func TestConnPool(t *testing.T) {
	pool := newConnPool(5, time.Second)

	// Pool should start empty
	if pool.get() != nil {
		t.Error("Pool should start empty")
	}

	// Create mock UDP connections for testing
	conn1, err := net.Dial("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("Cannot create test connection: %v", err)
	}
	defer conn1.Close()

	conn2, err := net.Dial("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("Cannot create test connection: %v", err)
	}
	defer conn2.Close()

	// Put connections
	pool.put(conn1)
	pool.put(conn2)

	// Should be able to get them back
	retrieved := pool.get()
	if retrieved == nil {
		t.Error("Should be able to get connection from pool")
	}

	pool.close()
}

// DNS-as-DoH Server
// A DNS tunnel server that acts as an authoritative DNS server,
// decrypts queries, performs real DNS resolution, and returns encrypted responses.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/user/dns-as-doh/internal/crypto"
	"github.com/user/dns-as-doh/internal/server"
	"github.com/user/dns-as-doh/pkg/service"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	// Parse flags
	var (
		listenAddr   = flag.String("listen", ":53", "Address to listen for DNS queries")
		domain       = flag.String("domain", "", "Domain this server is authoritative for (e.g., t.example.com)")
		upstream     = flag.String("upstream", "8.8.8.8:53", "Upstream DNS resolver (UDP: 8.8.8.8:53, DoH: https://dns.google/dns-query, DoT: dns.google:853)")
		keyHex       = flag.String("key", "", "Encryption key (64 hex characters)")
		keyFile      = flag.String("key-file", "", "File containing the encryption key")
		maxUDPSize   = flag.Int("mtu", 1232, "Maximum UDP payload size")
		responseTTL  = flag.Uint("ttl", 60, "Response TTL in seconds")
		rateLimit    = flag.Int("rate-limit", 100, "Per-IP rate limit (queries per second)")
		showVersion  = flag.Bool("version", false, "Show version information")
		genKey       = flag.Bool("gen-key", false, "Generate a new encryption key")
		installSvc   = flag.Bool("install", false, "Install as system service")
		uninstallSvc = flag.Bool("uninstall", false, "Uninstall system service")
		runSvc       = flag.Bool("service", false, "Run as system service")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "DNS-as-DoH Server - DNS tunnel server\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nUpstream resolver formats:\n")
		fmt.Fprintf(os.Stderr, "  UDP DNS: 8.8.8.8:53 or 8.8.8.8\n")
		fmt.Fprintf(os.Stderr, "  DNS over HTTPS: https://dns.google/dns-query\n")
		fmt.Fprintf(os.Stderr, "  DNS over TLS: dns.google:853\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Generate a new key\n")
		fmt.Fprintf(os.Stderr, "  %s -gen-key\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Run server with UDP DNS upstream\n")
		fmt.Fprintf(os.Stderr, "  %s -domain t.example.com -key <hex-key>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Run server with DoH upstream\n")
		fmt.Fprintf(os.Stderr, "  %s -domain t.example.com -key <hex-key> -upstream https://dns.google/dns-query\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "DNS Zone Setup:\n")
		fmt.Fprintf(os.Stderr, "  A     tns.example.com  → <server-ip>\n")
		fmt.Fprintf(os.Stderr, "  AAAA  tns.example.com  → <server-ipv6>\n")
		fmt.Fprintf(os.Stderr, "  NS    t.example.com   → tns.example.com\n")
	}

	flag.Parse()

	// Handle version
	if *showVersion {
		fmt.Printf("dns-as-doh-server %s (%s) built %s\n", version, commit, date)
		return
	}

	// Handle key generation
	if *genKey {
		key, err := crypto.GenerateKey()
		if err != nil {
			log.Fatalf("Failed to generate key: %v", err)
		}
		fmt.Printf("Generated encryption key:\n%s\n", hex.EncodeToString(key))
		fmt.Println("\nSave this key securely and use it on both client and server.")
		return
	}

	// Handle service installation/uninstallation
	if *installSvc {
		if err := service.Install("dns-as-doh-server", "DNS-as-DoH Server", os.Args[1:]); err != nil {
			log.Fatalf("Failed to install service: %v", err)
		}
		fmt.Println("Service installed successfully")
		return
	}

	if *uninstallSvc {
		if err := service.Uninstall("dns-as-doh-server"); err != nil {
			log.Fatalf("Failed to uninstall service: %v", err)
		}
		fmt.Println("Service uninstalled successfully")
		return
	}

	// Validate required arguments
	if *domain == "" {
		log.Fatal("Domain is required (-domain)")
	}

	// Load encryption key
	var key []byte
	var err error

	if *keyFile != "" {
		keyData, err := os.ReadFile(*keyFile)
		if err != nil {
			log.Fatalf("Failed to read key file: %v", err)
		}
		key, err = hex.DecodeString(strings.TrimSpace(string(keyData)))
		if err != nil {
			log.Fatalf("Invalid key in file: %v", err)
		}
	} else if *keyHex != "" {
		key, err = hex.DecodeString(*keyHex)
		if err != nil {
			log.Fatalf("Invalid key format: %v", err)
		}
	} else {
		log.Fatal("Encryption key is required (-key or -key-file)")
	}

	if len(key) != crypto.KeySize {
		log.Fatalf("Key must be %d bytes (%d hex characters)", crypto.KeySize, crypto.KeySize*2)
	}

	// Parse upstream configuration
	upstreamAddr, upstreamType, err := server.ParseUpstreamConfig(*upstream)
	if err != nil {
		log.Fatalf("Invalid upstream configuration: %v", err)
	}

	// Create config
	config := &server.Config{
		ListenAddr:       *listenAddr,
		Domain:           *domain,
		SharedSecret:     key,
		UpstreamResolver: upstreamAddr,
		UpstreamType:     upstreamType,
		MaxUDPSize:       *maxUDPSize,
		ResponseTTL:      uint32(*responseTTL),
		MaxConcurrent:    1000,
		RateLimit:        *rateLimit,
	}

	// Run as service or standalone
	if *runSvc {
		if err := service.Run("dns-as-doh-server", func() error {
			return runServer(config)
		}, func() {
			// Stop handler - will be handled by signal
		}); err != nil {
			log.Fatalf("Service error: %v", err)
		}
	} else {
		if err := runServer(config); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}
}

func runServer(config *server.Config) error {
	// Create handler
	handler, err := server.NewHandler(config)
	if err != nil {
		return fmt.Errorf("failed to create handler: %w", err)
	}

	// Start handler
	if err := handler.Start(); err != nil {
		return fmt.Errorf("failed to start handler: %w", err)
	}

	log.Println("DNS tunnel server started")

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	log.Printf("Received signal %v, shutting down...", sig)

	// Stop handler
	handler.Stop()

	log.Println("Server stopped")
	return nil
}

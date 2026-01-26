// DNS-as-DoH Client
// A DNS tunnel client that encrypts DNS queries and sends them through
// public DNS resolvers to bypass DoH/DoT filtering.
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

	"github.com/user/dns-as-doh/internal/client"
	"github.com/user/dns-as-doh/internal/crypto"
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
		listenAddr   = flag.String("listen", "127.0.0.1:53", "Address to listen for DNS queries")
		serverDomain = flag.String("domain", "", "Server domain (e.g., t.example.com)")
		resolvers    = flag.String("resolvers", "8.8.8.8:53,1.1.1.1:53,9.9.9.9:53", "Comma-separated list of public DNS resolvers")
		keyHex       = flag.String("key", "", "Encryption key (64 hex characters)")
		keyFile      = flag.String("key-file", "", "File containing the encryption key")
		timeout      = flag.Duration("timeout", client.DefaultConfig().Timeout, "Query timeout")
		showVersion  = flag.Bool("version", false, "Show version information")
		genKey       = flag.Bool("gen-key", false, "Generate a new encryption key")
		installSvc   = flag.Bool("install", false, "Install as system service")
		uninstallSvc = flag.Bool("uninstall", false, "Uninstall system service")
		runSvc       = flag.Bool("service", false, "Run as system service")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "DNS-as-DoH Client - DNS tunnel client\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Generate a new key\n")
		fmt.Fprintf(os.Stderr, "  %s -gen-key\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Run client\n")
		fmt.Fprintf(os.Stderr, "  %s -domain t.example.com -key <hex-key>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Install as service (Windows/Linux)\n")
		fmt.Fprintf(os.Stderr, "  %s -install -domain t.example.com -key <hex-key>\n", os.Args[0])
	}

	flag.Parse()

	// Handle version
	if *showVersion {
		fmt.Printf("dns-as-doh-client %s (%s) built %s\n", version, commit, date)
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
		if err := service.Install("dns-as-doh-client", "DNS-as-DoH Client", os.Args[1:]); err != nil {
			log.Fatalf("Failed to install service: %v", err)
		}
		fmt.Println("Service installed successfully")
		return
	}

	if *uninstallSvc {
		if err := service.Uninstall("dns-as-doh-client"); err != nil {
			log.Fatalf("Failed to uninstall service: %v", err)
		}
		fmt.Println("Service uninstalled successfully")
		return
	}

	// Validate required arguments
	if *serverDomain == "" {
		log.Fatal("Server domain is required (-domain)")
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

	// Parse resolvers
	resolverList := strings.Split(*resolvers, ",")
	for i, r := range resolverList {
		resolverList[i] = strings.TrimSpace(r)
	}

	// Create config
	config := &client.Config{
		ListenAddr:    *listenAddr,
		ServerDomain:  *serverDomain,
		Resolvers:     resolverList,
		SharedSecret:  key,
		Timeout:       *timeout,
		MaxConcurrent: 100,
	}

	// Run as service or standalone
	if *runSvc {
		if err := service.Run("dns-as-doh-client", func() error {
			return runClient(config)
		}, func() {
			// Stop handler - will be handled by signal
		}); err != nil {
			log.Fatalf("Service error: %v", err)
		}
	} else {
		if err := runClient(config); err != nil {
			log.Fatalf("Client error: %v", err)
		}
	}
}

func runClient(config *client.Config) error {
	// Create resolver
	resolver, err := client.NewResolver(config)
	if err != nil {
		return fmt.Errorf("failed to create resolver: %w", err)
	}

	// Start resolver
	if err := resolver.Start(); err != nil {
		return fmt.Errorf("failed to start resolver: %w", err)
	}

	log.Println("DNS tunnel client started")

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	log.Printf("Received signal %v, shutting down...", sig)

	// Stop resolver
	resolver.Stop()

	log.Println("Client stopped")
	return nil
}

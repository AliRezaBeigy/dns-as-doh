# DNS-as-DoH

A DNS tunnel that uses plain DNS queries as transport to bypass DoH/DoT filtering. This allows users in countries where DoH/DoT is blocked to access encrypted DNS resolution through a tunnel.

## How It Works

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐         ┌─────────────┐
│   System    │  DNS    │    Client    │  DNS    │   Public    │  DNS    │   Server    │
│   Apps      │────────>│  (Resolver)  │────────>│  Resolver   │────────>│(Authoritative)│
│             │         │              │         │ (UDP DNS)   │         │             │
└─────────────┘         └──────────────┘         └─────────────┘         └─────────────┘
                                                                               │
                                                                               │ DNS/DoH/DoT
                                                                               ▼
                                                                         ┌─────────────┐
                                                                         │    Real     │
                                                                         │    DNS      │
                                                                         │   Servers   │
                                                                         └─────────────┘
```

1. Client intercepts DNS queries from system applications
2. Client encrypts and encodes queries into DNS names
3. Client sends encoded queries via plain UDP DNS to public resolvers
4. Public resolver forwards to your authoritative server
5. Server decodes, decrypts, and performs real DNS resolution
6. Server encrypts response and encodes into DNS TXT record
7. Response travels back through the same path

## Features

- **Simple Architecture**: No KCP, smux, or complex protocols - just DNS request/response
- **Parallel Resolvers**: Send queries to multiple DNS resolvers simultaneously, use fastest response
- **Strong Encryption**: ChaCha20-Poly1305 with HKDF key derivation
- **Anti-Fingerprinting**: Random padding, timing randomization, query variation
- **Replay Protection**: Timestamp-based replay detection
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Easy Installation**: Install as system service on Windows and Linux

## Quick Start

### 1. Generate Encryption Key

```bash
# On either client or server
./dns-as-doh-client -gen-key
# or
./dns-as-doh-server -gen-key
```

Save the generated key securely - you'll need it on both client and server.

### 2. DNS Zone Setup

Configure your DNS zone with the following records:

```
A     tns.example.com    → <server-ip>
AAAA  tns.example.com    → <server-ipv6>  (optional)
NS    t.example.com      → tns.example.com
```

Replace:
- `example.com` with your domain
- `<server-ip>` with your server's IP address
- `t` can be any short subdomain

### 3. Start the Server

```bash
./dns-as-doh-server \
    -domain t.example.com \
    -key <your-key> \
    -upstream 8.8.8.8:53 \
    -listen :53
```

### 4. Start the Client

```bash
./dns-as-doh-client \
    -domain t.example.com \
    -key <your-key> \
    -resolvers 8.8.8.8:53,1.1.1.1:53 \
    -listen 127.0.0.1:53
```

### 5. Configure System DNS

Point your system's DNS to `127.0.0.1` to use the tunnel.

## Installation

### Building from Source

```bash
# Build for current platform
./build.sh

# Build for all platforms
./build.sh all

# Build for specific platform
./build.sh linux
./build.sh windows
```

On Windows:
```powershell
.\build.ps1
.\build.ps1 -Target all
```

### Installing as Service

#### Linux (systemd)

```bash
# Using the install script
sudo ./install.sh generate-key
sudo ./install.sh install-client ./dist/dns-as-doh-client t.example.com <key>

# Or manually
sudo cp dist/dns-as-doh-client /usr/local/bin/
sudo cp install/dns-as-doh-client.service /etc/systemd/system/
# Edit the service file with your configuration
sudo systemctl enable dns-as-doh-client
sudo systemctl start dns-as-doh-client
```

#### Windows

```powershell
# Run as Administrator
.\dns-as-doh-client.exe -install -domain t.example.com -key <your-key>

# Start the service
net start dns-as-doh-client
```

## Command Reference

### Client Options

```
Usage:
  dns-as-doh-client [options]

Options:
  -listen string
        Address to listen for DNS queries (default "127.0.0.1:53")
  -domain string
        Server domain (e.g., t.example.com) (required)
  -resolvers string
        Comma-separated list of public DNS resolvers (default "8.8.8.8:53,1.1.1.1:53,9.9.9.9:53")
  -key string
        Encryption key (64 hex characters)
  -key-file string
        File containing the encryption key
  -timeout duration
        Query timeout (default 2s)
  -gen-key
        Generate a new encryption key
  -install
        Install as system service
  -uninstall
        Uninstall system service
  -version
        Show version information
```

### Server Options

```
Usage:
  dns-as-doh-server [options]

Options:
  -listen string
        Address to listen for DNS queries (default ":53")
  -domain string
        Domain this server is authoritative for (required)
  -upstream string
        Upstream DNS resolver (default "8.8.8.8:53")
        Formats:
          UDP DNS: 8.8.8.8:53
          DoH: https://dns.google/dns-query
          DoT: dns.google:853
  -key string
        Encryption key (64 hex characters)
  -key-file string
        File containing the encryption key
  -mtu int
        Maximum UDP payload size (default 1232)
  -ttl uint
        Response TTL in seconds (default 60)
  -rate-limit int
        Per-IP rate limit (queries per second) (default 100)
  -gen-key
        Generate a new encryption key
  -install
        Install as system service
  -uninstall
        Uninstall system service
  -version
        Show version information
```

## Security Considerations

### Encryption

- Uses ChaCha20-Poly1305 (AEAD) for encryption
- Keys derived using HKDF-SHA256 with context separation
- 12-byte nonces (8-byte counter + 4-byte random)
- Timestamps for replay protection (5-minute window)

### Anti-Fingerprinting

- Random padding (3-8 bytes per query)
- Variable query sizes
- Random DNS query IDs
- Random UDP source ports
- Query timing randomization (0-50ms delays)
- Realistic TTL values (60-300 seconds)
- Realistic response delays (10-100ms)

### Limitations

- DNS query size limits (~200 bytes payload)
- Higher latency than direct DNS (50-200ms typical)
- Throughput limited by DNS query rate
- Advanced DPI may detect patterns despite mitigations

## Performance

### Parallel Resolvers

The client sends queries to multiple resolvers simultaneously and uses the first valid response. This provides:

- **Lower Latency**: Uses the fastest resolver (30-50% improvement)
- **Redundancy**: If one resolver fails, others can respond
- **Resilience**: Works even if some resolvers are blocked

Configure multiple resolvers:
```bash
-resolvers 8.8.8.8:53,1.1.1.1:53,9.9.9.9:53,208.67.222.222:53
```

## Troubleshooting

### Client Not Resolving

1. Check if the client is running: `systemctl status dns-as-doh-client`
2. Check logs: `journalctl -u dns-as-doh-client`
3. Verify DNS is pointing to 127.0.0.1
4. Test with: `dig @127.0.0.1 example.com`

### Server Not Receiving Queries

1. Check if port 53 is open: `sudo ss -ulnp | grep 53`
2. Check firewall rules: `sudo iptables -L -n | grep 53`
3. Verify DNS zone configuration
4. Test NS record: `dig NS t.example.com`

### Encryption Key Issues

- Key must be exactly 64 hex characters (32 bytes)
- Same key must be used on both client and server
- Store keys securely (use `-key-file` for production)

## Comparison with dnstt

| Feature | DNS-as-DoH | dnstt |
|---------|-----------|-------|
| Protocol | Simple request/response | KCP + smux |
| Encryption | ChaCha20-Poly1305 | Noise Protocol |
| Use Case | DNS-only tunneling | General TCP tunneling |
| Complexity | Low | High |
| Reliability | DNS handles retries | KCP handles retries |

DNS-as-DoH is specifically designed for DNS resolution tunneling, making it simpler than dnstt which supports general TCP tunneling.

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please open an issue or pull request on GitHub.

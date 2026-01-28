# DNS-as-DoH

> **⚠️ Disclaimer**: I know this is a somewhat stupid idea - using DNS to tunnel DNS queries. It's not the most practical solution, but I wanted to implement it anyway to explore the concept.

---

A DNS tunnel that uses plain DNS queries as transport to bypass DoH/DoT filtering. This allows users in countries where DoH/DoT is blocked to access encrypted DNS resolution through a tunnel.

## 🎯 What This Does

Instead of directly using DoH/DoT (which may be blocked), this project:
1. **Intercepts** your DNS queries locally
2. **Encrypts** them with ChaCha20-Poly1305
3. **Encodes** them into DNS query names
4. **Sends** them via plain UDP DNS to public resolvers
5. **Routes** them to your tunnel server
6. **Decrypts** and resolves the actual DNS query
7. **Returns** the encrypted response back through the same path

Yes, it's DNS-over-DNS-over-DNS. Yes, it's recursive. Yes, I know it's a bit silly. But it works!

### Data Flow

1. **System App** → **Client**: Standard DNS query (UDP port 53)
2. **Client** → **Public Resolver**: Encoded/encrypted DNS query (UDP DNS)
3. **Public Resolver** → **Server**: Forwarded DNS query (UDP DNS)
4. **Server** → **Real DNS**: Actual DNS resolution (DNS/DoH/DoT)
5. **Server** → **Public Resolver**: Encoded/encrypted DNS response
6. **Public Resolver** → **Client**: Forwarded DNS response
7. **Client** → **System App**: Decoded DNS response

## 🚀 Quick Start

### One-Click Installation

**For Linux (Client or Server):**
```bash
sudo bash <(curl -Ls https://raw.githubusercontent.com/AliRezaBeigy/dns-as-doh/master/scripts/deploy.sh)
```

**For Windows (Client or Server):**
```powershell
powershell -ExecutionPolicy Bypass -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/AliRezaBeigy/dns-as-doh/master/scripts/deploy.ps1' -UseBasicParsing | Invoke-Expression}"
```

**Note:** Windows installation requires Administrator privileges.

### Manual Installation

#### Prerequisites

- Go 1.24 or later
- A domain name with DNS control
- A server with a public IP address

### 1. Generate Encryption Key

```bash
# On either client or server
./dns-as-doh-client -gen-key
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

### 3. Build the Project

```bash
# Build for current platform
./scripts/build.sh

# Or on Windows
.\scripts\build.ps1

# Build for all platforms
./scripts/build.sh all
```

### 4. Start the Server

```bash
./dns-as-doh-server \
    -domain t.example.com \
    -key <your-key> \
    -upstream 8.8.8.8:53 \
    -listen :53
```

### 5. Start the Client

```bash
./dns-as-doh-client \
    -domain t.example.com \
    -key <your-key> \
    -resolvers 8.8.8.8:53,1.1.1.1:53 \
    -listen 127.0.0.1:53
```

### 6. Configure System DNS

Point your system's DNS to `127.0.0.1` to use the tunnel.

## 📖 Usage

### Client Options

```
Usage: dns-as-doh-client [options]

Options:
  -domain string
        Server domain (e.g., t.example.com) (required)
  -key string
        Encryption key (64 hex characters)
  -key-file string
        File containing the encryption key
  -listen string
        Address to listen for DNS queries (default "127.0.0.1:53")
  -resolvers string
        Comma-separated list of public DNS resolvers
        (default "8.8.8.8:53,1.1.1.1:53,9.9.9.9:53")
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
Usage: dns-as-doh-server [options]

Options:
  -domain string
        Domain this server is authoritative for (required)
  -key string
        Encryption key (64 hex characters)
  -key-file string
        File containing the encryption key
  -listen string
        Address to listen for DNS queries (default ":53")
  -upstream string
        Upstream DNS resolver
        Formats:
          UDP DNS: 8.8.8.8:53
          DoH: https://dns.google/dns-query
          DoT: dns.google:853
        (default "8.8.8.8:53")
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

## 🔧 Installation

### Linux (systemd)

**One-click installation:**
```bash
sudo bash <(curl -Ls https://raw.githubusercontent.com/AliRezaBeigy/dns-as-doh/master/scripts/deploy.sh)
```

**Manual installation:**
```bash
# Build the binaries
./scripts/build.sh

# Install client
sudo ./scripts/install.sh install-client ./dist/dns-as-doh-client t.example.com <key>

# Install server
sudo ./scripts/install.sh install-server ./dist/dns-as-doh-server t.example.com <key>

# Or manually
sudo cp dist/dns-as-doh-client /usr/local/bin/
sudo cp install/dns-as-doh-client.service /etc/systemd/system/
# Edit the service file with your configuration
sudo systemctl enable dns-as-doh-client
sudo systemctl start dns-as-doh-client
```

### Windows

```powershell
# Run as Administrator
.\dns-as-doh-client.exe -install -domain t.example.com -key <your-key>

# Start the service
net start dns-as-doh-client
```

## 🔐 Security

### Encryption

- **Algorithm**: ChaCha20-Poly1305 (AEAD)
- **Key Derivation**: HKDF-SHA256 with context separation
- **Nonce Format**: 12 bytes (8-byte counter + 4-byte random)
- **Replay Protection**: Timestamp-based (5-minute window)

### Anti-Fingerprinting

- Random padding (3-8 bytes per query)
- Variable query sizes
- Random DNS query IDs
- Random UDP source ports
- Query timing randomization (0-50ms delays)
- Realistic TTL values (60-300 seconds)
- Realistic response delays (10-100ms)

## ⚡ Performance

### Parallel Resolvers

The client sends queries to multiple resolvers simultaneously and uses the first valid response. This provides:

- **Lower Latency**: Uses the fastest resolver (30-50% improvement)
- **Redundancy**: If one resolver fails, others can still respond
- **Resilience**: Works even if some resolvers are blocked/slow

Configure multiple resolvers:
```bash
-resolvers 8.8.8.8:53,1.1.1.1:53,9.9.9.9:53,208.67.222.222:53
```

## ⚠️ Limitations

1. **DNS Query Size Limits**: Maximum ~200 bytes per query (after encoding), limits throughput
2. **Latency**: Multiple DNS hops add latency (50-200ms typical)
   - **Mitigation**: Parallel resolver queries reduce latency by using fastest resolver
3. **Reliability**: DNS is UDP-based, no guaranteed delivery (DNS handles retries)
   - **Mitigation**: Parallel resolvers provide redundancy
4. **Throughput**: Limited by DNS query/response rate (typically 10-100 queries/second)
5. **Detection Risk**: Advanced DPI may still detect patterns despite mitigations
6. **Bandwidth**: Parallel resolvers increase bandwidth usage (trade-off for speed)

See [tests/README.md](tests/README.md) for more information.

## 🐛 Troubleshooting

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

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

MIT License - see LICENSE file for details.

## 🙏 Acknowledgments

- Inspired by [dnstt](https://github.com/Mygod/dnstt) but simplified for DNS-only use
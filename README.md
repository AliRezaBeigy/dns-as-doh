# DNS-as-DoH

### A DNS tunnel that uses plain DNS queries as transport to bypass DoH/DoT filtering.

> **Note:** This is probably a stupid idea, but I enjoyed implementing it.

DNS-as-DoH allows users in countries where DoH/DoT is blocked to access encrypted DNS resolution through a tunnel. It's a simple, lightweight, and surprisingly effective way to bypass DNS filtering.

---

## 🚀 Features

- **Simple & Lightweight:** No complex protocols, just plain DNS request/response.
- **High Performance:** Parallel resolvers for low latency and high availability.
- **Strong Encryption:** ChaCha20-Poly1305 with HKDF for secure communication.
- **Anti-Fingerprinting:** Techniques to evade detection by DPI.
- **Cross-Platform:** Works on Windows, Linux, and macOS.
- **Easy to Install:** Can be installed as a system service.

---

## Diagram

The diagram below shows how DNS-as-DoH works.

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

---

## 🛠️ How It Works

1.  **Intercept:** The client intercepts DNS queries from your system.
2.  **Encrypt & Encode:** The client encrypts the query and encodes it into a DNS name (e.g., `<encoded-query>.t.example.com`).
3.  **Resolve:** The client sends the encoded query to a public DNS resolver (like 8.8.8.8).
4.  **Forward:** The public resolver forwards the query to your authoritative server.
5.  **Decode & Decrypt:** The server decodes and decrypts the query.
6.  **Resolve Real Query:** The server resolves the real DNS query (e.g., `google.com`) using an upstream resolver.
7.  **Encrypt & Encode Response:** The server encrypts the response and encodes it into a TXT record.
8.  **Return:** The response is returned to the client through the same path.

---

## 🏁 Quick Start

### 1. Generate Encryption Key

```bash
# On either client or server
./dns-as-doh-client -gen-key
# or
./dns-as-doh-server -gen-key
```

### 2. DNS Zone Setup

Configure your DNS zone with the following records:

```
A     tns.example.com    → <server-ip>
AAAA  tns.example.com    → <server-ipv6>  (optional)
NS    t.example.com      → tns.example.com
```

- Replace `example.com` with your domain.
- Replace `<server-ip>` with your server's IP address.
- `t` can be any short subdomain.

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

Set your system's DNS to `127.0.0.1`.

---

## 📦 Installation

### Build from Source

```bash
# Build for the current platform
./build.sh

# Or on Windows
./build.ps1
```

### Install as a Service

#### Linux (systemd)

```bash
sudo ./install.sh install-client ./dist/dns-as-doh-client t.example.com <key>
```

#### Windows

```powershell
# Run as Administrator
.
```

---

## ⚙️ Command Reference

<details>
<summary>Client Options</summary>

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
</details>

<details>
<summary>Server Options</summary>

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
</details>

---

## 🛡️ Security

- **Encryption:** ChaCha20-Poly1305 (AEAD)
- **Key Derivation:** HKDF-SHA256
- **Replay Protection:** Timestamp-based with a 5-minute window.
- **Anti-Fingerprinting:** Random padding, timing randomization, and query variation.

---

## 🆚 Comparison with dnstt

| Feature      | DNS-as-DoH          | dnstt               |
|--------------|---------------------|---------------------|
| **Protocol** | Simple req/resp     | KCP + smux          |
| **Use Case** | DNS-only tunneling  | General TCP tunneling |
| **Complexity** | Low                 | High                |

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or pull request.

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
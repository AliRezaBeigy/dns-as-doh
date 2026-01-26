# Scripts

This directory contains build and deployment scripts for DNS-as-DoH.

## Scripts

### `build.sh`
Build script for creating binaries.

**Usage:**
```bash
./scripts/build.sh [target]
```

**Targets:**
- `current` (default) - Build for current platform
- `all` - Build for all platforms (Linux, Windows, macOS)
- `linux` - Build for Linux (amd64, arm64, arm)
- `windows` - Build for Windows (amd64, arm64)
- `darwin` or `macos` - Build for macOS (amd64, arm64)

**Examples:**
```bash
./scripts/build.sh              # Build for current platform
./scripts/build.sh all          # Build for all platforms
./scripts/build.sh linux        # Build for Linux only
```

### `build.ps1`
Windows PowerShell build script.

**Usage:**
```powershell
.\scripts\build.ps1 [-Target <target>]
```

**Targets:** Same as `build.sh`

### `install.sh`
Installation script for Linux (systemd).

**Usage:**
```bash
sudo ./scripts/install.sh <command> [options]
```

**Commands:**
- `install-client <binary> <domain> <key> [resolvers] [listen]` - Install client service
- `install-server <binary> <domain> <key> [upstream] [listen]` - Install server service
- `uninstall-client` - Uninstall client service
- `uninstall-server` - Uninstall server service
- `generate-key` - Generate encryption key

**Examples:**
```bash
# Generate key
./scripts/install.sh generate-key

# Install client
sudo ./scripts/install.sh install-client ./dist/dns-as-doh-client t.example.com <key>

# Install server
sudo ./scripts/install.sh install-server ./dist/dns-as-doh-server t.example.com <key>
```

### `deploy.sh`
One-click deployment script. Clones the repository, builds binaries, and guides through interactive installation.

**Usage:**
```bash
sudo bash <(curl -Ls https://raw.githubusercontent.com/AliRezaBeigy/dns-as-doh/master/scripts/deploy.sh)
```

Or if you have the repository cloned:
```bash
sudo bash scripts/deploy.sh
```

**Features:**
- Automatically clones repository if needed
- Builds binaries
- Interactive configuration prompts
- Sets up systemd services
- Generates encryption keys if needed

**Requirements:**
- Root/sudo access
- Go 1.24+ installed
- Git installed (for cloning)

## Notes

- All scripts use `set -e` to exit on errors
- Scripts include proper error handling and cleanup
- The deploy script creates temporary directories that are cleaned up automatically

#!/bin/bash
# One-click deployment script for DNS-as-DoH
# Usage: bash <(curl -Ls https://raw.githubusercontent.com/AliRezaBeigy/dns-as-doh/master/scripts/deploy.sh)

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_URL="https://github.com/AliRezaBeigy/dns-as-doh.git"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/dns-as-doh"
SERVICE_DIR="/etc/systemd/system"
TEMP_DIR="/tmp/dns-as-doh-install"

# Print functions
info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

question() {
    echo -e "${BLUE}[?]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root (sudo bash <(curl -Ls ...))"
    fi
}

# Check for Go
check_go() {
    if ! command -v go &> /dev/null; then
        error "Go is not installed. Please install Go 1.24+ first."
    fi
    
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    GO_MAJOR=$(echo $GO_VERSION | cut -d. -f1)
    GO_MINOR=$(echo $GO_VERSION | cut -d. -f2)
    
    if [ "$GO_MAJOR" -lt 1 ] || ([ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt 24 ]); then
        error "Go 1.24+ is required. Found: $GO_VERSION"
    fi
}

# Cleanup function
cleanup() {
    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}
trap cleanup EXIT

# Clone or use existing repo
setup_repo() {
    if [ -d ".git" ] && [ -f "go.mod" ]; then
        info "Using existing repository"
        REPO_DIR="$(pwd)"
    else
        info "Cloning repository..."
        rm -rf "$TEMP_DIR"
        git clone "$REPO_URL" "$TEMP_DIR" || error "Failed to clone repository"
        REPO_DIR="$TEMP_DIR"
    fi
    
    cd "$REPO_DIR"
}

# Build binaries
build_binaries() {
    info "Building binaries..."
    
    cd "$REPO_DIR"
    
    # Check if build script exists
    if [ -f "scripts/build.sh" ]; then
        bash scripts/build.sh current
    else
        # Fallback: build directly
        go build -o dist/dns-as-doh-client ./cmd/client
        go build -o dist/dns-as-doh-server ./cmd/server
    fi
    
    if [ ! -f "dist/dns-as-doh-client" ] || [ ! -f "dist/dns-as-doh-server" ]; then
        error "Build failed - binaries not found"
    fi
    
    info "Build complete!"
}

# Generate encryption key
generate_key() {
    info "Generating encryption key..."
    
    if command -v openssl &> /dev/null; then
        KEY=$(openssl rand -hex 32)
    elif command -v xxd &> /dev/null; then
        KEY=$(head -c 32 /dev/urandom | xxd -p | tr -d '\n')
    else
        # Fallback: use Go
        KEY=$(cat << 'EOF' | go run -
package main
import (
    "crypto/rand"
    "encoding/hex"
    "fmt"
)
func main() {
    b := make([]byte, 32)
    rand.Read(b)
    fmt.Print(hex.EncodeToString(b))
}
EOF
)
    fi
    
    echo ""
    echo -e "${GREEN}Generated encryption key:${NC}"
    echo "$KEY"
    echo ""
    warn "Save this key securely! You'll need it on both client and server."
    echo ""
    
    read -p "Press Enter to continue..."
    echo "$KEY"
}

# Install client
install_client_interactive() {
    info "Installing DNS-as-DoH Client..."
    
    # Prompt for configuration
    question "Enter server domain (e.g., t.example.com):"
    read -r DOMAIN
    
    if [ -z "$DOMAIN" ]; then
        error "Domain is required"
    fi
    
    question "Enter encryption key (or press Enter to generate one):"
    read -r KEY
    
    if [ -z "$KEY" ]; then
        KEY=$(generate_key)
    fi
    
    question "Enter DNS resolvers (comma-separated, default: 8.8.8.8:53,1.1.1.1:53,9.9.9.9:53):"
    read -r RESOLVERS
    RESOLVERS=${RESOLVERS:-"8.8.8.8:53,1.1.1.1:53,9.9.9.9:53"}
    
    question "Enter listen address (default: 127.0.0.1:53):"
    read -r LISTEN
    LISTEN=${LISTEN:-"127.0.0.1:53"}
    
    # Copy binary
    cp "$REPO_DIR/dist/dns-as-doh-client" "$INSTALL_DIR/dns-as-doh-client"
    chmod +x "$INSTALL_DIR/dns-as-doh-client"
    
    # Create config directory
    mkdir -p "$CONFIG_DIR"
    
    # Save key to file
    echo "$KEY" > "$CONFIG_DIR/client.key"
    chmod 600 "$CONFIG_DIR/client.key"
    
    # Create systemd service
    cat > "$SERVICE_DIR/dns-as-doh-client.service" << EOF
[Unit]
Description=DNS-as-DoH Client
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/dns-as-doh-client -domain $DOMAIN -key-file $CONFIG_DIR/client.key -resolvers $RESOLVERS -listen $LISTEN
Restart=on-failure
RestartSec=5
User=root
Group=root

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/log
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload
    
    # Enable service
    systemctl enable dns-as-doh-client
    
    info "Client installed successfully!"
    echo ""
    echo -e "${GREEN}Next steps:${NC}"
    echo "1. Configure your DNS zone:"
    echo "   A     tns.$DOMAIN    → <server-ip>"
    echo "   NS    $DOMAIN        → tns.$DOMAIN"
    echo ""
    echo "2. Start the service:"
    echo "   systemctl start dns-as-doh-client"
    echo ""
    echo "3. Check status:"
    echo "   systemctl status dns-as-doh-client"
    echo ""
    echo "4. Configure your system DNS to point to $LISTEN"
}

# Install server
install_server_interactive() {
    info "Installing DNS-as-DoH Server..."
    
    # Prompt for configuration
    question "Enter domain (e.g., t.example.com):"
    read -r DOMAIN
    
    if [ -z "$DOMAIN" ]; then
        error "Domain is required"
    fi
    
    question "Enter encryption key (or press Enter to generate one):"
    read -r KEY
    
    if [ -z "$KEY" ]; then
        KEY=$(generate_key)
    fi
    
    question "Enter upstream DNS resolver (default: 8.8.8.8:53):"
    read -r UPSTREAM
    UPSTREAM=${UPSTREAM:-"8.8.8.8:53"}
    
    question "Enter listen address (default: :53):"
    read -r LISTEN
    LISTEN=${LISTEN:-":53"}
    
    # Copy binary
    cp "$REPO_DIR/dist/dns-as-doh-server" "$INSTALL_DIR/dns-as-doh-server"
    chmod +x "$INSTALL_DIR/dns-as-doh-server"
    
    # Create config directory
    mkdir -p "$CONFIG_DIR"
    
    # Save key to file
    echo "$KEY" > "$CONFIG_DIR/server.key"
    chmod 600 "$CONFIG_DIR/server.key"
    
    # Create systemd service
    cat > "$SERVICE_DIR/dns-as-doh-server.service" << EOF
[Unit]
Description=DNS-as-DoH Server
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/dns-as-doh-server -domain $DOMAIN -key-file $CONFIG_DIR/server.key -upstream $UPSTREAM -listen $LISTEN
Restart=on-failure
RestartSec=5
User=root
Group=root

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/log
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload
    
    # Enable service
    systemctl enable dns-as-doh-server
    
    info "Server installed successfully!"
    echo ""
    echo -e "${GREEN}Next steps:${NC}"
    echo "1. Configure your DNS zone:"
    echo "   A     tns.$DOMAIN    → <server-ip>"
    echo "   NS    $DOMAIN        → tns.$DOMAIN"
    echo ""
    echo "2. Start the service:"
    echo "   systemctl start dns-as-doh-server"
    echo ""
    echo "3. Check status:"
    echo "   systemctl status dns-as-doh-server"
    echo ""
    echo -e "${YELLOW}Important:${NC} Save this encryption key - you'll need it for the client!"
    echo "$KEY"
}

# Main menu
main_menu() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║   DNS-as-DoH Deployment Script       ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo "What would you like to install?"
    echo ""
    echo "1) Client (for end users)"
    echo "2) Server (for tunnel server)"
    echo "3) Generate encryption key only"
    echo "4) Exit"
    echo ""
    question "Enter your choice [1-4]:"
    read -r choice
    
    case $choice in
        1)
            install_client_interactive
            ;;
        2)
            install_server_interactive
            ;;
        3)
            generate_key
            ;;
        4)
            info "Exiting..."
            exit 0
            ;;
        *)
            error "Invalid choice"
            ;;
    esac
}

# Main execution
main() {
    check_root
    check_go
    
    info "Starting DNS-as-DoH deployment..."
    
    setup_repo
    build_binaries
    main_menu
}

# Run main
main "$@"

#!/bin/bash
# Installation script for DNS-as-DoH

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/dns-as-doh"
SERVICE_DIR="/etc/systemd/system"

# Print colored output
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

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root (sudo ./install.sh)"
    fi
}

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    elif [ -f /etc/redhat-release ]; then
        OS="rhel"
    else
        OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    fi
    echo $OS
}

# Install client
install_client() {
    local binary=$1
    local domain=$2
    local key=$3
    local resolvers=${4:-"8.8.8.8:53,1.1.1.1:53,9.9.9.9:53"}
    local listen=${5:-"127.0.0.1:53"}
    
    info "Installing DNS-as-DoH Client..."
    
    # Copy binary
    cp "$binary" "${INSTALL_DIR}/dns-as-doh-client"
    chmod +x "${INSTALL_DIR}/dns-as-doh-client"
    
    # Create config directory
    mkdir -p "${CONFIG_DIR}"
    
    # Save key to file
    echo "$key" > "${CONFIG_DIR}/client.key"
    chmod 600 "${CONFIG_DIR}/client.key"
    
    # Create systemd service
    cat > "${SERVICE_DIR}/dns-as-doh-client.service" << EOF
[Unit]
Description=DNS-as-DoH Client
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/dns-as-doh-client -domain ${domain} -key-file ${CONFIG_DIR}/client.key -resolvers ${resolvers} -listen ${listen}
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
    info "Start with: systemctl start dns-as-doh-client"
    info "Check status: systemctl status dns-as-doh-client"
}

# Install server
install_server() {
    local binary=$1
    local domain=$2
    local key=$3
    local upstream=${4:-"8.8.8.8:53"}
    local listen=${5:-":53"}
    
    info "Installing DNS-as-DoH Server..."
    
    # Copy binary
    cp "$binary" "${INSTALL_DIR}/dns-as-doh-server"
    chmod +x "${INSTALL_DIR}/dns-as-doh-server"
    
    # Create config directory
    mkdir -p "${CONFIG_DIR}"
    
    # Save key to file
    echo "$key" > "${CONFIG_DIR}/server.key"
    chmod 600 "${CONFIG_DIR}/server.key"
    
    # Create systemd service
    cat > "${SERVICE_DIR}/dns-as-doh-server.service" << EOF
[Unit]
Description=DNS-as-DoH Server
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/dns-as-doh-server -domain ${domain} -key-file ${CONFIG_DIR}/server.key -upstream ${upstream} -listen ${listen}
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
    info "Start with: systemctl start dns-as-doh-server"
    info "Check status: systemctl status dns-as-doh-server"
}

# Uninstall
uninstall() {
    local component=$1
    
    info "Uninstalling ${component}..."
    
    # Stop and disable service
    systemctl stop "dns-as-doh-${component}" 2>/dev/null || true
    systemctl disable "dns-as-doh-${component}" 2>/dev/null || true
    
    # Remove files
    rm -f "${INSTALL_DIR}/dns-as-doh-${component}"
    rm -f "${SERVICE_DIR}/dns-as-doh-${component}.service"
    rm -f "${CONFIG_DIR}/${component}.key"
    
    # Reload systemd
    systemctl daemon-reload
    
    info "${component} uninstalled successfully!"
}

# Generate key
generate_key() {
    info "Generating encryption key..."
    
    if command -v openssl &> /dev/null; then
        key=$(openssl rand -hex 32)
    else
        key=$(head -c 32 /dev/urandom | xxd -p | tr -d '\n')
    fi
    
    echo ""
    echo "Generated key:"
    echo "$key"
    echo ""
    echo "Save this key securely and use it on both client and server."
}

# Print usage
usage() {
    echo "DNS-as-DoH Installation Script"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  install-client <binary> <domain> <key> [resolvers] [listen]"
    echo "      Install the client service"
    echo ""
    echo "  install-server <binary> <domain> <key> [upstream] [listen]"
    echo "      Install the server service"
    echo ""
    echo "  uninstall-client"
    echo "      Uninstall the client service"
    echo ""
    echo "  uninstall-server"
    echo "      Uninstall the server service"
    echo ""
    echo "  generate-key"
    echo "      Generate a new encryption key"
    echo ""
    echo "Examples:"
    echo "  $0 generate-key"
    echo "  $0 install-client ./dns-as-doh-client t.example.com <key>"
    echo "  $0 install-server ./dns-as-doh-server t.example.com <key>"
}

# Main
main() {
    case "${1:-}" in
        install-client)
            check_root
            if [ $# -lt 4 ]; then
                error "Usage: $0 install-client <binary> <domain> <key> [resolvers] [listen]"
            fi
            install_client "$2" "$3" "$4" "${5:-}" "${6:-}"
            ;;
        install-server)
            check_root
            if [ $# -lt 4 ]; then
                error "Usage: $0 install-server <binary> <domain> <key> [upstream] [listen]"
            fi
            install_server "$2" "$3" "$4" "${5:-}" "${6:-}"
            ;;
        uninstall-client)
            check_root
            uninstall client
            ;;
        uninstall-server)
            check_root
            uninstall server
            ;;
        generate-key)
            generate_key
            ;;
        *)
            usage
            ;;
    esac
}

main "$@"

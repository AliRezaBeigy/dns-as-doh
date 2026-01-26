#!/bin/bash
# Build script for DNS-as-DoH

set -e

VERSION=${VERSION:-"dev"}
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}"

echo "Building DNS-as-DoH..."
echo "Version: ${VERSION}"
echo "Commit: ${COMMIT}"
echo "Date: ${DATE}"
echo ""

# Create output directory
mkdir -p dist

# Build for multiple platforms
build() {
    local os=$1
    local arch=$2
    local ext=$3
    
    echo "Building for ${os}/${arch}..."
    
    GOOS=${os} GOARCH=${arch} go build -ldflags "${LDFLAGS}" -o "dist/dns-as-doh-client-${os}-${arch}${ext}" ./cmd/client
    GOOS=${os} GOARCH=${arch} go build -ldflags "${LDFLAGS}" -o "dist/dns-as-doh-server-${os}-${arch}${ext}" ./cmd/server
}

# Build for current platform only
build_current() {
    echo "Building for current platform..."
    
    go build -ldflags "${LDFLAGS}" -o "dist/dns-as-doh-client" ./cmd/client
    go build -ldflags "${LDFLAGS}" -o "dist/dns-as-doh-server" ./cmd/server
}

# Build all platforms
build_all() {
    # Linux
    build linux amd64 ""
    build linux arm64 ""
    build linux arm ""
    
    # Windows
    build windows amd64 ".exe"
    build windows arm64 ".exe"
    
    # macOS
    build darwin amd64 ""
    build darwin arm64 ""
}

# Parse arguments
case "${1:-current}" in
    all)
        build_all
        ;;
    linux)
        build linux amd64 ""
        build linux arm64 ""
        ;;
    windows)
        build windows amd64 ".exe"
        build windows arm64 ".exe"
        ;;
    darwin|macos)
        build darwin amd64 ""
        build darwin arm64 ""
        ;;
    current|*)
        build_current
        ;;
esac

echo ""
echo "Build complete. Binaries are in the dist/ directory."
ls -la dist/

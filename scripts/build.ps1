# Build script for DNS-as-DoH (Windows)

param(
    [string]$Target = "current"
)

$ErrorActionPreference = "Stop"

# Get version info
$Version = if ($env:VERSION) { $env:VERSION } else { "dev" }
$Commit = try { git rev-parse --short HEAD } catch { "unknown" }
$Date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$LDFlags = "-s -w -X main.version=$Version -X main.commit=$Commit -X main.date=$Date"

Write-Host "Building DNS-as-DoH..."
Write-Host "Version: $Version"
Write-Host "Commit: $Commit"
Write-Host "Date: $Date"
Write-Host ""

# Create output directory
New-Item -ItemType Directory -Force -Path "dist" | Out-Null

function Build($OS, $Arch, $Ext) {
    Write-Host "Building for $OS/$Arch..."
    
    $env:GOOS = $OS
    $env:GOARCH = $Arch
    
    go build -ldflags $LDFlags -o "dist/dns-as-doh-client-$OS-$Arch$Ext" ./cmd/client
    go build -ldflags $LDFlags -o "dist/dns-as-doh-server-$OS-$Arch$Ext" ./cmd/server
}

function BuildCurrent() {
    Write-Host "Building for current platform..."
    
    go build -ldflags $LDFlags -o "dist/dns-as-doh-client.exe" ./cmd/client
    go build -ldflags $LDFlags -o "dist/dns-as-doh-server.exe" ./cmd/server
}

switch ($Target) {
    "all" {
        # Linux
        Build "linux" "amd64" ""
        Build "linux" "arm64" ""
        Build "linux" "arm" ""
        
        # Windows
        Build "windows" "amd64" ".exe"
        Build "windows" "arm64" ".exe"
        
        # macOS
        Build "darwin" "amd64" ""
        Build "darwin" "arm64" ""
    }
    "linux" {
        Build "linux" "amd64" ""
        Build "linux" "arm64" ""
    }
    "windows" {
        Build "windows" "amd64" ".exe"
        Build "windows" "arm64" ".exe"
    }
    "darwin" {
        Build "darwin" "amd64" ""
        Build "darwin" "arm64" ""
    }
    default {
        BuildCurrent
    }
}

Write-Host ""
Write-Host "Build complete. Binaries are in the dist/ directory."
Get-ChildItem dist/

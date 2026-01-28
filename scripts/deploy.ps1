# One-click deployment script for DNS-as-DoH (Windows)
# Usage: powershell -ExecutionPolicy Bypass -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/AliRezaBeigy/dns-as-doh/master/scripts/deploy.ps1' -UseBasicParsing | Invoke-Expression}"

$ErrorActionPreference = "Stop"

# Colors
function Write-Info { Write-Host "[INFO] $args" -ForegroundColor Green }
function Write-Warn { Write-Host "[WARN] $args" -ForegroundColor Yellow }
function Write-Error { Write-Host "[ERROR] $args" -ForegroundColor Red; exit 1 }
function Write-Question { Write-Host "[?] $args" -ForegroundColor Cyan }

# Configuration
$REPO_URL = "https://github.com/AliRezaBeigy/dns-as-doh.git"
$INSTALL_DIR = "$env:ProgramFiles\DNS-as-DoH"
$CONFIG_DIR = "$env:ProgramData\DNS-as-DoH"
$TEMP_DIR = "$env:TEMP\dns-as-doh-install"

# Check if running as Administrator
function Test-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "Please run PowerShell as Administrator (Right-click -> Run as Administrator)"
    }
}

# Check for Go
function Test-Go {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        Write-Error "Go is not installed. Please install Go 1.24+ from https://go.dev/dl/"
    }
    
    $goVersion = (go version).Split(' ')[2].TrimStart('go')
    $versionParts = $goVersion.Split('.')
    $major = [int]$versionParts[0]
    $minor = [int]$versionParts[1]
    
    if ($major -lt 1 -or ($major -eq 1 -and $minor -lt 24)) {
        Write-Error "Go 1.24+ is required. Found: $goVersion"
    }
    
    Write-Info "Found Go $goVersion"
}

# Cleanup function
function Remove-TempDir {
    if (Test-Path $TEMP_DIR) {
        Remove-Item -Recurse -Force $TEMP_DIR -ErrorAction SilentlyContinue
    }
}
Register-ObjectEvent -InputObject ([System.Management.Automation.PSEvent]::Engine) -EventName Exiting -Action { Remove-TempDir } | Out-Null

# Clone or use existing repo
function Setup-Repo {
    if ((Test-Path ".git") -and (Test-Path "go.mod")) {
        Write-Info "Using existing repository"
        $script:REPO_DIR = (Get-Location).Path
    } else {
        Write-Info "Cloning repository..."
        Remove-TempDir
        git clone $REPO_URL $TEMP_DIR
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to clone repository"
        }
        $script:REPO_DIR = $TEMP_DIR
    }
    
    Set-Location $script:REPO_DIR
}

# Build binaries
function Build-Binaries {
    Write-Info "Building binaries..."
    
    Set-Location $script:REPO_DIR
    
    # Check if build script exists
    if (Test-Path "scripts\build.ps1") {
        & "scripts\build.ps1" -Target "current"
    } else {
        # Fallback: build directly
        New-Item -ItemType Directory -Force -Path "dist" | Out-Null
        go build -o "dist\dns-as-doh-client.exe" ./cmd/client
        go build -o "dist\dns-as-doh-server.exe" ./cmd/server
    }
    
    if (-not (Test-Path "dist\dns-as-doh-client.exe") -or -not (Test-Path "dist\dns-as-doh-server.exe")) {
        Write-Error "Build failed - binaries not found"
    }
    
    Write-Info "Build complete!"
}

# Generate encryption key
function New-EncryptionKey {
    Write-Info "Generating encryption key..."
    
    $key = $null
    
    # Try different methods to generate random hex
    if (Get-Command openssl -ErrorAction SilentlyContinue) {
        $key = openssl rand -hex 32
    } elseif (Get-Command certutil -ErrorAction SilentlyContinue) {
        # Use certutil to generate random bytes
        $bytes = New-Object byte[] 32
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        $key = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
    } else {
        # Fallback: use .NET
        $bytes = New-Object byte[] 32
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        $key = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
    }
    
    Write-Host ""
    Write-Host "Generated encryption key:" -ForegroundColor Green
    Write-Host $key
    Write-Host ""
    Write-Warn "Save this key securely! You'll need it on both client and server."
    Write-Host ""
    
    Read-Host "Press Enter to continue"
    return $key
}

# Install client
function Install-Client {
    Write-Info "Installing DNS-as-DoH Client..."
    
    # Prompt for configuration
    Write-Question "Enter server domain (e.g., t.example.com):"
    $domain = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($domain)) {
        Write-Error "Domain is required"
    }
    
    Write-Question "Enter encryption key (or press Enter to generate one):"
    $key = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($key)) {
        $key = New-EncryptionKey
    }
    
    Write-Question "Enter DNS resolvers (comma-separated, default: 8.8.8.8:53,1.1.1.1:53,9.9.9.9:53):"
    $resolvers = Read-Host
    if ([string]::IsNullOrWhiteSpace($resolvers)) {
        $resolvers = "8.8.8.8:53,1.1.1.1:53,9.9.9.9:53"
    }
    
    Write-Question "Enter listen address (default: 127.0.0.1:53):"
    $listen = Read-Host
    if ([string]::IsNullOrWhiteSpace($listen)) {
        $listen = "127.0.0.1:53"
    }
    
    # Create install directory
    New-Item -ItemType Directory -Force -Path $INSTALL_DIR | Out-Null
    
    # Copy binary
    Copy-Item "$REPO_DIR\dist\dns-as-doh-client.exe" "$INSTALL_DIR\dns-as-doh-client.exe" -Force
    
    # Create config directory
    New-Item -ItemType Directory -Force -Path $CONFIG_DIR | Out-Null
    
    # Save key to file
    $keyFile = "$CONFIG_DIR\client.key"
    $key | Out-File -FilePath $keyFile -Encoding ASCII -NoNewline
    $acl = Get-Acl $keyFile
    $acl.SetAccessRuleProtection($true, $false)
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule([System.Security.Principal.WindowsIdentity]::GetCurrent().Name, "FullControl", "Allow")
    $acl.SetAccessRule($accessRule)
    Set-Acl $keyFile $acl
    
    # Build service arguments
    $serviceArgs = @(
        "-domain", $domain,
        "-key-file", $keyFile,
        "-resolvers", $resolvers,
        "-listen", $listen,
        "-install"
    )
    
    # Install service
    Write-Info "Installing Windows service..."
    & "$INSTALL_DIR\dns-as-doh-client.exe" $serviceArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to install service"
    }
    
    Write-Info "Client installed successfully!"
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Green
    Write-Host "1. Configure your DNS zone:"
    Write-Host "   A     tns.$domain    → <server-ip>"
    Write-Host "   NS    $domain        → tns.$domain"
    Write-Host ""
    Write-Host "2. Start the service:"
    Write-Host "   Start-Service -Name 'dns-as-doh-client'"
    Write-Host ""
    Write-Host "3. Check status:"
    Write-Host "   Get-Service -Name 'dns-as-doh-client'"
    Write-Host ""
    Write-Host "4. Configure your system DNS to point to $listen"
}

# Install server
function Install-Server {
    Write-Info "Installing DNS-as-DoH Server..."
    
    # Prompt for configuration
    Write-Question "Enter domain (e.g., t.example.com):"
    $domain = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($domain)) {
        Write-Error "Domain is required"
    }
    
    Write-Question "Enter encryption key (or press Enter to generate one):"
    $key = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($key)) {
        $key = New-EncryptionKey
    }
    
    Write-Question "Enter upstream DNS resolver (default: 8.8.8.8:53):"
    $upstream = Read-Host
    if ([string]::IsNullOrWhiteSpace($upstream)) {
        $upstream = "8.8.8.8:53"
    }
    
    Write-Question "Enter listen address (default: :53):"
    $listen = Read-Host
    if ([string]::IsNullOrWhiteSpace($listen)) {
        $listen = ":53"
    }
    
    # Create install directory
    New-Item -ItemType Directory -Force -Path $INSTALL_DIR | Out-Null
    
    # Copy binary
    Copy-Item "$REPO_DIR\dist\dns-as-doh-server.exe" "$INSTALL_DIR\dns-as-doh-server.exe" -Force
    
    # Create config directory
    New-Item -ItemType Directory -Force -Path $CONFIG_DIR | Out-Null
    
    # Save key to file
    $keyFile = "$CONFIG_DIR\server.key"
    $key | Out-File -FilePath $keyFile -Encoding ASCII -NoNewline
    $acl = Get-Acl $keyFile
    $acl.SetAccessRuleProtection($true, $false)
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule([System.Security.Principal.WindowsIdentity]::GetCurrent().Name, "FullControl", "Allow")
    $acl.SetAccessRule($accessRule)
    Set-Acl $keyFile $acl
    
    # Build service arguments
    $serviceArgs = @(
        "-domain", $domain,
        "-key-file", $keyFile,
        "-upstream", $upstream,
        "-listen", $listen,
        "-install"
    )
    
    # Install service
    Write-Info "Installing Windows service..."
    & "$INSTALL_DIR\dns-as-doh-server.exe" $serviceArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to install service"
    }
    
    Write-Info "Server installed successfully!"
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Green
    Write-Host "1. Configure your DNS zone:"
    Write-Host "   A     tns.$domain    → <server-ip>"
    Write-Host "   NS    $domain        → tns.$domain"
    Write-Host ""
    Write-Host "2. Start the service:"
    Write-Host "   Start-Service -Name 'dns-as-doh-server'"
    Write-Host ""
    Write-Host "3. Check status:"
    Write-Host "   Get-Service -Name 'dns-as-doh-server'"
    Write-Host ""
    Write-Warn "Important: Save this encryption key - you'll need it for the client!"
    Write-Host $key
}

# Main menu
function Show-Menu {
    Write-Host ""
    Write-Host "╔════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   DNS-as-DoH Deployment Script       ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "What would you like to install?"
    Write-Host ""
    Write-Host "1) Client (for end users)"
    Write-Host "2) Server (for tunnel server)"
    Write-Host "3) Generate encryption key only"
    Write-Host "4) Exit"
    Write-Host ""
    Write-Question "Enter your choice [1-4]:"
    $choice = Read-Host
    
    switch ($choice) {
        "1" { Install-Client }
        "2" { Install-Server }
        "3" { New-EncryptionKey }
        "4" { Write-Info "Exiting..."; exit 0 }
        default { Write-Error "Invalid choice" }
    }
}

# Main execution
function Main {
    Test-Administrator
    Test-Go
    
    Write-Info "Starting DNS-as-DoH deployment..."
    
    Setup-Repo
    Build-Binaries
    Show-Menu
    
    # Cleanup
    Remove-TempDir
}

# Run main
Main

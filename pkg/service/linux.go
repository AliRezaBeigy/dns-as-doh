//go:build !windows
// +build !windows

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
)

const systemdServiceTemplate = `[Unit]
Description={{.DisplayName}}
After=network.target

[Service]
Type=simple
ExecStart={{.ExecPath}} {{.Args}}
Restart=on-failure
RestartSec=5
User=root
Group=root

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`

type serviceConfig struct {
	Name        string
	DisplayName string
	ExecPath    string
	Args        string
}

// Install installs the service on Linux using systemd.
func Install(name, displayName string, args []string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Get absolute path
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Filter out -install and add -service
	serviceArgs := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "-install" || arg == "--install" {
			continue
		}
		serviceArgs = append(serviceArgs, arg)
	}

	// Create service config
	config := serviceConfig{
		Name:        name,
		DisplayName: displayName,
		ExecPath:    exePath,
		Args:        strings.Join(serviceArgs, " "),
	}

	// Generate service file
	tmpl, err := template.New("service").Parse(systemdServiceTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", name)
	f, err := os.Create(servicePath)
	if err != nil {
		return fmt.Errorf("failed to create service file: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, config); err != nil {
		os.Remove(servicePath)
		return fmt.Errorf("failed to write service file: %w", err)
	}

	// Reload systemd
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	// Enable service
	if err := exec.Command("systemctl", "enable", name).Run(); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}

	fmt.Printf("Service installed: %s\n", servicePath)
	fmt.Printf("Start with: systemctl start %s\n", name)
	fmt.Printf("Check status: systemctl status %s\n", name)

	return nil
}

// Uninstall uninstalls the service on Linux.
func Uninstall(name string) error {
	// Stop service if running (best-effort; may fail if not running)
	_ = exec.Command("systemctl", "stop", name).Run()

	// Disable service (best-effort)
	_ = exec.Command("systemctl", "disable", name).Run()

	// Remove service file
	servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", name)
	if err := os.Remove(servicePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove service file: %w", err)
	}

	// Reload systemd
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	return nil
}

// Run runs the service on Linux.
// On Linux, the service just runs directly - systemd handles the lifecycle.
func Run(name string, start func() error, stop func()) error {
	return start()
}

// IsService returns true if running as a service.
// On Linux, we can check for INVOCATION_ID which systemd sets.
func IsService() bool {
	return os.Getenv("INVOCATION_ID") != ""
}

// GetConfigPath returns the config file path for the service.
func GetConfigPath(name string) string {
	// Check /etc first
	etcPath := fmt.Sprintf("/etc/%s/%s.conf", name, name)
	if _, err := os.Stat(etcPath); err == nil {
		return etcPath
	}

	// Fall back to executable directory
	exePath, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exePath), name+".conf")
}

// CreateClientServiceFile creates a systemd service file for the client.
func CreateClientServiceFile(name, domain, key, resolvers, listen string) string {
	args := []string{
		"-domain", domain,
		"-key", key,
		"-resolvers", resolvers,
		"-listen", listen,
	}
	return fmt.Sprintf(`[Unit]
Description=DNS-as-DoH Client
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/%s %s
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`, name, strings.Join(args, " "))
}

// CreateServerServiceFile creates a systemd service file for the server.
func CreateServerServiceFile(name, domain, key, upstream, listen string) string {
	args := []string{
		"-domain", domain,
		"-key", key,
		"-upstream", upstream,
		"-listen", listen,
	}
	return fmt.Sprintf(`[Unit]
Description=DNS-as-DoH Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/%s %s
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`, name, strings.Join(args, " "))
}

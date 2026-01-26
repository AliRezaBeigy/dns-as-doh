//go:build windows
// +build windows

package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// windowsService implements svc.Handler for Windows services.
type windowsService struct {
	name    string
	start   func() error
	stop    func()
	running bool
}

func (s *windowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	// Start the service
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.start()
	}()

	// Give it a moment to start
	select {
	case err := <-errCh:
		if err != nil {
			elog, _ := eventlog.Open(s.name)
			if elog != nil {
				elog.Error(1, fmt.Sprintf("Service start failed: %v", err))
				elog.Close()
			}
			return false, 1
		}
	case <-time.After(5 * time.Second):
		// Service is starting, continue
	}

	s.running = true
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	// Wait for stop request
loop:
	for {
		select {
		case err := <-errCh:
			if err != nil {
				elog, _ := eventlog.Open(s.name)
				if elog != nil {
					elog.Error(1, fmt.Sprintf("Service error: %v", err))
					elog.Close()
				}
				break loop
			}
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				break loop
			default:
				elog, _ := eventlog.Open(s.name)
				if elog != nil {
					elog.Warning(1, fmt.Sprintf("Unexpected control request #%d", c))
					elog.Close()
				}
			}
		}
	}

	changes <- svc.Status{State: svc.StopPending}
	s.stop()
	return false, 0
}

// Install installs the service on Windows.
func Install(name, displayName string, args []string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	// Check if service already exists
	s, err := m.OpenService(name)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", name)
	}

	// Build service command line
	// Replace -install with -service in args
	serviceArgs := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "-install" || arg == "--install" {
			continue
		}
		serviceArgs = append(serviceArgs, arg)
	}
	serviceArgs = append(serviceArgs, "-service")

	// Create service
	s, err = m.CreateService(name, exePath, mgr.Config{
		DisplayName: displayName,
		StartType:   mgr.StartAutomatic,
		Description: "DNS-as-DoH DNS Tunnel Service",
	}, serviceArgs...)
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}
	defer s.Close()

	// Create event log source
	err = eventlog.InstallAsEventCreate(name, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		s.Delete()
		return fmt.Errorf("failed to create event log source: %w", err)
	}

	return nil
}

// Uninstall uninstalls the service on Windows.
func Uninstall(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("service %s not found: %w", name, err)
	}
	defer s.Close()

	// Stop service if running
	status, err := s.Query()
	if err == nil && status.State != svc.Stopped {
		s.Control(svc.Stop)
		// Wait for stop
		for i := 0; i < 10; i++ {
			time.Sleep(500 * time.Millisecond)
			status, err := s.Query()
			if err != nil || status.State == svc.Stopped {
				break
			}
		}
	}

	// Delete service
	err = s.Delete()
	if err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}

	// Remove event log source
	eventlog.Remove(name)

	return nil
}

// Run runs the service on Windows.
func Run(name string, start func() error, stop func()) error {
	// Check if running as service
	isInteractive, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("failed to determine if running as service: %w", err)
	}

	if !isInteractive {
		// Running as service
		return svc.Run(name, &windowsService{
			name:  name,
			start: start,
			stop:  stop,
		})
	}

	// Running interactively
	return start()
}

// IsService returns true if running as a Windows service.
func IsService() bool {
	isService, _ := svc.IsWindowsService()
	return isService
}

// GetConfigPath returns the config file path for the service.
func GetConfigPath(name string) string {
	// Use the executable directory
	exePath, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exePath), name+".conf")
}

// parseArgs parses command line arguments from a string.
func parseArgs(cmdLine string) []string {
	var args []string
	var current strings.Builder
	inQuote := false

	for _, r := range cmdLine {
		switch r {
		case '"':
			inQuote = !inQuote
		case ' ':
			if inQuote {
				current.WriteRune(r)
			} else if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		args = append(args, current.String())
	}

	return args
}

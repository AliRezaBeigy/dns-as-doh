# Test Organization

This directory contains the test suite for DNS-as-DoH.

## Structure

```
tests/
├── README.md              # This file
├── helpers/               # Shared test helpers and utilities
│   └── helpers.go
└── integration/           # End-to-end integration tests
    └── client_server_test.go
```

## Test Types

### Unit Tests
Unit tests are located alongside the code they test (Go convention):
- `internal/dns/*_test.go` - DNS encoding/decoding tests
- `internal/crypto/*_test.go` - Encryption tests
- `internal/client/*_test.go` - Client component tests
- `internal/server/*_test.go` - Server component tests

### Integration Tests
Integration tests are in `tests/integration/`:
- `client_server_test.go` - Full client-server communication tests

### Test Helpers
Shared test utilities are in `tests/helpers/`:
- Common functions for setting up test environments
- Mock servers and clients
- Test data generators

## Running Tests

```bash
# Run all tests
go test ./...

# Run only unit tests
go test ./internal/...

# Run only integration tests
go test ./tests/integration/...

# Run tests with coverage
go test -cover ./...

# Run tests with verbose output
go test -v ./...

# Run specific test
go test -v -run TestClientServerFullCommunication ./tests/integration/...
```

## Test Coverage Goals

- **Unit Tests**: >80% coverage for core components
- **Integration Tests**: Cover all major communication flows
- **Error Cases**: Test error handling and edge cases

## Writing Tests

### Unit Tests
- Place test files next to the code they test
- Use table-driven tests where appropriate
- Test both success and error cases
- Use descriptive test names

### Integration Tests
- Test complete workflows
- Use real components where possible
- Mock external dependencies (DNS resolvers, etc.)
- Clean up resources properly

### Test Helpers
- Place reusable helpers in `tests/helpers/`
- Use `t.Helper()` for helper functions
- Document helper functions clearly

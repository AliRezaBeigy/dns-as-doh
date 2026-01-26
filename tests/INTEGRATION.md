# Integration Tests

Integration tests verify end-to-end functionality of the DNS-as-DoH system.

## Test Files

### `client_server_test.go`
Tests the complete client-server communication flow.

**Test Cases:**
- `TestClientServerFullCommunication` - Basic round-trip test
- `TestClientServerRoundTrip` - Multiple query types (A, AAAA, TXT)
- `TestClientServerEncryption` - Encryption verification
- `TestClientServerMultipleQueries` - Sequential queries
- `TestClientServerErrorHandling` - Error handling
- `TestClientServerConcurrentQueries` - Concurrent queries

## Test Environment

Each test uses `SetupTestEnvironment` which creates:
- A mock upstream DNS server
- A DNS tunnel server
- A DNS tunnel client
- Proper cleanup functions

## Running Integration Tests

```bash
# Run all integration tests
go test ./tests/integration/... -v

# Run specific test
go test ./tests/integration/... -v -run TestClientServerFullCommunication

# Run with timeout
go test ./tests/integration/... -timeout 30s
```

## Test Coverage

Integration tests verify:
- ✅ Client receives DNS query
- ✅ Client encrypts and encodes query
- ✅ Client sends tunnel query to server
- ✅ Server receives and decodes tunnel query
- ✅ Server decrypts query
- ✅ Server resolves upstream DNS
- ✅ Server encrypts and encodes response
- ✅ Server sends tunnel response
- ✅ Client receives and decodes response
- ✅ Client decrypts response
- ✅ Client returns DNS response to caller

## Mock Components

### MockUpstreamDNS
A mock DNS server that responds to queries. Located in `tests/helpers/helpers.go`.

## Notes

- Tests use random ports to avoid conflicts
- Tests include proper cleanup to avoid resource leaks
- Tests verify both success and error cases
- Tests can run concurrently (use `-parallel` flag)

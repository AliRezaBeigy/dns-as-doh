package dns

import (
	"testing"
)

func TestEncodeDecodePayload(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		domain   string
		wantErr  bool
		checkLen bool
	}{
		{
			name:     "empty payload",
			payload:  []byte{},
			domain:   "t.example.com",
			wantErr:  false,
			checkLen: true,
		},
		{
			name:     "small payload",
			payload:  []byte{1, 2, 3, 4, 5},
			domain:   "t.example.com",
			wantErr:  false,
			checkLen: true,
		},
		{
			name:     "medium payload",
			payload:  make([]byte, 100),
			domain:   "t.example.com",
			wantErr:  false,
			checkLen: true,
		},
		{
			name:     "large payload",
			payload:  make([]byte, 100), // Reduced to fit DNS name limits
			domain:   "t.example.com",
			wantErr:  false,
			checkLen: true,
		},
		{
			name:     "single byte domain",
			payload:  []byte{42},
			domain:   "t.com",
			wantErr:  false,
			checkLen: true,
		},
		{
			name:     "long domain",
			payload:  []byte{1, 2, 3},
			domain:   "tunnel.example.com",
			wantErr:  false,
			checkLen: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientID := NewClientID()
			domain, err := ParseName(tt.domain)
			if err != nil {
				t.Fatalf("ParseName failed: %v", err)
			}

			// Encode
			encodedName, err := EncodePayload(tt.payload, clientID, domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodePayload() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			if tt.checkLen && len(encodedName) == 0 {
				t.Error("Encoded name is empty")
			}

			// Decode
			decodedClientID, decodedPayload, err := DecodePayload(encodedName, domain)
			if err != nil {
				t.Errorf("DecodePayload() error = %v", err)
				return
			}

			// Verify client ID matches
			if decodedClientID != clientID {
				t.Errorf("ClientID mismatch: got %x, want %x", decodedClientID, clientID)
			}

			// Verify payload matches
			if len(decodedPayload) != len(tt.payload) {
				t.Errorf("Payload length mismatch: got %d, want %d", len(decodedPayload), len(tt.payload))
				return
			}

			for i := range tt.payload {
				if decodedPayload[i] != tt.payload[i] {
					t.Errorf("Payload mismatch at index %d: got %d, want %d", i, decodedPayload[i], tt.payload[i])
				}
			}
		})
	}
}

func TestEncodePayloadTooLong(t *testing.T) {
	// Create a payload that's too large
	payload := make([]byte, 1000)
	clientID := NewClientID()
	domain, _ := ParseName("t.example.com")

	_, err := EncodePayload(payload, clientID, domain)
	if err == nil {
		t.Error("Expected error for payload that's too long")
	}
}

func TestEncodeDecodeResponse(t *testing.T) {
	tests := []struct {
		name    string
		packets [][]byte
	}{
		{
			name:    "single packet",
			packets: [][]byte{{1, 2, 3, 4, 5}},
		},
		{
			name:    "multiple packets",
			packets: [][]byte{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}},
		},
		{
			name:    "empty packets",
			packets: [][]byte{{}, {1, 2}, {}},
		},
		{
			name:    "large packet",
			packets: [][]byte{make([]byte, 1000)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			encoded := EncodeResponse(tt.packets)

			// Decode
			decoded, err := DecodeResponse(encoded)
			if err != nil {
				t.Errorf("DecodeResponse() error = %v", err)
				return
			}

			// Verify
			if len(decoded) != len(tt.packets) {
				t.Errorf("Packet count mismatch: got %d, want %d", len(decoded), len(tt.packets))
				return
			}

			for i := range tt.packets {
				if len(decoded[i]) != len(tt.packets[i]) {
					t.Errorf("Packet %d length mismatch: got %d, want %d", i, len(decoded[i]), len(tt.packets[i]))
					continue
				}

				for j := range tt.packets[i] {
					if decoded[i][j] != tt.packets[i][j] {
						t.Errorf("Packet %d byte %d mismatch: got %d, want %d", i, j, decoded[i][j], tt.packets[i][j])
					}
				}
			}
		})
	}
}

func TestGenerateQueryID(t *testing.T) {
	// Generate multiple IDs and check they're different
	ids := make(map[uint16]bool)
	for i := 0; i < 100; i++ {
		id := GenerateQueryID()
		if ids[id] {
			t.Errorf("Duplicate query ID generated: %d", id)
		}
		ids[id] = true
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	// Test vectors similar to slipstream-rust style
	vectors := []struct {
		name    string
		payload string // hex encoded
		domain  string
	}{
		{
			name:    "empty",
			payload: "",
			domain:  "t.example.com",
		},
		{
			name:    "small",
			payload: "0102030405",
			domain:  "t.example.com",
		},
		{
			name:    "medium",
			payload: "deadbeefcafebabe",
			domain:  "tunnel.example.com",
		},
		{
			name:    "realistic_dns_query",
			payload: "00120100000100000000000103646e7306676f6f676c6503636f6d00000100010000291000000000000000",
			domain:  "t.example.com",
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			payload := decodeHex(v.payload)
			clientID := NewClientID()
			domain, err := ParseName(v.domain)
			if err != nil {
				t.Fatalf("ParseName failed: %v", err)
			}

			// Encode
			encoded, err := EncodePayload(payload, clientID, domain)
			if err != nil {
				t.Fatalf("EncodePayload failed: %v", err)
			}

			// Decode
			decodedClientID, decodedPayload, err := DecodePayload(encoded, domain)
			if err != nil {
				t.Fatalf("DecodePayload failed: %v", err)
			}

			// Verify
			if decodedClientID != clientID {
				t.Errorf("ClientID mismatch")
			}

			if len(decodedPayload) != len(payload) {
				t.Errorf("Payload length mismatch: got %d, want %d", len(decodedPayload), len(payload))
			}

			for i := range payload {
				if decodedPayload[i] != payload[i] {
					t.Errorf("Payload mismatch at index %d", i)
				}
			}
		})
	}
}

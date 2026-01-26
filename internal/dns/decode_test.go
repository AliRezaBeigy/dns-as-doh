package dns

import (
	"testing"
)

func TestExtractQueryPayload(t *testing.T) {
	domain, _ := ParseName("t.example.com")
	clientID := NewClientID()
	payload := []byte{1, 2, 3, 4, 5}

	// Encode payload
	encodedName, err := EncodePayload(payload, clientID, domain)
	if err != nil {
		t.Fatalf("EncodePayload failed: %v", err)
	}

	// Create query
	query := &Message{
		ID:    0x1234,
		Flags: 0x0100,
		Question: []Question{
			{
				Name:  encodedName,
				Type:  RRTypeTXT,
				Class: ClassIN,
			},
		},
	}

	// Extract payload
	extractedClientID, extractedPayload, err := ExtractQueryPayload(query, domain)
	if err != nil {
		t.Fatalf("ExtractQueryPayload failed: %v", err)
	}

	if extractedClientID != clientID {
		t.Errorf("ClientID mismatch")
	}

	if len(extractedPayload) != len(payload) {
		t.Errorf("Payload length mismatch: got %d, want %d", len(extractedPayload), len(payload))
	}
}

func TestExtractQueryPayloadInvalid(t *testing.T) {
	domain, _ := ParseName("t.example.com")

	tests := []struct {
		name    string
		query   *Message
		wantErr bool
	}{
		{
			name: "response instead of query",
			query: &Message{
				ID:    0x1234,
				Flags: 0x8000, // QR=1
				Question: []Question{
					{
						Name:  mustParseName("test.t.example.com"),
						Type:  RRTypeTXT,
						Class: ClassIN,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "no questions",
			query: &Message{
				ID:    0x1234,
				Flags: 0x0100,
			},
			wantErr: true,
		},
		{
			name: "wrong query type",
			query: &Message{
				ID:    0x1234,
				Flags: 0x0100,
				Question: []Question{
					{
						Name:  mustParseName("test.t.example.com"),
						Type:  RRTypeA,
						Class: ClassIN,
					},
				},
			},
			wantErr: true, // A/AAAA without encoded payload should fail
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ExtractQueryPayload(tt.query, domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractQueryPayload() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExtractResponsePayload(t *testing.T) {
	domain, _ := ParseName("t.example.com")
	payload := []byte{1, 2, 3, 4, 5}

	// Encode as TXT record
	txtData := EncodeTXTData(payload)

	response := &Message{
		ID:    0x1234,
		Flags: 0x8000, // QR=1
		Question: []Question{
			{
				Name:  mustParseName("test.t.example.com"),
				Type:  RRTypeTXT,
				Class: ClassIN,
			},
		},
		Answer: []RR{
			{
				Name:  mustParseName("test.t.example.com"),
				Type:  RRTypeTXT,
				Class: ClassIN,
				TTL:   300,
				Data:  txtData,
			},
		},
	}

	extracted, err := ExtractResponsePayload(response, domain)
	if err != nil {
		t.Fatalf("ExtractResponsePayload failed: %v", err)
	}

	if len(extracted) != len(payload) {
		t.Errorf("Payload length mismatch: got %d, want %d", len(extracted), len(payload))
	}
}

func TestExtractResponsePayloadInvalid(t *testing.T) {
	domain, _ := ParseName("t.example.com")

	tests := []struct {
		name     string
		response *Message
		wantErr  bool
	}{
		{
			name: "query instead of response",
			response: &Message{
				ID:    0x1234,
				Flags: 0x0100, // QR=0
			},
			wantErr: true,
		},
		{
			name: "error response",
			response: &Message{
				ID:    0x1234,
				Flags: 0x8003, // QR=1, RCODE=3 (NXDOMAIN)
			},
			wantErr: true,
		},
		{
			name: "no answer",
			response: &Message{
				ID:    0x1234,
				Flags: 0x8000,
			},
			wantErr: true,
		},
		{
			name: "wrong record type",
			response: &Message{
				ID:    0x1234,
				Flags: 0x8000,
				Answer: []RR{
					{
						Name:  mustParseName("test.t.example.com"),
						Type:  RRTypeA,
						Class: ClassIN,
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ExtractResponsePayload(tt.response, domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractResponsePayload() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCreateTunnelResponse(t *testing.T) {
	domain, _ := ParseName("t.example.com")
	payload := []byte{1, 2, 3, 4, 5}

	query := &Message{
		ID:    0x1234,
		Flags: 0x0100,
		Question: []Question{
			{
				Name:  mustParseName("test.t.example.com"),
				Type:  RRTypeTXT,
				Class: ClassIN,
			},
		},
	}

	response, err := CreateTunnelResponse(query, domain, payload, 300)
	if err != nil {
		t.Fatalf("CreateTunnelResponse failed: %v", err)
	}

	if !response.IsResponse() {
		t.Error("Response should have QR=1")
	}

	if response.ID != query.ID {
		t.Errorf("Response ID mismatch: got %x, want %x", response.ID, query.ID)
	}

	if len(response.Answer) != 1 {
		t.Errorf("Answer count: got %d, want 1", len(response.Answer))
	}

	if response.Answer[0].Type != RRTypeTXT {
		t.Error("Answer should be TXT record")
	}
}

func TestCreateErrorResponse(t *testing.T) {
	domain, _ := ParseName("t.example.com")

	query := &Message{
		ID:    0x1234,
		Flags: 0x0100,
		Question: []Question{
			{
				Name:  mustParseName("test.t.example.com"),
				Type:  RRTypeTXT,
				Class: ClassIN,
			},
		},
	}

	response := CreateErrorResponse(query, domain, RcodeNameError)

	if !response.IsResponse() {
		t.Error("Response should have QR=1")
	}

	if response.Rcode() != RcodeNameError {
		t.Errorf("RCODE mismatch: got %d, want %d", response.Rcode(), RcodeNameError)
	}
}

func TestValidateQuery(t *testing.T) {
	domain, _ := ParseName("t.example.com")

	tests := []struct {
		name    string
		query   *Message
		wantErr bool
	}{
		{
			name: "valid query",
			query: func() *Message {
				msg := &Message{
					ID:    0x1234,
					Flags: 0x0100,
					Question: []Question{
						{
							Name:  mustParseName("test.t.example.com"),
							Type:  RRTypeTXT,
							Class: ClassIN,
						},
					},
				}
				msg.AddEDNS0(4096)
				return msg
			}(),
			wantErr: false,
		},
		{
			name: "response instead of query",
			query: &Message{
				ID:    0x1234,
				Flags: 0x8000,
			},
			wantErr: true,
		},
		{
			name: "wrong domain",
			query: &Message{
				ID:    0x1234,
				Flags: 0x0100,
				Question: []Question{
					{
						Name:  mustParseName("test.other.com"),
						Type:  RRTypeTXT,
						Class: ClassIN,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "no questions",
			query: &Message{
				ID:    0x1234,
				Flags: 0x0100,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateQuery(tt.query, domain, 512)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateQuery() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsValidTunnelResponse(t *testing.T) {
	domain, _ := ParseName("t.example.com")

	tests := []struct {
		name     string
		response *Message
		want     bool
	}{
		{
			name: "valid response",
			response: &Message{
				ID:    0x1234,
				Flags: 0x8000,
				Answer: []RR{
					{
						Name:  mustParseName("test.t.example.com"),
						Type:  RRTypeTXT,
						Class: ClassIN,
					},
				},
			},
			want: true,
		},
		{
			name: "query instead of response",
			response: &Message{
				ID:    0x1234,
				Flags: 0x0100,
			},
			want: false,
		},
		{
			name: "error response",
			response: &Message{
				ID:    0x1234,
				Flags: 0x8003,
			},
			want: false,
		},
		{
			name: "no TXT answer",
			response: &Message{
				ID:    0x1234,
				Flags: 0x8000,
				Answer: []RR{
					{
						Name:  mustParseName("test.t.example.com"),
						Type:  RRTypeA,
						Class: ClassIN,
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidTunnelResponse(tt.response, domain)
			if got != tt.want {
				t.Errorf("IsValidTunnelResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

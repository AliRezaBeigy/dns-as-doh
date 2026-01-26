package dns

import (
	"testing"
)

func TestParseName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "simple domain",
			input:   "example.com",
			wantErr: false,
		},
		{
			name:    "domain with trailing dot",
			input:   "example.com.",
			wantErr: false,
		},
		{
			name:    "root domain",
			input:   ".",
			wantErr: false,
		},
		{
			name:    "empty domain",
			input:   "",
			wantErr: false,
		},
		{
			name:    "single label",
			input:   "com",
			wantErr: false,
		},
		{
			name:    "long domain",
			input:   "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.example.com",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			// Round trip test
			back := parsed.String()
			expected := tt.input
			if expected != "" && expected[len(expected)-1] == '.' {
				expected = expected[:len(expected)-1]
			}
			if back != expected && back != expected+"." {
				t.Errorf("Round trip failed: got %q, want %q", back, expected)
			}
		})
	}
}

func TestNewName(t *testing.T) {
	tests := []struct {
		name    string
		labels  [][]byte
		wantErr bool
	}{
		{
			name:    "valid labels",
			labels:  [][]byte{[]byte("example"), []byte("com")},
			wantErr: false,
		},
		{
			name:    "empty labels",
			labels:  [][]byte{},
			wantErr: false,
		},
		{
			name:    "label too long",
			labels:  [][]byte{make([]byte, 64)}, // 64 > 63
			wantErr: true,
		},
		{
			name:    "zero length label",
			labels:  [][]byte{[]byte("example"), []byte{}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewName(tt.labels)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseMessage(t *testing.T) {
	// Simple DNS query: example.com A query
	queryHex := "123401000001000000000001076578616d706c6503636f6d00000100010000291000000000000000"
	queryBytes := decodeHex(queryHex)

	msg, err := ParseMessage(queryBytes)
	if err != nil {
		t.Fatalf("ParseMessage() error = %v", err)
	}

	if msg.ID != 0x1234 {
		t.Errorf("ID mismatch: got %x, want 1234", msg.ID)
	}

	if len(msg.Question) != 1 {
		t.Errorf("Question count: got %d, want 1", len(msg.Question))
	}

	if msg.Question[0].Name.String() != "example.com" {
		t.Errorf("Question name: got %q, want example.com", msg.Question[0].Name.String())
	}

	if msg.Question[0].Type != RRTypeA {
		t.Errorf("Question type: got %d, want %d", msg.Question[0].Type, RRTypeA)
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name string
		msg  *Message
	}{
		{
			name: "simple query",
			msg: &Message{
				ID:    0x1234,
				Flags: 0x0100,
				Question: []Question{
					{
						Name:  mustParseName("example.com"),
						Type:  RRTypeA,
						Class: ClassIN,
					},
				},
			},
		},
		{
			name: "query with EDNS0",
			msg: &Message{
				ID:    0x5678,
				Flags: 0x0100,
				Question: []Question{
					{
						Name:  mustParseName("test.example.com"),
						Type:  RRTypeTXT,
						Class: ClassIN,
					},
				},
			},
		},
		{
			name: "response with answer",
			msg: &Message{
				ID:    0x9abc,
				Flags: 0x8100, // QR=1
				Question: []Question{
					{
						Name:  mustParseName("example.com"),
						Type:  RRTypeA,
						Class: ClassIN,
					},
				},
				Answer: []RR{
					{
						Name:  mustParseName("example.com"),
						Type:  RRTypeA,
						Class: ClassIN,
						TTL:   300,
						Data:  []byte{192, 168, 1, 1},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			data, err := tt.msg.Marshal()
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}

			// Unmarshal
			parsed, err := ParseMessage(data)
			if err != nil {
				t.Fatalf("ParseMessage() error = %v", err)
			}

			// Verify
			if parsed.ID != tt.msg.ID {
				t.Errorf("ID mismatch: got %x, want %x", parsed.ID, tt.msg.ID)
			}

			if parsed.Flags != tt.msg.Flags {
				t.Errorf("Flags mismatch: got %x, want %x", parsed.Flags, tt.msg.Flags)
			}

			if len(parsed.Question) != len(tt.msg.Question) {
				t.Errorf("Question count mismatch: got %d, want %d", len(parsed.Question), len(tt.msg.Question))
			}

			if len(parsed.Answer) != len(tt.msg.Answer) {
				t.Errorf("Answer count mismatch: got %d, want %d", len(parsed.Answer), len(tt.msg.Answer))
			}
		})
	}
}

func TestCreateQuery(t *testing.T) {
	name := mustParseName("example.com")
	query := CreateQuery(name, RRTypeA, 0x1234)

	if query.ID != 0x1234 {
		t.Errorf("ID mismatch: got %x, want 1234", query.ID)
	}

	if query.IsQuery() != true {
		t.Error("Should be a query")
	}

	if len(query.Question) != 1 {
		t.Errorf("Question count: got %d, want 1", len(query.Question))
	}
}

func TestCreateResponse(t *testing.T) {
	query := CreateQuery(mustParseName("example.com"), RRTypeA, 0x1234)
	response := CreateResponse(query)

	if response.ID != query.ID {
		t.Errorf("ID mismatch: got %x, want %x", response.ID, query.ID)
	}

	if response.IsResponse() != true {
		t.Error("Should be a response")
	}

	if len(response.Question) != len(query.Question) {
		t.Errorf("Question count mismatch")
	}
}

func TestEDNS0(t *testing.T) {
	query := CreateQuery(mustParseName("example.com"), RRTypeA, 0x1234)
	query.AddEDNS0(4096)

	if query.GetEDNS0Size() != 4096 {
		t.Errorf("EDNS0 size: got %d, want 4096", query.GetEDNS0Size())
	}

	response := CreateResponse(query)
	if response.GetEDNS0Size() != 0 {
		t.Error("Response should not have EDNS0 by default")
	}

	response.AddEDNS0(4096)
	if response.GetEDNS0Size() != 4096 {
		t.Errorf("Response EDNS0 size: got %d, want 4096", response.GetEDNS0Size())
	}
}

func TestTXTData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty",
			data: []byte{},
		},
		{
			name: "small",
			data: []byte("hello"),
		},
		{
			name: "medium",
			data: []byte("this is a test string"),
		},
		{
			name: "large",
			data: make([]byte, 500),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := EncodeTXTData(tt.data)
			decoded, err := DecodeTXTData(encoded)
			if err != nil {
				t.Fatalf("DecodeTXTData() error = %v", err)
			}

			if len(decoded) != len(tt.data) {
				t.Errorf("Length mismatch: got %d, want %d", len(decoded), len(tt.data))
				return
			}

			for i := range tt.data {
				if decoded[i] != tt.data[i] {
					t.Errorf("Byte mismatch at index %d", i)
				}
			}
		})
	}
}

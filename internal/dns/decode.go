package dns

import (
	"bytes"
	"errors"
)

var (
	ErrNotAuthoritative = errors.New("not authoritative for this domain")
	ErrInvalidQuery     = errors.New("invalid DNS query")
	ErrInvalidResponse  = errors.New("invalid DNS response")
	ErrNoAnswer         = errors.New("no answer in response")
)

// ExtractQueryPayload extracts the encoded payload from a DNS query.
// Returns the ClientID and decrypted payload from the query name.
func ExtractQueryPayload(msg *Message, domain Name) (ClientID, []byte, error) {
	var clientID ClientID

	// Validate query
	if msg.IsResponse() {
		return clientID, nil, ErrInvalidQuery
	}

	if len(msg.Question) != 1 {
		return clientID, nil, ErrInvalidQuery
	}

	q := msg.Question[0]

	// Check if query type is TXT (we also accept A/AAAA for variation)
	if q.Type != RRTypeTXT && q.Type != RRTypeA && q.Type != RRTypeAAAA {
		return clientID, nil, ErrInvalidQuery
	}

	// Decode the payload from the query name
	return DecodePayload(q.Name, domain)
}

// ExtractResponsePayload extracts the payload from a DNS response TXT record.
func ExtractResponsePayload(msg *Message, domain Name) ([]byte, error) {
	// Validate response
	if !msg.IsResponse() {
		return nil, ErrInvalidResponse
	}

	if msg.Rcode() != RcodeNoError {
		return nil, ErrInvalidResponse
	}

	// Look for TXT record in answer section
	for _, rr := range msg.Answer {
		if rr.Type != RRTypeTXT {
			continue
		}

		// Verify the name matches our domain
		_, ok := rr.Name.TrimSuffix(domain)
		if !ok {
			continue
		}

		// Decode the TXT record data
		txtData, err := DecodeTXTData(rr.Data)
		if err != nil {
			continue
		}

		return txtData, nil
	}

	return nil, ErrNoAnswer
}

// CreateTunnelResponse creates a DNS response with encoded payload.
func CreateTunnelResponse(query *Message, domain Name, payload []byte, ttl uint32) (*Message, error) {
	if len(query.Question) != 1 {
		return nil, ErrInvalidQuery
	}

	resp := CreateResponse(query)
	resp.Flags |= 0x0400 // AA = 1 (authoritative)

	// Encode payload as TXT record
	txtData := EncodeTXTData(payload)

	resp.Answer = []RR{
		{
			Name:  query.Question[0].Name,
			Type:  RRTypeTXT,
			Class: ClassIN,
			TTL:   ttl,
			Data:  txtData,
		},
	}

	// Add EDNS0 if query had it
	if ednsSize := query.GetEDNS0Size(); ednsSize > 0 {
		resp.AddEDNS0(ednsSize)
	}

	return resp, nil
}

// CreateErrorResponse creates a DNS error response.
func CreateErrorResponse(query *Message, domain Name, rcode uint16) *Message {
	resp := CreateResponse(query)
	resp.SetRcode(rcode)

	// Check if query is for our domain to set AA bit
	if len(query.Question) == 1 {
		_, ok := query.Question[0].Name.TrimSuffix(domain)
		if ok {
			resp.Flags |= 0x0400 // AA = 1
		}
	}

	// Add EDNS0 if query had it
	if ednsSize := query.GetEDNS0Size(); ednsSize > 0 {
		resp.AddEDNS0(ednsSize)
	}

	return resp
}

// ValidateQuery validates a DNS query for tunnel use.
func ValidateQuery(msg *Message, domain Name, minEDNSSize uint16) error {
	if msg.IsResponse() {
		return ErrInvalidQuery
	}

	if msg.Opcode() != 0 {
		return errors.New("unsupported opcode")
	}

	if len(msg.Question) != 1 {
		return errors.New("query must have exactly one question")
	}

	q := msg.Question[0]

	// Check if authoritative for this domain
	_, ok := q.Name.TrimSuffix(domain)
	if !ok {
		return ErrNotAuthoritative
	}

	// Check EDNS0 size (we need reasonable payload size)
	if minEDNSSize > 0 {
		ednsSize := msg.GetEDNS0Size()
		if ednsSize < minEDNSSize {
			return errors.New("EDNS0 payload size too small")
		}
	}

	return nil
}

// IsValidTunnelResponse checks if a response is a valid tunnel response.
func IsValidTunnelResponse(msg *Message, domain Name) bool {
	if !msg.IsResponse() {
		return false
	}

	if msg.Rcode() != RcodeNoError {
		return false
	}

	// Must have at least one TXT answer
	for _, rr := range msg.Answer {
		if rr.Type == RRTypeTXT {
			_, ok := rr.Name.TrimSuffix(domain)
			if ok {
				return true
			}
		}
	}

	return false
}

// JoinLabels joins DNS name labels with dots.
func JoinLabels(labels [][]byte) string {
	if len(labels) == 0 {
		return ""
	}
	var buf bytes.Buffer
	for i, label := range labels {
		if i > 0 {
			buf.WriteByte('.')
		}
		buf.Write(label)
	}
	return buf.String()
}

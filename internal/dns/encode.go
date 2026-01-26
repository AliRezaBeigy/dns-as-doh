package dns

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Encoding constants
const (
	// ClientID size
	ClientIDSize = 8

	// Padding range
	MinPadding     = 3
	MaxPadding     = 8
	MinPaddingPoll = 8 // More padding for empty/poll queries

	// Prefix codes for length-prefixed packets
	// L < 0xe0 means data packet of L bytes
	// L >= 0xe0 means padding of L - 0xe0 bytes
	PaddingPrefixBase = 224 // 0xe0
)

var (
	// base32Encoding is base32 without padding, lowercase
	base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

	ErrPayloadTooLong = errors.New("payload too long to encode in DNS name")
	ErrInvalidPayload = errors.New("invalid encoded payload")
)

// ClientID represents an 8-byte client identifier.
type ClientID [ClientIDSize]byte

// NewClientID generates a new random ClientID.
func NewClientID() ClientID {
	var id ClientID
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		panic(fmt.Sprintf("failed to generate ClientID: %v", err))
	}
	return id
}

// DNSNameCapacity calculates the available bytes for encoded data
// given a domain suffix.
func DNSNameCapacity(domain Name) int {
	// Maximum DNS name is 255 bytes
	capacity := 255 - 1 // null terminator

	// Subtract domain labels and their length bytes
	for _, label := range domain {
		capacity -= len(label) + 1
	}

	// Each label can hold up to 63 bytes, but needs 64 bytes to encode
	// (63 bytes data + 1 byte length prefix)
	capacity = capacity * 63 / 64

	// Base32 expands 5 bytes to 8
	capacity = capacity * 5 / 8

	return capacity
}

// EncodePayload encodes a payload into a DNS query name.
// Format: [ClientID][padding][length-prefixed data]
// The result is base32 encoded and split into DNS labels.
func EncodePayload(payload []byte, clientID ClientID, domain Name) (Name, error) {
	capacity := DNSNameCapacity(domain)

	// Build the raw data: ClientID + padding + length-prefixed payload
	var raw bytes.Buffer

	// Write ClientID
	raw.Write(clientID[:])

	// Calculate and write padding
	paddingLen := MinPadding
	if len(payload) == 0 {
		paddingLen = MinPaddingPoll
	}
	// Add some randomness to padding length
	var randByte [1]byte
	if _, err := rand.Read(randByte[:]); err == nil {
		paddingLen += int(randByte[0]) % (MaxPadding - MinPadding + 1)
	}

	// Write padding prefix (0xe0 + paddingLen)
	raw.WriteByte(byte(PaddingPrefixBase + paddingLen))

	// Write random padding bytes
	padding := make([]byte, paddingLen)
	if _, err := io.ReadFull(rand.Reader, padding); err != nil {
		return nil, fmt.Errorf("failed to generate padding: %w", err)
	}
	raw.Write(padding)

	// Write length-prefixed payload (if any)
	if len(payload) > 0 {
		if len(payload) >= PaddingPrefixBase {
			return nil, ErrPayloadTooLong
		}
		raw.WriteByte(byte(len(payload)))
		raw.Write(payload)
	}

	// Check if it fits
	if raw.Len() > capacity {
		return nil, ErrPayloadTooLong
	}

	// Base32 encode
	encoded := make([]byte, base32Encoding.EncodedLen(raw.Len()))
	base32Encoding.Encode(encoded, raw.Bytes())

	// Convert to lowercase
	for i, b := range encoded {
		if b >= 'A' && b <= 'Z' {
			encoded[i] = b + 32
		}
	}

	// Split into DNS labels (max 63 bytes each)
	labels := splitLabels(encoded, MaxLabelLength)

	// Append domain
	labels = append(labels, domain...)

	return Name(labels), nil
}

// splitLabels splits data into chunks of at most maxLen bytes.
func splitLabels(data []byte, maxLen int) [][]byte {
	var labels [][]byte
	for len(data) > 0 {
		n := len(data)
		if n > maxLen {
			n = maxLen
		}
		labels = append(labels, data[:n])
		data = data[n:]
	}
	return labels
}

// DecodePayload decodes a DNS name back into the original payload.
// Returns the ClientID and the payload data.
func DecodePayload(name Name, domain Name) (ClientID, []byte, error) {
	var clientID ClientID

	// Trim domain suffix
	prefix, ok := name.TrimSuffix(domain)
	if !ok {
		return clientID, nil, ErrInvalidPayload
	}

	// Join labels and uppercase for base32 decoding
	encoded := bytes.ToUpper(bytes.Join(prefix, nil))

	// Base32 decode
	decoded := make([]byte, base32Encoding.DecodedLen(len(encoded)))
	n, err := base32Encoding.Decode(decoded, encoded)
	if err != nil {
		return clientID, nil, fmt.Errorf("base32 decode failed: %w", err)
	}
	decoded = decoded[:n]

	// Read ClientID
	if len(decoded) < ClientIDSize {
		return clientID, nil, ErrInvalidPayload
	}
	copy(clientID[:], decoded[:ClientIDSize])
	decoded = decoded[ClientIDSize:]

	// Read packets (skip padding)
	var payload []byte
	r := bytes.NewReader(decoded)

	for {
		prefix, err := r.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			return clientID, nil, err
		}

		if prefix >= PaddingPrefixBase {
			// Padding - skip it
			paddingLen := int(prefix - PaddingPrefixBase)
			if _, err := io.CopyN(io.Discard, r, int64(paddingLen)); err != nil {
				return clientID, nil, err
			}
		} else {
			// Data packet
			dataLen := int(prefix)
			data := make([]byte, dataLen)
			if _, err := io.ReadFull(r, data); err != nil {
				return clientID, nil, err
			}
			payload = append(payload, data...)
		}
	}

	return clientID, payload, nil
}

// EncodeResponse encodes response data into TXT record format.
// Format: [length-prefixed packets]
func EncodeResponse(packets [][]byte) []byte {
	var buf bytes.Buffer
	for _, p := range packets {
		if len(p) > 0xffff {
			continue // Skip packets that are too large
		}
		binary.Write(&buf, binary.BigEndian, uint16(len(p)))
		buf.Write(p)
	}
	return buf.Bytes()
}

// DecodeResponse decodes TXT record data into packets.
func DecodeResponse(data []byte) ([][]byte, error) {
	var packets [][]byte
	r := bytes.NewReader(data)

	for r.Len() > 0 {
		var length uint16
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		packet := make([]byte, length)
		if _, err := io.ReadFull(r, packet); err != nil {
			return nil, err
		}
		packets = append(packets, packet)
	}

	return packets, nil
}

// GenerateQueryID generates a random DNS query ID.
func GenerateQueryID() uint16 {
	var id uint16
	binary.Read(rand.Reader, binary.BigEndian, &id)
	return id
}

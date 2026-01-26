// Package dns provides DNS message encoding and decoding utilities.
package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// DNS constants
const (
	// Record types
	RRTypeA    uint16 = 1
	RRTypeAAAA uint16 = 28
	RRTypeTXT  uint16 = 16
	RRTypeOPT  uint16 = 41

	// Classes
	ClassIN uint16 = 1

	// Response codes
	RcodeNoError     uint16 = 0
	RcodeFormatError uint16 = 1
	RcodeServerFail  uint16 = 2
	RcodeNameError   uint16 = 3 // NXDOMAIN
	RcodeNotImpl     uint16 = 4
	RcodeRefused     uint16 = 5

	// Maximum sizes
	MaxLabelLength = 63
	MaxNameLength  = 255
	MaxUDPSize     = 512
	MaxEDNSSize    = 4096

	// Compression pointer limit
	compressionPointerLimit = 10
)

var (
	ErrZeroLengthLabel   = errors.New("name contains a zero-length label")
	ErrLabelTooLong      = errors.New("label exceeds 63 bytes")
	ErrNameTooLong       = errors.New("name exceeds 255 bytes")
	ErrTooManyPointers   = errors.New("too many compression pointers")
	ErrReservedLabelType = errors.New("reserved label type")
	ErrTrailingBytes     = errors.New("trailing bytes after message")
	ErrIntegerOverflow   = errors.New("integer overflow")
	ErrInvalidMessage    = errors.New("invalid DNS message")
)

// Name represents a DNS domain name as a sequence of labels.
type Name [][]byte

// NewName creates a new Name from labels after validation.
func NewName(labels [][]byte) (Name, error) {
	totalLen := 0
	for _, label := range labels {
		if len(label) == 0 {
			return nil, ErrZeroLengthLabel
		}
		if len(label) > MaxLabelLength {
			return nil, ErrLabelTooLong
		}
		totalLen += len(label) + 1
	}
	totalLen++ // null terminator
	if totalLen > MaxNameLength {
		return nil, ErrNameTooLong
	}
	return Name(labels), nil
}

// ParseName parses a domain name from a dot-separated string.
func ParseName(s string) (Name, error) {
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return Name{}, nil
	}
	parts := strings.Split(s, ".")
	labels := make([][]byte, len(parts))
	for i, part := range parts {
		labels[i] = []byte(part)
	}
	return NewName(labels)
}

// String returns the name as a dot-separated string.
func (n Name) String() string {
	if len(n) == 0 {
		return "."
	}
	var buf strings.Builder
	for i, label := range n {
		if i > 0 {
			buf.WriteByte('.')
		}
		for _, b := range label {
			if b == '-' || (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') {
				buf.WriteByte(b)
			} else {
				fmt.Fprintf(&buf, "\\x%02x", b)
			}
		}
	}
	return buf.String()
}

// TrimSuffix removes the suffix from the name and returns the prefix.
func (n Name) TrimSuffix(suffix Name) (Name, bool) {
	if len(n) < len(suffix) {
		return nil, false
	}
	split := len(n) - len(suffix)
	fore, aft := n[:split], n[split:]
	for i := 0; i < len(aft); i++ {
		if !bytes.EqualFold(aft[i], suffix[i]) {
			return nil, false
		}
	}
	return fore, true
}

// Question represents a DNS question.
type Question struct {
	Name  Name
	Type  uint16
	Class uint16
}

// RR represents a DNS resource record.
type RR struct {
	Name  Name
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

// Message represents a DNS message.
type Message struct {
	ID         uint16
	Flags      uint16
	Question   []Question
	Answer     []RR
	Authority  []RR
	Additional []RR
}

// Opcode returns the OPCODE from the flags.
func (m *Message) Opcode() uint16 {
	return (m.Flags >> 11) & 0xf
}

// Rcode returns the RCODE from the flags.
func (m *Message) Rcode() uint16 {
	return m.Flags & 0xf
}

// IsQuery returns true if this is a query (QR=0).
func (m *Message) IsQuery() bool {
	return m.Flags&0x8000 == 0
}

// IsResponse returns true if this is a response (QR=1).
func (m *Message) IsResponse() bool {
	return m.Flags&0x8000 != 0
}

// SetResponse sets the QR bit to 1 (response).
func (m *Message) SetResponse() {
	m.Flags |= 0x8000
}

// SetRcode sets the RCODE in the flags.
func (m *Message) SetRcode(rcode uint16) {
	m.Flags = (m.Flags & 0xfff0) | (rcode & 0xf)
}

// readName reads a DNS name from a reader with compression support.
func readName(r io.ReadSeeker) (Name, error) {
	var labels [][]byte
	numPointers := 0
	var seekTo int64 = -1

	for {
		var labelType byte
		if err := binary.Read(r, binary.BigEndian, &labelType); err != nil {
			return nil, err
		}

		switch labelType & 0xc0 {
		case 0x00:
			// Normal label
			length := int(labelType & 0x3f)
			if length == 0 {
				// End of name
				if seekTo >= 0 {
					if _, err := r.Seek(seekTo, io.SeekStart); err != nil {
						return nil, err
					}
				}
				return NewName(labels)
			}
			label := make([]byte, length)
			if _, err := io.ReadFull(r, label); err != nil {
				return nil, err
			}
			labels = append(labels, label)

		case 0xc0:
			// Compression pointer
			upper := labelType & 0x3f
			var lower byte
			if err := binary.Read(r, binary.BigEndian, &lower); err != nil {
				return nil, err
			}
			offset := (uint16(upper) << 8) | uint16(lower)

			if numPointers == 0 {
				var err error
				seekTo, err = r.Seek(0, io.SeekCurrent)
				if err != nil {
					return nil, err
				}
			}
			numPointers++
			if numPointers > compressionPointerLimit {
				return nil, ErrTooManyPointers
			}

			if _, err := r.Seek(int64(offset), io.SeekStart); err != nil {
				return nil, err
			}

		default:
			return nil, ErrReservedLabelType
		}
	}
}

// readQuestion reads a DNS question from a reader.
func readQuestion(r io.ReadSeeker) (Question, error) {
	var q Question
	var err error

	q.Name, err = readName(r)
	if err != nil {
		return q, err
	}

	if err := binary.Read(r, binary.BigEndian, &q.Type); err != nil {
		return q, err
	}
	if err := binary.Read(r, binary.BigEndian, &q.Class); err != nil {
		return q, err
	}

	return q, nil
}

// readRR reads a DNS resource record from a reader.
func readRR(r io.ReadSeeker) (RR, error) {
	var rr RR
	var err error

	rr.Name, err = readName(r)
	if err != nil {
		return rr, err
	}

	if err := binary.Read(r, binary.BigEndian, &rr.Type); err != nil {
		return rr, err
	}
	if err := binary.Read(r, binary.BigEndian, &rr.Class); err != nil {
		return rr, err
	}
	if err := binary.Read(r, binary.BigEndian, &rr.TTL); err != nil {
		return rr, err
	}

	var rdLength uint16
	if err := binary.Read(r, binary.BigEndian, &rdLength); err != nil {
		return rr, err
	}

	rr.Data = make([]byte, rdLength)
	if _, err := io.ReadFull(r, rr.Data); err != nil {
		return rr, err
	}

	return rr, nil
}

// ParseMessage parses a DNS message from wire format.
func ParseMessage(buf []byte) (*Message, error) {
	r := bytes.NewReader(buf)

	var msg Message
	var qdCount, anCount, nsCount, arCount uint16

	if err := binary.Read(r, binary.BigEndian, &msg.ID); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &msg.Flags); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &qdCount); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &anCount); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &nsCount); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &arCount); err != nil {
		return nil, err
	}

	// Read questions
	for i := uint16(0); i < qdCount; i++ {
		q, err := readQuestion(r)
		if err != nil {
			return nil, err
		}
		msg.Question = append(msg.Question, q)
	}

	// Read answers
	for i := uint16(0); i < anCount; i++ {
		rr, err := readRR(r)
		if err != nil {
			return nil, err
		}
		msg.Answer = append(msg.Answer, rr)
	}

	// Read authority
	for i := uint16(0); i < nsCount; i++ {
		rr, err := readRR(r)
		if err != nil {
			return nil, err
		}
		msg.Authority = append(msg.Authority, rr)
	}

	// Read additional
	for i := uint16(0); i < arCount; i++ {
		rr, err := readRR(r)
		if err != nil {
			return nil, err
		}
		msg.Additional = append(msg.Additional, rr)
	}

	// Check for trailing bytes
	if r.Len() > 0 {
		return nil, ErrTrailingBytes
	}

	return &msg, nil
}

// messageBuilder helps build DNS messages with name compression.
type messageBuilder struct {
	buf       bytes.Buffer
	nameCache map[string]int
}

func newMessageBuilder() *messageBuilder {
	return &messageBuilder{
		nameCache: make(map[string]int),
	}
}

func (b *messageBuilder) Bytes() []byte {
	return b.buf.Bytes()
}

func (b *messageBuilder) writeName(name Name) {
	for i := range name {
		suffix := name[i:].String()
		if ptr, ok := b.nameCache[suffix]; ok && ptr&0x3fff == ptr {
			binary.Write(&b.buf, binary.BigEndian, uint16(0xc000|ptr))
			return
		}

		b.nameCache[suffix] = b.buf.Len()
		length := len(name[i])
		b.buf.WriteByte(byte(length))
		b.buf.Write(name[i])
	}
	b.buf.WriteByte(0)
}

func (b *messageBuilder) writeQuestion(q *Question) {
	b.writeName(q.Name)
	binary.Write(&b.buf, binary.BigEndian, q.Type)
	binary.Write(&b.buf, binary.BigEndian, q.Class)
}

func (b *messageBuilder) writeRR(rr *RR) error {
	b.writeName(rr.Name)
	binary.Write(&b.buf, binary.BigEndian, rr.Type)
	binary.Write(&b.buf, binary.BigEndian, rr.Class)
	binary.Write(&b.buf, binary.BigEndian, rr.TTL)

	rdLength := uint16(len(rr.Data))
	if int(rdLength) != len(rr.Data) {
		return ErrIntegerOverflow
	}
	binary.Write(&b.buf, binary.BigEndian, rdLength)
	b.buf.Write(rr.Data)
	return nil
}

// Marshal converts a Message to wire format.
func (m *Message) Marshal() ([]byte, error) {
	b := newMessageBuilder()

	binary.Write(&b.buf, binary.BigEndian, m.ID)
	binary.Write(&b.buf, binary.BigEndian, m.Flags)

	counts := []int{len(m.Question), len(m.Answer), len(m.Authority), len(m.Additional)}
	for _, count := range counts {
		c := uint16(count)
		if int(c) != count {
			return nil, ErrIntegerOverflow
		}
		binary.Write(&b.buf, binary.BigEndian, c)
	}

	for i := range m.Question {
		b.writeQuestion(&m.Question[i])
	}

	for _, rrs := range [][]RR{m.Answer, m.Authority, m.Additional} {
		for i := range rrs {
			if err := b.writeRR(&rrs[i]); err != nil {
				return nil, err
			}
		}
	}

	return b.Bytes(), nil
}

// DecodeTXTData decodes TXT record data (character strings).
func DecodeTXTData(data []byte) ([]byte, error) {
	var result bytes.Buffer
	for len(data) > 0 {
		if len(data) < 1 {
			return nil, io.ErrUnexpectedEOF
		}
		length := int(data[0])
		data = data[1:]
		if len(data) < length {
			return nil, io.ErrUnexpectedEOF
		}
		result.Write(data[:length])
		data = data[length:]
	}
	return result.Bytes(), nil
}

// EncodeTXTData encodes data as TXT record format (character strings).
func EncodeTXTData(data []byte) []byte {
	var buf bytes.Buffer
	for len(data) > 255 {
		buf.WriteByte(255)
		buf.Write(data[:255])
		data = data[255:]
	}
	buf.WriteByte(byte(len(data)))
	buf.Write(data)
	return buf.Bytes()
}

// CreateQuery creates a basic DNS query message.
func CreateQuery(name Name, qtype uint16, id uint16) *Message {
	return &Message{
		ID:    id,
		Flags: 0x0100, // RD=1
		Question: []Question{
			{Name: name, Type: qtype, Class: ClassIN},
		},
	}
}

// CreateResponse creates a DNS response message for a query.
func CreateResponse(query *Message) *Message {
	resp := &Message{
		ID:       query.ID,
		Flags:    0x8000, // QR=1
		Question: query.Question,
	}
	return resp
}

// AddEDNS0 adds an EDNS0 OPT record to the message.
func (m *Message) AddEDNS0(udpSize uint16) {
	m.Additional = append(m.Additional, RR{
		Name:  Name{},
		Type:  RRTypeOPT,
		Class: udpSize,
		TTL:   0,
		Data:  []byte{},
	})
}

// GetEDNS0Size returns the EDNS0 UDP payload size, or 0 if not present.
func (m *Message) GetEDNS0Size() uint16 {
	for _, rr := range m.Additional {
		if rr.Type == RRTypeOPT {
			return rr.Class
		}
	}
	return 0
}

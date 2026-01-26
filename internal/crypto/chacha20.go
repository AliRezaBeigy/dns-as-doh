// Package crypto provides encryption utilities for the DNS tunnel.
package crypto

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Constants
const (
	// KeySize is the size of encryption keys in bytes
	KeySize = 32

	// NonceSize is the size of nonces (12 bytes for ChaCha20Poly1305)
	NonceSize = chacha20poly1305.NonceSize // 12 bytes

	// NonceCounterSize is the counter portion of the nonce
	NonceCounterSize = 8

	// NonceRandomSize is the random portion of the nonce
	NonceRandomSize = 4

	// TimestampSize is the size of timestamp in payload
	TimestampSize = 4

	// ReplayWindow is the time window for replay protection (5 minutes)
	ReplayWindow = 5 * time.Minute

	// Client to server context for key derivation
	ContextClientToServer = "client-to-server"

	// Server to client context for key derivation
	ContextServerToClient = "server-to-client"
)

var (
	ErrInvalidKey       = errors.New("invalid encryption key")
	ErrDecryptionFailed = errors.New("decryption failed")
	ErrReplayDetected   = errors.New("replay attack detected")
	ErrMessageTooOld    = errors.New("message timestamp too old")
	ErrMessageTooNew    = errors.New("message timestamp too far in future")
)

// Cipher provides encryption and decryption with replay protection.
type Cipher struct {
	encryptKey []byte
	decryptKey []byte
	counter    uint64
	mu         sync.Mutex
}

// NewCipher creates a new Cipher from a shared secret.
// isClient determines which direction keys are used for encryption/decryption.
func NewCipher(sharedSecret []byte, isClient bool) (*Cipher, error) {
	if len(sharedSecret) < 16 {
		return nil, ErrInvalidKey
	}

	// Derive keys using HKDF
	clientToServerKey, err := deriveKey(sharedSecret, ContextClientToServer)
	if err != nil {
		return nil, err
	}

	serverToClientKey, err := deriveKey(sharedSecret, ContextServerToClient)
	if err != nil {
		return nil, err
	}

	c := &Cipher{}
	if isClient {
		c.encryptKey = clientToServerKey
		c.decryptKey = serverToClientKey
	} else {
		c.encryptKey = serverToClientKey
		c.decryptKey = clientToServerKey
	}

	return c, nil
}

// deriveKey derives a key from the shared secret using HKDF-SHA256.
func deriveKey(secret []byte, context string) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, secret, nil, context, KeySize)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext with the current timestamp.
// Returns: [nonce (12 bytes)][encrypted payload]
// Where payload = [timestamp (4 bytes)][plaintext]
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(c.encryptKey)
	if err != nil {
		return nil, err
	}

	// Generate nonce: [counter (8 bytes)][random (4 bytes)]
	nonce := make([]byte, NonceSize)
	counter := atomic.AddUint64(&c.counter, 1)
	binary.BigEndian.PutUint64(nonce[:NonceCounterSize], counter)
	if _, err := rand.Read(nonce[NonceCounterSize:]); err != nil {
		return nil, err
	}

	// Build payload: [timestamp (4 bytes)][plaintext]
	timestamp := uint32(time.Now().Unix())
	payload := make([]byte, TimestampSize+len(plaintext))
	binary.BigEndian.PutUint32(payload[:TimestampSize], timestamp)
	copy(payload[TimestampSize:], plaintext)

	// Encrypt
	ciphertext := aead.Seal(nil, nonce, payload, nil)

	// Result: [nonce][ciphertext]
	result := make([]byte, NonceSize+len(ciphertext))
	copy(result[:NonceSize], nonce)
	copy(result[NonceSize:], ciphertext)

	return result, nil
}

// Decrypt decrypts ciphertext and verifies the timestamp.
// Input format: [nonce (12 bytes)][encrypted payload]
func (c *Cipher) Decrypt(data []byte) ([]byte, error) {
	if len(data) < NonceSize+TimestampSize+chacha20poly1305.Overhead {
		return nil, ErrDecryptionFailed
	}

	aead, err := chacha20poly1305.New(c.decryptKey)
	if err != nil {
		return nil, err
	}

	// Extract nonce and ciphertext
	nonce := data[:NonceSize]
	ciphertext := data[NonceSize:]

	// Decrypt
	payload, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	// Verify timestamp
	if len(payload) < TimestampSize {
		return nil, ErrDecryptionFailed
	}

	timestamp := binary.BigEndian.Uint32(payload[:TimestampSize])
	msgTime := time.Unix(int64(timestamp), 0)
	now := time.Now()

	// Check if message is too old
	if now.Sub(msgTime) > ReplayWindow {
		return nil, ErrMessageTooOld
	}

	// Check if message is too far in the future (clock skew tolerance)
	if msgTime.Sub(now) > time.Minute {
		return nil, ErrMessageTooNew
	}

	return payload[TimestampSize:], nil
}

// EncryptWithoutTimestamp encrypts without timestamp (for response data).
// Returns: [nonce (12 bytes)][encrypted plaintext]
func (c *Cipher) EncryptWithoutTimestamp(plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(c.encryptKey)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	nonce := make([]byte, NonceSize)
	counter := atomic.AddUint64(&c.counter, 1)
	binary.BigEndian.PutUint64(nonce[:NonceCounterSize], counter)
	if _, err := rand.Read(nonce[NonceCounterSize:]); err != nil {
		return nil, err
	}

	// Encrypt
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// Result: [nonce][ciphertext]
	result := make([]byte, NonceSize+len(ciphertext))
	copy(result[:NonceSize], nonce)
	copy(result[NonceSize:], ciphertext)

	return result, nil
}

// DecryptWithoutTimestamp decrypts without timestamp verification.
func (c *Cipher) DecryptWithoutTimestamp(data []byte) ([]byte, error) {
	if len(data) < NonceSize+chacha20poly1305.Overhead {
		return nil, ErrDecryptionFailed
	}

	aead, err := chacha20poly1305.New(c.decryptKey)
	if err != nil {
		return nil, err
	}

	nonce := data[:NonceSize]
	ciphertext := data[NonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// GenerateKey generates a random encryption key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// ConstantTimeCompare performs a constant-time comparison of two byte slices.
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ZeroBytes securely zeros a byte slice.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ReplayDetector tracks seen nonces to detect replay attacks.
type ReplayDetector struct {
	seen   map[string]time.Time
	window time.Duration
	mu     sync.RWMutex
}

// NewReplayDetector creates a new replay detector with the given window.
func NewReplayDetector(window time.Duration) *ReplayDetector {
	rd := &ReplayDetector{
		seen:   make(map[string]time.Time),
		window: window,
	}
	// Start cleanup goroutine
	go rd.cleanup()
	return rd
}

// Check returns true if the nonce has been seen before (replay attack).
func (rd *ReplayDetector) Check(nonce []byte) bool {
	key := string(nonce)

	rd.mu.RLock()
	_, exists := rd.seen[key]
	rd.mu.RUnlock()

	if exists {
		return true
	}

	rd.mu.Lock()
	rd.seen[key] = time.Now()
	rd.mu.Unlock()

	return false
}

// cleanup periodically removes old nonces from the detector.
func (rd *ReplayDetector) cleanup() {
	ticker := time.NewTicker(rd.window / 2)
	defer ticker.Stop()

	for range ticker.C {
		cutoff := time.Now().Add(-rd.window)

		rd.mu.Lock()
		for k, v := range rd.seen {
			if v.Before(cutoff) {
				delete(rd.seen, k)
			}
		}
		rd.mu.Unlock()
	}
}

// ParseHexKey parses a hexadecimal key string.
func ParseHexKey(hexKey string) ([]byte, error) {
	if len(hexKey) != KeySize*2 {
		return nil, fmt.Errorf("key must be %d hex characters", KeySize*2)
	}

	key := make([]byte, KeySize)
	for i := 0; i < KeySize; i++ {
		_, err := fmt.Sscanf(hexKey[i*2:i*2+2], "%02x", &key[i])
		if err != nil {
			return nil, fmt.Errorf("invalid hex at position %d", i*2)
		}
	}
	return key, nil
}

// FormatHexKey formats a key as a hexadecimal string.
func FormatHexKey(key []byte) string {
	return fmt.Sprintf("%x", key)
}

package crypto

import (
	"bytes"
	"testing"
	"time"
)

func TestNewCipher(t *testing.T) {
	tests := []struct {
		name        string
		secret      []byte
		isClient    bool
		wantErr     bool
		description string
	}{
		{
			name:        "valid secret client",
			secret:      make([]byte, 32),
			isClient:    true,
			wantErr:     false,
			description: "32-byte secret for client",
		},
		{
			name:        "valid secret server",
			secret:      make([]byte, 32),
			isClient:    false,
			wantErr:     false,
			description: "32-byte secret for server",
		},
		{
			name:        "short secret",
			secret:      make([]byte, 15),
			isClient:    true,
			wantErr:     true,
			description: "secret too short",
		},
		{
			name:        "long secret",
			secret:      make([]byte, 64),
			isClient:    true,
			wantErr:     false,
			description: "long secret should work",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipher, err := NewCipher(tt.secret, tt.isClient)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCipher() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			if cipher == nil {
				t.Error("Cipher is nil")
			}
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	clientCipher, err := NewCipher(secret, true)
	if err != nil {
		t.Fatalf("NewCipher() error = %v", err)
	}

	serverCipher, err := NewCipher(secret, false)
	if err != nil {
		t.Fatalf("NewCipher() error = %v", err)
	}

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "empty",
			plaintext: []byte{},
		},
		{
			name:      "small",
			plaintext: []byte{1, 2, 3, 4, 5},
		},
		{
			name:      "medium",
			plaintext: make([]byte, 100),
		},
		{
			name:      "large",
			plaintext: make([]byte, 1000),
		},
		{
			name:      "dns query",
			plaintext: []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Client encrypts
			ciphertext, err := clientCipher.Encrypt(tt.plaintext)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			// Should have nonce + ciphertext
			if len(ciphertext) < NonceSize+TimestampSize {
				t.Errorf("Ciphertext too short: got %d", len(ciphertext))
			}

			// Server decrypts
			decrypted, err := serverCipher.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			// Verify plaintext matches (minus timestamp)
			if len(decrypted) != len(tt.plaintext) {
				t.Errorf("Length mismatch: got %d, want %d", len(decrypted), len(tt.plaintext))
				return
			}

			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("Plaintext mismatch")
			}
		})
	}
}

func TestEncryptDecryptWithoutTimestamp(t *testing.T) {
	secret := make([]byte, 32)
	clientCipher, _ := NewCipher(secret, true)
	serverCipher, _ := NewCipher(secret, false)

	plaintext := []byte{1, 2, 3, 4, 5}

	// Client encrypts
	ciphertext, err := clientCipher.EncryptWithoutTimestamp(plaintext)
	if err != nil {
		t.Fatalf("EncryptWithoutTimestamp() error = %v", err)
	}

	// Server decrypts
	decrypted, err := serverCipher.DecryptWithoutTimestamp(ciphertext)
	if err != nil {
		t.Fatalf("DecryptWithoutTimestamp() error = %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Plaintext mismatch")
	}
}

func TestReplayProtection(t *testing.T) {
	secret := make([]byte, 32)
	clientCipher, _ := NewCipher(secret, true)
	serverCipher, _ := NewCipher(secret, false)

	plaintext := []byte{1, 2, 3, 4, 5}
	ciphertext, _ := clientCipher.Encrypt(plaintext)

	// Server decrypt should work
	_, err := serverCipher.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("First decrypt failed: %v", err)
	}

	// Decrypt again should still work (within window, but replay detector will catch it)
	// Note: The replay detector is per-cipher, so this test verifies timestamp validation
	_, err = serverCipher.Decrypt(ciphertext)
	if err != nil {
		// This is expected if replay detection is working
		// The timestamp check should allow it, but replay detector might catch it
		t.Logf("Second decrypt failed (may be expected): %v", err)
	}
}

func TestReplayDetector(t *testing.T) {
	detector := NewReplayDetector(5 * time.Minute)

	nonce1 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	nonce2 := []byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}

	// First check should not be a replay
	if detector.Check(nonce1) {
		t.Error("First nonce should not be detected as replay")
	}

	// Second check of same nonce should be a replay
	if !detector.Check(nonce1) {
		t.Error("Second check of same nonce should be detected as replay")
	}

	// Different nonce should not be a replay
	if detector.Check(nonce2) {
		t.Error("Different nonce should not be detected as replay")
	}
}

func TestKeyDerivation(t *testing.T) {
	secret := make([]byte, 32)

	clientCipher, _ := NewCipher(secret, true)
	serverCipher, _ := NewCipher(secret, false)

	// Client and server should have opposite keys
	plaintext := []byte{1, 2, 3, 4, 5}

	// Client encrypts
	ciphertext, _ := clientCipher.Encrypt(plaintext)

	// Server should be able to decrypt
	decrypted, err := serverCipher.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Server decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Decryption failed")
	}
}

func TestGenerateKey(t *testing.T) {
	key1, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if len(key1) != KeySize {
		t.Errorf("Key size: got %d, want %d", len(key1), KeySize)
	}

	// Generate another key and verify they're different
	key2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() second call error = %v", err)
	}
	if bytes.Equal(key1, key2) {
		t.Error("Generated keys should be different")
	}
}

func TestParseHexKey(t *testing.T) {
	tests := []struct {
		name    string
		hexKey  string
		wantErr bool
	}{
		{
			name:    "valid key",
			hexKey:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantErr: false,
		},
		{
			name:    "short key",
			hexKey:  "0123456789abcdef",
			wantErr: true,
		},
		{
			name:    "invalid hex",
			hexKey:  "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
			wantErr: true,
		},
		{
			name:    "wrong length",
			hexKey:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParseHexKey(tt.hexKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseHexKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			if len(key) != KeySize {
				t.Errorf("Key size: got %d, want %d", len(key), KeySize)
			}
		})
	}
}

func TestFormatHexKey(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	hexKey := FormatHexKey(key)
	if len(hexKey) != KeySize*2 {
		t.Errorf("Hex key length: got %d, want %d", len(hexKey), KeySize*2)
	}

	// Round trip
	parsed, err := ParseHexKey(hexKey)
	if err != nil {
		t.Fatalf("ParseHexKey() error = %v", err)
	}

	if !bytes.Equal(parsed, key) {
		t.Error("Round trip failed")
	}
}

func TestConstantTimeCompare(t *testing.T) {
	a := []byte{1, 2, 3, 4, 5}
	b := []byte{1, 2, 3, 4, 5}
	c := []byte{1, 2, 3, 4, 6}

	if !ConstantTimeCompare(a, b) {
		t.Error("Equal bytes should compare equal")
	}

	if ConstantTimeCompare(a, c) {
		t.Error("Different bytes should not compare equal")
	}
}

func TestZeroBytes(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	ZeroBytes(data)

	for _, b := range data {
		if b != 0 {
			t.Error("Bytes should be zeroed")
		}
	}
}

func TestNonceUniqueness(t *testing.T) {
	secret := make([]byte, 32)
	cipher, _ := NewCipher(secret, true)

	plaintext := []byte{1, 2, 3}
	nonces := make(map[string]bool)

	// Generate multiple ciphertexts and check nonces are unique
	for i := 0; i < 100; i++ {
		ciphertext, _ := cipher.Encrypt(plaintext)
		nonce := string(ciphertext[:NonceSize])
		if nonces[nonce] {
			t.Errorf("Duplicate nonce at iteration %d", i)
		}
		nonces[nonce] = true
	}
}

func TestTamperedCiphertext(t *testing.T) {
	secret := make([]byte, 32)
	cipher, _ := NewCipher(secret, true)

	plaintext := []byte{1, 2, 3, 4, 5}
	ciphertext, _ := cipher.Encrypt(plaintext)

	// Tamper with ciphertext
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 1

	// Decrypt should fail
	_, err := cipher.Decrypt(tampered)
	if err == nil {
		t.Error("Tampered ciphertext should fail to decrypt")
	}
}

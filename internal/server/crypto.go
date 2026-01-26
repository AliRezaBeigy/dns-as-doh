package server

import (
	"github.com/user/dns-as-doh/internal/crypto"
)

// ServerCrypto wraps the crypto package for server-specific usage.
type ServerCrypto struct {
	cipher *crypto.Cipher
}

// NewServerCrypto creates a new server crypto handler.
func NewServerCrypto(sharedSecret []byte) (*ServerCrypto, error) {
	cipher, err := crypto.NewCipher(sharedSecret, false) // isClient=false
	if err != nil {
		return nil, err
	}
	return &ServerCrypto{cipher: cipher}, nil
}

// DecryptQuery decrypts a DNS query payload with timestamp verification.
func (c *ServerCrypto) DecryptQuery(query []byte) ([]byte, error) {
	return c.cipher.Decrypt(query)
}

// EncryptResponse encrypts a DNS response payload.
func (c *ServerCrypto) EncryptResponse(response []byte) ([]byte, error) {
	return c.cipher.EncryptWithoutTimestamp(response)
}

// GetCipher returns the underlying cipher.
func (c *ServerCrypto) GetCipher() *crypto.Cipher {
	return c.cipher
}

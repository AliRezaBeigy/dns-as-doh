package client

import (
	"github.com/AliRezaBeigy/dns-as-doh/internal/crypto"
)

// ClientCrypto wraps the crypto package for client-specific usage.
type ClientCrypto struct {
	cipher *crypto.Cipher
}

// NewClientCrypto creates a new client crypto handler.
func NewClientCrypto(sharedSecret []byte) (*ClientCrypto, error) {
	cipher, err := crypto.NewCipher(sharedSecret, true) // isClient=true
	if err != nil {
		return nil, err
	}
	return &ClientCrypto{cipher: cipher}, nil
}

// EncryptQuery encrypts a DNS query payload with timestamp.
func (c *ClientCrypto) EncryptQuery(query []byte) ([]byte, error) {
	return c.cipher.Encrypt(query)
}

// DecryptResponse decrypts a DNS response payload.
func (c *ClientCrypto) DecryptResponse(response []byte) ([]byte, error) {
	return c.cipher.DecryptWithoutTimestamp(response)
}

// GetCipher returns the underlying cipher.
func (c *ClientCrypto) GetCipher() *crypto.Cipher {
	return c.cipher
}

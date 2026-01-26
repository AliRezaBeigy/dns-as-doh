package dns

import (
	"encoding/hex"
)

// Helper functions for package tests.
// For shared test helpers, use tests/helpers package.

// mustParseName parses a DNS name or panics.
func mustParseName(s string) Name {
	n, err := ParseName(s)
	if err != nil {
		panic(err)
	}
	return n
}

// decodeHex decodes a hex string or panics.
func decodeHex(s string) []byte {
	if s == "" {
		return []byte{}
	}
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

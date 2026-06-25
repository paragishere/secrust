package utils

import (
	"crypto/sha256"
	"encoding/hex"
)

func GenerateHash(domain string) string {

	hash := sha256.Sum256(
		[]byte(domain),
	)

	return hex.EncodeToString(
		hash[:],
	)[:12]
}

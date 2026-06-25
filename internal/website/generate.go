package website

import (
	"crypto/rand"
	"encoding/hex"
)

func GenerateAPIKey() string {

	bytes := make([]byte, 32)

	rand.Read(bytes)

	return hex.EncodeToString(bytes)
}

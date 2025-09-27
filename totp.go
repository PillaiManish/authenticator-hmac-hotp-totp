package hmac

import (
	"crypto"
	"time"
)

// GenerateTotp generates a d-digit OTP from a given key K using HMAC-Hash-Based Message Authentication Code.
func GenerateTotp(K []byte, p uint64, d int, H crypto.Hash) string {
	// get the current time in seconds and divide by period
	t := time.Now().Unix() / int64(p)

	// convert to uint64
	C := uint64(t)

	// generate the OTP
	return Hmac(K, C, d, H)
}

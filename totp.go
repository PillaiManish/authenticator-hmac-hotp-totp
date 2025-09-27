package hmac

import (
	"crypto"
	"time"
)

// GenerateTotp generates a d-digit OTP from a given key K using HMAC-Hash-Based Message Authentication Code.
// p is the period in seconds.
// d is the length of the OTP.
// H is the hash function.
func GenerateTotp(K string, p uint64, d int, H crypto.Hash) string {
	// get the current time in seconds and divide by period
	t := time.Now().Unix() / int64(p)

	// convert to uint64
	C := uint64(t)

	// generate the OTP
	return Hmac(K, C, d, H)
}

// VerifyTotp verifies a given OTP against a given counter C using HMAC-Hash-Based Message Authentication Code.
// p is the period in seconds.
// windowSize is the range of the OTP to check.
// C is the counter.
// otp is the OTP to check.
// d is the length of the OTP.
// H is the hash function.
func VerifyTotp(K string, p uint64, windowSize int, otp string, d int, H crypto.Hash) bool {
	// get the current time in seconds and divide by period
	t := time.Now().Unix() / int64(p)

	// try the OTPs for current time and windowSize before and after
	for i := -windowSize; i <= windowSize; i++ {
		ts := t + int64(i)
		if ts < 0 {
			continue
		}

		// generate OTP for this timestamp
		if Hmac(K, uint64(ts), d, H) == otp {
			return true
		}
	}
	return false
}

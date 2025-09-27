package hmac

import "crypto"

// GenerateHotp generates a d-digit OTP from a given counter C using HMAC-Hash-Based Message Authentication Code.
// K is the secret key.
// C is the counter.
// d is the length of the OTP.
// H is the hash function.
func GenerateHotp(K string, C uint64, d int, H crypto.Hash) string {
	return Hmac(K, C, d, H)
}

// VerifyHotp verifies a given OTP against a given counter C using HMAC-Hash-Based Message Authentication Code.
// K is the secret key.
// windowSize is the range of the OTP to check.
// C is the counter.
// otp is the OTP to check.
// d is the length of the OTP.
// H is the hash function.
func VerifyHotp(K string, windowSize int, C uint64, otp string, d int, H crypto.Hash) bool {

	for i := 0; i < windowSize; i++ {
		if Hmac(K, C+uint64(i), d, H) == otp {
			return true
		}

		if C-uint64(i) > 0 {
			if Hmac(K, C-uint64(i), d, H) == otp {
				return true
			}
		}

	}

	return false
}

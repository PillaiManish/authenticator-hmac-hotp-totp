package hmac

import "crypto"

func GenerateHotp(K []byte, C uint64, d int, H crypto.Hash) string {
	return Hmac(K, C, d, H)
}

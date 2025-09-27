package hmac

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
)

// Hmac generates a d-digit OTP from a given counter C using HMAC-Hash-Based Message Authentication Code.
// K is the secret key.
// C is the counter.
// d is the length of the OTP.
// H is the hash function.
func Hmac(k string, C uint64, d int, H crypto.Hash) string {
	if !H.Available() {
		panic("hmac: requested hash function is not available")
	}

	K, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(k)

	mac := hmac.New(sha1.New, K)

	// convert C to 8 bytes
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, C)

	// generate mac from hash
	mac.Write(counterBytes)

	// generate mac from hash of 20 bytes
	hash := mac.Sum(nil)

	// generate d-digit OTP from hash
	return dynamicTruncation(hash, d)
}

// dynamicTruncation generates a d-digit OTP by extracting and processing a portion of the given hash.
// It computes an offset from the hash's last byte, constructs a 4-byte binary value starting at the offset,
// and returns the OTP as a zero-padded string.
// hash is the hash to process.
// d is the length of the OTP.
func dynamicTruncation(hash []byte, d int) string {
	// take out the last byte of the hash
	// AND with 0x0f
	// generates the offset in between 0 and 15
	offset := hash[len(hash)-1] & 0x0f

	// generate 32 bit binary digit
	// from the offset's last 4 bytes of the hash
	// shift it to the left
	binaryDigit := int32(hash[offset]&0x7F)<<24 |
		int32(hash[offset+1]&0xFF)<<16 |
		int32(hash[offset+2]&0xFF)<<8 |
		int32(hash[offset+3]&0xFF)

	// take mod 10^d to get the OTP of d digits
	otp := binaryDigit % int32(pow10(d))
	return fmt.Sprintf("%0*d", d, otp)

}

// pow10 returns the power of 10
// n is the power of 10
func pow10(n int) int {
	p := 1
	for i := 0; i < n; i++ {
		p *= 10
	}
	return p
}

package hmac

import "fmt"

// GenerateQRCode generates a QR code for the given parameters
// issuer is the name of the service provider
// account is the name of the account
// secret is the secret key
// otpType is the type of OTP, e.g. totp, hotp
func GenerateQRCode(issuer string, account string, secret string, otpType string) string {
	uri := fmt.Sprintf("otpauth://%s/%s?secret=%s&issuer=%s", otpType, account, secret, issuer)

	return uri
}

package hmac

import "fmt"

func GenerateQRCode(issuer string, account string, secret string, otpType string) string {
	uri := fmt.Sprintf("otpauth://%s/%s?secret=%s&issuer=%s", otpType, account, secret, issuer)

	return uri
}

package hmac

import (
	"crypto"
	"encoding/base32"
	"fmt"
	"testing"
)

func Test_GenerateTotp(t *testing.T) {
	secret := "AUSJD7LZ5H27TAC7NW2IJMATDMVDUPUG"
	K, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)

	got := GenerateTotp(K, 30, 6, crypto.SHA1)
	fmt.Println(got)
}

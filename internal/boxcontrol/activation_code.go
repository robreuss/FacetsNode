package boxcontrol

import (
	"crypto/rand"
	"io"
)

// GenerateActivationCode creates the human-entered, one-time Box claim secret.
// Keep this separate from machine credentials, including on Desktop Box.
func GenerateActivationCode() (string, error) {
	return generateActivationCode(rand.Reader)
}

func generateActivationCode(source io.Reader) (string, error) {
	const alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	code := make([]byte, 12)
	if _, err := io.ReadFull(source, code); err != nil {
		return "", err
	}
	for index := range code {
		// The 32-character alphabet divides the byte range evenly.
		code[index] = alphabet[int(code[index])%len(alphabet)]
	}
	return string(code[:4]) + "-" + string(code[4:8]) + "-" + string(code[8:]), nil
}

package boxcontrol

import (
	"crypto/rand"
	"io"
	"strings"
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

// The human-readable generator has one letter case, so accepting ASCII case
// variants does not merge distinct generated secrets. Do not use this for
// owner passwords, machine tokens, or Unicode lookalike characters.
func normalizeActivationCode(value string) string {
	return strings.Map(func(character rune) rune {
		if character >= 'a' && character <= 'z' {
			return character - ('a' - 'A')
		}
		return character
	}, strings.TrimSpace(value))
}

func verifyActivationCode(encoded, value string) bool {
	return verifySecret(encoded, normalizeActivationCode(value))
}

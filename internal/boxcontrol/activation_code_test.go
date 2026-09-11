package boxcontrol

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"testing/iotest"
)

func TestActivationCodeUsesHumanReadableGroupedFormat(t *testing.T) {
	format := regexp.MustCompile(`^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}(-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}){2}$`)
	for range 32 {
		code, err := GenerateActivationCode()
		if err != nil || !format.MatchString(code) {
			t.Fatal("activation code must use the grouped human-readable alphabet", err)
		}
		verifier, err := HashActivationCode(code)
		if err != nil || !verifySecret(verifier, code) {
			t.Fatal("generated activation code was not accepted by the claim verifier", err)
		}
	}
}

func TestActivationCodeFailsClosedWithoutRandomness(t *testing.T) {
	unavailable := errors.New("randomness unavailable")
	code, err := generateActivationCode(iotest.ErrReader(unavailable))
	if code != "" || !errors.Is(err, unavailable) {
		t.Fatal("must not return an activation code after entropy failure")
	}
}

func TestActivationCodeMapsFullByteRangeToReadableAlphabet(t *testing.T) {
	code, err := generateActivationCode(strings.NewReader(strings.Repeat("\xff", 12)))
	if err != nil || code != "ZZZZ-ZZZZ-ZZZZ" {
		t.Fatal("random bytes must map into the 32-character alphabet", err)
	}
}

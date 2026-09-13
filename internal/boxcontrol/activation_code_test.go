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

func TestActivationCodeCaseNormalizationDoesNotNormalizeOtherSecrets(t *testing.T) {
	withFastArgon(t)
	for _, input := range []string{"ABCD-EFGH-2345", "abcd-efgh-2345", "AbCd-eFgH-2345"} {
		verifier, err := HashActivationCode(input)
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range []string{"ABCD-EFGH-2345", "abcd-efgh-2345", "  AbCd-eFgH-2345\n"} {
			if !verifyActivationCode(verifier, candidate) {
				t.Fatal("ASCII case variant rejected")
			}
		}
		for _, wrong := range []string{"ABCD-EFGH-2346", "ABCDEFGH2345", "ＡBCD-EFGH-2345", "ABCD EFGH 2345", ""} {
			if verifyActivationCode(verifier, wrong) {
				t.Fatal("changed code or lookalike accepted")
			}
		}
	}
	password := "A Case Sensitive Owner Passphrase"
	verifier, err := hashSecret(password, nil)
	if err != nil || !verifySecret(verifier, password) || verifySecret(verifier, strings.ToLower(password)) {
		t.Fatal("general secret verification must remain case-sensitive", err)
	}
}

func TestActivationCodeMapsFullByteRangeToReadableAlphabet(t *testing.T) {
	code, err := generateActivationCode(strings.NewReader(strings.Repeat("\xff", 12)))
	if err != nil || code != "ZZZZ-ZZZZ-ZZZZ" {
		t.Fatal("random bytes must map into the 32-character alphabet", err)
	}
}

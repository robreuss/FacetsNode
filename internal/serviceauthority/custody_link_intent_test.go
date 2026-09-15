package serviceauthority_test

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/backupcustody"
	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func custodyLinkFixture() serviceauthority.CustodyLinkIntent {
	return serviceauthority.CustodyLinkIntent{BackupAccountID: uuid.MustParse("11111111-1111-4111-8111-111111111111"), BackupBindingID: uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		BackupSetID: uuid.MustParse("33333333-3333-4333-8333-333333333333"), BackupTargetID: uuid.MustParse("44444444-4444-4444-8444-444444444444"), ContentEpoch: math.MaxUint64,
		ContentScopeID: uuid.MustParse("55555555-5555-4555-8555-555555555555"), LedgerID: uuid.MustParse("66666666-6666-4666-8666-666666666666"), LinkID: uuid.MustParse("77777777-7777-4777-8777-777777777777"),
		PoolID: uuid.MustParse("88888888-8888-4888-8888-888888888888"), SyncBindingID: uuid.MustParse("99999999-9999-4999-8999-999999999999"), SyncDomainID: uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
		SyncPrincipalID: uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), SyncSpaceID: uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc"), Version: 1}
}

func TestCustodyLinkIntentBindsBothCompleteResources(t *testing.T) {
	i := custodyLinkFixture()
	if err := i.Validate(); err != nil {
		t.Fatal(err)
	}
	b, err := backupcustody.NewObjectScopeConsent(i)
	if err != nil {
		t.Fatal(err)
	}
	s, err := devicesync.NewObjectScopeConsent(i)
	if err != nil {
		t.Fatal(err)
	}
	if b.ValidateIntent(i) != nil || s.ValidateIntent(i) != nil || b.LinkIntentDigest != s.LinkIntentDigest || b.BindingID == s.BindingID {
		t.Fatal("halves do not match")
	}
	// A change to EITHER service's resource invalidates BOTH halves, including
	// coordinates not duplicated in the other service's local consent record.
	typ := reflect.TypeOf(i)
	for field := 0; field < typ.NumField(); field++ {
		t.Run(typ.Field(field).Name, func(t *testing.T) {
			changed := i
			value := reflect.ValueOf(&changed).Elem().Field(field)
			switch value.Type() {
			case reflect.TypeOf(uuid.UUID{}):
				value.Set(reflect.ValueOf(uuid.New()))
			case reflect.TypeOf(uint64(0)):
				value.SetUint(1)
			default:
				value.SetInt(2)
			}
			if b.ValidateIntent(changed) == nil || s.ValidateIntent(changed) == nil {
				t.Fatal("cross-service substitution accepted")
			}
		})
	}
	for _, consent := range []any{b, s} {
		value := reflect.ValueOf(consent)
		for field := 0; field < value.NumField(); field++ {
			copy := reflect.New(value.Type())
			copy.Elem().Set(value)
			v := copy.Elem().Field(field)
			switch v.Type() {
			case reflect.TypeOf(uuid.UUID{}):
				v.Set(reflect.ValueOf(uuid.New()))
			case reflect.TypeOf(uint64(0)):
				v.SetUint(1)
			case reflect.TypeOf(""):
				v.SetString(strings.Repeat("a", 64))
			default:
				v.SetInt(2)
			}
			var err error
			switch c := copy.Elem().Interface().(type) {
			case backupcustody.ObjectScopeConsent:
				err = c.ValidateIntent(i)
			case devicesync.ObjectScopeConsent:
				err = c.ValidateIntent(i)
			}
			if err == nil {
				t.Fatal("local consent substitution accepted", field)
			}
		}
	}
	encoded, _ := json.Marshal(i)
	decoded, err := serviceauthority.DecodeCustodyLinkIntent(encoded)
	if err != nil || decoded != i {
		t.Fatal("full UInt64 canonical roundtrip", err)
	}
	encodedSync, _ := json.Marshal(s)
	decodedSync, err := devicesync.DecodeObjectScopeConsent(encodedSync)
	if err != nil || decodedSync != s {
		t.Fatal("portable Sync consent roundtrip", err)
	}
	for _, bad := range [][]byte{append(encodedSync, ' '), append(encodedSync, encodedSync...),
		[]byte(strings.Replace(string(encodedSync), `"version":1`, `"version":1,"extra":0`, 1)),
		[]byte(strings.Replace(string(encodedSync), `"version":1`, `"version":1,"version":1`, 1)),
		[]byte(strings.Replace(string(encodedSync), s.LinkIntentDigest, strings.ToUpper(s.LinkIntentDigest), 1)),
	} {
		if _, err := devicesync.DecodeObjectScopeConsent(bad); err == nil {
			t.Fatal("ambiguous Sync consent accepted")
		}
	}
	digest, _ := i.ReferenceDigest()
	if digest != "17077a4e374ad44c644b2aa8d4a572d4d05313e7be49bce3ba89b59bc6e65778" {
		t.Fatal("portable intent fixture changed", digest)
	}
	backupDigest, _ := b.ReferenceDigest()
	syncDigest, _ := s.ReferenceDigest()
	if backupDigest != "2f79711798d73f9c16ea1a7c723b81448ee1efe40714419b5715a106abdde839" ||
		syncDigest != "f1aa7af138fcab5f3425403d0d9466f15a0b45bf6098faeada2eae5bd1763e97" {
		t.Fatal("portable consent fixture changed", backupDigest, syncDigest)
	}
}

func TestCustodyLinkIntentRejectsAmbiguousAndMalformedWire(t *testing.T) {
	i := custodyLinkFixture()
	body, _ := json.Marshal(i)
	for _, bad := range [][]byte{nil, []byte("{}"), append(body, ' '), append(body, body...),
		[]byte(strings.Replace(string(body), "18446744073709551615", "18446744073709551616", 1)),
		[]byte(strings.Replace(string(body), "18446744073709551615", "1.0", 1)),
		[]byte(strings.Replace(string(body), "18446744073709551615", "0", 1)),
		[]byte(strings.Replace(string(body), `"version":1`, `"version":1,"version":1`, 1)),
		[]byte(strings.Replace(string(body), `"version":1`, `"version":1,"extra":0`, 1)),
		[]byte(strings.Replace(string(body), "cccccccc", "CCCCCCCC", 1)),
		[]byte(strings.Repeat(" ", serviceauthority.MaximumCustodyLinkIntentBytes+1)),
	} {
		if _, err := serviceauthority.DecodeCustodyLinkIntent(bad); err == nil {
			t.Fatal("ambiguous input accepted")
		}
	}
	for field := 0; field < reflect.TypeOf(i).NumField(); field++ {
		copy := i
		value := reflect.ValueOf(&copy).Elem().Field(field)
		value.Set(reflect.Zero(value.Type()))
		if copy.Validate() == nil {
			t.Fatal("missing coordinate accepted", field)
		}
	}
	i.BackupBindingID = i.SyncBindingID
	if i.Validate() == nil {
		t.Fatal("one binding assumed two service roles")
	}
	i = custodyLinkFixture()
	i.ContentScopeID = i.SyncSpaceID
	if i.Validate() == nil {
		t.Fatal("public Space ID reused as content scope")
	}
}

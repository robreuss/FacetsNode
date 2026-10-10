package proxmoxadapter

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

type fakeRunner struct {
	outputs map[string][]byte
	err     error
}

func (runner fakeRunner) Output(_ context.Context, name string, arguments ...string) ([]byte, error) {
	if runner.err != nil {
		return nil, runner.err
	}
	key := name
	for _, argument := range arguments {
		key += " " + argument
	}
	return runner.outputs[key], nil
}

func (fakeRunner) Run(context.Context, string, ...string) error { return nil }

func TestAvailableVMIDAcceptsPVEStringAndNumber(t *testing.T) {
	for _, fixture := range []string{`"191"`, `191`} {
		runner := fakeRunner{outputs: map[string][]byte{
			"/usr/bin/pvesh get /cluster/nextid --output-format json": []byte(fixture),
		}}
		value, err := AvailableVMID(context.Background(), runner)
		if err != nil || value != 191 {
			t.Fatalf("fixture %s: value=%d err=%v", fixture, value, err)
		}
	}
}

func TestAvailableVMIDRejectsRetainedAndUnavailableInventory(t *testing.T) {
	for _, fixture := range []string{`190`, `"180"`, `null`, `"bad"`} {
		runner := fakeRunner{outputs: map[string][]byte{
			"/usr/bin/pvesh get /cluster/nextid --output-format json": []byte(fixture),
		}}
		if _, err := AvailableVMID(context.Background(), runner); err == nil {
			t.Fatalf("accepted VM ID fixture %s", fixture)
		}
	}
	runner := fakeRunner{err: errors.New("unavailable")}
	if _, err := AvailableVMID(context.Background(), runner); err == nil {
		t.Fatal("accepted unavailable PVE inventory")
	}
}

func TestReviewContainsOnlyFixedQMProgramAndPlanArguments(t *testing.T) {
	review := Review(validPlan())
	commands, ok := review["commands"].([]map[string]any)
	if !ok || len(commands) != 6 {
		t.Fatalf("unexpected review: %#v", review)
	}
	for _, command := range commands {
		if command["program"] != "/usr/sbin/qm" {
			t.Fatalf("unexpected program: %#v", command)
		}
		if reflect.ValueOf(command["arguments"]).Len() == 0 {
			t.Fatalf("missing arguments: %#v", command)
		}
	}
}

func TestSSHPublicKeyValidation(t *testing.T) {
	if !validSSHPublicKey([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJeodct0V0EeaDSJQAwgqpqW7rMaucm/Ag5B0QFGp3J appliance\n")) {
		t.Fatal("valid Ed25519 key rejected")
	}
	for _, invalid := range []string{"ssh-rsa AAAA", "ssh-ed25519 bad", "command=x ssh-ed25519 AAAA"} {
		if validSSHPublicKey([]byte(invalid)) {
			t.Fatalf("invalid key accepted: %s", invalid)
		}
	}
}

func TestPVEBooleanAcceptsBooleanAndNumericForms(t *testing.T) {
	for _, fixture := range []string{`{"active":true,"enabled":1,"avail":100000000000,"content":"iso,images"}`, `{"active":1,"enabled":true,"avail":100000000000,"content":"images"}`} {
		var status storageStatus
		if err := json.Unmarshal([]byte(fixture), &status); err != nil {
			t.Fatal(err)
		}
		if !bool(status.Active) || !bool(status.Enabled) || !containsCSV(status.Content, "images") {
			t.Fatalf("invalid status decode: %+v", status)
		}
	}
}

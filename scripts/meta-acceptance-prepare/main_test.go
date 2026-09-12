package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestPrepareFreshAcceptanceIdentityAndRefuseOverwrite(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "acceptance")
	if err := prepare(directory, "192.168.86.44", 10443, 18080); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(directory, "keys/deployment-signing-key")
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepare(directory, "192.168.86.44", 10443, 18080); err == nil {
		t.Fatal("overwrote existing deployment")
	}
	after, _ := os.ReadFile(keyPath)
	if string(before) != string(after) {
		t.Fatal("identity changed")
	}
	info, err := os.Stat(filepath.Join(directory, ".env"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("configuration permissions")
	}
	// Load the generated route document through the production parser. Its ID
	// is supplied by the document, not a copied identity from another Box.
	data, _ := os.ReadFile(filepath.Join(directory, "policy/deployment-routes.json"))
	var template serviceauthority.DeploymentOfferTemplate
	if err := json.Unmarshal(data, &template); err != nil {
		t.Fatal(err)
	}
	if template.Deployment.DeploymentID == uuid.Nil {
		t.Fatal("missing deployment ID")
	}
	signer, err := serviceauthority.LoadDeploymentSigner(template.Deployment.DeploymentID, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := serviceauthority.LoadDeploymentOfferTemplate(filepath.Join(directory, "policy/deployment-routes.json"), signer)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Deployment.Routes) != 1 || loaded.Deployment.Routes[0].Endpoint != "https://192.168.86.44:10443/facetsbox/device-sync" {
		t.Fatal("unexpected acceptance routes")
	}
}

func TestRejectPublicAddressAndUnsafeDirectoryBeforeWriting(t *testing.T) {
	root := filepath.Join(t.TempDir(), "must-not-exist")
	if err := prepare(root, "8.8.8.8", 10443, 18080); err == nil {
		t.Fatal("accepted public address")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("wrote invalid configuration")
	}
	if err := prepare("/", "127.0.0.1", 10443, 18080); err == nil {
		t.Fatal("accepted broad root")
	}
}

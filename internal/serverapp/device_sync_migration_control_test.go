package serverapp

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/config"
	"github.com/robreuss/FacetsNode/internal/postgres"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type migrationControlFixtureSubset struct {
	AuthorityAnchor  serviceauthority.TrustAnchor `json:"authorityAnchor"`
	RollbackEvidence struct {
		ActivationEvidence serviceauthority.MigrationActivationEvidence `json:"activationEvidence"`
	} `json:"rollbackEvidence"`
}

func TestDeviceSyncMigrationControlRejectsUnknownActionsBeforeConfiguration(t *testing.T) {
	var output bytes.Buffer
	for _, arguments := range [][]string{
		nil,
		{"unknown"},
		{"source-prepare"},
		{"target-prepare", "one", "extra"},
	} {
		if err := runDeviceSyncMigrationControl(
			context.Background(),
			config.DeviceSync,
			arguments,
			&output,
			func() time.Time { return time.UnixMilli(1) },
		); err == nil {
			t.Fatalf("invalid migration control arguments accepted: %v", arguments)
		}
	}
	if err := runDeviceSyncMigrationControl(
		context.Background(),
		config.SharedSpaces,
		[]string{"activate", "request.json"},
		&output,
		func() time.Time { return time.UnixMilli(1) },
	); err == nil {
		t.Fatal("Shared Spaces binary accepted Device Sync migration control")
	}
}

func TestDeviceSyncMigrationControlReadsOnlyPrivateBoundedJSON(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "request.json")
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var value struct {
		Version int `json:"version"`
	}
	if err := readPrivateControlJSON(path, &value); err != nil || value.Version != 1 {
		t.Fatalf("private control request value=%+v err=%v", value, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := readPrivateControlJSON(path, &value); err == nil {
		t.Fatal("group/world-readable migration control input accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := readPrivateControlJSON(path, &value); err == nil {
		t.Fatal("unknown migration control field accepted")
	}
}

func TestInitialDeviceSyncAuthorityEvidenceIsRecoveredExactlyFromScopeState(t *testing.T) {
	fixtureBytes, err := os.ReadFile(
		filepath.Join(
			"..", "serviceauthority", "testdata", "service-migration-portable-v2.json",
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	var fixture migrationControlFixtureSubset
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatal(err)
	}
	initial := fixture.RollbackEvidence.ActivationEvidence.Preparation.CurrentManifest
	payload, err := initial.VerifiedPayload()
	if err != nil || payload.Revision != 1 {
		t.Fatalf("fixture initial authority=%+v err=%v", payload, err)
	}
	record, err := json.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	validatedAt := payload.ValidFromMilliseconds
	state := postgres.DeviceSyncScopeEnforcement{
		InitialAuthorityValidatedAtMilliseconds: &validatedAt,
		InitialAuthorityManifestRecord:          record,
	}
	recovered, err := initialDeviceSyncAuthorityFromState(state)
	if err != nil || recovered.ValidatedAtMilliseconds != validatedAt ||
		!bytes.Equal(recovered.Manifest.Payload, initial.Payload) ||
		recovered.Manifest.Signature.Signature != initial.Signature.Signature {
		t.Fatalf("recovered initial authority=%+v err=%v", recovered, err)
	}
	if _, err := recovered.Manifest.Authorize(fixture.AuthorityAnchor, validatedAt); err != nil {
		t.Fatalf("recovered initial authority no longer validates: %v", err)
	}
	state.InitialAuthorityManifestRecord = append(record, '\n')
	if _, err := initialDeviceSyncAuthorityFromState(state); err == nil {
		t.Fatal("noncanonical stored initial authority accepted")
	}
}

func TestDeviceSyncMigrationTargetOfferBindsProtectedDeploymentAndClientCustodyKey(
	t *testing.T,
) {
	seed := make([]byte, 32)
	seed[31] = 7
	deploymentID := uuid.New()
	signer, err := serviceauthority.NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	routeID := uuid.New()
	descriptor := serviceauthority.DeploymentDescriptor{
		CreatedAtMilliseconds: 1_000,
		DeploymentID:          deploymentID,
		PublicSigningKeyX963:  signer.PublicSigningKeyX963(),
		Routes: []serviceauthority.TransportRoute{{
			Endpoint:     "https://migration-target.example:8443",
			Kind:         serviceauthority.RouteDirectHTTPS,
			NetworkScope: serviceauthority.NetworkTrustedLAN,
			RouteID:      routeID,
			ServerAuthentication: serviceauthority.ServerAuthentication{
				Kind: "web_pki",
			},
		}},
		SigningKeyFingerprint: signer.SigningKeyFingerprint(),
		Version:               serviceauthority.SchemaVersion,
	}
	policy := serviceauthority.TransportPolicy{
		BulkRouteIDs:    []uuid.UUID{routeID},
		ControlRouteIDs: []uuid.UUID{routeID},
		MessageRouteIDs: []uuid.UUID{routeID},
		Version:         serviceauthority.SchemaVersion,
	}
	template := serviceauthority.DeploymentOfferTemplate{
		Deployment: descriptor, TransportPolicy: policy,
		Version: serviceauthority.SchemaVersion,
	}
	templateRecord, err := json.Marshal(template)
	if err != nil {
		t.Fatal(err)
	}
	templatePath := filepath.Join(t.TempDir(), "deployment-routes.json")
	if err := os.WriteFile(templatePath, templateRecord, 0o600); err != nil {
		t.Fatal(err)
	}
	custody, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	custodyFingerprint := sha256.Sum256(custody.PublicKey().Bytes())
	now := time.UnixMilli(2_000)
	runtime := deviceSyncMigrationControlRuntime{
		configuration: config.Config{DeploymentRoutePolicyFile: templatePath},
		signer:        signer,
	}
	control := deviceSyncMigrationTargetOfferRequest{
		CustodyAgreementKeyFingerprint: hex.EncodeToString(custodyFingerprint[:]),
		CustodyAgreementPublicKeyX963: base64.RawURLEncoding.EncodeToString(
			custody.PublicKey().Bytes(),
		),
		ExpiresAtMilliseconds: now.Add(time.Hour).UnixMilli(),
		MigrationID:           uuid.New(),
		Scope: serviceauthority.Scope{
			Kind: serviceauthority.ScopeDeviceSync, ScopeID: uuid.New(),
		},
		SourceManifestDigest: hex.EncodeToString(make([]byte, sha256.Size)),
		Version:              deviceSyncMigrationControlVersion,
	}
	response, err := runtime.issueTargetOffer(control, now)
	if err != nil || response.TargetOffer == nil ||
		response.DeploymentID != deploymentID ||
		response.MigrationID == nil || *response.MigrationID != control.MigrationID ||
		response.PrincipalID == nil || *response.PrincipalID != control.Scope.ScopeID {
		t.Fatalf("target-offer response=%+v err=%v", response, err)
	}
	payload, err := response.TargetOffer.VerifiedPayload(pointerToMillisecondsForControlTest(now))
	if err != nil || payload.MigrationID != control.MigrationID ||
		payload.Scope != control.Scope ||
		payload.CustodyAgreementKeyFingerprint != control.CustodyAgreementKeyFingerprint ||
		payload.CustodyAgreementPublicKeyX963 != control.CustodyAgreementPublicKeyX963 ||
		payload.SourceManifestDigest != control.SourceManifestDigest {
		t.Fatalf("target-offer payload=%+v err=%v", payload, err)
	}
}

func pointerToMillisecondsForControlTest(value time.Time) *int64 {
	milliseconds := value.UnixMilli()
	return &milliseconds
}

func TestDeviceSyncMigrationControlOmitsAbsentUUIDFacts(t *testing.T) {
	response := deviceSyncMigrationControlResponse{
		Action: "rollback-settle", DeploymentID: uuid.New(),
		Version: deviceSyncMigrationControlVersion,
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(`"migrationID"`)) ||
		bytes.Contains(encoded, []byte(`"principalID"`)) {
		t.Fatalf("absent UUID response facts were serialized: %s", encoded)
	}
}

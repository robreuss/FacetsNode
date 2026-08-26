package serverapp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/config"
	"github.com/robreuss/FacetsNode/internal/migrationcoordinator"
)

type rollbackSourceControlOperationsStub struct {
	calls      []string
	recoverErr error
	recovered  []migrationcoordinator.DeviceSyncRollbackSourceOperationResult
	statuses   []migrationcoordinator.DeviceSyncRollbackSourceOperationStatus
}

func (stub *rollbackSourceControlOperationsStub) ListStatus(
	_ context.Context,
	_ time.Time,
) ([]migrationcoordinator.DeviceSyncRollbackSourceOperationStatus, error) {
	stub.calls = append(stub.calls, "status")
	return stub.statuses, nil
}

func (stub *rollbackSourceControlOperationsStub) Recover(
	_ context.Context,
	_ time.Time,
) ([]migrationcoordinator.DeviceSyncRollbackSourceOperationResult, error) {
	stub.calls = append(stub.calls, "recover")
	return stub.recovered, stub.recoverErr
}

func TestDeviceSyncRollbackSourceControlReportsAndRecoversSignedOperations(
	t *testing.T,
) {
	now := time.UnixMilli(4_000)
	principalID := uuid.New()
	migrationID := uuid.New()
	snapshotID := uuid.New()
	accepted := migrationcoordinator.DeviceSyncRollbackSourceOperationStatus{
		AcceptedAtMilliseconds:   3_600,
		ActivationEvidenceDigest: string(bytes.Repeat([]byte{'a'}, 64)),
		ExportWriteFenceID:       uuid.New(),
		MigrationID:              migrationID,
		PrincipalID:              principalID,
		SnapshotID:               snapshotID,
		State: migrationcoordinator.
			DeviceSyncRollbackSourceOperationAccepted,
	}
	stub := &rollbackSourceControlOperationsStub{statuses: []migrationcoordinator.DeviceSyncRollbackSourceOperationStatus{accepted}}
	var output bytes.Buffer
	if err := executeDeviceSyncRollbackSourceControl(
		context.Background(), "status", stub, &output, now,
	); err != nil {
		t.Fatal(err)
	}
	response := decodeRollbackSourceControlResponse(t, output.Bytes())
	if response.Version != deviceSyncRollbackSourceControlVersion ||
		response.Action != "status" || response.RecoveredOperationCount != 0 ||
		len(response.Operations) != 1 || response.Operations[0] != accepted ||
		len(stub.calls) != 1 || stub.calls[0] != "status" {
		t.Fatalf("status response=%+v calls=%v", response, stub.calls)
	}

	snapshotDigest := string(bytes.Repeat([]byte{'b'}, 64))
	stateDigest := string(bytes.Repeat([]byte{'c'}, 64))
	prepared := accepted
	prepared.State = migrationcoordinator.DeviceSyncRollbackSourceOperationPrepared
	prepared.SnapshotReferenceDigest = &snapshotDigest
	prepared.StateCommitmentDigest = &stateDigest
	stub = &rollbackSourceControlOperationsStub{
		recovered: []migrationcoordinator.DeviceSyncRollbackSourceOperationResult{{}},
		statuses:  []migrationcoordinator.DeviceSyncRollbackSourceOperationStatus{prepared},
	}
	output.Reset()
	if err := executeDeviceSyncRollbackSourceControl(
		context.Background(), "recover", stub, &output, now,
	); err != nil {
		t.Fatal(err)
	}
	response = decodeRollbackSourceControlResponse(t, output.Bytes())
	if response.Action != "recover" || response.RecoveredOperationCount != 1 ||
		len(response.Operations) != 1 ||
		response.Operations[0].State !=
			migrationcoordinator.DeviceSyncRollbackSourceOperationPrepared ||
		len(stub.calls) != 2 || stub.calls[0] != "recover" ||
		stub.calls[1] != "status" {
		t.Fatalf("recover response=%+v calls=%v", response, stub.calls)
	}
}

func TestDeviceSyncRollbackSourceControlFailsClosedBeforeStatusOnRecoveryError(
	t *testing.T,
) {
	stub := &rollbackSourceControlOperationsStub{
		recoverErr: errors.New("tampered operation"),
	}
	var output bytes.Buffer
	if err := executeDeviceSyncRollbackSourceControl(
		context.Background(), "recover", stub, &output, time.UnixMilli(4_000),
	); err == nil || output.Len() != 0 || len(stub.calls) != 1 ||
		stub.calls[0] != "recover" {
		t.Fatalf("recover error=%v output=%q calls=%v", err, output.String(), stub.calls)
	}
	if err := executeDeviceSyncRollbackSourceControl(
		context.Background(), "begin", stub, &output, time.UnixMilli(4_000),
	); err == nil {
		t.Fatal("rollback source control accepted a command that could initiate work")
	}
}

func TestDeviceSyncRollbackSourceStatusNeedsNoDatabaseOrBindingRegistry(t *testing.T) {
	directory := t.TempDir()
	seed := make([]byte, 32)
	seed[31] = 1
	keyPath := filepath.Join(directory, "deployment.key")
	if err := os.WriteFile(
		keyPath,
		[]byte(base64.RawURLEncoding.EncodeToString(seed)),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	deploymentID := uuid.New()
	t.Setenv("FACETS_DEVICE_SYNC_DATABASE_URL", "postgres://unavailable.invalid/facets")
	t.Setenv("FACETS_DEVICE_SYNC_DEPLOYMENT_ID", deploymentID.String())
	t.Setenv("FACETS_DEVICE_SYNC_DEPLOYMENT_SIGNING_KEY_FILE", keyPath)
	t.Setenv(
		"FACETS_DEVICE_SYNC_DEPLOYMENT_ROUTE_POLICY_FILE",
		filepath.Join(directory, "missing-route-policy.json"),
	)
	t.Setenv(
		"FACETS_DEVICE_SYNC_SERVICE_AUTHORITY_BINDINGS_FILE",
		filepath.Join(directory, "missing-bindings.json"),
	)
	var output bytes.Buffer
	if err := runDeviceSyncRollbackSourceControl(
		context.Background(), config.DeviceSync, []string{"status"},
		&output, func() time.Time { return time.UnixMilli(4_000) },
	); err != nil {
		t.Fatal(err)
	}
	response := decodeRollbackSourceControlResponse(t, output.Bytes())
	if response.Action != "status" || len(response.Operations) != 0 {
		t.Fatalf("status without database=%+v", response)
	}
	if !bytes.Contains(output.Bytes(), []byte(`"operations": []`)) {
		t.Fatalf("empty status was not emitted as an array: %s", output.Bytes())
	}
	if _, err := os.Lstat(filepath.Join(directory, "migration-custody")); !os.IsNotExist(err) {
		t.Fatalf("read-only status created migration custody: %v", err)
	}
	if err := runDeviceSyncRollbackSourceControl(
		context.Background(), config.SharedSpaces, []string{"status"},
		&output, func() time.Time { return time.UnixMilli(4_000) },
	); err == nil {
		t.Fatal("Shared Spaces binary accepted Device Sync rollback-source control")
	}
}

func decodeRollbackSourceControlResponse(
	t *testing.T,
	encoded []byte,
) deviceSyncRollbackSourceControlResponse {
	t.Helper()
	var response deviceSyncRollbackSourceControlResponse
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		t.Fatal(err)
	}
	return response
}

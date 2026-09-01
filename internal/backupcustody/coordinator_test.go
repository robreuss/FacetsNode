package backupcustody

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func TestCoordinatorReadUsesDurableAuthoritySnapshotAndVerifiesObject(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	content, err := OpenContentStore(filepath.Join(parent, "custody"))
	if err != nil {
		t.Fatal(err)
	}
	defer content.Close()
	accountID, targetID, setID, uploadID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	opaque := []byte("opaque encrypted Backup generation")
	if err := content.PrepareUpload(uploadID); err != nil {
		t.Fatal(err)
	}
	if _, err := content.ReconcileAndAppend(uploadID, 0, opaque, uint64(len(opaque)), uint64(len(opaque))); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(opaque)
	generation := serviceauthority.BackupCustodyGenerationRecord{
		Version: Version, AccountID: accountID, TargetID: targetID, BackupSetID: setID,
		Generation: 1, UploadID: uploadID, OuterByteCount: uint64(len(opaque)),
		OuterDigest: base64.RawURLEncoding.EncodeToString(digest[:]),
	}
	object, err := content.Publish(generation)
	if err != nil {
		t.Fatal(err)
	}
	deploymentID := uuid.New()
	seed := make([]byte, 32)
	seed[31] = 7
	signer, err := serviceauthority.NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	reference := TargetCredentialReference{
		Version: Version, AccountID: accountID, TargetID: targetID, BackupSetID: setID,
		CredentialID: uuid.New(), Capabilities: []Capability{Read},
		ExpiresAtMilliseconds: 2_000, RequestNonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	credential, err := NewTargetCredential(reference)
	if err != nil {
		t.Fatal(err)
	}
	credentialDigest, err := credential.AuthorizationDigest()
	if err != nil {
		t.Fatal(err)
	}
	credentialAuthority := testAcceptedCredentialAuthority(t, reference, credentialDigest)
	authorityDigest := strings.Repeat("a", 64)
	scope := serviceauthority.Scope{Kind: serviceauthority.ScopeBackupCustody, ScopeID: accountID}
	receipt, err := signer.SignBackupCustodyReceipt(serviceauthority.BackupCustodyReceiptPayload{
		Version: serviceauthority.BackupCustodyReceiptVersion, ReceiptID: uuid.New(), RequestID: uuid.New(),
		CredentialID: reference.CredentialID, Kind: serviceauthority.BackupCustodyCommittedKind,
		IssuedAtMilliseconds: 1_000, Generation: generation,
		Authority: serviceauthority.BackupCustodyAuthorityContext{Scope: scope, AuthorityRevision: 1,
			AuthorityManifestDigest: authorityDigest, DeploymentID: deploymentID},
		CredentialGrantReferenceDigest: credentialAuthority.GrantReferenceDigest,
		ControlHeadReferenceDigest:     credentialAuthority.ControlHead.ReferenceDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	storedGeneration, err := generationStorage(generation, receipt, object)
	if err != nil {
		t.Fatal(err)
	}
	target := TargetRecord{AccountID: accountID, TargetID: targetID, BackupSetID: setID}
	store := &readCoordinatorStore{target: target, generation: storedGeneration, credentialAuthority: credentialAuthority}
	registry := serviceauthority.NewBindingRegistry()
	if err := registry.Activate(scope, serviceauthority.CurrentBinding{
		Revision: 1, Digest: authorityDigest, DeploymentID: deploymentID,
	}); err != nil {
		t.Fatal(err)
	}
	binding := serviceauthority.RequestBinding{Scope: scope, AuthorityRevision: 1,
		AuthorityDigest: authorityDigest, DeploymentID: deploymentID,
		RouteID: uuid.New(), TrafficClass: serviceauthority.TrafficBulk}
	coordinator := Coordinator{Store: store, Content: content, Registry: registry, Signer: signer,
		AuthorityHistory: unusedAuthorityHistory{}, Clock: fixedBackupClock{time.UnixMilli(1_100)},
		MaximumChunkBytes: 1024, MaximumGenerationBytes: 4096, NewID: uuid.New}
	request := ReadRequest{Version: Version, RequestID: uuid.New(), RequestedAtMilliseconds: 1_100,
		Credential: reference, GenerationReferenceDigest: storedGeneration.GenerationReferenceDigest,
		MaximumByteCount: uint64(len(opaque)), RangeOffset: 0}
	result, err := coordinator.Read(context.Background(), credential, request, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Content.Close()
	read, err := io.ReadAll(result.Content)
	if err != nil || string(read) != string(opaque) {
		t.Fatalf("read=%q err=%v", read, err)
	}
	if store.readCount != 1 || store.lastAuthorization.AuthorityRevision() != 1 ||
		store.lastAuthorization.AuthorityManifestDigest() != authorityDigest ||
		store.lastAuthorization.AuthorizedAtMilliseconds() != 1_100 {
		t.Fatalf("durable read admission was not exact: count=%d auth=%+v", store.readCount, store.lastAuthorization)
	}
	controlBinding := binding
	controlBinding.TrafficClass = serviceauthority.TrafficControl
	if _, err := coordinator.Read(context.Background(), credential, request, controlBinding); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("control route read err=%v", err)
	}

	if err := os.Chmod(filepath.Join(parent, "custody", object), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "custody", object), make([]byte, len(opaque)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Read(context.Background(), credential, request, binding); err == nil {
		t.Fatal("tampered opaque generation was returned")
	}
}

func TestCoordinatorPinsGenerationPagesAndIssuesExactBulkGrants(t *testing.T) {
	harness := newCoordinatorHarness(t, []Capability{Publish, Read})
	defer harness.content.Close()
	makeStored := func(number uint64, predecessor *string) GenerationRecord {
		t.Helper()
		generation := serviceauthority.BackupCustodyGenerationRecord{
			Version: Version, AccountID: harness.target.AccountID, TargetID: harness.target.TargetID,
			BackupSetID: harness.target.BackupSetID, Generation: number, UploadID: uuid.New(),
			PredecessorReferenceDigest: predecessor,
			OuterDigest:                base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(number)}, 32)),
			OuterByteCount:             4096,
		}
		receipt, err := harness.coordinator.Signer.SignBackupCustodyReceipt(serviceauthority.BackupCustodyReceiptPayload{
			Version: serviceauthority.BackupCustodyReceiptVersion, ReceiptID: uuid.New(), RequestID: uuid.New(),
			CredentialID: harness.credential.Reference.CredentialID, Kind: serviceauthority.BackupCustodyCommittedKind,
			IssuedAtMilliseconds: 1_000 + int64(number), Generation: generation,
			Authority: serviceauthority.BackupCustodyAuthorityContext{Scope: harness.binding.Scope, AuthorityRevision: harness.binding.AuthorityRevision,
				AuthorityManifestDigest: harness.binding.AuthorityDigest, DeploymentID: harness.binding.DeploymentID},
			CredentialGrantReferenceDigest: harness.store.credentialAuthority.GrantReferenceDigest,
			ControlHeadReferenceDigest:     harness.store.credentialAuthority.ControlHead.ReferenceDigest,
		})
		if err != nil {
			t.Fatal(err)
		}
		stored, err := generationStorage(generation, receipt, objectPath(generation))
		if err != nil {
			t.Fatal(err)
		}
		return stored
	}
	first := makeStored(1, nil)
	second := makeStored(2, &first.GenerationReferenceDigest)
	third := makeStored(3, &second.GenerationReferenceDigest)
	fourth := makeStored(4, &third.GenerationReferenceDigest)
	headReference := third.GenerationReferenceDigest
	target := harness.target
	target.Head = cloneGeneration(&fourth.Generation)
	target.HeadReferenceDigest = &fourth.GenerationReferenceDigest
	upload := UploadRecord{AccountID: target.AccountID, TargetID: target.TargetID, BackupSetID: target.BackupSetID,
		UploadID: uuid.New(), CommittedBytes: 128}
	store := &readCoordinatorStore{target: target, generation: third, items: []GenerationRecord{third},
		upload: upload, credentialAuthority: harness.store.credentialAuthority}
	harness.coordinator.Store = store
	controlBinding := harness.binding
	controlBinding.TrafficClass = serviceauthority.TrafficControl

	list := GenerationListRequest{Version: Version, RequestID: uuid.New(), Credential: harness.credential.Reference,
		AfterGeneration: 2, AfterGenerationReferenceDigest: &second.GenerationReferenceDigest,
		SnapshotHeadReferenceDigest: &headReference, PageCount: 2, RequestedAtMilliseconds: 1_100}
	listed, err := harness.coordinator.ListGenerations(context.Background(), harness.credential, list, controlBinding)
	if err != nil || listed.Head.GenerationReferenceDigest != headReference || len(listed.Items) != 1 ||
		listed.Target.HeadReferenceDigest == nil || *listed.Target.HeadReferenceDigest != fourth.GenerationReferenceDigest {
		t.Fatalf("list=%+v err=%v", listed, err)
	}
	page := GenerationListPage{Version: Version, RequestID: list.RequestID,
		AfterGeneration: list.AfterGeneration, AfterGenerationReferenceDigest: list.AfterGenerationReferenceDigest,
		SnapshotHeadReferenceDigest: listed.Head.GenerationReferenceDigest,
		SnapshotHeadCustodyReceipt:  listed.Head.CustodyReceipt,
		Items: []GenerationListItem{{GenerationReferenceDigest: listed.Items[0].GenerationReferenceDigest,
			CustodyReceipt: listed.Items[0].CustodyReceipt}}}
	if err := page.ValidateResponse(list); err != nil {
		t.Fatalf("historical head did not remain pinned after current advance: %v", err)
	}
	if _, err := harness.coordinator.ListGenerations(context.Background(), harness.credential, list, harness.binding); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("bulk route list err=%v", err)
	}

	downloadResource, err := DownloadRangeResourceID(harness.credential.Reference, headReference, 64, 1024)
	if err != nil {
		t.Fatal(err)
	}
	downloadRequest := serviceauthority.BulkGrantRequest{Version: serviceauthority.SchemaVersion,
		Direction: serviceauthority.BulkDownload, RequiredByteCount: 1024,
		ResourceID: downloadResource, RouteID: harness.binding.RouteID}
	downloadGrant, err := harness.coordinator.IssueBulkTransferGrant(
		context.Background(), harness.credential, downloadRequest, controlBinding,
	)
	var downloadPayload serviceauthority.BulkGrantPayload
	if err != nil || json.Unmarshal(downloadGrant.Payload, &downloadPayload) != nil ||
		downloadPayload.ResourceID != downloadResource || downloadPayload.Direction != serviceauthority.BulkDownload ||
		downloadPayload.MaximumByteCount != 1024 || downloadPayload.RouteID != harness.binding.RouteID {
		t.Fatalf("download payload=%+v err=%v", downloadPayload, err)
	}
	wrongRouteRequest := downloadRequest
	wrongRouteRequest.RouteID = uuid.New()
	if _, err := harness.coordinator.IssueBulkTransferGrant(
		context.Background(), harness.credential, wrongRouteRequest, controlBinding,
	); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("undeclared bulk route grant err=%v", err)
	}

	uploadResource, err := UploadChunkResourceID(harness.credential.Reference, upload.UploadID, upload.CommittedBytes, 512)
	if err != nil {
		t.Fatal(err)
	}
	uploadRequest := serviceauthority.BulkGrantRequest{Version: serviceauthority.SchemaVersion,
		Direction: serviceauthority.BulkUpload, RequiredByteCount: 512,
		ResourceID: uploadResource, RouteID: harness.binding.RouteID}
	uploadGrant, err := harness.coordinator.IssueBulkTransferGrant(
		context.Background(), harness.credential, uploadRequest, controlBinding,
	)
	var uploadPayload serviceauthority.BulkGrantPayload
	if err != nil || json.Unmarshal(uploadGrant.Payload, &uploadPayload) != nil ||
		uploadPayload.ResourceID != uploadResource || uploadPayload.Direction != serviceauthority.BulkUpload ||
		uploadPayload.MaximumByteCount != 512 {
		t.Fatalf("upload payload=%+v err=%v", uploadPayload, err)
	}

	conflictResource, _ := UploadChunkResourceID(harness.credential.Reference, upload.UploadID, upload.CommittedBytes+1, 512)
	uploadRequest.ResourceID = conflictResource
	if _, err := harness.coordinator.IssueBulkTransferGrant(context.Background(), harness.credential, uploadRequest, controlBinding); err == nil {
		t.Fatal("grant issued for a non-current upload offset")
	}
}

func TestCoordinatorAppendRepairsLostOffsetCommitAndRejectsConflictingReplay(t *testing.T) {
	harness := newCoordinatorHarness(t, []Capability{Publish})
	defer harness.content.Close()
	chunk := []byte("first encrypted chunk")
	digest := fmt.Sprintf("%x", sha256.Sum256(chunk))
	uploadID := uuid.New()
	harness.store.upload = UploadRecord{AccountID: harness.target.AccountID, TargetID: harness.target.TargetID,
		BackupSetID: harness.target.BackupSetID, UploadID: uploadID,
		Request: PublishRequest{Version: Version, RequestID: uuid.New(), RequestedAtMilliseconds: 1_100,
			Credential: harness.credential.Reference, Generation: 1}, MaximumChunkCount: 10}
	if err := harness.content.PrepareUpload(uploadID); err != nil {
		t.Fatal(err)
	}
	harness.store.ambiguousAppendOnce = true
	if _, err := harness.coordinator.AppendUploadChunk(context.Background(), harness.credential, harness.binding, uploadID, 0, chunk, digest); err == nil {
		t.Fatal("ambiguous offset commit reported success")
	}
	if harness.store.upload.CommittedBytes != uint64(len(chunk)) {
		t.Fatalf("durable offset=%d", harness.store.upload.CommittedBytes)
	}
	next, err := harness.coordinator.AppendUploadChunk(context.Background(), harness.credential, harness.binding, uploadID, 0, chunk, digest)
	if err != nil || next != uint64(len(chunk)) {
		t.Fatalf("lost-response replay next=%d err=%v", next, err)
	}
	conflicting := []byte("other encrypted data")
	conflictingDigest := fmt.Sprintf("%x", sha256.Sum256(conflicting))
	if _, err := harness.coordinator.AppendUploadChunk(context.Background(), harness.credential, harness.binding, uploadID, 0, conflicting, conflictingDigest); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting replay err=%v", err)
	}

	uploadID = uuid.New()
	harness.store.upload = UploadRecord{AccountID: harness.target.AccountID, TargetID: harness.target.TargetID,
		BackupSetID: harness.target.BackupSetID, UploadID: uploadID,
		Request: PublishRequest{Version: Version, RequestID: uuid.New(), RequestedAtMilliseconds: 1_100,
			Credential: harness.credential.Reference, Generation: 1}, MaximumChunkCount: 10}
	if err := harness.content.PrepareUpload(uploadID); err != nil {
		t.Fatal(err)
	}
	harness.store.failAppendBeforeCommitOnce = true
	if _, err := harness.coordinator.AppendUploadChunk(context.Background(), harness.credential, harness.binding, uploadID, 0, chunk, digest); err == nil {
		t.Fatal("injected precommit failure reported success")
	}
	if harness.store.upload.CommittedBytes != 0 {
		t.Fatal("failed DB offset advanced")
	}
	next, err = harness.coordinator.AppendUploadChunk(context.Background(), harness.credential, harness.binding, uploadID, 0, chunk, digest)
	if err != nil || next != uint64(len(chunk)) {
		t.Fatalf("tail reconciliation next=%d err=%v", next, err)
	}
}

func TestCoordinatorFinalizeRepairsPublishedObjectAndAmbiguousCommit(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		t.Run(fmt.Sprintf("ambiguous=%t", ambiguous), func(t *testing.T) {
			harness := newCoordinatorHarness(t, []Capability{Publish})
			defer harness.content.Close()
			wire := testOuterWire(t, harness.target.BackupSetID, 1, nil, 32)
			uploadID := uuid.New()
			harness.store.upload = UploadRecord{AccountID: harness.target.AccountID, TargetID: harness.target.TargetID,
				BackupSetID: harness.target.BackupSetID, UploadID: uploadID, CommittedBytes: uint64(len(wire)),
				MaximumChunkCount: 10, Request: PublishRequest{Version: Version, RequestID: uuid.New(),
					RequestedAtMilliseconds: 1_100, Credential: harness.credential.Reference, Generation: 1}}
			if err := harness.content.PrepareUpload(uploadID); err != nil {
				t.Fatal(err)
			}
			if _, err := harness.content.ReconcileAndAppend(uploadID, 0, wire, uint64(len(wire)), uint64(len(wire))); err != nil {
				t.Fatal(err)
			}
			if ambiguous {
				harness.store.ambiguousFinalizeOnce = true
			} else {
				harness.store.failFinalizeBeforeCommitOnce = true
			}
			if _, err := harness.coordinator.FinalizeUpload(context.Background(), harness.credential, harness.binding, uploadID); err == nil {
				t.Fatal("injected finalization failure reported success")
			}
			if _, err := os.Lstat(filepath.Join(harness.root, stagingPath(uploadID))); !os.IsNotExist(err) {
				t.Fatalf("writable staging remains after publication: %v", err)
			}
			receipt, err := harness.coordinator.FinalizeUpload(context.Background(), harness.credential, harness.binding, uploadID)
			if err != nil {
				t.Fatalf("finalization recovery failed: %v", err)
			}
			if _, err := receipt.VerifiedPayload(); err != nil || harness.store.generation.ValidateStored() != nil {
				t.Fatalf("recovered receipt err=%v", err)
			}
		})
	}
}

func TestCoordinatorFinalizeFreshReauthorizationPrecedesPublication(t *testing.T) {
	harness := newCoordinatorHarness(t, []Capability{Publish})
	defer harness.content.Close()
	wire := testOuterWire(t, harness.target.BackupSetID, 1, nil, 16)
	uploadID := uuid.New()
	harness.store.upload = UploadRecord{AccountID: harness.target.AccountID, TargetID: harness.target.TargetID,
		BackupSetID: harness.target.BackupSetID, UploadID: uploadID, CommittedBytes: uint64(len(wire)),
		MaximumChunkCount: 10, Request: PublishRequest{Version: Version, RequestID: uuid.New(),
			RequestedAtMilliseconds: 1_100, Credential: harness.credential.Reference, Generation: 1}}
	if err := harness.content.PrepareUpload(uploadID); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.content.ReconcileAndAppend(uploadID, 0, wire, uint64(len(wire)), uint64(len(wire))); err != nil {
		t.Fatal(err)
	}
	harness.clock.times = []time.Time{time.UnixMilli(1_100), time.UnixMilli(20_000)}
	if _, err := harness.coordinator.FinalizeUpload(context.Background(), harness.credential, harness.binding, uploadID); err == nil {
		t.Fatal("expired fresh reauthorization accepted")
	}
	if _, err := os.Lstat(filepath.Join(harness.root, objectPath(serviceauthority.BackupCustodyGenerationRecord{
		Version: Version, AccountID: harness.target.AccountID, TargetID: harness.target.TargetID,
		BackupSetID: harness.target.BackupSetID, Generation: 1, UploadID: uploadID,
		OuterByteCount: uint64(len(wire)), OuterDigest: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}))); !os.IsNotExist(err) {
		t.Fatalf("object published before fresh reauthorization: %v", err)
	}
}

func TestCoordinatorRetentionChecksMinimumLinkReplayAndClockRollback(t *testing.T) {
	harness := newCoordinatorHarness(t, []Capability{Publish, Read, RetentionProof})
	defer harness.content.Close()
	wire := testOuterWire(t, harness.target.BackupSetID, 1, nil, 16)
	uploadID := uuid.New()
	harness.store.upload = UploadRecord{AccountID: harness.target.AccountID, TargetID: harness.target.TargetID,
		BackupSetID: harness.target.BackupSetID, UploadID: uploadID, CommittedBytes: uint64(len(wire)),
		MaximumChunkCount: 10, Request: PublishRequest{Version: Version, RequestID: uuid.New(),
			RequestedAtMilliseconds: 1_100, Credential: harness.credential.Reference, Generation: 1}}
	if err := harness.content.PrepareUpload(uploadID); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.content.ReconcileAndAppend(uploadID, 0, wire, uint64(len(wire)), uint64(len(wire))); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.coordinator.FinalizeUpload(context.Background(), harness.credential, harness.binding, uploadID); err != nil {
		t.Fatal(err)
	}
	request := RetentionProofRequest{Version: Version, RequestID: uuid.New(), RequestedAtMilliseconds: 1_100,
		Credential: harness.credential.Reference, GenerationReferenceDigest: harness.store.generation.GenerationReferenceDigest,
		CustodyReceiptReferenceDigest:      harness.store.generation.CustodyReceiptReferenceDigest,
		MinimumRetainedThroughMilliseconds: 1_100}
	harness.store.retentionHighWater = 1_200
	if _, err := harness.coordinator.ConfirmRetention(context.Background(), harness.credential, request, harness.binding); !errors.Is(err, ErrClockRollback) {
		t.Fatalf("clock rollback err=%v", err)
	}
	harness.store.retentionHighWater = 1_000
	harness.clock.times = []time.Time{time.UnixMilli(1_200), time.UnixMilli(1_200)}
	receipt, err := harness.coordinator.ConfirmRetention(context.Background(), harness.credential, request, harness.binding)
	if err != nil {
		t.Fatal(err)
	}
	if harness.store.retention.ValidateStored() != nil {
		t.Fatal("retention record was not durably exact")
	}
	harness.clock.times = []time.Time{time.UnixMilli(20_000)}
	replayed, err := harness.coordinator.ConfirmRetention(context.Background(), harness.credential, request, harness.binding)
	if err != nil || replayed.Signature.Signature != receipt.Signature.Signature {
		t.Fatalf("historical exact replay err=%v", err)
	}
	wrongLink := request
	wrongLink.RequestID = uuid.New()
	wrongLink.CustodyReceiptReferenceDigest = strings.Repeat("f", 64)
	harness.clock.times = []time.Time{time.UnixMilli(1_200), time.UnixMilli(1_200)}
	if _, err := harness.coordinator.ConfirmRetention(context.Background(), harness.credential, wrongLink, harness.binding); err == nil {
		t.Fatal("wrong custody linkage accepted")
	}
	tooEarly := request
	tooEarly.RequestID = uuid.New()
	tooEarly.MinimumRetainedThroughMilliseconds = 1_500
	harness.clock.times = []time.Time{time.UnixMilli(1_200)}
	if _, err := harness.coordinator.ConfirmRetention(context.Background(), harness.credential, tooEarly, harness.binding); err == nil {
		t.Fatal("retention proof issued before requested minimum")
	}
}

type fixedBackupClock struct{ now time.Time }

func (clock fixedBackupClock) Now() time.Time { return clock.now }

type scriptedBackupClock struct {
	times []time.Time
	last  time.Time
}

func (clock *scriptedBackupClock) Now() time.Time {
	if len(clock.times) == 0 {
		return clock.last
	}
	clock.last = clock.times[0]
	clock.times = clock.times[1:]
	return clock.last
}

type unusedAuthorityHistory struct{}

func (unusedAuthorityHistory) ResolveBackupCustodyAuthority(context.Context, serviceauthority.BackupCustodyAuthorityContext) (serviceauthority.TrustAnchor, serviceauthority.Manifest, error) {
	return serviceauthority.TrustAnchor{}, serviceauthority.Manifest{}, errors.New("unexpected authority-history lookup")
}

type readCoordinatorStore struct {
	target              TargetRecord
	generation          GenerationRecord
	items               []GenerationRecord
	upload              UploadRecord
	credentialAuthority AcceptedCredentialAuthority
	lastAuthorization   ReadAuthorization
	readCount           int
}

func (store *readCoordinatorStore) LoadTarget(context.Context, uuid.UUID, uuid.UUID) (TargetRecord, error) {
	return store.target, nil
}
func (store *readCoordinatorStore) ReadSnapshot(_ context.Context, authorization ReadAuthorization, use CredentialUse, _ Clock, targetID uuid.UUID, reference string) (TargetRecord, GenerationRecord, error) {
	if authorization.Validate() != nil || targetID != store.target.TargetID || reference != store.generation.GenerationReferenceDigest {
		return TargetRecord{}, GenerationRecord{}, serviceauthority.ErrInvalid
	}
	if !reflect.DeepEqual(use.Reference, store.credentialAuthority.Grant.Credential) || use.AuthorizationDigest != store.credentialAuthority.Grant.AuthorizationDigest {
		return TargetRecord{}, GenerationRecord{}, ErrUnauthorized
	}
	store.lastAuthorization = authorization
	store.readCount++
	return store.target, store.generation, nil
}
func (store *readCoordinatorStore) AuthorizeUploadSnapshot(_ context.Context, authorization ReadAuthorization, use CredentialUse, _ Clock, uploadID uuid.UUID) (UploadRecord, error) {
	if authorization.Validate() != nil || uploadID != store.upload.UploadID ||
		!reflect.DeepEqual(use.Reference, store.credentialAuthority.Grant.Credential) ||
		use.AuthorizationDigest != store.credentialAuthority.Grant.AuthorizationDigest {
		return UploadRecord{}, ErrUnauthorized
	}
	return store.upload, nil
}
func (store *readCoordinatorStore) ListGenerationSnapshot(_ context.Context, authorization ReadAuthorization, use CredentialUse, _ Clock, request GenerationListRequest) (TargetRecord, GenerationRecord, []GenerationRecord, error) {
	if authorization.Validate() != nil || request.Validate() != nil ||
		!reflect.DeepEqual(use.Reference, store.credentialAuthority.Grant.Credential) ||
		use.AuthorizationDigest != store.credentialAuthority.Grant.AuthorizationDigest || len(store.items) == 0 {
		return TargetRecord{}, GenerationRecord{}, nil, ErrUnauthorized
	}
	return store.target, store.generation, append([]GenerationRecord(nil), store.items...), nil
}
func (*readCoordinatorStore) LoadAccountClaim(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (AccountRecord, string, error) {
	return AccountRecord{}, "", ErrNotFound
}
func (*readCoordinatorStore) PrepareAccount(context.Context, AccountRecord) error {
	return serviceauthority.ErrInvalid
}
func (*readCoordinatorStore) ActivateAccount(context.Context, uuid.UUID, uint64, string, uuid.UUID, int64) error {
	return serviceauthority.ErrInvalid
}
func (*readCoordinatorStore) ApplyControlCommand(context.Context, SignedControlCommand, serviceauthority.MutationAuthorization) (ControlCommandAcceptance, error) {
	return ControlCommandAcceptance{}, serviceauthority.ErrInvalid
}
func (*readCoordinatorStore) ValidateControlLedger(context.Context, uuid.UUID) error { return nil }
func (*readCoordinatorStore) ReserveUpload(context.Context, UploadRecord, CredentialUse, Clock, serviceauthority.MutationAuthorization) (UploadRecord, bool, error) {
	return UploadRecord{}, false, serviceauthority.ErrInvalid
}
func (*readCoordinatorStore) LoadUpload(context.Context, uuid.UUID, uuid.UUID) (UploadRecord, error) {
	return UploadRecord{}, serviceauthority.ErrInvalid
}
func (*readCoordinatorStore) BeginUploadAppend(context.Context, uuid.UUID, uuid.UUID, uint64, string, uint64, CredentialUse, Clock, serviceauthority.MutationAuthorization) (UploadAppend, error) {
	return nil, serviceauthority.ErrInvalid
}
func (*readCoordinatorStore) BeginFinalization(context.Context, uuid.UUID, uuid.UUID, CredentialUse, serviceauthority.MutationAuthorization) (Finalization, error) {
	return nil, serviceauthority.ErrInvalid
}
func (*readCoordinatorStore) LoadGenerationByUpload(context.Context, uuid.UUID, uuid.UUID) (GenerationRecord, error) {
	return GenerationRecord{}, serviceauthority.ErrInvalid
}
func (*readCoordinatorStore) LoadGeneration(context.Context, uuid.UUID, string) (GenerationRecord, error) {
	return GenerationRecord{}, serviceauthority.ErrInvalid
}
func (*readCoordinatorStore) AuthorizeHistoricalCredential(context.Context, CredentialUse, string, string, Capability, int64) error {
	return serviceauthority.ErrInvalid
}
func (*readCoordinatorStore) LoadRetentionByRequest(context.Context, uuid.UUID, uuid.UUID) (RetentionRecord, error) {
	return RetentionRecord{}, serviceauthority.ErrInvalid
}
func (*readCoordinatorStore) BeginRetention(context.Context, RetentionProofRequest, []byte, CredentialUse, serviceauthority.MutationAuthorization) (RetentionConfirmation, error) {
	return nil, serviceauthority.ErrInvalid
}

type coordinatorHarness struct {
	coordinator Coordinator
	store       *faultingCoordinatorStore
	content     *ContentStore
	root        string
	target      TargetRecord
	credential  TargetCredential
	binding     serviceauthority.RequestBinding
	clock       *scriptedBackupClock
}

func newCoordinatorHarness(t *testing.T, capabilities []Capability) coordinatorHarness {
	t.Helper()
	accountID, targetID, setID := uuid.New(), uuid.New(), uuid.New()
	enrollment, signer := fixtureBackupEnrollmentAndSigner(t, accountID)
	manifestPayload, err := enrollment.Manifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := enrollment.Manifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	registry := serviceauthority.NewBindingRegistry()
	scope := serviceauthority.Scope{Kind: serviceauthority.ScopeBackupCustody, ScopeID: accountID}
	if err := registry.Activate(scope, serviceauthority.CurrentBinding{Revision: 1, Digest: digest,
		DeploymentID: signer.DeploymentID(), Manifest: &enrollment.Manifest}); err != nil {
		t.Fatal(err)
	}
	reference := TargetCredentialReference{Version: Version, AccountID: accountID, TargetID: targetID,
		BackupSetID: setID, CredentialID: uuid.New(), Capabilities: capabilities,
		ExpiresAtMilliseconds: 10_000, RequestNonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	credential, err := NewTargetCredential(reference)
	if err != nil {
		t.Fatal(err)
	}
	credentialDigest, err := credential.AuthorizationDigest()
	if err != nil {
		t.Fatal(err)
	}
	target := TargetRecord{AccountID: accountID, TargetID: targetID, BackupSetID: setID}
	store := &faultingCoordinatorStore{target: target,
		credentialAuthority: testAcceptedCredentialAuthority(t, reference, credentialDigest)}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "custody")
	content, err := OpenContentStore(root)
	if err != nil {
		t.Fatal(err)
	}
	clock := &scriptedBackupClock{times: []time.Time{time.UnixMilli(1_100)}, last: time.UnixMilli(1_100)}
	coordinator := Coordinator{Store: store, Content: content, Registry: registry, Signer: signer,
		AuthorityHistory: fixedAuthorityHistory{anchor: enrollment.Anchor, manifest: enrollment.Manifest}, Clock: clock,
		MaximumChunkBytes: 2 * 1024 * 1024, MaximumGenerationBytes: 8 * 1024 * 1024, NewID: uuid.New}
	return coordinatorHarness{coordinator: coordinator, store: store, content: content, root: root,
		target: target, credential: credential,
		binding: serviceauthority.RequestBinding{Scope: scope, AuthorityRevision: 1, AuthorityDigest: digest,
			DeploymentID: signer.DeploymentID(), RouteID: manifestPayload.ActiveDeployment.Routes[0].RouteID,
			TrafficClass: serviceauthority.TrafficBulk}, clock: clock}
}

type fixedAuthorityHistory struct {
	anchor   serviceauthority.TrustAnchor
	manifest serviceauthority.Manifest
}

func testAcceptedCredentialAuthority(t *testing.T, reference TargetCredentialReference, authorizationDigest string) AcceptedCredentialAuthority {
	t.Helper()
	grant := CredentialGrant{Version: CredentialAuthorityVersion, Credential: reference, AuthorizationDigest: authorizationDigest}
	grantReference, err := grant.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	return AcceptedCredentialAuthority{Grant: grant, GrantReferenceDigest: grantReference,
		ControlHead: AcceptedControlHead{AccountID: reference.AccountID, Sequence: 1,
			ControlGeneration: 1, ControlKeyID: uuid.New(), ReferenceDigest: strings.Repeat("c", 64)}}
}

func (history fixedAuthorityHistory) ResolveBackupCustodyAuthority(_ context.Context, authority serviceauthority.BackupCustodyAuthorityContext) (serviceauthority.TrustAnchor, serviceauthority.Manifest, error) {
	digest, err := history.manifest.ReferenceDigest()
	if err != nil || authority.Scope != history.anchor.Scope || authority.AuthorityManifestDigest != digest {
		return serviceauthority.TrustAnchor{}, serviceauthority.Manifest{}, serviceauthority.ErrInvalid
	}
	return history.anchor, history.manifest, nil
}

type faultingCoordinatorStore struct {
	readCoordinatorStore
	target                       TargetRecord
	upload                       UploadRecord
	generation                   GenerationRecord
	retention                    RetentionRecord
	retentionHighWater           int64
	chunkDigest                  string
	chunkLength                  uint64
	ambiguousAppendOnce          bool
	failAppendBeforeCommitOnce   bool
	ambiguousFinalizeOnce        bool
	failFinalizeBeforeCommitOnce bool
	credentialAuthority          AcceptedCredentialAuthority
}

func (store *faultingCoordinatorStore) LoadTarget(_ context.Context, accountID, targetID uuid.UUID) (TargetRecord, error) {
	if store.target.AccountID != accountID || store.target.TargetID != targetID {
		return TargetRecord{}, ErrNotFound
	}
	return store.target, nil
}

func (store *faultingCoordinatorStore) BeginUploadAppend(_ context.Context, accountID, uploadID uuid.UUID, offset uint64, digest string, length uint64, use CredentialUse, _ Clock, _ serviceauthority.MutationAuthorization) (UploadAppend, error) {
	if store.upload.AccountID != accountID || store.upload.UploadID != uploadID {
		return nil, ErrNotFound
	}
	if !reflect.DeepEqual(use.Reference, store.credentialAuthority.Grant.Credential) || use.AuthorizationDigest != store.credentialAuthority.Grant.AuthorizationDigest {
		return nil, ErrUnauthorized
	}
	lease := &faultingUploadAppend{store: store, upload: store.upload, digest: digest, length: length}
	if offset < store.upload.CommittedBytes {
		if offset != 0 || digest != store.chunkDigest || length != store.chunkLength || offset+length != store.upload.CommittedBytes {
			return nil, ErrConflict
		}
		next := offset + length
		lease.existing = &next
		return lease, nil
	}
	if offset != store.upload.CommittedBytes {
		return nil, ErrConflict
	}
	return lease, nil
}

func (store *faultingCoordinatorStore) LoadGenerationByUpload(_ context.Context, accountID, uploadID uuid.UUID) (GenerationRecord, error) {
	if store.generation.Generation.AccountID == accountID && store.generation.Generation.UploadID == uploadID {
		return store.generation, nil
	}
	return GenerationRecord{}, ErrNotFound
}

func (store *faultingCoordinatorStore) AuthorizeHistoricalCredential(_ context.Context, use CredentialUse, grantReference, headReference string, required Capability, issuedAt int64) error {
	if !reflect.DeepEqual(use.Reference, store.credentialAuthority.Grant.Credential) || use.AuthorizationDigest != store.credentialAuthority.Grant.AuthorizationDigest ||
		grantReference != store.credentialAuthority.GrantReferenceDigest || headReference != store.credentialAuthority.ControlHead.ReferenceDigest ||
		!store.credentialAuthority.Grant.Credential.Admits(required, issuedAt) {
		return ErrUnauthorized
	}
	return nil
}

func (store *faultingCoordinatorStore) BeginFinalization(_ context.Context, accountID, uploadID uuid.UUID, use CredentialUse, _ serviceauthority.MutationAuthorization) (Finalization, error) {
	if store.upload.AccountID != accountID || store.upload.UploadID != uploadID {
		return nil, ErrNotFound
	}
	if !reflect.DeepEqual(use.Reference, store.credentialAuthority.Grant.Credential) || use.AuthorizationDigest != store.credentialAuthority.Grant.AuthorizationDigest {
		return nil, ErrUnauthorized
	}
	return &faultingFinalization{store: store}, nil
}

func (store *faultingCoordinatorStore) LoadRetentionByRequest(_ context.Context, accountID, requestID uuid.UUID) (RetentionRecord, error) {
	if store.retention.AccountID == accountID && store.retention.Request.RequestID == requestID {
		return store.retention, nil
	}
	return RetentionRecord{}, ErrNotFound
}

func (store *faultingCoordinatorStore) BeginRetention(_ context.Context, request RetentionProofRequest, requestBytes []byte, use CredentialUse, _ serviceauthority.MutationAuthorization) (RetentionConfirmation, error) {
	if store.generation.GenerationReferenceDigest != request.GenerationReferenceDigest {
		return nil, ErrNotFound
	}
	if !reflect.DeepEqual(use.Reference, store.credentialAuthority.Grant.Credential) || use.AuthorizationDigest != store.credentialAuthority.Grant.AuthorizationDigest {
		return nil, ErrUnauthorized
	}
	return &faultingRetention{store: store, request: request, requestBytes: append([]byte(nil), requestBytes...)}, nil
}

type faultingUploadAppend struct {
	store    *faultingCoordinatorStore
	upload   UploadRecord
	digest   string
	length   uint64
	existing *uint64
}

func (lease *faultingUploadAppend) Upload() UploadRecord { return lease.upload }
func (lease *faultingUploadAppend) ExistingNextOffset() *uint64 {
	if lease.existing == nil {
		return nil
	}
	value := *lease.existing
	return &value
}
func (*faultingUploadAppend) Abort(context.Context) error { return nil }
func (lease *faultingUploadAppend) Commit(_ context.Context, next uint64) error {
	if next != lease.upload.CommittedBytes+lease.length {
		return serviceauthority.ErrInvalid
	}
	if lease.store.failAppendBeforeCommitOnce {
		lease.store.failAppendBeforeCommitOnce = false
		return errors.New("injected offset commit failure")
	}
	lease.store.upload.CommittedBytes = next
	lease.store.chunkDigest, lease.store.chunkLength = lease.digest, lease.length
	if lease.store.ambiguousAppendOnce {
		lease.store.ambiguousAppendOnce = false
		return errors.New("injected ambiguous offset commit")
	}
	return nil
}

type faultingFinalization struct{ store *faultingCoordinatorStore }

func (lease *faultingFinalization) Upload() UploadRecord { return lease.store.upload }
func (lease *faultingFinalization) Target() TargetRecord { return lease.store.target }
func (lease *faultingFinalization) Existing() *GenerationRecord {
	if lease.store.generation.Generation.AccountID == uuid.Nil {
		return nil
	}
	copy := lease.store.generation
	return &copy
}
func (lease *faultingFinalization) CredentialAuthority() AcceptedCredentialAuthority {
	return lease.store.credentialAuthority
}
func (*faultingFinalization) Revalidate(context.Context, serviceauthority.MutationAuthorization) error {
	return nil
}
func (*faultingFinalization) Abort(context.Context) error { return nil }
func (lease *faultingFinalization) Commit(_ context.Context, record GenerationRecord) error {
	if lease.store.failFinalizeBeforeCommitOnce {
		lease.store.failFinalizeBeforeCommitOnce = false
		return errors.New("injected generation commit failure")
	}
	lease.store.generation = record
	lease.store.upload.Committed = true
	lease.store.target.Head = cloneGeneration(&record.Generation)
	lease.store.target.HeadReferenceDigest = cloneString(&record.GenerationReferenceDigest)
	if lease.store.ambiguousFinalizeOnce {
		lease.store.ambiguousFinalizeOnce = false
		return errors.New("injected ambiguous generation commit")
	}
	return nil
}

type faultingRetention struct {
	store        *faultingCoordinatorStore
	request      RetentionProofRequest
	requestBytes []byte
}

func (lease *faultingRetention) Target() TargetRecord         { return lease.store.target }
func (lease *faultingRetention) Generation() GenerationRecord { return lease.store.generation }
func (*faultingRetention) Existing() *RetentionRecord         { return nil }
func (lease *faultingRetention) CredentialAuthority() AcceptedCredentialAuthority {
	return lease.store.credentialAuthority
}
func (lease *faultingRetention) ServerTimeHighWaterMilliseconds() int64 {
	return lease.store.retentionHighWater
}
func (*faultingRetention) Revalidate(context.Context, serviceauthority.MutationAuthorization) error {
	return nil
}
func (*faultingRetention) Abort(context.Context) error { return nil }
func (lease *faultingRetention) Commit(_ context.Context, record RetentionRecord, highWater int64) error {
	if string(record.RequestBytes) != string(lease.requestBytes) || highWater < lease.store.retentionHighWater {
		return serviceauthority.ErrInvalid
	}
	lease.store.retention = record
	lease.store.retentionHighWater = highWater
	return nil
}

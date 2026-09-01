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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/traffic"
)

type acceptingAdmissionVerifier struct{}

func (acceptingAdmissionVerifier) VerifyAccountAdmission(AccountAdmissionCredential, serviceauthority.InitialEnrollment) bool {
	return true
}

func TestBackupHTTPBootstrapAndBoundDeploymentProofs(t *testing.T) {
	handler, harness := newBackupHTTPTestHandler(t, []Capability{Read}, traffic.DefaultLimits(), nil)
	defer harness.content.Close()
	history := harness.coordinator.AuthorityHistory.(fixedAuthorityHistory)
	manifestPayload, err := history.manifest.VerifiedPayload()
	if err != nil {
		t.Fatal(err)
	}
	offer, err := harness.coordinator.Signer.SignDeploymentOffer(serviceauthority.DeploymentOfferPayload{
		Version:               serviceauthority.SchemaVersion,
		Deployment:            manifestPayload.ActiveDeployment,
		TransportPolicy:       manifestPayload.TransportPolicy,
		IssuedAtMilliseconds:  1_000,
		ExpiresAtMilliseconds: 2_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	offerDigest, err := offer.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	bootstrapRequest := serviceauthority.BootstrapProofRequest{
		Version:               serviceauthority.SchemaVersion,
		Challenge:             base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x62}, 32)),
		DeploymentID:          harness.binding.DeploymentID,
		DeploymentOfferDigest: offerDigest,
		RouteID:               harness.binding.RouteID,
		Scope:                 harness.binding.Scope,
		TrafficClass:          serviceauthority.TrafficBulk,
	}
	bootstrapBody, _ := json.Marshal(bootstrapDeploymentProofInput{
		DeploymentOffer: offer, Request: bootstrapRequest,
	})
	bootstrapHTTP := httptest.NewRequest(
		http.MethodPost, "/v1/service-deployment/bootstrap-proof", bytes.NewReader(bootstrapBody),
	)
	bootstrapHTTP.Header.Set("Content-Type", "application/json")
	bootstrapResponse := httptest.NewRecorder()
	handler.Handler().ServeHTTP(bootstrapResponse, bootstrapHTTP)
	var bootstrapProof serviceauthority.BootstrapProof
	if bootstrapResponse.Code != http.StatusOK ||
		json.Unmarshal(bootstrapResponse.Body.Bytes(), &bootstrapProof) != nil {
		t.Fatalf("bootstrap proof status=%d body=%s", bootstrapResponse.Code, bootstrapResponse.Body.String())
	}
	var bootstrapPayload serviceauthority.BootstrapProofPayload
	if json.Unmarshal(bootstrapProof.Payload, &bootstrapPayload) != nil ||
		bootstrapPayload.Request != bootstrapRequest || bootstrapProof.Signature.SignerID != harness.binding.DeploymentID {
		t.Fatal("bootstrap proof did not bind the exact request/deployment")
	}

	boundRequest := serviceauthority.ProofRequest{
		Version:                 serviceauthority.SchemaVersion,
		AuthorityManifestDigest: harness.binding.AuthorityDigest,
		AuthorityRevision:       harness.binding.AuthorityRevision,
		Challenge:               base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x63}, 32)),
		DeploymentID:            harness.binding.DeploymentID, RouteID: harness.binding.RouteID,
		Scope: harness.binding.Scope, TrafficClass: serviceauthority.TrafficBulk,
	}
	boundBody, _ := json.Marshal(boundRequest)
	boundHTTP := httptest.NewRequest(
		http.MethodPost, "/v1/service-deployment/proof", bytes.NewReader(boundBody),
	)
	boundHTTP.Header.Set("Content-Type", "application/json")
	boundResponse := httptest.NewRecorder()
	handler.Handler().ServeHTTP(boundResponse, boundHTTP)
	var boundProof serviceauthority.DeploymentProof
	if boundResponse.Code != http.StatusOK || json.Unmarshal(boundResponse.Body.Bytes(), &boundProof) != nil {
		t.Fatalf("bound proof status=%d body=%s", boundResponse.Code, boundResponse.Body.String())
	}
	var boundPayload serviceauthority.ProofPayload
	if json.Unmarshal(boundProof.Payload, &boundPayload) != nil ||
		boundPayload.Request != boundRequest || boundProof.Signature.SignerID != harness.binding.DeploymentID {
		t.Fatal("bound proof did not bind the exact request/deployment")
	}
}

func TestBackupHTTPProvisionRunsDurableReconciliationOutsideCallerCancellation(t *testing.T) {
	for _, afterErr := range []error{nil, errors.New("injected reconciliation failure")} {
		t.Run(fmt.Sprintf("after-error=%t", afterErr != nil), func(t *testing.T) {
			reference := fixtureAdmissionReference()
			reference.ExpiresAtMilliseconds = 1_500
			credential, err := NewAccountAdmissionCredential(reference)
			if err != nil {
				t.Fatal(err)
			}
			enrollment, signer := fixtureBackupEnrollmentAndSigner(t, reference.AccountID)
			store := &cancelingProvisionStore{}
			registry := serviceauthority.NewBindingRegistry()
			parent := t.TempDir()
			if err := os.Chmod(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			journal, err := OpenPreparedAccountJournal(filepath.Join(parent, "claims"))
			if err != nil {
				t.Fatal(err)
			}
			defer journal.Close()
			content, err := OpenContentStore(filepath.Join(parent, "custody"))
			if err != nil {
				t.Fatal(err)
			}
			defer content.Close()
			clock := &mutableBackupClock{now: time.UnixMilli(1_100)}
			provisioning := &ProvisioningCustody{
				Store: store, Journal: journal, Registry: registry, Signer: signer, Clock: clock,
			}
			coordinator := &Coordinator{
				Store: store, Content: content, Registry: registry, Signer: signer,
				AuthorityHistory: fixedAuthorityHistory{anchor: enrollment.Anchor, manifest: enrollment.Manifest},
				Clock:            clock, MaximumChunkBytes: 1024, MaximumGenerationBytes: 4096, NewID: uuid.New,
			}
			var reconciliations int
			handler, err := NewHTTPHandler(
				coordinator, provisioning, acceptingAdmissionVerifier{}, signer, registry,
				1024, time.Minute, traffic.DefaultLimits(),
				func(context.Context) error { return nil },
				func() error { reconciliations++; return afterErr },
			)
			if err != nil {
				t.Fatal(err)
			}
			handler.now = func() time.Time { return time.UnixMilli(1_100) }
			body, _ := json.Marshal(ProvisionAccountRequest{
				Version: Version, Admission: reference, ClaimID: uuid.New(), InitialEnrollment: enrollment,
				InitialControlAnchor: newTestControlSigner(t, reference.AccountID, 1, 72).anchor(t),
			})
			ctx, cancel := context.WithCancel(context.Background())
			store.cancel = cancel
			request := httptest.NewRequest(
				http.MethodPost,
				"/v1/backup-accounts/"+reference.AccountID.String()+"/provision",
				bytes.NewReader(body),
			).WithContext(ctx)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+credential.TransportBearer())
			response := httptest.NewRecorder()
			handler.Handler().ServeHTTP(response, request)
			expectedStatus := http.StatusNoContent
			if afterErr != nil {
				expectedStatus = http.StatusInternalServerError
			}
			if response.Code != expectedStatus || reconciliations != 1 || store.state != AccountStateWritable {
				t.Fatalf("status=%d reconciliations=%d state=%q", response.Code, reconciliations, store.state)
			}
		})
	}
}

func TestBackupHTTPRejectsUnboundedChunksAndBodySmuggledFinalization(t *testing.T) {
	handler, harness := newBackupHTTPTestHandler(t, []Capability{Publish}, traffic.DefaultLimits(), nil)
	defer harness.content.Close()
	uploadID := uuid.New()
	chunk := []byte("opaque-chunk")
	digest := fmt.Sprintf("%x", sha256.Sum256(chunk))

	missingType := httptest.NewRequest(http.MethodPut, "/v1/backup-accounts/"+harness.target.AccountID.String()+"/uploads/"+uploadID.String()+"/chunks?offset=0", bytes.NewReader(chunk))
	setBackupHTTPAuthority(missingType, harness.binding, serviceauthority.TrafficBulk)
	setBackupTargetHeaders(t, missingType, harness.credential)
	missingType.Header.Set(HeaderChunkSHA256, digest)
	response := httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, missingType)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("missing content type status=%d", response.Code)
	}

	chunked := httptest.NewRequest(http.MethodPut, "/v1/backup-accounts/"+harness.target.AccountID.String()+"/uploads/"+uploadID.String()+"/chunks?offset=0", bytes.NewReader(chunk))
	chunked.Header.Set("Content-Type", "application/octet-stream")
	chunked.Header.Set(HeaderChunkSHA256, digest)
	chunked.ContentLength = -1
	chunked.TransferEncoding = []string{"chunked"}
	setBackupHTTPAuthority(chunked, harness.binding, serviceauthority.TrafficBulk)
	setBackupTargetHeaders(t, chunked, harness.credential)
	response = httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, chunked)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("chunked content status=%d", response.Code)
	}

	finalize := httptest.NewRequest(http.MethodPost, "/v1/backup-accounts/"+harness.target.AccountID.String()+"/uploads/"+uploadID.String()+"/finalize", bytes.NewReader([]byte("smuggled")))
	finalize.ContentLength = -1
	finalize.TransferEncoding = []string{"chunked"}
	setBackupHTTPAuthority(finalize, harness.binding, serviceauthority.TrafficControl)
	setBackupTargetHeaders(t, finalize, harness.credential)
	response = httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, finalize)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("smuggled finalization status=%d", response.Code)
	}
}

func TestBackupHTTPHandlerRejectsChunkLimitAboveFixedMemoryCap(t *testing.T) {
	harness := newCoordinatorHarness(t, []Capability{Publish})
	defer harness.content.Close()
	harness.coordinator.MaximumChunkBytes = maximumHTTPChunkBytes + 1
	harness.coordinator.MaximumGenerationBytes = maximumHTTPChunkBytes + 1
	provisioning := &ProvisioningCustody{
		Store: harness.coordinator.Store, Journal: &PreparedAccountJournal{},
		Registry: harness.coordinator.Registry, Signer: harness.coordinator.Signer,
		Clock: harness.coordinator.Clock,
	}
	_, err := NewHTTPHandler(
		&harness.coordinator, provisioning, acceptingAdmissionVerifier{},
		harness.coordinator.Signer, harness.coordinator.Registry,
		maximumHTTPChunkBytes+1, time.Minute, traffic.DefaultLimits(),
		func(context.Context) error { return nil }, func() error { return nil },
	)
	if err == nil {
		t.Fatal("HTTP chunk limit above fixed 64 MiB cap accepted")
	}
	harness.coordinator.MaximumChunkBytes = maximumHTTPChunkBytes
	harness.coordinator.MaximumGenerationBytes = maximumHTTPChunkBytes
	if _, err := NewHTTPHandler(
		&harness.coordinator, provisioning, acceptingAdmissionVerifier{},
		harness.coordinator.Signer, harness.coordinator.Registry,
		maximumHTTPChunkBytes, time.Minute, traffic.DefaultLimits(),
		func(context.Context) error { return nil }, func() error { return nil },
	); err != nil {
		t.Fatalf("fixed 64 MiB cap rejected: %v", err)
	}
}

func TestBackupHTTPControlCommandUsesOwnerSignatureAndControlAuthority(t *testing.T) {
	harness := newCoordinatorHarness(t, []Capability{Publish})
	defer harness.content.Close()
	authority := newTestControlSigner(t, harness.target.AccountID, 1, 75)
	anchor := authority.anchor(t)
	predecessor, _ := anchor.ReferenceDigest()
	digest, _ := harness.credential.AuthorizationDigest()
	grant := CredentialGrant{Version: CredentialAuthorityVersion, Credential: harness.credential.Reference, AuthorizationDigest: digest}
	payload := ControlCommandPayload{Version: CredentialAuthorityVersion, AccountID: harness.target.AccountID,
		CommandID: uuid.New(), ControlGeneration: 1, ControlKeyID: authority.keyID, Sequence: 1,
		PredecessorReferenceDigest: predecessor, Effect: ControlEffect{Kind: CreateTargetWithInitialGrant,
			TargetID: &harness.target.TargetID, BackupSetID: &harness.target.BackupSetID, Grant: &grant}}
	record, err := signControlCommand(payload, authority, nil)
	if err != nil {
		t.Fatal(err)
	}
	store := &httpControlStore{faultingCoordinatorStore: *harness.store, expected: record}
	harness.coordinator.Store = store
	handler, _ := newBackupHTTPTestHandlerFromHarness(t, &harness, traffic.DefaultLimits())
	body, _ := record.CanonicalJSON()
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/backup-accounts/"+harness.target.AccountID.String()+"/control-commands",
		bytes.NewReader(body),
	)
	request.Header.Set("Content-Type", "application/json")
	setBackupHTTPAuthority(request, harness.binding, serviceauthority.TrafficControl)
	response := httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || store.calls != 1 {
		t.Fatalf("control command status=%d calls=%d", response.Code, store.calls)
	}
	if strings.Contains(string(body), harness.credential.TransportBearer()) {
		t.Fatal("control command exposed raw bearer")
	}
}

func TestBackupHTTPExactBeginReplayIsTheResumeStatusOperation(t *testing.T) {
	harness := newCoordinatorHarness(t, []Capability{Publish})
	defer harness.content.Close()
	store := &httpBeginStore{faultingCoordinatorStore: *harness.store}
	harness.coordinator.Store = store
	handler, _ := newBackupHTTPTestHandlerFromHarness(t, &harness, traffic.DefaultLimits())
	requestValue := PublishRequest{
		Version:                 Version,
		Credential:              harness.credential.Reference,
		Generation:              1,
		RequestID:               uuid.New(),
		RequestedAtMilliseconds: 1_100,
	}
	first := backupBeginRequest(t, harness, requestValue)
	firstResponse := httptest.NewRecorder()
	handler.Handler().ServeHTTP(firstResponse, first)
	if firstResponse.Code != http.StatusOK {
		t.Fatalf("first begin status=%d body=%s", firstResponse.Code, firstResponse.Body.String())
	}
	var firstResult struct {
		CommittedBytes uint64    `json:"committedBytes"`
		UploadID       uuid.UUID `json:"uploadID"`
	}
	if json.Unmarshal(firstResponse.Body.Bytes(), &firstResult) != nil || firstResult.UploadID == uuid.Nil {
		t.Fatal("invalid first begin response")
	}
	chunk := bytes.Repeat([]byte{7}, 123)
	if _, err := harness.content.ReconcileAndAppend(firstResult.UploadID, 0, chunk, harness.coordinator.MaximumChunkBytes, harness.coordinator.MaximumGenerationBytes); err != nil {
		t.Fatal(err)
	}
	store.upload.CommittedBytes = uint64(len(chunk))
	replayResponse := httptest.NewRecorder()
	handler.Handler().ServeHTTP(replayResponse, backupBeginRequest(t, harness, requestValue))
	var replayResult struct {
		CommittedBytes uint64    `json:"committedBytes"`
		UploadID       uuid.UUID `json:"uploadID"`
	}
	if replayResponse.Code != http.StatusOK || json.Unmarshal(replayResponse.Body.Bytes(), &replayResult) != nil ||
		replayResult.UploadID != firstResult.UploadID || replayResult.CommittedBytes != uint64(len(chunk)) {
		t.Fatalf("resume replay status=%d result=%+v", replayResponse.Code, replayResult)
	}
	conflict := requestValue
	conflict.RequestedAtMilliseconds++
	conflictResponse := httptest.NewRecorder()
	handler.Handler().ServeHTTP(conflictResponse, backupBeginRequest(t, harness, conflict))
	if conflictResponse.Code != http.StatusUnauthorized {
		t.Fatalf("conflicting request reuse status=%d", conflictResponse.Code)
	}
}

func TestBackupHTTPUploadFinalizeReadAndRetentionVertical(t *testing.T) {
	harness := newCoordinatorHarness(t, []Capability{Publish, Read, RetentionProof})
	defer harness.content.Close()
	store := &httpBeginStore{faultingCoordinatorStore: *harness.store}
	harness.coordinator.Store = store
	handler, _ := newBackupHTTPTestHandlerFromHarness(t, &harness, traffic.DefaultLimits())
	publish := PublishRequest{
		Version: Version, Credential: harness.credential.Reference,
		Generation: 1, RequestID: uuid.New(), RequestedAtMilliseconds: 1_100,
	}
	beginResponse := httptest.NewRecorder()
	handler.Handler().ServeHTTP(beginResponse, backupBeginRequest(t, harness, publish))
	var begin struct {
		CommittedBytes uint64    `json:"committedBytes"`
		UploadID       uuid.UUID `json:"uploadID"`
	}
	if beginResponse.Code != http.StatusOK || json.Unmarshal(beginResponse.Body.Bytes(), &begin) != nil ||
		begin.UploadID == uuid.Nil || begin.CommittedBytes != 0 {
		t.Fatalf("begin status=%d body=%s", beginResponse.Code, beginResponse.Body.String())
	}
	wire := testOuterWire(t, harness.target.BackupSetID, 1, nil, 32)
	digest := fmt.Sprintf("%x", sha256.Sum256(wire))
	chunkRequest := httptest.NewRequest(
		http.MethodPut,
		"/v1/backup-accounts/"+harness.target.AccountID.String()+"/uploads/"+begin.UploadID.String()+"/chunks?offset=0",
		bytes.NewReader(wire),
	)
	chunkRequest.Header.Set("Content-Type", "application/octet-stream")
	chunkRequest.Header.Set(HeaderChunkSHA256, digest)
	setBackupHTTPAuthority(chunkRequest, harness.binding, serviceauthority.TrafficBulk)
	setBackupTargetHeaders(t, chunkRequest, harness.credential)
	uploadResource, err := UploadChunkResourceID(harness.credential.Reference, begin.UploadID, 0, uint64(len(wire)))
	if err != nil {
		t.Fatal(err)
	}
	wrongGrantRequest := chunkRequest.Clone(chunkRequest.Context())
	wrongGrantRequest.Body = io.NopCloser(bytes.NewReader(wire))
	wrongGrantRequest.ContentLength = int64(len(wire))
	setBackupBulkGrant(
		t, wrongGrantRequest, harness, serviceauthority.BulkUpload, uploadResource, uint64(len(wire)-1),
	)
	wrongGrantResponse := httptest.NewRecorder()
	handler.Handler().ServeHTTP(wrongGrantResponse, wrongGrantRequest)
	if wrongGrantResponse.Code != http.StatusUnauthorized || store.upload.CommittedBytes != 0 {
		t.Fatalf("mismatched grant status=%d offset=%d", wrongGrantResponse.Code, store.upload.CommittedBytes)
	}
	uploadGrant := requestBackupBulkGrant(t, handler, harness, harness.credential, serviceauthority.BulkGrantRequest{
		Version: serviceauthority.SchemaVersion, Direction: serviceauthority.BulkUpload,
		RequiredByteCount: int64(len(wire)), ResourceID: uploadResource, RouteID: harness.binding.RouteID,
	})
	setBackupBulkGrantRecord(t, chunkRequest, uploadGrant, serviceauthority.BulkUpload, uploadResource)
	chunkResponse := httptest.NewRecorder()
	handler.Handler().ServeHTTP(chunkResponse, chunkRequest)
	if chunkResponse.Code != http.StatusOK {
		t.Fatalf("chunk status=%d body=%s", chunkResponse.Code, chunkResponse.Body.String())
	}

	wrongClass := httptest.NewRequest(
		http.MethodPut,
		"/v1/backup-accounts/"+harness.target.AccountID.String()+"/uploads/"+begin.UploadID.String()+"/chunks?offset=0",
		bytes.NewReader(wire),
	)
	wrongClass.Header.Set("Content-Type", "application/octet-stream")
	wrongClass.Header.Set(HeaderChunkSHA256, digest)
	setBackupHTTPAuthority(wrongClass, harness.binding, serviceauthority.TrafficControl)
	setBackupTargetHeaders(t, wrongClass, harness.credential)
	wrongClassResponse := httptest.NewRecorder()
	handler.Handler().ServeHTTP(wrongClassResponse, wrongClass)
	if wrongClassResponse.Code != http.StatusConflict {
		t.Fatalf("wrong traffic class status=%d", wrongClassResponse.Code)
	}

	finalizeRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/backup-accounts/"+harness.target.AccountID.String()+"/uploads/"+begin.UploadID.String()+"/finalize",
		http.NoBody,
	)
	setBackupHTTPAuthority(finalizeRequest, harness.binding, serviceauthority.TrafficControl)
	setBackupTargetHeaders(t, finalizeRequest, harness.credential)
	finalizeResponse := httptest.NewRecorder()
	handler.Handler().ServeHTTP(finalizeResponse, finalizeRequest)
	if finalizeResponse.Code != http.StatusOK {
		t.Fatalf("finalize status=%d body=%s", finalizeResponse.Code, finalizeResponse.Body.String())
	}
	var custodyReceipt serviceauthority.BackupCustodyReceipt
	if json.Unmarshal(finalizeResponse.Body.Bytes(), &custodyReceipt) != nil {
		t.Fatal("invalid finalized custody receipt")
	}
	custodyReference, err := custodyReceipt.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	listRequest := GenerationListRequest{Version: Version, RequestID: uuid.New(), Credential: harness.credential.Reference,
		AfterGeneration: 0, PageCount: 1, RequestedAtMilliseconds: 1_100}
	listBody, _ := json.Marshal(listRequest)
	listHTTP := httptest.NewRequest(
		http.MethodPost,
		"/v1/backup-accounts/"+harness.target.AccountID.String()+"/generations/list",
		bytes.NewReader(listBody),
	)
	listHTTP.Header.Set("Content-Type", "application/json")
	listHTTP.Header.Set("Authorization", "Bearer "+harness.credential.TransportBearer())
	setBackupHTTPAuthority(listHTTP, harness.binding, serviceauthority.TrafficControl)
	listResponse := httptest.NewRecorder()
	handler.Handler().ServeHTTP(listResponse, listHTTP)
	page, pageErr := DecodeGenerationListPage(listResponse.Body.Bytes())
	if listResponse.Code != http.StatusOK || pageErr != nil || len(page.Items) != 1 ||
		page.SnapshotHeadReferenceDigest != store.generation.GenerationReferenceDigest {
		t.Fatalf("list status=%d body=%s err=%v", listResponse.Code, listResponse.Body.String(), pageErr)
	}

	readRequest := ReadRequest{
		Version: Version, Credential: harness.credential.Reference,
		RequestID: uuid.New(), RequestedAtMilliseconds: 1_100,
		GenerationReferenceDigest: store.generation.GenerationReferenceDigest,
		MaximumByteCount:          41, RangeOffset: 17,
	}
	readHTTP := backupReadRequest(t, harness, readRequest, harness.credential.TransportBearer())
	downloadResource, err := DownloadRangeResourceID(
		readRequest.Credential, readRequest.GenerationReferenceDigest, readRequest.RangeOffset, readRequest.MaximumByteCount,
	)
	if err != nil {
		t.Fatal(err)
	}
	downloadGrant := requestBackupBulkGrant(t, handler, harness, harness.credential, serviceauthority.BulkGrantRequest{
		Version: serviceauthority.SchemaVersion, Direction: serviceauthority.BulkDownload,
		RequiredByteCount: int64(readRequest.MaximumByteCount), ResourceID: downloadResource, RouteID: harness.binding.RouteID,
	})
	setBackupBulkGrantRecord(t, readHTTP, downloadGrant, serviceauthority.BulkDownload, downloadResource)
	readResponse := httptest.NewRecorder()
	handler.Handler().ServeHTTP(readResponse, readHTTP)
	if readResponse.Code != http.StatusPartialContent || !bytes.Equal(readResponse.Body.Bytes(), wire[17:58]) ||
		readResponse.Header().Get(HeaderGenerationReference) != store.generation.GenerationReferenceDigest ||
		readResponse.Header().Get(HeaderOuterDigest) != store.generation.Generation.OuterDigest ||
		readResponse.Header().Get(HeaderCustodyReceipt) == "" ||
		readResponse.Header().Get("Content-Range") != fmt.Sprintf("bytes 17-57/%d", len(wire)) ||
		readResponse.Header().Get(HeaderRangeOffset) != "17" ||
		readResponse.Header().Get(HeaderRangeByteCount) != "41" {
		t.Fatalf("read status=%d headers=%v bytes=%d", readResponse.Code, readResponse.Header(), readResponse.Body.Len())
	}

	retention := RetentionProofRequest{
		Version: Version, Credential: harness.credential.Reference, RequestID: uuid.New(),
		RequestedAtMilliseconds: 1_100, MinimumRetainedThroughMilliseconds: 1_100,
		GenerationReferenceDigest:     store.generation.GenerationReferenceDigest,
		CustodyReceiptReferenceDigest: custodyReference,
	}
	retentionBody, _ := json.Marshal(retention)
	retentionRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/backup-accounts/"+harness.target.AccountID.String()+"/retention-proofs",
		bytes.NewReader(retentionBody),
	)
	retentionRequest.Header.Set("Content-Type", "application/json")
	retentionRequest.Header.Set("Authorization", "Bearer "+harness.credential.TransportBearer())
	setBackupHTTPAuthority(retentionRequest, harness.binding, serviceauthority.TrafficControl)
	retentionResponse := httptest.NewRecorder()
	handler.Handler().ServeHTTP(retentionResponse, retentionRequest)
	if retentionResponse.Code != http.StatusOK || store.retention.ValidateStored() != nil {
		t.Fatalf("retention status=%d body=%s", retentionResponse.Code, retentionResponse.Body.String())
	}
}

func TestBackupHTTPDoesNotEnumerateMissingAuthenticatedObjects(t *testing.T) {
	harness := newCoordinatorHarness(t, []Capability{Read})
	defer harness.content.Close()
	store := &httpReadNotFoundStore{faultingCoordinatorStore: *harness.store}
	harness.coordinator.Store = store
	handler, _ := newBackupHTTPTestHandlerFromHarness(t, &harness, traffic.DefaultLimits())
	read := ReadRequest{
		Version:                   Version,
		Credential:                harness.credential.Reference,
		RequestID:                 uuid.New(),
		RequestedAtMilliseconds:   1_100,
		GenerationReferenceDigest: strings.Repeat("a", 64),
		MaximumByteCount:          1, RangeOffset: 0,
	}
	correct := backupReadRequest(t, harness, read, harness.credential.TransportBearer())
	resource, err := DownloadRangeResourceID(read.Credential, read.GenerationReferenceDigest, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	setBackupBulkGrant(t, correct, harness, serviceauthority.BulkDownload, resource, 1)
	correctResponse := httptest.NewRecorder()
	handler.Handler().ServeHTTP(correctResponse, correct)
	wrong := backupReadRequest(t, harness, read, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	setBackupBulkGrant(t, wrong, harness, serviceauthority.BulkDownload, resource, 1)
	wrongResponse := httptest.NewRecorder()
	handler.Handler().ServeHTTP(wrongResponse, wrong)
	if correctResponse.Code != http.StatusUnauthorized || wrongResponse.Code != http.StatusUnauthorized ||
		correctResponse.Body.String() != wrongResponse.Body.String() {
		t.Fatalf("enumerating responses correct=%d/%q wrong=%d/%q", correctResponse.Code, correctResponse.Body.String(), wrongResponse.Code, wrongResponse.Body.String())
	}
}

func TestBackupHTTPUnauthorizedNotFoundAndConflictResponsesAreIndistinguishable(t *testing.T) {
	var expectedStatus int
	var expectedBody string
	for index, operationErr := range []error{ErrUnauthorized, ErrNotFound, ErrConflict} {
		response := httptest.NewRecorder()
		writeBackupOperationError(response, operationErr)
		if index == 0 {
			expectedStatus = response.Code
			expectedBody = response.Body.String()
		}
		if response.Code != expectedStatus || response.Body.String() != expectedBody {
			t.Fatalf("enumerating operation error=%v status=%d body=%q", operationErr, response.Code, response.Body.String())
		}
	}
	if expectedStatus != http.StatusUnauthorized {
		t.Fatalf("nonenumerating status=%d", expectedStatus)
	}
}

func TestBackupHTTPTrafficLimitIsBounded(t *testing.T) {
	limits := traffic.DefaultLimits()
	management := limits[traffic.SurfaceManagement]
	management.RequestsPerMinute = 1
	management.Burst = 1
	limits[traffic.SurfaceManagement] = management
	handler, harness := newBackupHTTPTestHandler(t, []Capability{Read}, limits, nil)
	defer harness.content.Close()
	first := httptest.NewRecorder()
	handler.Handler().ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/livez", nil))
	second := httptest.NewRecorder()
	handler.Handler().ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/livez", nil))
	if first.Code != http.StatusOK || second.Code != http.StatusTooManyRequests {
		t.Fatalf("traffic statuses=%d,%d", first.Code, second.Code)
	}
}

func TestBackupHTTPStalledStreamReleasesStorageConcurrencyAfterIdleDeadline(t *testing.T) {
	limits := traffic.DefaultLimits()
	storage := limits[traffic.SurfaceStorage]
	storage.Concurrency = 1
	limits[traffic.SurfaceStorage] = storage
	handler, harness := newBackupHTTPTestHandler(t, []Capability{Read}, limits, nil)
	defer harness.content.Close()
	handler.streamIdlePeriod = 20 * time.Millisecond
	handler.streamNow = time.Now
	streaming := handler.limited(handler.storage, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
		controller := http.NewResponseController(writer)
		_, _ = copyBackupStream(
			writer, controller, bytes.NewReader(bytes.Repeat([]byte{0x5a}, 128)),
			handler.streamIdlePeriod, handler.streamNow,
		)
	}))
	stalled := newDeadlineStalledWriter()
	firstDone := make(chan struct{})
	go func() {
		streaming.ServeHTTP(stalled, httptest.NewRequest(http.MethodGet, "/stream", nil))
		close(firstDone)
	}()
	select {
	case <-stalled.entered:
	case <-time.After(time.Second):
		t.Fatal("stalled writer was not entered")
	}
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("idle deadline did not release stalled handler")
	}
	second := httptest.NewRecorder()
	secondRequest := httptest.NewRequest(http.MethodGet, "/stream", nil)
	secondRequest.RemoteAddr = "127.0.0.2:1234"
	streaming.ServeHTTP(second, secondRequest)
	if second.Code != http.StatusOK || second.Body.Len() != 128 {
		t.Fatalf("released slot response=%d bytes=%d", second.Code, second.Body.Len())
	}
}

func newBackupHTTPTestHandler(t *testing.T, capabilities []Capability, limits traffic.Limits, store Store) (*HTTPHandler, coordinatorHarness) {
	t.Helper()
	harness := newCoordinatorHarness(t, capabilities)
	if store != nil {
		harness.coordinator.Store = store
	}
	handler, _ := newBackupHTTPTestHandlerFromHarness(t, &harness, limits)
	return handler, harness
}

func newBackupHTTPTestHandlerFromHarness(t *testing.T, harness *coordinatorHarness, limits traffic.Limits) (*HTTPHandler, *ProvisioningCustody) {
	t.Helper()
	provisioning := &ProvisioningCustody{
		Store:    harness.coordinator.Store,
		Journal:  &PreparedAccountJournal{},
		Registry: harness.coordinator.Registry,
		Signer:   harness.coordinator.Signer,
		Clock:    harness.coordinator.Clock,
	}
	handler, err := NewHTTPHandler(
		&harness.coordinator,
		provisioning,
		acceptingAdmissionVerifier{},
		harness.coordinator.Signer,
		harness.coordinator.Registry,
		harness.coordinator.MaximumChunkBytes,
		time.Minute,
		limits,
		func(context.Context) error { return nil },
		func() error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	handler.now = func() time.Time { return time.UnixMilli(1_100) }
	return handler, provisioning
}

func setBackupHTTPAuthority(request *http.Request, binding serviceauthority.RequestBinding, class serviceauthority.TrafficClass) {
	request.Header.Set(serviceauthority.HeaderScopeKind, string(binding.Scope.Kind))
	request.Header.Set(serviceauthority.HeaderScopeID, binding.Scope.ScopeID.String())
	request.Header.Set(serviceauthority.HeaderAuthorityRevision, fmt.Sprintf("%d", binding.AuthorityRevision))
	request.Header.Set(serviceauthority.HeaderAuthorityDigest, binding.AuthorityDigest)
	request.Header.Set(serviceauthority.HeaderDeploymentID, binding.DeploymentID.String())
	request.Header.Set(serviceauthority.HeaderRouteID, binding.RouteID.String())
	request.Header.Set(serviceauthority.HeaderTrafficClass, string(class))
}

func setBackupTargetHeaders(t *testing.T, request *http.Request, credential TargetCredential) {
	t.Helper()
	reference, err := json.Marshal(credential.Reference)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+credential.TransportBearer())
	request.Header.Set(HeaderTargetCredentialReference, base64.RawURLEncoding.EncodeToString(reference))
}

func setBackupBulkGrant(
	t *testing.T,
	request *http.Request,
	harness coordinatorHarness,
	direction serviceauthority.BulkDirection,
	resourceID string,
	byteCount uint64,
) {
	t.Helper()
	grant, err := harness.coordinator.Signer.SignBulkTransferGrant(serviceauthority.BulkGrantPayload{
		Version: serviceauthority.SchemaVersion, GrantID: uuid.New(), Scope: harness.binding.Scope,
		AuthorityManifestDigest: harness.binding.AuthorityDigest, DeploymentID: harness.binding.DeploymentID,
		RouteID: harness.binding.RouteID, ResourceID: resourceID, Direction: direction,
		MaximumByteCount: int64(byteCount), NotBeforeMilliseconds: 1_000, ExpiresAtMilliseconds: 1_200,
	})
	if err != nil {
		t.Fatal(err)
	}
	setBackupBulkGrantRecord(t, request, grant, direction, resourceID)
}

func setBackupBulkGrantRecord(
	t *testing.T,
	request *http.Request,
	grant serviceauthority.BulkTransferGrant,
	direction serviceauthority.BulkDirection,
	resourceID string,
) {
	t.Helper()
	encoded, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(serviceauthority.HeaderBulkTransferGrant, base64.RawURLEncoding.EncodeToString(encoded))
	request.Header.Set(serviceauthority.HeaderBulkResourceID, resourceID)
	request.Header.Set(serviceauthority.HeaderBulkDirection, string(direction))
}

func requestBackupBulkGrant(
	t *testing.T,
	handler *HTTPHandler,
	harness coordinatorHarness,
	credential TargetCredential,
	value serviceauthority.BulkGrantRequest,
) serviceauthority.BulkTransferGrant {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/backup-accounts/"+credential.Reference.AccountID.String()+"/bulk-transfer-grants",
		bytes.NewReader(body),
	)
	request.Header.Set("Content-Type", "application/json")
	setBackupHTTPAuthority(request, harness.binding, serviceauthority.TrafficControl)
	setBackupTargetHeaders(t, request, credential)
	response := httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, request)
	var grant serviceauthority.BulkTransferGrant
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &grant) != nil {
		t.Fatalf("bulk grant status=%d body=%s", response.Code, response.Body.String())
	}
	return grant
}

func backupBeginRequest(t *testing.T, harness coordinatorHarness, value PublishRequest) *http.Request {
	t.Helper()
	body, _ := json.Marshal(value)
	request := httptest.NewRequest(http.MethodPost, "/v1/backup-accounts/"+harness.target.AccountID.String()+"/uploads", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+harness.credential.TransportBearer())
	setBackupHTTPAuthority(request, harness.binding, serviceauthority.TrafficControl)
	return request
}

func backupReadRequest(t *testing.T, harness coordinatorHarness, value ReadRequest, bearer string) *http.Request {
	t.Helper()
	body, _ := json.Marshal(value)
	request := httptest.NewRequest(http.MethodPost, "/v1/backup-accounts/"+harness.target.AccountID.String()+"/read", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+bearer)
	setBackupHTTPAuthority(request, harness.binding, serviceauthority.TrafficBulk)
	return request
}

type httpBeginStore struct {
	faultingCoordinatorStore
	reserved UploadRecord
}

func (store *httpBeginStore) AuthorizeUploadSnapshot(
	_ context.Context,
	authorization ReadAuthorization,
	use CredentialUse,
	_ Clock,
	uploadID uuid.UUID,
) (UploadRecord, error) {
	if authorization.Validate() != nil || uploadID != store.upload.UploadID || store.upload.Committed ||
		!reflect.DeepEqual(use.Reference, store.credentialAuthority.Grant.Credential) ||
		use.AuthorizationDigest != store.credentialAuthority.Grant.AuthorizationDigest {
		return UploadRecord{}, ErrUnauthorized
	}
	return store.upload, nil
}

func (store *httpBeginStore) ListGenerationSnapshot(
	_ context.Context,
	authorization ReadAuthorization,
	use CredentialUse,
	_ Clock,
	request GenerationListRequest,
) (TargetRecord, GenerationRecord, []GenerationRecord, error) {
	if authorization.Validate() != nil || request.Validate() != nil || store.generation.ValidateStored() != nil ||
		!reflect.DeepEqual(use.Reference, store.credentialAuthority.Grant.Credential) ||
		use.AuthorizationDigest != store.credentialAuthority.Grant.AuthorizationDigest {
		return TargetRecord{}, GenerationRecord{}, nil, ErrUnauthorized
	}
	return store.target, store.generation, []GenerationRecord{store.generation}, nil
}

func (store *httpBeginStore) ReserveUpload(_ context.Context, proposed UploadRecord, use CredentialUse, _ Clock, _ serviceauthority.MutationAuthorization) (UploadRecord, bool, error) {
	if !reflect.DeepEqual(use.Reference, store.credentialAuthority.Grant.Credential) || use.AuthorizationDigest != store.credentialAuthority.Grant.AuthorizationDigest {
		return UploadRecord{}, false, ErrUnauthorized
	}
	if store.reserved.UploadID == uuid.Nil {
		store.reserved = proposed
		store.upload = proposed
		return proposed, true, nil
	}
	if !reflect.DeepEqual(store.reserved.Request, proposed.Request) || !bytes.Equal(store.reserved.RequestBytes, proposed.RequestBytes) {
		return UploadRecord{}, false, ErrConflict
	}
	return store.upload, false, nil
}

func (store *httpBeginStore) ReadSnapshot(
	_ context.Context,
	authorization ReadAuthorization,
	use CredentialUse,
	_ Clock,
	targetID uuid.UUID,
	reference string,
) (TargetRecord, GenerationRecord, error) {
	if authorization.Validate() != nil || !reflect.DeepEqual(use.Reference, store.credentialAuthority.Grant.Credential) ||
		use.AuthorizationDigest != store.credentialAuthority.Grant.AuthorizationDigest || targetID != store.target.TargetID ||
		reference != store.generation.GenerationReferenceDigest {
		return TargetRecord{}, GenerationRecord{}, ErrNotFound
	}
	return store.target, store.generation, nil
}

type httpReadNotFoundStore struct{ faultingCoordinatorStore }

func (*httpReadNotFoundStore) ReadSnapshot(context.Context, ReadAuthorization, CredentialUse, Clock, uuid.UUID, string) (TargetRecord, GenerationRecord, error) {
	return TargetRecord{}, GenerationRecord{}, ErrNotFound
}

type httpControlStore struct {
	faultingCoordinatorStore
	expected SignedControlCommand
	calls    int
}

func (store *httpControlStore) ApplyControlCommand(
	_ context.Context,
	record SignedControlCommand,
	authorization serviceauthority.MutationAuthorization,
) (ControlCommandAcceptance, error) {
	expectedBytes, _ := store.expected.CanonicalJSON()
	recordBytes, _ := record.CanonicalJSON()
	payload, _ := record.DecodedPayload()
	reference, _ := record.ReferenceDigest()
	if authorization.ValidateFor(
		serviceauthority.ScopeBackupCustody, authorization.DeploymentID(),
	) != nil || authorization.Scope().ScopeID != payload.AccountID || !bytes.Equal(expectedBytes, recordBytes) {
		return ControlCommandAcceptance{}, ErrConflict
	}
	store.calls++
	return ControlCommandAcceptance{Version: CredentialAuthorityVersion, AccountID: payload.AccountID,
		CommandID: payload.CommandID, Sequence: payload.Sequence, CommandReferenceDigest: reference,
		ControlHeadReferenceDigest: reference, ControlGeneration: payload.ControlGeneration,
		ControlKeyID: payload.ControlKeyID}, nil
}

type cancelingProvisionStore struct {
	provisioningCoordinatorStore
	cancel context.CancelFunc
}

type deadlineStalledWriter struct {
	header   http.Header
	entered  chan struct{}
	once     sync.Once
	mu       sync.Mutex
	deadline time.Time
}

func newDeadlineStalledWriter() *deadlineStalledWriter {
	return &deadlineStalledWriter{header: make(http.Header), entered: make(chan struct{})}
}

func (writer *deadlineStalledWriter) Header() http.Header { return writer.header }
func (*deadlineStalledWriter) WriteHeader(int)            {}

func (writer *deadlineStalledWriter) SetWriteDeadline(deadline time.Time) error {
	writer.mu.Lock()
	writer.deadline = deadline
	writer.mu.Unlock()
	return nil
}

func (writer *deadlineStalledWriter) Write([]byte) (int, error) {
	writer.once.Do(func() { close(writer.entered) })
	writer.mu.Lock()
	deadline := writer.deadline
	writer.mu.Unlock()
	delay := time.Until(deadline)
	if delay > 0 {
		timer := time.NewTimer(delay)
		<-timer.C
	}
	return 0, os.ErrDeadlineExceeded
}

func (store *cancelingProvisionStore) ActivateAccount(
	ctx context.Context,
	accountID uuid.UUID,
	revision uint64,
	digest string,
	deploymentID uuid.UUID,
	now int64,
) error {
	err := store.provisioningCoordinatorStore.ActivateAccount(
		ctx, accountID, revision, digest, deploymentID, now,
	)
	if err == nil && store.cancel != nil {
		store.cancel()
	}
	return err
}

var _ Store = (*httpBeginStore)(nil)
var _ Store = (*httpReadNotFoundStore)(nil)

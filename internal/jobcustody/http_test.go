package jobcustody

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/carriage"
	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
	"github.com/robreuss/FacetsNode/internal/traffic"
)

func readyJobCustodyAdmissionSnapshot() storagecapacity.CoarseReadinessSnapshot {
	return storagecapacity.CoarseReadinessSnapshot{
		ProtocolVersion: storagecapacity.AuthorityProtocolVersion,
		Revision:        1, State: storagecapacity.ReadinessReady,
		ObservedAtMilliseconds: 1,
	}
}

func TestJobCustodyHTTPAdmissionCarriageAndReceiptReplay(t *testing.T) {
	fixture := newAdmissionPermitFixture(t)
	content, _ := temporaryContentStore(t)
	resultContent, _ := temporaryContentStore(t)
	ledger := newMemoryLedger()
	coordinator := &Coordinator{
		Ledger: ledger, Content: content, Capacity: &memoryCapacityAuthority{},
		Verifier: fixture.admission.verifier, ReceiptSigner: testJobCustodyReceiptSigner(t),
		Clock: fixedJobCustodyClock{time.UnixMilli(int64(fixture.issuedAt + 1))},
	}
	admissionReadiness := readyJobCustodyAdmissionSnapshot()
	var admissionReadinessError error
	handler, err := NewHTTPHandler(
		coordinator, &WorkerClaimCoordinator{Ledger: ledger, Content: content, Clock: coordinator.Clock},
		&ResultCoordinator{
			Ledger: ledger, Content: resultContent, Capacity: &memoryCapacityAuthority{},
			ReceiptSigner: coordinator.ReceiptSigner.(ResultReceiptSigner), Clock: coordinator.Clock,
		},
		&ResultDeliveryCoordinator{
			Ledger: ledger, Content: resultContent,
			ReceiptSigner: coordinator.ReceiptSigner.(ResultReceiptSigner), Clock: coordinator.Clock,
		},
		fixture.verifier, traffic.DefaultLimits(),
		func(context.Context) error { return nil },
		func(context.Context) (storagecapacity.CoarseReadinessSnapshot, error) {
			return admissionReadiness, admissionReadinessError
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	handler.now = func() time.Time { return time.UnixMilli(int64(fixture.issuedAt + 1)) }
	server := handler.Handler()
	operationalRequest := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	operationalResponse := httptest.NewRecorder()
	server.ServeHTTP(operationalResponse, operationalRequest)
	if operationalResponse.Code != http.StatusOK || operationalResponse.Body.String() != "{\"status\":\"ready\"}\n" {
		t.Fatalf("operational readiness status=%d body=%s", operationalResponse.Code, operationalResponse.Body.String())
	}
	readinessRequest := httptest.NewRequest(http.MethodGet, "/v1/readiness", nil)
	readinessResponse := httptest.NewRecorder()
	server.ServeHTTP(readinessResponse, readinessRequest)
	if readinessResponse.Code != http.StatusOK {
		t.Fatalf("admission readiness status=%d body=%s", readinessResponse.Code, readinessResponse.Body.String())
	}
	var readiness storagecapacity.CoarseReadinessSnapshot
	decodeJobCustodyTestJSON(t, readinessResponse.Body.Bytes(), &readiness)
	if readiness != admissionReadiness {
		t.Fatalf("admission readiness=%+v", readiness)
	}
	admissionReadiness = storagecapacity.CoarseReadinessSnapshot{
		ProtocolVersion: storagecapacity.AuthorityProtocolVersion,
		Revision:        2, State: storagecapacity.ReadinessStoragePressure,
		ObservedAtMilliseconds: 2,
		RetryAfterMilliseconds: storagecapacity.DefaultReadinessRetryAfterMilliseconds,
	}
	pressureRequest := httptest.NewRequest(http.MethodGet, "/v1/readiness", nil)
	pressureResponse := httptest.NewRecorder()
	server.ServeHTTP(pressureResponse, pressureRequest)
	if pressureResponse.Code != http.StatusOK || pressureResponse.Header().Get("Retry-After") != "30" {
		t.Fatalf("pressure readiness status=%d retry=%q body=%s", pressureResponse.Code, pressureResponse.Header().Get("Retry-After"), pressureResponse.Body.String())
	}
	admissionReadinessError = ErrUnavailable
	unavailableRequest := httptest.NewRequest(http.MethodGet, "/v1/readiness", nil)
	unavailableResponse := httptest.NewRecorder()
	server.ServeHTTP(unavailableResponse, unavailableRequest)
	if unavailableResponse.Code != http.StatusServiceUnavailable ||
		unavailableResponse.Body.String() != "{\"code\":\"readiness_unavailable\"}\n" {
		t.Fatalf("unavailable readiness status=%d body=%s", unavailableResponse.Code, unavailableResponse.Body.String())
	}
	admissionReadiness = readyJobCustodyAdmissionSnapshot()
	admissionReadinessError = nil

	admission := HTTPAdmissionRequest{
		AdmissionEnvelope: fixture.admission.envelopeBytes,
		Permit:            fixture.permit,
	}
	response := serveJobCustodyJSON(t, server, http.MethodPost, "/v1/job-custody/admissions", admission)
	if response.Code != http.StatusOK {
		t.Fatalf("admission status=%d body=%s", response.Code, response.Body.String())
	}
	var admitted HTTPAdmissionStatus
	decodeJobCustodyTestJSON(t, response.Body.Bytes(), &admitted)
	if admitted.State != AdmissionStaging || admitted.CommittedBytes != 0 ||
		admitted.ProtectedByteCount != int64(len(fixture.admission.protectedBytes)) ||
		len(admitted.CustodyReceipt) != 0 {
		t.Fatalf("admission=%+v", admitted)
	}

	for index := int64(0); index < fixture.admission.header.ProtectedObject.ChunkCount; index++ {
		offset := index * fixture.admission.header.ProtectedObject.ChunkByteCount
		end := min(
			offset+fixture.admission.header.ProtectedObject.ChunkByteCount,
			int64(len(fixture.admission.protectedBytes)),
		)
		chunk := fixture.admission.protectedBytes[offset:end]
		header, err := computequeue.EncodeCanonical(HTTPChunkHeader{
			ChunkIndex: index, ChunkSHA256: digestBytes(chunk),
			Permit: fixture.permit, Version: AdmissionPermitVersion,
		})
		if err != nil {
			t.Fatal(err)
		}
		wire, err := (carriage.Frame{
			SectionKind: JobCustodyChunkSectionKind,
			Header:      header,
			Payload:     chunk,
		}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		path := fmt.Sprintf(
			"/v1/job-custody/admissions/%s/chunks/%d",
			fixture.admission.header.CapsuleID, index,
		)
		request := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(wire))
		request.Header.Set("Content-Type", JobCustodyCarriageContentType)
		chunkResponse := httptest.NewRecorder()
		server.ServeHTTP(chunkResponse, request)
		if chunkResponse.Code != http.StatusOK {
			t.Fatalf("chunk %d status=%d body=%s", index, chunkResponse.Code, chunkResponse.Body.String())
		}
	}

	authorization := HTTPAuthorizationRequest{Permit: fixture.permit}
	finalizePath := fmt.Sprintf(
		"/v1/job-custody/admissions/%s/finalize",
		fixture.admission.header.CapsuleID,
	)
	firstFinalize := serveJobCustodyJSON(t, server, http.MethodPost, finalizePath, authorization)
	if firstFinalize.Code != http.StatusOK {
		t.Fatalf("finalize status=%d body=%s", firstFinalize.Code, firstFinalize.Body.String())
	}
	var retained HTTPAdmissionStatus
	decodeJobCustodyTestJSON(t, firstFinalize.Body.Bytes(), &retained)
	if retained.State != AdmissionRetained ||
		retained.CommittedBytes != int64(len(fixture.admission.protectedBytes)) ||
		len(retained.CustodyReceipt) == 0 {
		t.Fatalf("retained=%+v", retained)
	}
	var receipt serviceauthority.JobCustodyReceipt
	decodeJobCustodyTestJSON(t, retained.CustodyReceipt, &receipt)
	payload, err := receipt.VerifiedPayload()
	if err != nil || payload.CapsuleID.String() != string(fixture.admission.header.CapsuleID) {
		t.Fatalf("receipt payload=%+v err=%v", payload, err)
	}

	secondFinalize := serveJobCustodyJSON(t, server, http.MethodPost, finalizePath, authorization)
	if secondFinalize.Code != http.StatusOK {
		t.Fatalf("finalize replay status=%d body=%s", secondFinalize.Code, secondFinalize.Body.String())
	}
	var replay HTTPAdmissionStatus
	decodeJobCustodyTestJSON(t, secondFinalize.Body.Bytes(), &replay)
	if !bytes.Equal(replay.CustodyReceipt, retained.CustodyReceipt) {
		t.Fatal("finalize replay changed the persisted custody receipt")
	}

	statusPath := fmt.Sprintf(
		"/v1/job-custody/admissions/%s/status",
		fixture.admission.header.CapsuleID,
	)
	status := serveJobCustodyJSON(t, server, http.MethodPost, statusPath, authorization)
	if status.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", status.Code, status.Body.String())
	}
	var reconciled HTTPAdmissionStatus
	decodeJobCustodyTestJSON(t, status.Body.Bytes(), &reconciled)
	if !bytes.Equal(reconciled.CustodyReceipt, retained.CustodyReceipt) {
		t.Fatal("status reconciliation did not return the durable receipt")
	}
}

func TestJobCustodyHTTPWorkerClaimsExactRetainedCapsuleAndReadsProtectedChunks(t *testing.T) {
	fixture := newAdmissionPermitFixture(t)
	content, _ := temporaryContentStore(t)
	resultContent, _ := temporaryContentStore(t)
	ledger := newMemoryLedger()
	clock := fixedJobCustodyClock{time.UnixMilli(int64(fixture.issuedAt + 1))}
	coordinator := &Coordinator{
		Ledger: ledger, Content: content, Capacity: &memoryCapacityAuthority{},
		Verifier: fixture.admission.verifier, ReceiptSigner: testJobCustodyReceiptSigner(t),
		Clock: clock,
	}
	admissionAuthorization, err := fixture.verifier.Verify(
		fixture.permit, fixture.admission.envelopeBytes, fixture.issuedAt+1,
	)
	if err != nil {
		t.Fatal(err)
	}
	admissionHandle, err := coordinator.AdmitAuthorized(
		t.Context(), fixture.admission.envelopeBytes, admissionAuthorization,
	)
	if err != nil {
		t.Fatal(err)
	}
	for index := int64(0); index < fixture.admission.header.ProtectedObject.ChunkCount; index++ {
		offset := index * fixture.admission.header.ProtectedObject.ChunkByteCount
		end := min(offset+fixture.admission.header.ProtectedObject.ChunkByteCount,
			int64(len(fixture.admission.protectedBytes)))
		chunk := fixture.admission.protectedBytes[offset:end]
		if _, err := coordinator.AppendChunk(t.Context(), admissionHandle, index, chunk, digestBytes(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := coordinator.Finalize(t.Context(), admissionHandle); err != nil {
		t.Fatal(err)
	}
	workerClaims := &WorkerClaimCoordinator{Ledger: ledger, Content: content, Clock: clock}
	handler, err := NewHTTPHandler(
		coordinator, workerClaims,
		&ResultCoordinator{
			Ledger: ledger, Content: resultContent, Capacity: &memoryCapacityAuthority{},
			ReceiptSigner: coordinator.ReceiptSigner.(ResultReceiptSigner), Clock: coordinator.Clock,
		},
		&ResultDeliveryCoordinator{
			Ledger: ledger, Content: resultContent,
			ReceiptSigner: coordinator.ReceiptSigner.(ResultReceiptSigner), Clock: coordinator.Clock,
		},
		fixture.verifier, traffic.DefaultLimits(),
		func(context.Context) error { return nil },
		func(context.Context) (storagecapacity.CoarseReadinessSnapshot, error) {
			return readyJobCustodyAdmissionSnapshot(), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	handler.now = func() time.Time { return time.UnixMilli(int64(fixture.issuedAt + 1)) }
	server := handler.Handler()
	claimID := uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
	claimPayload := WorkerClaimPermitPayload{
		AuthorityID: fixture.authorityID, ClaimID: claimID,
		ExpiresAt: fixture.issuedAt + 50_000, IssuedAt: fixture.issuedAt,
		PermitID:                     uuid.MustParse("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
		RouteRecipientKeyFingerprint: fixture.admission.header.RouteRecipientKeyFingerprint,
		RouteRecipientWorkerID:       fixture.admission.header.RouteRecipientWorkerID,
		Version:                      WorkerClaimPermitVersion,
		WorkerCapabilitiesDigest:     fixture.payload.WorkerCapabilitiesDigest,
		WorkerOwnerAuthorityDigest:   computequeue.SHA256Digest("worker-claim-http", "owner"),
	}
	claimSigner, err := NewWorkerClaimPermitSigner(fixture.authorityID, fixture.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	claimPermit, err := claimSigner.Sign(claimPayload)
	if err != nil {
		t.Fatal(err)
	}
	claimPath := fmt.Sprintf(
		"/v1/job-custody/workers/%s/claims", fixture.admission.header.RouteRecipientWorkerID,
	)
	claimed := serveJobCustodyJSON(
		t, server, http.MethodPost, claimPath, HTTPWorkerClaimRequest{Permit: claimPermit},
	)
	if claimed.Code != http.StatusOK {
		t.Fatalf("claim status=%d body=%s", claimed.Code, claimed.Body.String())
	}
	var status HTTPWorkerClaimStatus
	decodeJobCustodyTestJSON(t, claimed.Body.Bytes(), &status)
	if status.ClaimID != claimID || status.CapsuleID != fixture.admission.header.CapsuleID ||
		status.AssignmentID != fixture.admission.header.AssignmentID ||
		status.ProtectedObject != fixture.admission.header.ProtectedObject ||
		status.State != WorkerClaimClaimed {
		t.Fatalf("claim=%+v", status)
	}
	var received []byte
	for index := int64(0); index < status.ProtectedObject.ChunkCount; index++ {
		path := fmt.Sprintf("/v1/job-custody/claims/%s/chunks/%d", claimID, index)
		response := serveJobCustodyJSON(
			t, server, http.MethodPost, path, HTTPWorkerClaimRequest{Permit: claimPermit},
		)
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != JobCustodyCarriageContentType {
			t.Fatalf("chunk %d status=%d body=%s", index, response.Code, response.Body.String())
		}
		frame, err := carriage.DecodeFrame(response.Body.Bytes())
		if err != nil || frame.SectionKind != JobCustodyWorkerChunkSectionKind {
			t.Fatalf("chunk %d frame=%+v err=%v", index, frame, err)
		}
		header, err := computequeue.DecodeCanonical[HTTPWorkerChunkHeader](frame.Header)
		if err != nil || header.ClaimID != claimID || header.ChunkIndex != index ||
			header.ChunkSHA256 != digestBytes(frame.Payload) {
			t.Fatalf("chunk %d header=%+v err=%v", index, header, err)
		}
		received = append(received, frame.Payload...)
	}
	if !bytes.Equal(received, fixture.admission.protectedBytes) {
		t.Fatal("Worker did not receive exact protected capsule bytes")
	}
	renewedPayload := claimPayload
	renewedPayload.PermitID = uuid.MustParse("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
	renewedPayload.ExpiresAt = fixture.issuedAt + 70_000
	renewedPermit, err := claimSigner.Sign(renewedPayload)
	if err != nil {
		t.Fatal(err)
	}
	renewed := serveJobCustodyJSON(
		t, server, http.MethodPost,
		fmt.Sprintf("/v1/job-custody/claims/%s/renew", claimID),
		HTTPWorkerClaimRequest{Permit: renewedPermit},
	)
	if renewed.Code != http.StatusOK {
		t.Fatalf("renew status=%d body=%s", renewed.Code, renewed.Body.String())
	}
	decodeJobCustodyTestJSON(t, renewed.Body.Bytes(), &status)
	if status.LeaseExpiresAt != renewedPayload.ExpiresAt {
		t.Fatalf("renewed claim=%+v", status)
	}
	chunkAfterRenewal := serveJobCustodyJSON(
		t, server, http.MethodPost,
		fmt.Sprintf("/v1/job-custody/claims/%s/chunks/0", claimID),
		HTTPWorkerClaimRequest{Permit: renewedPermit},
	)
	if chunkAfterRenewal.Code != http.StatusOK {
		t.Fatalf("renewed chunk status=%d body=%s", chunkAfterRenewal.Code, chunkAfterRenewal.Body.String())
	}

	protectedResult := []byte("opaque-encrypted-result-over-http")
	resultDescriptor, err := computequeue.NewJobCapsuleProtectedObjectDescriptor(
		int64(len(protectedResult)), digestBytes(protectedResult), 9,
	)
	if err != nil {
		t.Fatal(err)
	}
	resultHeader, err := NewWorkerResultHeader(
		fixture.admission.header.AssignmentID,
		claimID,
		fixture.admission.header.CapsuleID,
		computequeue.JobCapsuleID("ffffffff-ffff-4fff-8fff-ffffffffffff"),
		resultDescriptor,
		computequeue.SHA256Digest("job-custody-http-tests", "result-set"),
		computequeue.SHA256Digest("job-custody-http-tests", "worker-execution-receipt"),
		fixture.admission.header.RetentionUntil,
	)
	if err != nil {
		t.Fatal(err)
	}
	resultPayload := WorkerResultPermitPayload{
		AuthorityID: fixture.authorityID, ExpiresAt: fixture.issuedAt + 60_000,
		IssuedAt: fixture.issuedAt, PermitID: uuid.MustParse("12121212-1212-4212-8212-121212121212"),
		Result:                       resultHeader,
		RouteRecipientKeyFingerprint: fixture.admission.header.RouteRecipientKeyFingerprint,
		RouteRecipientWorkerID:       fixture.admission.header.RouteRecipientWorkerID,
		Version:                      WorkerResultPermitVersion,
		WorkerCapabilitiesDigest:     fixture.payload.WorkerCapabilitiesDigest,
		WorkerOwnerAuthorityDigest:   claimPayload.WorkerOwnerAuthorityDigest,
	}
	resultSigner, err := NewWorkerResultPermitSigner(fixture.authorityID, fixture.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	resultPermit, err := resultSigner.Sign(resultPayload)
	if err != nil {
		t.Fatal(err)
	}
	resultPath := fmt.Sprintf("/v1/job-custody/claims/%s/results", claimID)
	accepted := serveJobCustodyJSON(
		t, server, http.MethodPost, resultPath, HTTPWorkerResultRequest{Permit: resultPermit},
	)
	if accepted.Code != http.StatusOK {
		t.Fatalf("result admission status=%d body=%s", accepted.Code, accepted.Body.String())
	}
	var resultStatus HTTPWorkerResultStatus
	decodeJobCustodyTestJSON(t, accepted.Body.Bytes(), &resultStatus)
	if resultStatus.State != ResultStaging || resultStatus.ResultCapsuleID != resultHeader.ResultCapsuleID ||
		resultStatus.ProtectedObject != resultDescriptor || resultStatus.CommittedBytes != 0 ||
		len(resultStatus.CustodyReceipt) != 0 {
		t.Fatalf("accepted result=%+v", resultStatus)
	}
	for index := int64(0); index < resultDescriptor.ChunkCount; index++ {
		offset := index * resultDescriptor.ChunkByteCount
		end := min(offset+resultDescriptor.ChunkByteCount, int64(len(protectedResult)))
		chunk := protectedResult[offset:end]
		headerBytes, err := computequeue.EncodeCanonical(HTTPWorkerResultChunkHeader{
			ChunkIndex: index, ChunkSHA256: digestBytes(chunk),
			Permit: resultPermit, Version: WorkerResultPermitVersion,
		})
		if err != nil {
			t.Fatal(err)
		}
		wire, err := (carriage.Frame{
			SectionKind: JobCustodyResultChunkSectionKind, Header: headerBytes, Payload: chunk,
		}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		path := fmt.Sprintf(
			"/v1/job-custody/claims/%s/results/%s/chunks/%d",
			claimID, resultHeader.ResultCapsuleID, index,
		)
		response := serveJobCustodyCarriage(t, server, http.MethodPut, path, wire)
		if response.Code != http.StatusOK {
			t.Fatalf("result chunk %d status=%d body=%s", index, response.Code, response.Body.String())
		}
	}
	finalizeResultPath := fmt.Sprintf(
		"/v1/job-custody/claims/%s/results/%s/finalize",
		claimID, resultHeader.ResultCapsuleID,
	)
	finalized := serveJobCustodyJSON(
		t, server, http.MethodPost, finalizeResultPath,
		HTTPWorkerResultRequest{Permit: resultPermit},
	)
	if finalized.Code != http.StatusOK {
		t.Fatalf("result finalize status=%d body=%s", finalized.Code, finalized.Body.String())
	}
	decodeJobCustodyTestJSON(t, finalized.Body.Bytes(), &resultStatus)
	if resultStatus.State != ResultRetained ||
		resultStatus.CommittedBytes != int64(len(protectedResult)) ||
		len(resultStatus.CustodyReceipt) == 0 {
		t.Fatalf("finalized result=%+v", resultStatus)
	}
	resultReceipt, err := serviceauthority.DecodeJobCustodyResultReceipt(resultStatus.CustodyReceipt)
	if err != nil {
		t.Fatal(err)
	}
	resultReceiptPayload, err := resultReceipt.VerifiedPayload()
	if err != nil || resultReceiptPayload.ClaimID != claimID ||
		resultReceiptPayload.ResultCapsuleID.String() != string(resultHeader.ResultCapsuleID) ||
		resultReceiptPayload.ProtectedObjectSHA256 != string(resultDescriptor.SHA256) {
		t.Fatalf("result receipt=%+v err=%v", resultReceiptPayload, err)
	}
	replayed := serveJobCustodyJSON(
		t, server, http.MethodPost, finalizeResultPath,
		HTTPWorkerResultRequest{Permit: resultPermit},
	)
	if replayed.Code != http.StatusOK {
		t.Fatalf("result finalize replay status=%d body=%s", replayed.Code, replayed.Body.String())
	}
	var replayedResult HTTPWorkerResultStatus
	decodeJobCustodyTestJSON(t, replayed.Body.Bytes(), &replayedResult)
	if !bytes.Equal(replayedResult.CustodyReceipt, resultStatus.CustodyReceipt) {
		t.Fatal("result finalize replay changed the persisted custody receipt")
	}
	retrievalPayload := ResultRetrievalPermitPayload{
		AdmissionPermitDigest: admissionAuthorization.PermitDigest(),
		AuthorityID:           fixture.authorityID, ExpiresAt: fixture.issuedAt + 60_000,
		InputCapsuleID:           fixture.admission.header.CapsuleID,
		IssuedAt:                 fixture.issuedAt,
		PermitID:                 uuid.MustParse("34343434-3434-4434-8434-343434343434"),
		RequesterAuthorityDigest: fixture.payload.RequesterAuthorityDigest,
		Version:                  ResultRetrievalPermitVersion,
	}
	retrievalSigner, err := NewResultRetrievalPermitSigner(fixture.authorityID, fixture.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	retrievalPermit, err := retrievalSigner.Sign(retrievalPayload)
	if err != nil {
		t.Fatal(err)
	}
	retrievalAuthorization, err := fixture.verifier.VerifyResultRetrieval(
		retrievalPermit, fixture.issuedAt+1,
	)
	if err != nil {
		t.Fatal(err)
	}
	resultStatusPath := fmt.Sprintf(
		"/v1/job-custody/admissions/%s/results/status",
		fixture.admission.header.CapsuleID,
	)
	listed := serveJobCustodyJSON(
		t, server, http.MethodPost, resultStatusPath,
		HTTPResultRetrievalRequest{Permit: retrievalPermit},
	)
	if listed.Code != http.StatusOK {
		t.Fatalf("result list status=%d body=%s", listed.Code, listed.Body.String())
	}
	var listStatus HTTPResultListStatus
	decodeJobCustodyTestJSON(t, listed.Body.Bytes(), &listStatus)
	if len(listStatus.Results) != 1 ||
		listStatus.Results[0].ResultCapsuleID != resultHeader.ResultCapsuleID ||
		!bytes.Equal(listStatus.Results[0].CustodyReceipt, resultStatus.CustodyReceipt) {
		t.Fatalf("result list=%+v", listStatus)
	}
	var deliveredResult []byte
	for index := int64(0); index < resultDescriptor.ChunkCount; index++ {
		path := fmt.Sprintf(
			"/v1/job-custody/admissions/%s/results/%s/chunks/%d",
			fixture.admission.header.CapsuleID, resultHeader.ResultCapsuleID, index,
		)
		response := serveJobCustodyJSON(
			t, server, http.MethodPost, path,
			HTTPResultRetrievalRequest{Permit: retrievalPermit},
		)
		if response.Code != http.StatusOK ||
			response.Header().Get("Content-Type") != JobCustodyCarriageContentType {
			t.Fatalf("delivery chunk %d status=%d body=%s", index, response.Code, response.Body.String())
		}
		frame, err := carriage.DecodeFrame(response.Body.Bytes())
		if err != nil || frame.SectionKind != JobCustodyResultDeliveryChunkSectionKind {
			t.Fatalf("delivery chunk %d frame=%+v err=%v", index, frame, err)
		}
		header, err := computequeue.DecodeCanonical[HTTPResultDeliveryChunkHeader](frame.Header)
		if err != nil || header.Validate() != nil || header.ChunkIndex != index ||
			header.InputCapsuleID != fixture.admission.header.CapsuleID ||
			header.ResultCapsuleID != resultHeader.ResultCapsuleID ||
			header.RetrievalPermitDigest != retrievalAuthorization.PermitDigest() ||
			header.ChunkSHA256 != digestBytes(frame.Payload) {
			t.Fatalf("delivery chunk %d header=%+v err=%v", index, header, err)
		}
		deliveredResult = append(deliveredResult, frame.Payload...)
	}
	if !bytes.Equal(deliveredResult, protectedResult) {
		t.Fatal("source did not receive exact protected result bytes over HTTP")
	}
	custodyReceiptDigest, err := resultReceipt.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	mutationSigner, err := NewResultMutationPermitSigner(fixture.authorityID, fixture.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	mutationPayload := ResultMutationPermitPayload{
		Action:                        ResultMutationAcknowledgeDelivery,
		AdmissionPermitDigest:         admissionAuthorization.PermitDigest(),
		AuthorityID:                   fixture.authorityID,
		ExpiresAt:                     fixture.issuedAt + 60_000,
		InputCapsuleID:                fixture.admission.header.CapsuleID,
		IssuedAt:                      fixture.issuedAt,
		PermitID:                      uuid.MustParse("67676767-6767-4767-8767-676767676767"),
		RequesterAuthorityDigest:      fixture.payload.RequesterAuthorityDigest,
		ResultCapsuleID:               resultHeader.ResultCapsuleID,
		ResultCustodyReceiptDigest:    computequeue.Digest(custodyReceiptDigest),
		ResultSetDigest:               resultHeader.ResultSetDigest,
		SourceTransitionReceiptDigest: computequeue.SHA256Digest("job-custody-http-tests", "source-delivery-receipt"),
		Version:                       ResultMutationPermitVersion,
	}
	acknowledgementPermit, err := mutationSigner.Sign(mutationPayload)
	if err != nil {
		t.Fatal(err)
	}
	acknowledgementPath := fmt.Sprintf(
		"/v1/job-custody/admissions/%s/results/%s/acknowledgement",
		fixture.admission.header.CapsuleID, resultHeader.ResultCapsuleID,
	)
	acknowledged := serveJobCustodyJSON(
		t, server, http.MethodPost, acknowledgementPath,
		HTTPResultMutationRequest{Permit: acknowledgementPermit},
	)
	if acknowledged.Code != http.StatusOK {
		t.Fatalf("result acknowledgement status=%d body=%s", acknowledged.Code, acknowledged.Body.String())
	}
	decodeJobCustodyTestJSON(t, acknowledged.Body.Bytes(), &resultStatus)
	if resultStatus.State != ResultDelivered || resultStatus.DeliveryAcknowledgedAt == nil ||
		len(resultStatus.ReleaseReceipt) != 0 {
		t.Fatalf("acknowledged result=%+v", resultStatus)
	}
	mutationPayload.Action = ResultMutationReleaseCustody
	mutationPayload.PermitID = uuid.MustParse("78787878-7878-4787-8787-787878787878")
	mutationPayload.SourceTransitionReceiptDigest = computequeue.SHA256Digest(
		"job-custody-http-tests", "source-release-receipt",
	)
	releasePermit, err := mutationSigner.Sign(mutationPayload)
	if err != nil {
		t.Fatal(err)
	}
	releasePath := fmt.Sprintf(
		"/v1/job-custody/admissions/%s/results/%s/release",
		fixture.admission.header.CapsuleID, resultHeader.ResultCapsuleID,
	)
	released := serveJobCustodyJSON(
		t, server, http.MethodPost, releasePath, HTTPResultMutationRequest{Permit: releasePermit},
	)
	if released.Code != http.StatusOK {
		t.Fatalf("result release status=%d body=%s", released.Code, released.Body.String())
	}
	decodeJobCustodyTestJSON(t, released.Body.Bytes(), &resultStatus)
	if resultStatus.State != ResultReleased || resultStatus.ReleaseRequestedAt == nil ||
		len(resultStatus.ReleaseReceipt) == 0 {
		t.Fatalf("released result=%+v", resultStatus)
	}
	if _, err := serviceauthority.DecodeJobCustodyResultReleaseReceipt(resultStatus.ReleaseReceipt); err != nil {
		t.Fatal(err)
	}
	replayedRelease := serveJobCustodyJSON(
		t, server, http.MethodPost, releasePath, HTTPResultMutationRequest{Permit: releasePermit},
	)
	if replayedRelease.Code != http.StatusOK {
		t.Fatalf("result release replay status=%d body=%s", replayedRelease.Code, replayedRelease.Body.String())
	}
	var replayedReleaseStatus HTTPWorkerResultStatus
	decodeJobCustodyTestJSON(t, replayedRelease.Body.Bytes(), &replayedReleaseStatus)
	if !bytes.Equal(replayedReleaseStatus.ReleaseReceipt, resultStatus.ReleaseReceipt) {
		t.Fatal("result release replay changed the signed release receipt")
	}
	releasedChunkPath := fmt.Sprintf(
		"/v1/job-custody/admissions/%s/results/%s/chunks/0",
		fixture.admission.header.CapsuleID, resultHeader.ResultCapsuleID,
	)
	releasedChunk := serveJobCustodyJSON(
		t, server, http.MethodPost, releasedChunkPath,
		HTTPResultRetrievalRequest{Permit: retrievalPermit},
	)
	if releasedChunk.Code != http.StatusConflict {
		t.Fatalf("released result remained downloadable: status=%d body=%s", releasedChunk.Code, releasedChunk.Body.String())
	}
	wrongSourcePayload := retrievalPayload
	wrongSourcePayload.PermitID = uuid.MustParse("56565656-5656-4656-8656-565656565656")
	wrongSourcePayload.RequesterAuthorityDigest = computequeue.SHA256Digest(
		"job-custody-http-tests", "wrong-source-authority",
	)
	wrongSourcePermit, err := retrievalSigner.Sign(wrongSourcePayload)
	if err != nil {
		t.Fatal(err)
	}
	wrongSource := serveJobCustodyJSON(
		t, server, http.MethodPost, resultStatusPath,
		HTTPResultRetrievalRequest{Permit: wrongSourcePermit},
	)
	if wrongSource.Code != http.StatusConflict {
		t.Fatalf("wrong source status=%d body=%s", wrongSource.Code, wrongSource.Body.String())
	}
}

func TestJobCustodyHTTPRejectsPermitAndCarriageSubstitution(t *testing.T) {
	fixture := newAdmissionPermitFixture(t)
	content, _ := temporaryContentStore(t)
	resultContent, _ := temporaryContentStore(t)
	ledger := newMemoryLedger()
	coordinator := &Coordinator{
		Ledger: ledger, Content: content, Capacity: &memoryCapacityAuthority{},
		Verifier: fixture.admission.verifier, ReceiptSigner: testJobCustodyReceiptSigner(t),
		Clock: fixedJobCustodyClock{time.UnixMilli(int64(fixture.issuedAt + 1))},
	}
	handler, err := NewHTTPHandler(
		coordinator, &WorkerClaimCoordinator{Ledger: ledger, Content: content, Clock: coordinator.Clock},
		&ResultCoordinator{
			Ledger: ledger, Content: resultContent, Capacity: &memoryCapacityAuthority{},
			ReceiptSigner: coordinator.ReceiptSigner.(ResultReceiptSigner), Clock: coordinator.Clock,
		},
		&ResultDeliveryCoordinator{
			Ledger: ledger, Content: resultContent,
			ReceiptSigner: coordinator.ReceiptSigner.(ResultReceiptSigner), Clock: coordinator.Clock,
		},
		fixture.verifier, traffic.DefaultLimits(),
		func(context.Context) error { return nil },
		func(context.Context) (storagecapacity.CoarseReadinessSnapshot, error) {
			return readyJobCustodyAdmissionSnapshot(), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	handler.now = func() time.Time { return time.UnixMilli(int64(fixture.issuedAt + 1)) }
	server := handler.Handler()
	admission := HTTPAdmissionRequest{
		AdmissionEnvelope: fixture.admission.envelopeBytes, Permit: fixture.permit,
	}
	if response := serveJobCustodyJSON(t, server, http.MethodPost, "/v1/job-custody/admissions", admission); response.Code != http.StatusOK {
		t.Fatalf("admission status=%d", response.Code)
	}

	other := newAdmissionPermitFixture(t)
	wrongPermit := serveJobCustodyJSON(
		t, server, http.MethodPost,
		fmt.Sprintf("/v1/job-custody/admissions/%s/status", fixture.admission.header.CapsuleID),
		HTTPAuthorizationRequest{Permit: other.permit},
	)
	if wrongPermit.Code != http.StatusUnauthorized {
		t.Fatalf("wrong permit status=%d body=%s", wrongPermit.Code, wrongPermit.Body.String())
	}

	chunk := fixture.admission.protectedBytes[:fixture.admission.header.ProtectedObject.ChunkByteCount]
	header, err := computequeue.EncodeCanonical(HTTPChunkHeader{
		ChunkIndex: 1, ChunkSHA256: digestBytes(chunk),
		Permit: fixture.permit, Version: AdmissionPermitVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := (carriage.Frame{
		SectionKind: JobCustodyChunkSectionKind, Header: header, Payload: chunk,
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf(
		"/v1/job-custody/admissions/%s/chunks/0",
		fixture.admission.header.CapsuleID,
	)
	request := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(wire))
	request.Header.Set("Content-Type", JobCustodyCarriageContentType)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("substituted chunk index status=%d body=%s", response.Code, response.Body.String())
	}
}

func serveJobCustodyJSON(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	value any,
) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func serveJobCustodyCarriage(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	body []byte,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", JobCustodyCarriageContentType)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func decodeJobCustodyTestJSON(t *testing.T, input []byte, target any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatal(err)
	}
}

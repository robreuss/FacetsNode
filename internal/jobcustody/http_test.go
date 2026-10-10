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

	"github.com/robreuss/FacetsNode/internal/carriage"
	"github.com/robreuss/FacetsNode/internal/computequeue"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/traffic"
)

func TestJobCustodyHTTPAdmissionCarriageAndReceiptReplay(t *testing.T) {
	fixture := newAdmissionPermitFixture(t)
	content, _ := temporaryContentStore(t)
	coordinator := &Coordinator{
		Ledger: newMemoryLedger(), Content: content, Capacity: &memoryCapacityAuthority{},
		Verifier: fixture.admission.verifier, ReceiptSigner: testJobCustodyReceiptSigner(t),
		Clock: fixedJobCustodyClock{time.UnixMilli(int64(fixture.issuedAt + 1))},
	}
	handler, err := NewHTTPHandler(
		coordinator, fixture.verifier, traffic.DefaultLimits(),
		func(context.Context) error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	handler.now = func() time.Time { return time.UnixMilli(int64(fixture.issuedAt + 1)) }
	server := handler.Handler()

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

func TestJobCustodyHTTPRejectsPermitAndCarriageSubstitution(t *testing.T) {
	fixture := newAdmissionPermitFixture(t)
	content, _ := temporaryContentStore(t)
	coordinator := &Coordinator{
		Ledger: newMemoryLedger(), Content: content, Capacity: &memoryCapacityAuthority{},
		Verifier: fixture.admission.verifier, ReceiptSigner: testJobCustodyReceiptSigner(t),
		Clock: fixedJobCustodyClock{time.UnixMilli(int64(fixture.issuedAt + 1))},
	}
	handler, err := NewHTTPHandler(
		coordinator, fixture.verifier, traffic.DefaultLimits(),
		func(context.Context) error { return nil },
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

func decodeJobCustodyTestJSON(t *testing.T, input []byte, target any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatal(err)
	}
}

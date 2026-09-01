package backupcustody

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type portableFixture struct {
	DownloadRangeResourceID         string `json:"downloadRangeResourceID"`
	GenerationReferenceDigest       string `json:"generationReferenceDigest"`
	OuterEnvelopeBase64URL          string `json:"outerEnvelopeBase64URL"`
	PayloadCanonicalBase64URL       string `json:"payloadCanonicalBase64URL"`
	ReceiptCanonicalBase64URL       string `json:"receiptCanonicalBase64URL"`
	ReceiptReferenceDigest          string `json:"receiptReferenceDigest"`
	TargetCredentialReferenceDigest string `json:"targetCredentialReferenceDigest"`
	UploadChunkResourceID           string `json:"uploadChunkResourceID"`
}

func TestPortableFixtureComputesExactOpaqueGenerationAndReceipt(t *testing.T) {
	fixture := loadPortableFixture(t)
	outer, err := base64.RawURLEncoding.Strict().DecodeString(fixture.OuterEnvelopeBase64URL)
	if err != nil {
		t.Fatal(err)
	}
	credential := testCredential(Publish, Read, RetentionProof)
	request := PublishRequest{
		Credential: credential, Generation: 1,
		RequestID:               uuid.MustParse("70000000-0000-4000-8000-000000000001"),
		RequestedAtMilliseconds: 1_000, Version: Version,
	}
	record, err := ComputeGenerationRecord(
		request,
		uuid.MustParse("40000000-0000-4000-8000-000000000001"),
		outer,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	wantReference, err := record.ReferenceDigest()
	if err != nil || wantReference != fixture.GenerationReferenceDigest {
		t.Fatalf("generation reference=%s err=%v", wantReference, err)
	}
	outerDigest := sha256.Sum256(outer)
	if record.OuterByteCount != uint64(len(outer)) ||
		record.OuterDigest != base64.RawURLEncoding.EncodeToString(outerDigest[:]) {
		t.Fatal("generation did not bind exact accepted bytes")
	}
	receiptBytes, err := base64.RawURLEncoding.Strict().DecodeString(fixture.ReceiptCanonicalBase64URL)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := serviceauthority.DecodeBackupCustodyReceipt(receiptBytes)
	if err != nil {
		t.Fatal(err)
	}
	payloadBytes, err := base64.RawURLEncoding.Strict().DecodeString(fixture.PayloadCanonicalBase64URL)
	if err != nil || !bytes.Equal(receipt.Payload, payloadBytes) {
		t.Fatal("receipt payload bytes drifted")
	}
	payload, err := receipt.VerifiedPayload()
	if err != nil || payload.Generation != record {
		t.Fatalf("receipt generation mismatch: %v", err)
	}
	reference, err := receipt.ReferenceDigest()
	if err != nil || reference != fixture.ReceiptReferenceDigest {
		t.Fatalf("receipt reference=%s err=%v", reference, err)
	}
	portableCredential := TargetCredentialReference{
		Version: Version, AccountID: record.AccountID, TargetID: record.TargetID,
		BackupSetID: record.BackupSetID, CredentialID: payload.CredentialID,
		RequestNonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)),
		Capabilities: []Capability{Publish}, ExpiresAtMilliseconds: payload.IssuedAtMilliseconds + 1,
	}
	credentialReference, err := portableCredential.ReferenceDigest()
	if err != nil || credentialReference != fixture.TargetCredentialReferenceDigest {
		t.Fatalf("credential reference=%s err=%v", credentialReference, err)
	}
	uploadResource, err := UploadChunkResourceID(portableCredential, record.UploadID, 64, 1024)
	if err != nil || uploadResource != fixture.UploadChunkResourceID {
		t.Fatalf("upload resource=%s err=%v", uploadResource, err)
	}
	downloadResource, err := DownloadRangeResourceID(portableCredential, fixture.GenerationReferenceDigest, 64, 1024)
	if err != nil || downloadResource != fixture.DownloadRangeResourceID {
		t.Fatalf("download resource=%s err=%v", downloadResource, err)
	}
	parsed, err := ParseBackupBulkResourceID(downloadResource)
	if err != nil || parsed.Direction != serviceauthority.BulkDownload || parsed.Offset != 64 || parsed.ByteCount != 1024 ||
		parsed.GenerationReferenceDigest != fixture.GenerationReferenceDigest {
		t.Fatalf("parsed download resource=%+v err=%v", parsed, err)
	}
	item := GenerationListItem{GenerationReferenceDigest: fixture.GenerationReferenceDigest, CustodyReceipt: receipt}
	page := GenerationListPage{Version: Version, RequestID: uuid.New(), AfterGeneration: 0,
		SnapshotHeadReferenceDigest: fixture.GenerationReferenceDigest,
		SnapshotHeadCustodyReceipt:  receipt, Items: []GenerationListItem{item}}
	pageBytes := mustJSON(t, page)
	if decoded, err := DecodeGenerationListPage(pageBytes); err != nil || decoded.Validate() != nil {
		t.Fatalf("generation page rejected: %v", err)
	}
	if _, err := DecodeGenerationListPage(bytes.Repeat([]byte{'x'}, MaximumGenerationPageByteCount+1)); err == nil {
		t.Fatal("oversized generation page accepted")
	}
}

func TestGenerationPagesPinThreeGenerationSnapshotAndRejectDiscontinuity(t *testing.T) {
	credential := testCredential(Read)
	enrollment, signer := fixtureBackupEnrollmentAndSigner(t, credential.AccountID)
	manifestReference, err := enrollment.Manifest.ReferenceDigest()
	if err != nil {
		t.Fatal(err)
	}
	authority := serviceauthority.BackupCustodyAuthorityContext{
		Scope:             serviceauthority.Scope{Kind: serviceauthority.ScopeBackupCustody, ScopeID: credential.AccountID},
		AuthorityRevision: 1, AuthorityManifestDigest: manifestReference, DeploymentID: signer.DeploymentID(),
	}
	makeItem := func(generation uint64, predecessor *string, targetID uuid.UUID) GenerationListItem {
		t.Helper()
		record := serviceauthority.BackupCustodyGenerationRecord{
			Version: Version, AccountID: credential.AccountID, TargetID: targetID,
			BackupSetID: credential.BackupSetID, Generation: generation, UploadID: uuid.New(),
			PredecessorReferenceDigest: predecessor,
			OuterDigest:                base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(generation)}, 32)),
			OuterByteCount:             1024 + generation,
		}
		reference, err := record.ReferenceDigest()
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := signer.SignBackupCustodyReceipt(serviceauthority.BackupCustodyReceiptPayload{
			Version: serviceauthority.BackupCustodyReceiptVersion, ReceiptID: uuid.New(), RequestID: uuid.New(),
			CredentialID: credential.CredentialID, Kind: serviceauthority.BackupCustodyCommittedKind,
			IssuedAtMilliseconds: 1_000 + int64(generation), Generation: record, Authority: authority,
			CredentialGrantReferenceDigest: strings.Repeat("a", 64),
			ControlHeadReferenceDigest:     strings.Repeat("b", 64),
		})
		if err != nil {
			t.Fatal(err)
		}
		return GenerationListItem{GenerationReferenceDigest: reference, CustodyReceipt: receipt}
	}

	first := makeItem(1, nil, credential.TargetID)
	second := makeItem(2, &first.GenerationReferenceDigest, credential.TargetID)
	third := makeItem(3, &second.GenerationReferenceDigest, credential.TargetID)
	fourth := makeItem(4, &third.GenerationReferenceDigest, credential.TargetID)
	firstRequest := GenerationListRequest{Version: Version, RequestID: uuid.New(), Credential: credential,
		AfterGeneration: 0, PageCount: 2, RequestedAtMilliseconds: 1_000}
	firstPage := GenerationListPage{Version: Version, RequestID: firstRequest.RequestID, AfterGeneration: 0,
		SnapshotHeadReferenceDigest: third.GenerationReferenceDigest,
		SnapshotHeadCustodyReceipt:  third.CustodyReceipt, Items: []GenerationListItem{first, second}}
	if err := firstPage.ValidateResponse(firstRequest); err != nil {
		t.Fatalf("first pinned page rejected: %v", err)
	}
	secondRequest := GenerationListRequest{Version: Version, RequestID: uuid.New(), Credential: credential,
		AfterGeneration: 2, AfterGenerationReferenceDigest: &second.GenerationReferenceDigest,
		SnapshotHeadReferenceDigest: &third.GenerationReferenceDigest, PageCount: 2, RequestedAtMilliseconds: 1_000}
	secondPage := GenerationListPage{Version: Version, RequestID: secondRequest.RequestID, AfterGeneration: 2,
		AfterGenerationReferenceDigest: &second.GenerationReferenceDigest,
		SnapshotHeadReferenceDigest:    third.GenerationReferenceDigest,
		SnapshotHeadCustodyReceipt:     third.CustodyReceipt, Items: []GenerationListItem{third}}
	if err := secondPage.ValidateResponse(secondRequest); err != nil {
		t.Fatalf("successor pinned page rejected: %v", err)
	}

	// A valid fourth generation may become the service's current head after page
	// one, but it cannot replace the head pinned by the successor request.
	advancedPage := secondPage
	advancedPage.SnapshotHeadReferenceDigest = fourth.GenerationReferenceDigest
	advancedPage.SnapshotHeadCustodyReceipt = fourth.CustodyReceipt
	if advancedPage.Validate() != nil {
		t.Fatal("internally valid advanced page fixture rejected")
	}
	if advancedPage.ValidateResponse(secondRequest) == nil {
		t.Fatal("concurrent current-head advance replaced pinned snapshot")
	}

	wrongPredecessor := secondRequest
	wrongPredecessor.AfterGenerationReferenceDigest = &first.GenerationReferenceDigest
	if secondPage.ValidateResponse(wrongPredecessor) == nil {
		t.Fatal("wrong successor predecessor accepted")
	}
	wrongHead := secondRequest
	wrongHead.SnapshotHeadReferenceDigest = &fourth.GenerationReferenceDigest
	if secondPage.ValidateResponse(wrongHead) == nil {
		t.Fatal("wrong successor head accepted")
	}
	omitted := firstPage
	omitted.Items = []GenerationListItem{first}
	if omitted.Validate() != nil || omitted.ValidateResponse(firstRequest) == nil {
		t.Fatal("premature partial page was not distinguished from completion")
	}
	gapped := firstPage
	gapped.Items = []GenerationListItem{first, third}
	if gapped.Validate() == nil {
		t.Fatal("gapped page accepted")
	}
	reordered := firstPage
	reordered.Items = []GenerationListItem{second, first}
	if reordered.Validate() == nil {
		t.Fatal("reordered page accepted")
	}
	foreignSecond := makeItem(2, &first.GenerationReferenceDigest, uuid.New())
	mixed := firstPage
	mixed.Items = []GenerationListItem{first, foreignSecond}
	if mixed.Validate() == nil {
		t.Fatal("mixed target chain accepted")
	}
}

func TestGenerationCASBindsRecordHeadAndOuterPredecessor(t *testing.T) {
	fixture := loadPortableFixture(t)
	outer, err := base64.RawURLEncoding.Strict().DecodeString(fixture.OuterEnvelopeBase64URL)
	if err != nil {
		t.Fatal(err)
	}
	credential := testCredential(Publish)
	first, err := ComputeGenerationRecord(PublishRequest{
		Credential: credential, Generation: 1, RequestID: uuid.New(),
		RequestedAtMilliseconds: 1_000, Version: Version,
	}, uuid.New(), outer, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstReference, _ := first.ReferenceDigest()
	successorOuter := rewriteOuterHeader(t, outer, 2, &first.OuterDigest)
	successorRequest := PublishRequest{
		Credential: credential, ExpectedHeadReferenceDigest: &firstReference,
		Generation: 2, RequestID: uuid.New(), RequestedAtMilliseconds: 1_000,
		Version: Version,
	}
	second, err := ComputeGenerationRecord(successorRequest, uuid.New(), successorOuter, &first)
	if err != nil || second.ValidateSuccessor(first) != nil {
		t.Fatalf("valid successor rejected: %v", err)
	}

	wrongHead := strings.Repeat("a", 64)
	successorRequest.ExpectedHeadReferenceDigest = &wrongHead
	if _, err := ComputeGenerationRecord(successorRequest, uuid.New(), successorOuter, &first); err == nil {
		t.Fatal("stale/wrong CAS head accepted")
	}
	successorRequest.ExpectedHeadReferenceDigest = &firstReference
	wrongOuterDigest := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	wrongOuter := rewriteOuterHeader(t, outer, 2, &wrongOuterDigest)
	if _, err := ComputeGenerationRecord(successorRequest, uuid.New(), wrongOuter, &first); err == nil {
		t.Fatal("outer predecessor diverged from accepted head")
	}
	if _, err := ComputeGenerationRecord(successorRequest, uuid.New(), successorOuter[:len(successorOuter)-1], &first); err == nil {
		t.Fatal("truncated outer accepted")
	}

	otherSet := credential
	otherSet.BackupSetID = uuid.New()
	request := successorRequest
	request.Credential = otherSet
	if _, err := ComputeGenerationRecord(request, uuid.New(), successorOuter, &first); err == nil {
		t.Fatal("target Backup set rebind accepted")
	}
}

func TestAuthorizationTypesAndStrictCanonicalRequestDecoding(t *testing.T) {
	credential := testCredential(Read)
	read := ReadRequest{
		Credential: credential, RequestID: uuid.New(),
		GenerationReferenceDigest: strings.Repeat("a", 64), MaximumByteCount: MaximumRangeByteCount,
		RangeOffset: 0, RequestedAtMilliseconds: 1_000, Version: Version,
	}
	if read.Validate() != nil {
		t.Fatal("read capability rejected")
	}
	read.MaximumByteCount = MaximumRangeByteCount + 1
	if read.Validate() == nil {
		t.Fatal("oversized range accepted")
	}
	read.MaximumByteCount = MaximumRangeByteCount
	publish := PublishRequest{
		Credential: credential, Generation: 1, RequestID: uuid.New(),
		RequestedAtMilliseconds: 1_000, Version: Version,
	}
	if publish.Validate() == nil {
		t.Fatal("read credential admitted publish")
	}
	retention := RetentionProofRequest{
		Credential:                         testCredential(RetentionProof),
		CustodyReceiptReferenceDigest:      strings.Repeat("a", 64),
		GenerationReferenceDigest:          strings.Repeat("b", 64),
		MinimumRetainedThroughMilliseconds: 2_000,
		RequestID:                          uuid.New(), RequestedAtMilliseconds: 1_000, Version: Version,
	}
	if retention.Validate() != nil {
		t.Fatal("retention threshold request rejected")
	}
	retention.MinimumRetainedThroughMilliseconds = 999
	if retention.Validate() == nil {
		t.Fatal("retention threshold before descriptive request time accepted")
	}

	canonical := mustJSON(t, read)
	if _, err := DecodeReadRequest(canonical); err != nil {
		t.Fatalf("canonical read rejected: %v", err)
	}
	unknown := bytes.Replace(canonical, []byte(`{"credential":`), []byte(`{"extra":1,"credential":`), 1)
	if _, err := DecodeReadRequest(unknown); err == nil {
		t.Fatal("unknown request field accepted")
	}
	duplicate := bytes.Replace(
		canonical,
		[]byte(`{"credential":`),
		[]byte(`{"credential":`+string(mustJSON(t, credential))+`,"credential":`),
		1,
	)
	if _, err := DecodeReadRequest(duplicate); err == nil {
		t.Fatal("duplicate request field accepted")
	}
	noncanonical := append(append([]byte(nil), canonical...), '\n')
	if _, err := DecodeReadRequest(noncanonical); err == nil {
		t.Fatal("noncanonical request accepted")
	}

	list := GenerationListRequest{Version: Version, RequestID: uuid.New(), Credential: credential,
		AfterGeneration: 0, PageCount: MaximumGenerationPageCount, RequestedAtMilliseconds: 1_000}
	if list.Validate() != nil {
		t.Fatal("initial generation page request rejected")
	}
	list.AfterGeneration = 1
	if list.Validate() == nil {
		t.Fatal("unpinned successor generation page accepted")
	}
	afterReference, headReference := strings.Repeat("b", 64), strings.Repeat("c", 64)
	list.AfterGenerationReferenceDigest = &afterReference
	list.SnapshotHeadReferenceDigest = &headReference
	if list.Validate() != nil {
		t.Fatal("exact predecessor/head-pinned successor page rejected")
	}
	resource, err := DownloadRangeResourceID(credential, strings.Repeat("d", 64), 9, 17)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseBackupBulkResourceID(resource)
	if err != nil || parsed.Direction != serviceauthority.BulkDownload || parsed.Offset != 9 || parsed.ByteCount != 17 {
		t.Fatalf("bulk resource=%+v err=%v", parsed, err)
	}
	if _, err := ParseBackupBulkResourceID(strings.Replace(resource, strings.Repeat("d", 64), strings.Repeat("D", 64), 1)); err == nil {
		t.Fatal("noncanonical bulk resource digest accepted")
	}
	if _, err := ParseBackupBulkResourceID(strings.Replace(resource, ":9:17", ":09:17", 1)); err == nil {
		t.Fatal("noncanonical bulk resource offset accepted")
	}
	if _, err := DownloadRangeResourceID(credential, strings.Repeat("d", 64), 0, MaximumRangeByteCount+1); err == nil {
		t.Fatal("oversized bulk resource accepted")
	}

	admission := AccountAdmissionReference{
		AccountID: credential.AccountID, AdmissionID: uuid.New(),
		ExpiresAtMilliseconds: 10_000,
		RequestNonce:          base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)),
		Version:               Version,
	}
	if _, err := DecodeAccountAdmissionReference(mustJSON(t, admission)); err != nil {
		t.Fatalf("canonical admission rejected: %v", err)
	}
	if _, err := DecodeTargetCredentialReference(mustJSON(t, credential)); err != nil {
		t.Fatalf("canonical credential rejected: %v", err)
	}
	validPublish := PublishRequest{
		Credential: testCredential(Publish), Generation: 1,
		RequestID: uuid.New(), RequestedAtMilliseconds: 1_000, Version: Version,
	}
	if _, err := DecodePublishRequest(mustJSON(t, validPublish)); err != nil {
		t.Fatalf("canonical publish rejected: %v", err)
	}
	retention.MinimumRetainedThroughMilliseconds = 2_000
	if _, err := DecodeRetentionProofRequest(mustJSON(t, retention)); err != nil {
		t.Fatalf("canonical retention request rejected: %v", err)
	}
}

func TestPortableFixtureContainsNoSemanticOrParticipantMetadata(t *testing.T) {
	fixture := loadPortableFixture(t)
	receipt, err := base64.RawURLEncoding.Strict().DecodeString(fixture.ReceiptCanonicalBase64URL)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(receipt))
	for _, forbidden := range []string{
		"spaceid", "title", "participant", "recipient", "recovery",
		"capture", "semantic", "filename", "path", "url",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("portable custody fixture exposes %q", forbidden)
		}
	}
}

func testCredential(capabilities ...Capability) TargetCredentialReference {
	return TargetCredentialReference{
		AccountID:             uuid.MustParse("20000000-0000-4000-8000-000000000001"),
		BackupSetID:           uuid.MustParse("10000000-0000-4000-8000-000000000001"),
		Capabilities:          capabilities,
		CredentialID:          uuid.MustParse("50000000-0000-4000-8000-000000000001"),
		ExpiresAtMilliseconds: 10_000,
		RequestNonce:          base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)),
		TargetID:              uuid.MustParse("30000000-0000-4000-8000-000000000001"),
		Version:               Version,
	}
}

func loadPortableFixture(t *testing.T) portableFixture {
	t.Helper()
	input, err := os.ReadFile(filepath.Join("testdata", "backup-custody-portable-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture portableFixture
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func rewriteOuterHeader(t *testing.T, input []byte, generation uint64, predecessor *string) []byte {
	t.Helper()
	headerStart := len(outerMagic) + 4
	headerCount := int(binary.BigEndian.Uint32(input[len(outerMagic):headerStart]))
	var header backupOuterHeader
	if err := json.Unmarshal(input[headerStart:headerStart+headerCount], &header); err != nil {
		t.Fatal(err)
	}
	header.Generation = generation
	header.PredecessorOuterDigest = predecessor
	encoded := mustJSON(t, header)
	result := append([]byte(nil), input[:len(outerMagic)]...)
	count := make([]byte, 4)
	binary.BigEndian.PutUint32(count, uint32(len(encoded)))
	result = append(result, count...)
	result = append(result, encoded...)
	result = append(result, input[headerStart+headerCount:]...)
	return result
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

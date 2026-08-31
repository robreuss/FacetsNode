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
	GenerationReferenceDigest string `json:"generationReferenceDigest"`
	OuterEnvelopeBase64URL    string `json:"outerEnvelopeBase64URL"`
	PayloadCanonicalBase64URL string `json:"payloadCanonicalBase64URL"`
	ReceiptCanonicalBase64URL string `json:"receiptCanonicalBase64URL"`
	ReceiptReferenceDigest    string `json:"receiptReferenceDigest"`
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
		RequestedAtMilliseconds: 1_000, Version: Version,
	}
	if read.Validate() != nil {
		t.Fatal("read capability rejected")
	}
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

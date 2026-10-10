package computequeue

import "fmt"

const (
	MaximumJobCustodyProtectedBytes int64 = 1 << 40
	MaximumJobCustodyChunkBytes     int64 = 8 * 1024 * 1024
)

// JobCapsuleProtectedObjectDescriptor describes the exact opaque bytes Job
// Custody may store. It deliberately contains no plaintext Job semantics.
type JobCapsuleProtectedObjectDescriptor struct {
	ByteCount      int64  `json:"byteCount"`
	SHA256         Digest `json:"sha256"`
	ChunkByteCount int64  `json:"chunkByteCount"`
	ChunkCount     int64  `json:"chunkCount"`
}

func NewJobCapsuleProtectedObjectDescriptor(
	byteCount int64,
	sha256 Digest,
	chunkByteCount int64,
) (JobCapsuleProtectedObjectDescriptor, error) {
	if byteCount <= 0 || chunkByteCount <= 0 {
		return JobCapsuleProtectedObjectDescriptor{}, invalid("protectedObject.geometry")
	}
	value := JobCapsuleProtectedObjectDescriptor{
		ByteCount:      byteCount,
		SHA256:         sha256,
		ChunkByteCount: chunkByteCount,
		ChunkCount:     ((byteCount - 1) / chunkByteCount) + 1,
	}
	if err := value.Validate(); err != nil {
		return JobCapsuleProtectedObjectDescriptor{}, err
	}
	return value, nil
}

func (value JobCapsuleProtectedObjectDescriptor) Validate() error {
	if value.ByteCount <= 0 || value.ByteCount > MaximumJobCustodyProtectedBytes ||
		value.ChunkByteCount <= 0 || value.ChunkByteCount > MaximumJobCustodyChunkBytes ||
		value.ChunkCount <= 0 ||
		value.ChunkCount != ((value.ByteCount-1)/value.ChunkByteCount)+1 {
		return invalid("protectedObject.geometry")
	}
	if err := value.SHA256.Validate(); err != nil {
		return err
	}
	return nil
}

func (value JobCapsuleProtectedObjectDescriptor) Digest() Digest {
	return SHA256Digest(
		"facets.job-custody.protected-object.v1",
		fmt.Sprint(value.ByteCount),
		string(value.SHA256),
		fmt.Sprint(value.ChunkByteCount),
		fmt.Sprint(value.ChunkCount),
	)
}

// JobCustodyAdmissionHeader is the minimal clear routing and storage contract
// for an already-protected Job Capsule. The authenticated transport supplies
// the signer; source identity, Space identity, model, prompts and results must
// not be added to this Box-visible header.
type JobCustodyAdmissionHeader struct {
	ProtocolVersion              int                                 `json:"protocolVersion"`
	CapsuleID                    JobCapsuleID                        `json:"capsuleID"`
	AssignmentID                 AssignmentID                        `json:"assignmentID"`
	RouteRecipientWorkerID       WorkerID                            `json:"routeRecipientWorkerID"`
	RouteRecipientKeyFingerprint Digest                              `json:"routeRecipientKeyFingerprint"`
	ProtectedObject              JobCapsuleProtectedObjectDescriptor `json:"protectedObject"`
	NotBeforeAt                  Timestamp                           `json:"notBeforeAt"`
	ExpiresAt                    Timestamp                           `json:"expiresAt"`
	RetentionUntil               Timestamp                           `json:"retentionUntil"`
	IdempotencyKey               Digest                              `json:"idempotencyKey"`
}

func NewJobCustodyAdmissionHeader(
	capsuleID JobCapsuleID,
	assignmentID AssignmentID,
	routeRecipientWorkerID WorkerID,
	routeRecipientKeyFingerprint Digest,
	protectedObject JobCapsuleProtectedObjectDescriptor,
	notBeforeAt Timestamp,
	expiresAt Timestamp,
	retentionUntil Timestamp,
) (JobCustodyAdmissionHeader, error) {
	value := JobCustodyAdmissionHeader{
		ProtocolVersion:              ProtocolVersion,
		CapsuleID:                    capsuleID,
		AssignmentID:                 assignmentID,
		RouteRecipientWorkerID:       routeRecipientWorkerID,
		RouteRecipientKeyFingerprint: routeRecipientKeyFingerprint,
		ProtectedObject:              protectedObject,
		NotBeforeAt:                  notBeforeAt,
		ExpiresAt:                    expiresAt,
		RetentionUntil:               retentionUntil,
	}
	value.IdempotencyKey = value.MakeIdempotencyKey()
	if err := value.Validate(); err != nil {
		return JobCustodyAdmissionHeader{}, err
	}
	return value, nil
}

func (value JobCustodyAdmissionHeader) Validate() error {
	if err := requireProtocol(value.ProtocolVersion); err != nil {
		return err
	}
	if err := value.CapsuleID.Validate(); err != nil {
		return err
	}
	if err := value.AssignmentID.Validate(); err != nil {
		return err
	}
	if err := value.RouteRecipientWorkerID.Validate(); err != nil {
		return err
	}
	if err := value.RouteRecipientKeyFingerprint.Validate(); err != nil {
		return err
	}
	if err := value.ProtectedObject.Validate(); err != nil {
		return err
	}
	if err := value.NotBeforeAt.Validate(); err != nil {
		return err
	}
	if err := value.ExpiresAt.Validate(); err != nil {
		return err
	}
	if err := value.RetentionUntil.Validate(); err != nil {
		return err
	}
	if value.NotBeforeAt >= value.ExpiresAt || value.ExpiresAt > value.RetentionUntil ||
		value.IdempotencyKey != value.MakeIdempotencyKey() {
		return invalid("jobCustodyAdmissionHeader")
	}
	return nil
}

func (value JobCustodyAdmissionHeader) MakeIdempotencyKey() Digest {
	return SHA256Digest(
		"facets.job-custody.admission-idempotency.v1",
		string(value.CapsuleID),
		string(value.AssignmentID),
		string(value.RouteRecipientWorkerID),
		string(value.RouteRecipientKeyFingerprint),
		string(value.ProtectedObject.Digest()),
		fmt.Sprint(value.NotBeforeAt),
		fmt.Sprint(value.ExpiresAt),
		fmt.Sprint(value.RetentionUntil),
	)
}

func (value JobCustodyAdmissionHeader) Digest() Digest {
	return SHA256Digest(
		"facets.job-custody.admission-header.v1",
		fmt.Sprint(value.ProtocolVersion),
		string(value.CapsuleID),
		string(value.AssignmentID),
		string(value.RouteRecipientWorkerID),
		string(value.RouteRecipientKeyFingerprint),
		string(value.ProtectedObject.Digest()),
		fmt.Sprint(value.NotBeforeAt),
		fmt.Sprint(value.ExpiresAt),
		fmt.Sprint(value.RetentionUntil),
		string(value.IdempotencyKey),
	)
}

type JobCustodySignedAdmissionEnvelope struct {
	ProtocolVersion       int                       `json:"protocolVersion"`
	Header                JobCustodyAdmissionHeader `json:"header"`
	CanonicalHeaderDigest Digest                    `json:"canonicalHeaderDigest"`
	SignatureProfileID    string                    `json:"signatureProfileID"`
	Signature             SignatureValue            `json:"signature"`
}

func NewJobCustodySignedAdmissionEnvelope(
	header JobCustodyAdmissionHeader,
	signatureProfileID string,
	signature SignatureValue,
) (JobCustodySignedAdmissionEnvelope, error) {
	digest, err := jobCustodyCanonicalHeaderDigest(header)
	if err != nil {
		return JobCustodySignedAdmissionEnvelope{}, err
	}
	value := JobCustodySignedAdmissionEnvelope{
		ProtocolVersion:       ProtocolVersion,
		Header:                header,
		CanonicalHeaderDigest: digest,
		SignatureProfileID:    signatureProfileID,
		Signature:             signature,
	}
	if err := value.Validate(); err != nil {
		return JobCustodySignedAdmissionEnvelope{}, err
	}
	return value, nil
}

func (value JobCustodySignedAdmissionEnvelope) Validate() error {
	if err := requireProtocol(value.ProtocolVersion); err != nil {
		return err
	}
	if err := value.Header.Validate(); err != nil {
		return err
	}
	if err := requireMachineToken(value.SignatureProfileID, "admissionEnvelope.signatureProfileID"); err != nil {
		return err
	}
	if err := value.Signature.Validate(); err != nil {
		return err
	}
	expected, err := jobCustodyCanonicalHeaderDigest(value.Header)
	if err != nil {
		return err
	}
	if value.CanonicalHeaderDigest != expected {
		return invalid("admissionEnvelope.canonicalHeaderDigest")
	}
	return nil
}

func jobCustodyCanonicalHeaderDigest(header JobCustodyAdmissionHeader) (Digest, error) {
	encoded, err := EncodeCanonical(header)
	if err != nil {
		return "", err
	}
	return SHA256Digest(
		"facets.job-custody.admission-header-canonical.v1",
		string(encoded),
	), nil
}

func JobCustodyAdmissionSigningPayloadDigest(
	header JobCustodyAdmissionHeader,
	signer ReceiptSignerBinding,
) (Digest, error) {
	if err := header.Validate(); err != nil {
		return "", err
	}
	if err := signer.Validate(); err != nil {
		return "", err
	}
	canonicalHeaderDigest, err := jobCustodyCanonicalHeaderDigest(header)
	if err != nil {
		return "", err
	}
	return SHA256Digest(
		"facets.job-custody.admission-signature-payload.v1",
		fmt.Sprint(ProtocolVersion),
		signer.SignatureProfileID,
		string(signer.SignerID),
		string(signer.SigningKeyID),
		fmt.Sprint(signer.SigningKeyRevision),
		string(canonicalHeaderDigest),
	), nil
}

func (value JobCustodySignedAdmissionEnvelope) SignaturePayloadDigest(
	expectedSigner ReceiptSignerBinding,
) (Digest, error) {
	if err := expectedSigner.Validate(); err != nil {
		return "", err
	}
	if value.SignatureProfileID != expectedSigner.SignatureProfileID {
		return "", invalid("admissionEnvelope.signatureProfileID")
	}
	return JobCustodyAdmissionSigningPayloadDigest(value.Header, expectedSigner)
}

// JobCustodyAdmissionExpectation binds authenticated route metadata to an
// exact header and to the admission instant.
type JobCustodyAdmissionExpectation struct {
	header     JobCustodyAdmissionHeader
	acceptedAt Timestamp
}

func NewJobCustodyAdmissionExpectation(
	header JobCustodyAdmissionHeader,
	acceptedAt Timestamp,
) (JobCustodyAdmissionExpectation, error) {
	if err := header.Validate(); err != nil {
		return JobCustodyAdmissionExpectation{}, err
	}
	if err := acceptedAt.Validate(); err != nil {
		return JobCustodyAdmissionExpectation{}, err
	}
	if acceptedAt < header.NotBeforeAt || acceptedAt >= header.ExpiresAt {
		return JobCustodyAdmissionExpectation{}, invalid("jobCustodyAdmission.acceptedAt")
	}
	return JobCustodyAdmissionExpectation{header: header, acceptedAt: acceptedAt}, nil
}

// VerifiedJobCustodyAdmission is not a wire contract. Its unexported fields
// prevent decoded JSON from being treated as authenticated admission proof.
type VerifiedJobCustodyAdmission struct {
	header         JobCustodyAdmissionHeader
	expectedSigner ReceiptSignerBinding
}

func (value VerifiedJobCustodyAdmission) Header() JobCustodyAdmissionHeader {
	return value.header
}

func (value VerifiedJobCustodyAdmission) ExpectedSigner() ReceiptSignerBinding {
	return value.expectedSigner
}

type jobCustodyAdmissionSignatureVerifier interface {
	VerifySignature(
		signature SignatureValue,
		payloadDigest Digest,
		expectedSigner ReceiptSignerBinding,
	) error
}

// acceptVerifiedJobCustodyAdmission is the sole construction path for
// authenticated admission evidence. A later runtime slice will bind this
// boundary to a concrete trusted-key verifier in this package.
func acceptVerifiedJobCustodyAdmission(
	envelope JobCustodySignedAdmissionEnvelope,
	expectation JobCustodyAdmissionExpectation,
	expectedSigner ReceiptSignerBinding,
	verifier jobCustodyAdmissionSignatureVerifier,
) (VerifiedJobCustodyAdmission, error) {
	if err := envelope.Validate(); err != nil {
		return VerifiedJobCustodyAdmission{}, err
	}
	if err := expectation.header.Validate(); err != nil {
		return VerifiedJobCustodyAdmission{}, err
	}
	if err := expectedSigner.Validate(); err != nil {
		return VerifiedJobCustodyAdmission{}, err
	}
	if verifier == nil {
		return VerifiedJobCustodyAdmission{}, invalid("admissionEnvelope.verifier")
	}
	if envelope.Header != expectation.header ||
		envelope.SignatureProfileID != expectedSigner.SignatureProfileID {
		return VerifiedJobCustodyAdmission{}, invalid("verifiedJobCustodyAdmission")
	}
	payloadDigest, err := envelope.SignaturePayloadDigest(expectedSigner)
	if err != nil {
		return VerifiedJobCustodyAdmission{}, err
	}
	if err := verifier.VerifySignature(envelope.Signature, payloadDigest, expectedSigner); err != nil {
		return VerifiedJobCustodyAdmission{}, err
	}
	return VerifiedJobCustodyAdmission{
		header:         envelope.Header,
		expectedSigner: expectedSigner,
	}, nil
}

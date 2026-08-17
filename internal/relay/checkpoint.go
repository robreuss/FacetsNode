package relay

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"

	"github.com/google/uuid"
)

const MaximumCheckpointCollectionCount = int64(10_000)
const MinimumCheckpointFenceLifetimeMilliseconds = int64(5 * 60 * 1_000)
const DefaultCheckpointFenceLifetimeMilliseconds = int64(2 * 60 * 60 * 1_000)
const MaximumCheckpointFenceLifetimeMilliseconds = int64(24 * 60 * 60 * 1_000)

type CheckpointFenceStatus string

const (
	CheckpointFenceActive    CheckpointFenceStatus = "active"
	CheckpointFenceActivated CheckpointFenceStatus = "activated"
	CheckpointFenceExpired   CheckpointFenceStatus = "expired"
	CheckpointFenceAborted   CheckpointFenceStatus = "aborted"
)

type CheckpointFenceRequest struct {
	RetryID                 uuid.UUID `json:"retryID"`
	FenceID                 uuid.UUID `json:"fenceID"`
	RequestedAtMilliseconds int64     `json:"requestedAtMilliseconds"`
}

func (r CheckpointFenceRequest) Validate() error {
	if r.RetryID == uuid.Nil || r.FenceID == uuid.Nil || r.RequestedAtMilliseconds < 0 {
		return protocolError(CodeInvalidCheckpointFence, "checkpoint fence request is invalid")
	}
	return nil
}

type CheckpointFenceState struct {
	FenceID                uuid.UUID             `json:"fenceID"`
	Status                 CheckpointFenceStatus `json:"status"`
	BoundaryCursor         string                `json:"boundaryCursor"`
	AcquiredAtMilliseconds int64                 `json:"acquiredAtMilliseconds"`
	ExpiresAtMilliseconds  int64                 `json:"expiresAtMilliseconds"`
}

func (s CheckpointFenceState) Validate() error {
	if s.FenceID == uuid.Nil || s.AcquiredAtMilliseconds < 0 ||
		s.ExpiresAtMilliseconds <= s.AcquiredAtMilliseconds || ValidateOpaqueCursor(s.BoundaryCursor) != nil {
		return protocolError(CodeInvalidCheckpointFence, "checkpoint fence state is invalid")
	}
	switch s.Status {
	case CheckpointFenceActive, CheckpointFenceActivated, CheckpointFenceExpired, CheckpointFenceAborted:
		return nil
	default:
		return protocolError(CodeInvalidCheckpointFence, "checkpoint fence status is invalid")
	}
}

type CheckpointFenceResponse struct {
	Acceptance             Acceptance `json:"acceptance"`
	RetryID                uuid.UUID  `json:"retryID"`
	FenceID                uuid.UUID  `json:"fenceID"`
	BoundaryCursor         string     `json:"boundaryCursor"`
	AcquiredAtMilliseconds int64      `json:"acquiredAtMilliseconds"`
	ExpiresAtMilliseconds  int64      `json:"expiresAtMilliseconds"`
}

type CheckpointFenceAbortRequest struct {
	RetryID               uuid.UUID `json:"retryID"`
	FenceID               uuid.UUID `json:"fenceID"`
	AbortedAtMilliseconds int64     `json:"abortedAtMilliseconds"`
}

func (r CheckpointFenceAbortRequest) Validate() error {
	if r.RetryID == uuid.Nil || r.FenceID == uuid.Nil || r.AbortedAtMilliseconds < 0 {
		return protocolError(CodeInvalidCheckpointFence, "checkpoint fence abort is invalid")
	}
	return nil
}

type CheckpointFenceAbortResponse struct {
	Acceptance Acceptance            `json:"acceptance"`
	RetryID    uuid.UUID             `json:"retryID"`
	FenceID    uuid.UUID             `json:"fenceID"`
	Status     CheckpointFenceStatus `json:"status"`
}

type CheckpointCandidate struct {
	Version                 int         `json:"version"`
	RetryID                 uuid.UUID   `json:"retryID"`
	CheckpointID            uuid.UUID   `json:"checkpointID"`
	FenceID                 uuid.UUID   `json:"fenceID"`
	TenantID                uuid.UUID   `json:"tenantID"`
	DomainID                uuid.UUID   `json:"domainID"`
	PublisherSubscriptionID uuid.UUID   `json:"publisherSubscriptionID"`
	CoveredThroughCursor    string      `json:"coveredThroughCursor"`
	RetainedMessageIDs      []uuid.UUID `json:"retainedMessageIDs"`
	RetainedBlobIDs         []string    `json:"retainedBlobIDs"`
	CreatedAtMilliseconds   int64       `json:"createdAtMilliseconds"`
}

func (c CheckpointCandidate) Validate() error {
	if c.Version != SchemaVersion || c.RetryID == uuid.Nil ||
		c.CheckpointID == uuid.Nil || c.FenceID == uuid.Nil || c.TenantID == uuid.Nil ||
		c.DomainID == uuid.Nil || c.PublisherSubscriptionID == uuid.Nil ||
		c.CreatedAtMilliseconds < 0 || ValidateOpaqueCursor(c.CoveredThroughCursor) != nil {
		return protocolError(CodeInvalidCheckpoint, "checkpoint candidate fields are invalid")
	}
	for index, id := range c.RetainedMessageIDs {
		if id == uuid.Nil || (index > 0 && c.RetainedMessageIDs[index-1].String() >= id.String()) {
			return protocolError(CodeInvalidCheckpoint, "retained message IDs are not canonical")
		}
	}
	for index, id := range c.RetainedBlobIDs {
		if ValidateBlobID(id) != nil || (index > 0 && c.RetainedBlobIDs[index-1] >= id) {
			return protocolError(CodeInvalidCheckpoint, "retained blob IDs are not canonical")
		}
	}
	return nil
}

func CheckpointCandidateDigest(candidate CheckpointCandidate) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("Facets replica relay checkpoint candidate v1\x00"))
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], uint64(candidate.Version))
	_, _ = hash.Write(number[:])
	_, _ = hash.Write(candidate.RetryID[:])
	_, _ = hash.Write(candidate.CheckpointID[:])
	_, _ = hash.Write(candidate.FenceID[:])
	_, _ = hash.Write(candidate.TenantID[:])
	_, _ = hash.Write(candidate.DomainID[:])
	_, _ = hash.Write(candidate.PublisherSubscriptionID[:])
	checkpointDigestString(hash, candidate.CoveredThroughCursor, &number)
	binary.BigEndian.PutUint64(number[:], uint64(len(candidate.RetainedMessageIDs)))
	_, _ = hash.Write(number[:])
	for _, id := range candidate.RetainedMessageIDs {
		_, _ = hash.Write(id[:])
	}
	binary.BigEndian.PutUint64(number[:], uint64(len(candidate.RetainedBlobIDs)))
	_, _ = hash.Write(number[:])
	for _, id := range candidate.RetainedBlobIDs {
		checkpointDigestString(hash, id, &number)
	}
	binary.BigEndian.PutUint64(number[:], uint64(candidate.CreatedAtMilliseconds))
	_, _ = hash.Write(number[:])
	return hex.EncodeToString(hash.Sum(nil))
}

func checkpointDigestString(hash interface{ Write([]byte) (int, error) }, value string, number *[8]byte) {
	binary.BigEndian.PutUint64(number[:], uint64(len(value)))
	_, _ = hash.Write(number[:])
	_, _ = hash.Write([]byte(value))
}

type CheckpointStageResponse struct {
	Acceptance   Acceptance `json:"acceptance"`
	RetryID      uuid.UUID  `json:"retryID"`
	CheckpointID uuid.UUID  `json:"checkpointID"`
}

type CheckpointActivationRequest struct {
	RetryID                 uuid.UUID `json:"retryID"`
	CheckpointID            uuid.UUID `json:"checkpointID"`
	ActivatedAtMilliseconds int64     `json:"activatedAtMilliseconds"`
}

func (r CheckpointActivationRequest) Validate() error {
	if r.RetryID == uuid.Nil || r.CheckpointID == uuid.Nil || r.ActivatedAtMilliseconds < 0 {
		return protocolError(CodeInvalidCheckpoint, "checkpoint activation is invalid")
	}
	return nil
}

type CheckpointActivationResponse struct {
	Acceptance              Acceptance `json:"acceptance"`
	RetryID                 uuid.UUID  `json:"retryID"`
	CheckpointID            uuid.UUID  `json:"checkpointID"`
	ActivatedAtMilliseconds int64      `json:"activatedAtMilliseconds"`
	StartCursor             string     `json:"startCursor"`
}

type CheckpointDryRunRequest struct {
	CheckpointID uuid.UUID `json:"checkpointID"`
}

func (r CheckpointDryRunRequest) Validate() error {
	if r.CheckpointID == uuid.Nil {
		return protocolError(CodeInvalidCheckpoint, "checkpoint dry run is invalid")
	}
	return nil
}

type CheckpointDryRunResponse struct {
	CheckpointID                  uuid.UUID   `json:"checkpointID"`
	Eligible                      bool        `json:"eligible"`
	MessageCount                  int64       `json:"messageCount"`
	MessageByteCount              int64       `json:"messageByteCount"`
	BlobCount                     int64       `json:"blobCount"`
	BlobByteCount                 int64       `json:"blobByteCount"`
	MissingCustodySubscriptionIDs []uuid.UUID `json:"missingCustodySubscriptionIDs"`
	PlanDigest                    string      `json:"planDigest"`
}

type CheckpointCollectionRequest struct {
	RetryID                 uuid.UUID `json:"retryID"`
	CheckpointID            uuid.UUID `json:"checkpointID"`
	PlanDigest              string    `json:"planDigest"`
	MaximumMessageCount     int64     `json:"maximumMessageCount"`
	MaximumBlobCount        int64     `json:"maximumBlobCount"`
	RequestedAtMilliseconds int64     `json:"requestedAtMilliseconds"`
}

func (r CheckpointCollectionRequest) Validate() error {
	if r.RetryID == uuid.Nil || r.CheckpointID == uuid.Nil || !validDigest(r.PlanDigest) ||
		r.MaximumMessageCount < 0 || r.MaximumMessageCount > MaximumCheckpointCollectionCount ||
		r.MaximumBlobCount < 0 || r.MaximumBlobCount > MaximumCheckpointCollectionCount ||
		(r.MaximumMessageCount == 0 && r.MaximumBlobCount == 0) ||
		r.RequestedAtMilliseconds < 0 {
		return protocolError(CodeInvalidCheckpoint, "checkpoint collection is invalid")
	}
	return nil
}

type CheckpointCollectionResponse struct {
	Duplicate               bool      `json:"duplicate"`
	RetryID                 uuid.UUID `json:"retryID"`
	CheckpointID            uuid.UUID `json:"checkpointID"`
	PlanDigest              string    `json:"planDigest"`
	DeletedMessageCount     int64     `json:"deletedMessageCount"`
	DeletedMessageByteCount int64     `json:"deletedMessageByteCount"`
	DeletedBlobCount        int64     `json:"deletedBlobCount"`
	DeletedBlobByteCount    int64     `json:"deletedBlobByteCount"`
	Completed               bool      `json:"completed"`
}

type CheckpointPlanMessage struct {
	Sequence  uint64
	MessageID uuid.UUID
	ByteCount int64
}
type CheckpointPlanBlob struct {
	BlobID    string
	ByteCount int64
}

func CheckpointPlanDigest(tenantID, domainID, checkpointID uuid.UUID, activationOrdinal uint64, messages []CheckpointPlanMessage, blobs []CheckpointPlanBlob) string {
	messages = append([]CheckpointPlanMessage(nil), messages...)
	blobs = append([]CheckpointPlanBlob(nil), blobs...)
	sort.Slice(messages, func(i, j int) bool {
		if messages[i].Sequence != messages[j].Sequence {
			return messages[i].Sequence < messages[j].Sequence
		}
		return bytes.Compare(messages[i].MessageID[:], messages[j].MessageID[:]) < 0
	})
	sort.Slice(blobs, func(i, j int) bool { return blobs[i].BlobID < blobs[j].BlobID })
	hash := sha256.New()
	_, _ = hash.Write([]byte("Facets replica relay checkpoint collection plan v1\x00"))
	_, _ = hash.Write(tenantID[:])
	_, _ = hash.Write(domainID[:])
	_, _ = hash.Write(checkpointID[:])
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], activationOrdinal)
	_, _ = hash.Write(number[:])
	binary.BigEndian.PutUint64(number[:], uint64(len(messages)))
	_, _ = hash.Write(number[:])
	for _, message := range messages {
		binary.BigEndian.PutUint64(number[:], message.Sequence)
		_, _ = hash.Write(number[:])
		_, _ = hash.Write(message.MessageID[:])
		binary.BigEndian.PutUint64(number[:], uint64(message.ByteCount))
		_, _ = hash.Write(number[:])
	}
	binary.BigEndian.PutUint64(number[:], uint64(len(blobs)))
	_, _ = hash.Write(number[:])
	for _, blob := range blobs {
		binary.BigEndian.PutUint64(number[:], uint64(len(blob.BlobID)))
		_, _ = hash.Write(number[:])
		_, _ = hash.Write([]byte(blob.BlobID))
		binary.BigEndian.PutUint64(number[:], uint64(blob.ByteCount))
		_, _ = hash.Write(number[:])
	}
	return hex.EncodeToString(hash.Sum(nil))
}

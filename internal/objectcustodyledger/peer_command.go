package objectcustodyledger

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/objectcustodywire"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

// PeerCommand is a bounded interpretation of one deployment-verified body,
// NOT current client/link authority, challenge consumption or a storage permit.
// No ledger effect consumes this type yet. A future adapter must enforce those
// independent gates and the exact durable receipt/retirement authority.
type PeerCommand struct {
	request          serviceauthority.CustodyPeerRequest
	reference        objectcustodywire.Reference
	references       []objectcustodywire.Reference
	publication      Publication
	leaseID          uuid.UUID
	expectedRevision int64
	decisionDigest   string
	wire             []byte
}

func (c PeerCommand) Request() serviceauthority.CustodyPeerRequest { return c.request }
func (c PeerCommand) Publication() Publication                     { return c.publication }
func (c PeerCommand) Reference() objectcustodywire.Reference       { return c.reference }
func (c PeerCommand) References() []objectcustodywire.Reference {
	return append([]objectcustodywire.Reference(nil), c.references...)
}
func (c PeerCommand) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (c PeerCommand) String() string               { return "decoded-custody-command(not-an-effect-permit)" }
func (c PeerCommand) GoString() string             { return c.String() }

// DecodePeerCommand rechecks actual bytes against the sealed proof. It has no
// filesystem, database, network, decryption or trust-modification side effects.
func DecodePeerCommand(verified serviceauthority.VerifiedCustodyPeerRequest, body []byte) (PeerCommand, error) {
	r := verified.Request()
	if !r.MatchesBody(body) {
		return PeerCommand{}, ErrInvalid
	}
	c := PeerCommand{request: r}
	binding := r.Target.BindingID
	switch r.Operation {
	case serviceauthority.CustodyPutObject:
		ref, err := objectcustodywire.Inspect(body)
		if err != nil || !commandScope(ref, r.Target) {
			return PeerCommand{}, ErrInvalid
		}
		c.reference, c.wire = ref, bytes.Clone(body)
	case serviceauthority.CustodyReserveObject:
		var b peerReferenceBody
		if decodePeerBody(body, &b) != nil || b.Version != 1 {
			return PeerCommand{}, ErrInvalid
		}
		ref, err := b.Reference.decode(r.Target)
		if err != nil {
			return PeerCommand{}, err
		}
		c.reference = ref
	case serviceauthority.CustodyReadObject:
		var b peerReadBody
		if decodePeerBody(body, &b) != nil || b.Version != 1 || b.LeaseID == uuid.Nil || b.PublicationID == uuid.Nil {
			return PeerCommand{}, ErrInvalid
		}
		ref, err := b.Reference.decode(r.Target)
		if err != nil {
			return PeerCommand{}, err
		}
		c.reference, c.leaseID = ref, b.LeaseID
		c.publication = Publication{BindingID: binding, ID: b.PublicationID}
	case serviceauthority.CustodyBeginPublication:
		var b peerBeginBody
		if decodePeerBody(body, &b) != nil || b.Version != 1 {
			return PeerCommand{}, ErrInvalid
		}
		c.publication = Publication{BindingID: binding, ID: b.PublicationID, RootDigest: b.RootDigest, ObjectCount: b.ObjectCount}
		if c.publication.validateIdentity() != nil {
			return PeerCommand{}, ErrInvalid
		}
	case serviceauthority.CustodyAddPins:
		var b peerPinsBody
		if decodePeerBody(body, &b) != nil || b.Version != 1 || b.PublicationID == uuid.Nil || len(b.References) == 0 || len(b.References) > MaximumPinBatch {
			return PeerCommand{}, ErrInvalid
		}
		c.publication = Publication{BindingID: binding, ID: b.PublicationID}
		c.references = make([]objectcustodywire.Reference, 0, len(b.References))
		for _, encoded := range b.References {
			ref, err := encoded.decode(r.Target)
			if err != nil || (len(c.references) > 0 && c.references[len(c.references)-1].CiphertextID >= ref.CiphertextID) {
				return PeerCommand{}, ErrInvalid
			}
			c.references = append(c.references, ref)
		}
	case serviceauthority.CustodyPreparePublication:
		var b peerPrepareBody
		if decodePeerBody(body, &b) != nil || b.Version != 1 || b.PublicationID == uuid.Nil {
			return PeerCommand{}, ErrInvalid
		}
		c.publication = Publication{BindingID: binding, ID: b.PublicationID}
	case serviceauthority.CustodyConfirmPublication:
		var b peerConfirmBody
		if decodePeerBody(body, &b) != nil || b.Version != 1 || b.PublicationID == uuid.Nil || !validDigest(b.InventoryDigest) || !validDigest(b.ReceiptDigest) || !validDigest(b.RootDigest) {
			return PeerCommand{}, ErrInvalid
		}
		// Not a committed publication until its receipt is independently checked
		// and the existing ledger transition durably succeeds.
		c.publication = Publication{BindingID: binding, ID: b.PublicationID, RootDigest: b.RootDigest, InventoryDigest: b.InventoryDigest, ReceiptDigest: b.ReceiptDigest}
	case serviceauthority.CustodyAcquireLease:
		var b peerAcquireBody
		if decodePeerBody(body, &b) != nil || b.Version != 1 || b.LeaseID == uuid.Nil {
			return PeerCommand{}, ErrInvalid
		}
		p, err := b.Publication.decode(binding)
		if err != nil {
			return PeerCommand{}, err
		}
		c.publication, c.leaseID = p, b.LeaseID
	case serviceauthority.CustodyRenewLease, serviceauthority.CustodyCloseLease:
		var b peerChangeLeaseBody
		if decodePeerBody(body, &b) != nil || b.Version != 1 || b.PublicationID == uuid.Nil || b.LeaseID == uuid.Nil || b.ExpectedRevision <= 0 || b.ExpectedRevision == math.MaxInt64 {
			return PeerCommand{}, ErrInvalid
		}
		c.publication = Publication{BindingID: binding, ID: b.PublicationID}
		c.leaseID, c.expectedRevision = b.LeaseID, b.ExpectedRevision
	case serviceauthority.CustodyRetirePublication:
		var b peerRetireBody
		if decodePeerBody(body, &b) != nil || b.Version != 1 || !validDigest(b.DecisionDigest) {
			return PeerCommand{}, ErrInvalid
		}
		p, err := b.Publication.decode(binding)
		if err != nil {
			return PeerCommand{}, err
		}
		c.publication, c.decisionDigest = p, b.DecisionDigest
	default:
		return PeerCommand{}, ErrInvalid
	}
	return c, nil
}

func decodePeerBody(body []byte, value any) error {
	if len(body) == 0 || len(body) > serviceauthority.MaximumCustodyPeerControlBodyBytes || json.Unmarshal(body, value) != nil {
		return ErrInvalid
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, body) {
		return ErrInvalid
	}
	return nil
}

type peerReference struct {
	CiphertextID string `json:"ciphertextID"`
	Header       string `json:"header"`
}

func (r peerReference) decode(target serviceauthority.CustodyPeerTarget) (objectcustodywire.Reference, error) {
	if len(r.Header) != 72 || len(r.CiphertextID) != 64 {
		return objectcustodywire.Reference{}, ErrInvalid
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(r.Header)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != r.Header {
		return objectcustodywire.Reference{}, ErrInvalid
	}
	h, err := objectcustodywire.DecodeHeader(b)
	ref := objectcustodywire.Reference{Header: h, CiphertextID: r.CiphertextID}
	if err != nil || ref.Validate() != nil || !commandScope(ref, target) {
		return objectcustodywire.Reference{}, ErrInvalid
	}
	return ref, nil
}

func commandScope(ref objectcustodywire.Reference, target serviceauthority.CustodyPeerTarget) bool {
	return ref.Header.ScopeID == target.ContentScopeID && ref.Header.ContentEpoch == target.ContentEpoch
}

type peerReferenceBody struct {
	Reference peerReference `json:"reference"`
	Version   int           `json:"version"`
}
type peerReadBody struct {
	LeaseID       uuid.UUID     `json:"leaseID"`
	PublicationID uuid.UUID     `json:"publicationID"`
	Reference     peerReference `json:"reference"`
	Version       int           `json:"version"`
}
type peerBeginBody struct {
	ObjectCount   int64     `json:"objectCount"`
	PublicationID uuid.UUID `json:"publicationID"`
	RootDigest    string    `json:"rootDigest"`
	Version       int       `json:"version"`
}
type peerPinsBody struct {
	PublicationID uuid.UUID       `json:"publicationID"`
	References    []peerReference `json:"references"`
	Version       int             `json:"version"`
}
type peerPrepareBody struct {
	PublicationID uuid.UUID `json:"publicationID"`
	Version       int       `json:"version"`
}
type peerConfirmBody struct {
	InventoryDigest string    `json:"inventoryDigest"`
	PublicationID   uuid.UUID `json:"publicationID"`
	ReceiptDigest   string    `json:"receiptDigest"`
	RootDigest      string    `json:"rootDigest"`
	Version         int       `json:"version"`
}
type peerCommittedPublication struct {
	InventoryDigest string    `json:"inventoryDigest"`
	ObjectCount     int64     `json:"objectCount"`
	PublicationID   uuid.UUID `json:"publicationID"`
	ReceiptDigest   string    `json:"receiptDigest"`
	RootDigest      string    `json:"rootDigest"`
}

func (p peerCommittedPublication) decode(binding uuid.UUID) (Publication, error) {
	result := Publication{BindingID: binding, ID: p.PublicationID, RootDigest: p.RootDigest, ObjectCount: p.ObjectCount, InventoryDigest: p.InventoryDigest, ReceiptDigest: p.ReceiptDigest, State: "committed"}
	if result.validateState() != nil {
		return Publication{}, ErrInvalid
	}
	return result, nil
}

type peerAcquireBody struct {
	LeaseID     uuid.UUID                `json:"leaseID"`
	Publication peerCommittedPublication `json:"publication"`
	Version     int                      `json:"version"`
}
type peerChangeLeaseBody struct {
	ExpectedRevision int64     `json:"expectedRevision"`
	LeaseID          uuid.UUID `json:"leaseID"`
	PublicationID    uuid.UUID `json:"publicationID"`
	Version          int       `json:"version"`
}
type peerRetireBody struct {
	DecisionDigest string                   `json:"decisionDigest"`
	Publication    peerCommittedPublication `json:"publication"`
	Version        int                      `json:"version"`
}

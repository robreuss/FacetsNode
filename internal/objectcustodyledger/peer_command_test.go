package objectcustodyledger

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/objectcustodywire"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

func newCommandFixture(t *testing.T) (peerFixture, peerReference, []byte) {
	return newCommandFixtureKind(t, serviceauthority.ScopeDeviceSync)
}

func newCommandFixtureKind(t *testing.T, kind serviceauthority.ScopeKind) (peerFixture, peerReference, []byte) {
	t.Helper()
	b := Binding{ID: uuid.New(), ServiceKind: string(kind), ServiceScopeID: uuid.New(), ResourceID: uuid.New(), ContentScopeID: uuid.New(), ContentEpoch: math.MaxUint64}
	f := newPeerAuthorityFixture(t, b, uuid.New(), uuid.New())
	header := objectcustodywire.Header{ScopeID: b.ContentScopeID, ContentEpoch: b.ContentEpoch, IncarnationID: uuid.New(), PlaintextBytes: 7}
	encoded, err := header.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// Opaque synthetic bytes. Deployment signing below is real; these unit tests
	// do not claim client AEAD validation, a consumed challenge, or a linked scope.
	wire := append(bytes.Clone(encoded), make([]byte, objectcustodywire.WireOverhead-objectcustodywire.HeaderBytes+7)...)
	ref, err := objectcustodywire.Inspect(wire)
	if err != nil {
		t.Fatal(err)
	}
	return f, peerReference{CiphertextID: ref.CiphertextID, Header: base64.RawURLEncoding.EncodeToString(encoded)}, wire
}

func commandJSON(t *testing.T, body any) []byte {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func commandProof(t *testing.T, f peerFixture, op serviceauthority.CustodyPeerOperation, body []byte) serviceauthority.VerifiedCustodyPeerRequest {
	t.Helper()
	r := f.intent
	r.Operation, r.Challenge, r.BodyByteCount, r.BodySHA256 = op, strings.Repeat("A", 43), int64(len(body)), hashLabel(string(body))
	source := f.source
	if op == serviceauthority.CustodyPutObject || op == serviceauthority.CustodyReadObject {
		source.TrafficClass = serviceauthority.TrafficBulk
	}
	p, err := f.sender.SignCustodyPeerRequestAt(f.signer, source, r, body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.receiver.VerifyCustodyPeerRequestAt(p, r, body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPeerCommandAllExactOperationsAndNoAuthorityPromotion(t *testing.T) {
	for _, kind := range []serviceauthority.ScopeKind{serviceauthority.ScopeDeviceSync, serviceauthority.ScopeBackupCustody} {
		t.Run(string(kind), func(t *testing.T) { checkPeerCommandOperations(t, kind) })
	}
}

func checkPeerCommandOperations(t *testing.T, kind serviceauthority.ScopeKind) {
	f, ref, wire := newCommandFixtureKind(t, kind)
	p, lease := uuid.New(), uuid.New()
	root := peerCommittedPublication{InventoryDigest: hashLabel("inventory"), ObjectCount: 1, PublicationID: p, ReceiptDigest: hashLabel("receipt"), RootDigest: hashLabel("root")}
	tests := []struct {
		op   serviceauthority.CustodyPeerOperation
		body any
	}{
		{serviceauthority.CustodyReserveObject, peerReferenceBody{ref, 1}},
		{serviceauthority.CustodyReadObject, peerReadBody{lease, p, ref, 1}},
		{serviceauthority.CustodyBeginPublication, peerBeginBody{math.MaxInt64, p, root.RootDigest, 1}},
		{serviceauthority.CustodyAddPins, peerPinsBody{p, []peerReference{ref}, 1}},
		{serviceauthority.CustodyPreparePublication, peerPrepareBody{p, 1}},
		{serviceauthority.CustodyConfirmPublication, peerConfirmBody{root.InventoryDigest, p, root.ReceiptDigest, root.RootDigest, 1}},
		{serviceauthority.CustodyAcquireLease, peerAcquireBody{lease, root, 1}},
		{serviceauthority.CustodyRenewLease, peerChangeLeaseBody{math.MaxInt64 - 1, lease, p, 1}},
		{serviceauthority.CustodyCloseLease, peerChangeLeaseBody{1, lease, p, 1}},
		{serviceauthority.CustodyRetirePublication, peerRetireBody{hashLabel("retirement"), root, 1}},
	}
	for _, test := range tests {
		t.Run(string(test.op), func(t *testing.T) {
			body := commandJSON(t, test.body)
			verified := commandProof(t, f, test.op, body)
			c, err := DecodePeerCommand(verified, body)
			if err != nil || c.Request() != verified.Request() {
				t.Fatalf("decode: %v", err)
			}
			if _, err := json.Marshal(c); err == nil || fmt.Sprintf("%#v", c) != c.String() {
				t.Fatal("command escaped redacted diagnostic boundary")
			}
			if test.op != serviceauthority.CustodyReserveObject && c.Publication().BindingID != verified.Request().Target.BindingID {
				t.Fatal("binding did not come from exact verified target")
			}
			switch test.op {
			case serviceauthority.CustodyReadObject, serviceauthority.CustodyAcquireLease, serviceauthority.CustodyRenewLease, serviceauthority.CustodyCloseLease:
				if c.leaseID != lease {
					t.Fatal("lease identity lost")
				}
			case serviceauthority.CustodyConfirmPublication:
				if c.Publication().State != "" {
					t.Fatal("claimed receipt promoted to committed authority")
				}
			case serviceauthority.CustodyRetirePublication:
				if c.decisionDigest != hashLabel("retirement") || c.Publication().State != "committed" {
					t.Fatal("retirement parameters changed")
				}
			}
		})
	}
	verified := commandProof(t, f, serviceauthority.CustodyPutObject, wire)
	c, err := DecodePeerCommand(verified, wire)
	if err != nil || c.Reference().CiphertextID != ref.CiphertextID || !bytes.Equal(c.wire, wire) {
		t.Fatal("put mismatch", err)
	}
	wire[len(wire)-1] ^= 1
	if bytes.Equal(c.wire, wire) {
		t.Fatal("caller owns retained put buffer")
	}
	if _, err := DecodePeerCommand(verified, wire); err == nil {
		t.Fatal("accepted body changed after verification")
	}
	if _, err := DecodePeerCommand(serviceauthority.VerifiedCustodyPeerRequest{}, c.wire); err == nil {
		t.Fatal("zero proof authorized decoding")
	}
}

func TestPeerCommandRejectsSignedNoncanonicalOrMixedBodies(t *testing.T) {
	f, ref, _ := newCommandFixture(t)
	p := uuid.New()
	valid := string(commandJSON(t, peerBeginBody{0, p, hashLabel("root"), 1}))
	bad := []string{
		"", "null", "{}", "[]", valid + "\n", " " + valid, valid + valid,
		strings.Replace(valid, `"objectCount":0`, `"objectCount":0,"objectCount":0`, 1),
		strings.Replace(valid, `"objectCount":0`, `"objectCount":null`, 1),
		strings.Replace(valid, `"objectCount":0`, `"objectCount":0.0`, 1),
		strings.Replace(valid, `"objectCount":0`, `"objectCount":-1`, 1),
		strings.Replace(valid, `"objectCount":0`, `"objectCount":9223372036854775808`, 1),
		strings.Replace(valid, `"objectCount":0,`, "", 1),
		strings.Replace(valid, `"version":1`, `"version":2`, 1),
		strings.Replace(valid, `"version":1`, `"version":1,"bindingID":"`+uuid.NewString()+`"`, 1),
		strings.Replace(valid, p.String(), strings.ToUpper(p.String()), 1),
		strings.Replace(valid, p.String(), uuid.Nil.String(), 1),
		strings.Replace(valid, hashLabel("root"), "not-a-digest", 1),
		strings.Replace(valid, hashLabel("root"), strings.ToUpper(hashLabel("root")), 1),
		`{"version":1,"objectCount":0,"publicationID":"` + p.String() + `","rootDigest":"` + hashLabel("root") + `"}`,
		string(commandJSON(t, peerReferenceBody{ref, 1})),
	}
	for i, body := range bad {
		verified := commandProof(t, f, serviceauthority.CustodyBeginPublication, []byte(body))
		if _, err := DecodePeerCommand(verified, []byte(body)); err == nil {
			t.Fatalf("accepted malformed signed body %d", i)
		}
	}
}

func TestPeerCommandRejectsScopeReferenceLeaseAndReceiptSubstitution(t *testing.T) {
	f, ref, _ := newCommandFixture(t)
	p, lease := uuid.New(), uuid.New()
	root := peerCommittedPublication{InventoryDigest: hashLabel("inventory"), ObjectCount: 0, PublicationID: p, ReceiptDigest: hashLabel("receipt"), RootDigest: hashLabel("root")}
	bad := []struct {
		op   serviceauthority.CustodyPeerOperation
		body any
	}{
		{serviceauthority.CustodyReadObject, peerReferenceBody{ref, 1}},
		{serviceauthority.CustodyReadObject, peerReadBody{uuid.Nil, p, ref, 1}},
		{serviceauthority.CustodyReadObject, peerReadBody{lease, uuid.Nil, ref, 1}},
		{serviceauthority.CustodyPreparePublication, peerPrepareBody{uuid.Nil, 1}},
		{serviceauthority.CustodyConfirmPublication, peerConfirmBody{"", p, root.ReceiptDigest, root.RootDigest, 1}},
		{serviceauthority.CustodyConfirmPublication, peerConfirmBody{root.InventoryDigest, p, "", root.RootDigest, 1}},
		{serviceauthority.CustodyAcquireLease, peerAcquireBody{uuid.Nil, root, 1}},
		{serviceauthority.CustodyAcquireLease, peerAcquireBody{lease, peerCommittedPublication{}, 1}},
		{serviceauthority.CustodyRetirePublication, peerRetireBody{"", root, 1}},
		{serviceauthority.CustodyRetirePublication, peerRetireBody{hashLabel("decision"), peerCommittedPublication{}, 1}},
	}
	for _, op := range []serviceauthority.CustodyPeerOperation{serviceauthority.CustodyRenewLease, serviceauthority.CustodyCloseLease} {
		for _, revision := range []int64{-1, 0, math.MaxInt64} {
			bad = append(bad, struct {
				op   serviceauthority.CustodyPeerOperation
				body any
			}{op, peerChangeLeaseBody{revision, lease, p, 1}})
		}
	}
	for i, test := range bad {
		body := commandJSON(t, test.body)
		if _, err := DecodePeerCommand(commandProof(t, f, test.op, body), body); err == nil {
			t.Fatalf("accepted invalid operation %d", i)
		}
	}
	header, _ := base64.RawURLEncoding.DecodeString(ref.Header)
	for _, offset := range []int{0, 4, 20, 28, 44, 46} {
		changed := bytes.Clone(header)
		if offset == 28 { // A different nonzero incarnation is structurally valid.
			clear(changed[28:44])
		} else {
			changed[offset] ^= 0x80
		}
		body := commandJSON(t, peerReferenceBody{peerReference{ref.CiphertextID, base64.RawURLEncoding.EncodeToString(changed)}, 1})
		if _, err := DecodePeerCommand(commandProof(t, f, serviceauthority.CustodyReserveObject, body), body); err == nil {
			t.Fatalf("accepted invalid/foreign header field %d", offset)
		}
	}
	for _, malformed := range []peerReference{{"", ref.Header}, {strings.ToUpper(ref.CiphertextID), ref.Header}, {ref.CiphertextID, ref.Header + "="}, {ref.CiphertextID, "null"}} {
		body := commandJSON(t, peerReferenceBody{malformed, 1})
		if _, err := DecodePeerCommand(commandProof(t, f, serviceauthority.CustodyReserveObject, body), body); err == nil {
			t.Fatal("accepted malformed reference")
		}
	}
}

func TestPeerCommandBoundedPinSetsAndPut(t *testing.T) {
	f, ref, wire := newCommandFixture(t)
	refs := make([]peerReference, MaximumPinBatch)
	for i := range refs {
		refs[i] = peerReference{fmt.Sprintf("%064x", i), ref.Header}
	}
	p := uuid.New()
	body := commandJSON(t, peerPinsBody{p, refs, 1})
	c, err := DecodePeerCommand(commandProof(t, f, serviceauthority.CustodyAddPins, body), body)
	if err != nil || len(c.References()) != MaximumPinBatch {
		t.Fatal("maximum pin batch failed", err)
	}
	copyRefs := c.References()
	copyRefs[0].CiphertextID = "changed"
	clear(body)
	if c.References()[0].CiphertextID != refs[0].CiphertextID {
		t.Fatal("references aliased caller")
	}
	for _, bad := range [][]peerReference{nil, {}, {ref, ref}, {refs[1], refs[0]}, append(refs, peerReference{fmt.Sprintf("%064x", 256), ref.Header})} {
		body = commandJSON(t, peerPinsBody{p, bad, 1})
		if _, err := DecodePeerCommand(commandProof(t, f, serviceauthority.CustodyAddPins, body), body); err == nil {
			t.Fatal("accepted invalid pin set")
		}
	}
	large := make([]byte, objectcustodywire.MaximumPlaintextBytes+objectcustodywire.WireOverhead)
	copy(large, wire[:objectcustodywire.HeaderBytes])
	binary.BigEndian.PutUint64(large[46:54], objectcustodywire.MaximumPlaintextBytes)
	verified := commandProof(t, f, serviceauthority.CustodyPutObject, large)
	if c, err := DecodePeerCommand(verified, large); err != nil || len(c.wire) != len(large) {
		t.Fatal("maximum put failed", err)
	}
	if _, err := DecodePeerCommand(verified, append(large, 0)); err == nil {
		t.Fatal("oversized put accepted")
	}
	for _, offset := range []int{0, 4, 20, 44, 46} {
		changed := bytes.Clone(wire)
		changed[offset] ^= 0x80
		if _, err := DecodePeerCommand(commandProof(t, f, serviceauthority.CustodyPutObject, changed), changed); err == nil {
			t.Fatalf("signed invalid put accepted at %d", offset)
		}
	}
}

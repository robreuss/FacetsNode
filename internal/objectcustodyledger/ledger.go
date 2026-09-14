// Package objectcustodyledger is the isolated neutral storage owner's durable
// reservation/pin component. No HTTP or service calls use it yet. Its binding
// registration and receipt-confirmation inputs MUST come from the separately
// authenticated service adapter before production integration. Structure and
// equality checks here are not proof of principal or service authorization.
package objectcustodyledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"math"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/robreuss/FacetsNode/internal/objectcustodyfiles"
	"github.com/robreuss/FacetsNode/internal/objectcustodywire"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

//go:embed schema.sql
var schema string

var (
	ErrInvalid     = errors.New("invalid immutable custody ledger state")
	ErrConflict    = errors.New("immutable custody operation conflicts with retained state")
	ErrUnavailable = errors.New("immutable custody ledger unavailable")
	ErrIncomplete  = errors.New("immutable custody publication is incomplete")
)

const MaximumPinBatch = 256

type Binding struct {
	ID                                         uuid.UUID
	ServiceKind                                string
	ServiceScopeID, ResourceID, ContentScopeID uuid.UUID
	ContentEpoch                               uint64
}

func (b Binding) Validate() error {
	if b.ID == uuid.Nil || b.ServiceScopeID == uuid.Nil || b.ResourceID == uuid.Nil ||
		b.ContentScopeID == uuid.Nil || b.ContentEpoch == 0 ||
		(b.ServiceKind != "device_sync" && b.ServiceKind != "backup_custody") {
		return ErrInvalid
	}
	return nil
}

type Publication struct {
	BindingID, ID                  uuid.UUID
	RootDigest                     string
	ObjectCount                    int64
	State                          string
	InventoryDigest, ReceiptDigest string
}

func (p Publication) validateIdentity() error {
	if p.BindingID == uuid.Nil || p.ID == uuid.Nil || !validDigest(p.RootDigest) || p.ObjectCount < 0 {
		return ErrInvalid
	}
	return nil
}

func (p Publication) validateState() error {
	if p.validateIdentity() != nil {
		return ErrInvalid
	}
	switch p.State {
	case "open":
		if p.InventoryDigest != "" || p.ReceiptDigest != "" {
			return ErrInvalid
		}
	case "prepared":
		if !validDigest(p.InventoryDigest) || p.ReceiptDigest != "" {
			return ErrInvalid
		}
	case "committed":
		if !validDigest(p.InventoryDigest) || !validDigest(p.ReceiptDigest) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type Ledger struct {
	pool     *pgxpool.Pool
	poolID   uuid.UUID
	files    *objectcustodyfiles.Store
	capacity storagecapacity.Provider
	fault    func(string) error // fixed labels only; test fault injection
}

// Initialize creates only an empty dedicated schema. No deployed service data
// is migrated, truncated or adopted. Callers own that dedicated database/schema.
func Initialize(ctx context.Context, pool *pgxpool.Pool, poolID uuid.UUID) error {
	if ctx == nil || pool == nil || poolID == uuid.Nil {
		return ErrInvalid
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return ErrUnavailable
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(507093455930912)`); err != nil {
		return ErrUnavailable
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN ('r','v','m','f','p')`).Scan(&count); err != nil || count != 0 {
		return ErrInvalid
	}
	if _, err = tx.Exec(ctx, schema); err != nil {
		return ErrUnavailable
	}
	if _, err = tx.Exec(ctx, `INSERT INTO immutable_custody_pool VALUES (true,$1,1)`, poolID); err != nil {
		return ErrUnavailable
	}
	if tx.Commit(ctx) != nil {
		return ErrUnavailable
	}
	return nil
}

// Open requires the same configured pool, file owner and capacity authority for
// every caller. It cannot prove that a host assigned one ledger per filesystem;
// authenticated provisioning must enforce that before exposing a service.
func Open(ctx context.Context, pool *pgxpool.Pool, poolID uuid.UUID, files *objectcustodyfiles.Store, capacity storagecapacity.Provider) (*Ledger, error) {
	if ctx == nil || pool == nil || poolID == uuid.Nil || files == nil || capacity == nil {
		return nil, ErrInvalid
	}
	l := &Ledger{pool: pool, poolID: poolID, files: files, capacity: capacity}
	tx, err := l.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN ('r','v','m','f','p')`).Scan(&count); err != nil || count != 5 {
		return nil, ErrInvalid
	}
	if tx.Commit(ctx) != nil {
		return nil, ErrUnavailable
	}
	return l, nil
}

// RegisterBinding is a trusted-owner storage seam, NOT a public grant endpoint.
// The future adapter must verify current, dual-service scope-link authority.
func (l *Ledger) RegisterBinding(ctx context.Context, binding Binding) error {
	if binding.Validate() != nil {
		return ErrInvalid
	}
	tx, err := l.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	existing, err := loadBinding(ctx, tx, binding.ID)
	if err == nil {
		if existing != binding {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err = l.admit(ctx, tx, storagecapacity.MutationMetadataAllowance); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO immutable_custody_bindings VALUES ($1,$2,$3,$4,$5,$6)`, binding.ID, binding.ServiceKind,
		binding.ServiceScopeID, binding.ResourceID, binding.ContentScopeID, strconv.FormatUint(binding.ContentEpoch, 10)); err != nil {
		return ErrUnavailable
	}
	return l.commit(ctx, tx)
}

// Reserve persists the exact object's one physical reservation before a file
// write. Multiple compatible bindings reuse it, not one reservation per pin.
func (l *Ledger) Reserve(ctx context.Context, bindingID uuid.UUID, reference objectcustodywire.Reference) error {
	if reference.Validate() != nil {
		return ErrInvalid
	}
	tx, err := l.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = matchBinding(ctx, tx, bindingID, reference); err != nil {
		return err
	}
	_, err = loadObject(ctx, tx, reference)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	count := wireBytes(reference)
	reservation, err := storagecapacity.UploadReservation(count, 0, 0)
	if err != nil {
		return err
	}
	if err = l.admit(ctx, tx, reservation); err != nil {
		return err
	}
	header, _ := reference.Header.Encode()
	if _, err = tx.Exec(ctx, `INSERT INTO immutable_custody_objects VALUES ($1,$2,$3,'reserved')`, reference.CiphertextID, header, count); err != nil {
		return ErrUnavailable
	}
	return l.commit(ctx, tx)
}

// Put combines a previously durable reservation with verified file custody.
// Rollback after a file effect keeps the reservation for exact reconciliation.
func (l *Ledger) Put(ctx context.Context, bindingID uuid.UUID, reference objectcustodywire.Reference, wire []byte) error {
	if objectcustodywire.Verify(wire, reference) != nil {
		return ErrInvalid
	}
	if err := l.Reserve(ctx, bindingID, reference); err != nil {
		return err
	}
	tx, err := l.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = matchBinding(ctx, tx, bindingID, reference); err != nil {
		return err
	}
	state, err := loadObject(ctx, tx, reference)
	if err != nil {
		return err
	}
	if state == "retained" {
		_, err = l.files.Read(reference)
		return err
	}
	outstanding, err := reservations(ctx, tx)
	if err != nil {
		return err
	}
	admission := func(offset, count int64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if offset < 0 || count < 0 || offset > wireBytes(reference)-count || outstanding < offset ||
			(count == 0 && offset != wireBytes(reference)) {
			return ErrInvalid
		}
		snapshot, err := l.capacity.Snapshot(ctx)
		if err != nil {
			return err
		}
		// Physical free space already excludes this exact retained prefix. The
		// pool transaction fences other reservations while this bounded wire is
		// written; the remaining staging/publication promises stay charged.
		return storagecapacity.Check(snapshot, outstanding-offset, 0)
	}
	if err = l.files.PutWithWriteAdmission(reference, wire, admission); err != nil {
		return err
	}
	if err = l.checkpoint("after_file_custody"); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE immutable_custody_objects SET state='retained' WHERE ciphertext_id=$1 AND state='reserved'`, reference.CiphertextID); err != nil {
		return ErrUnavailable
	}
	return l.commit(ctx, tx)
}

func (l *Ledger) Read(ctx context.Context, bindingID uuid.UUID, reference objectcustodywire.Reference) ([]byte, error) {
	if reference.Validate() != nil {
		return nil, ErrInvalid
	}
	tx, err := l.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err = matchBinding(ctx, tx, bindingID, reference); err != nil {
		return nil, err
	}
	state, err := loadObject(ctx, tx, reference)
	if err != nil {
		return nil, err
	}
	if state != "retained" {
		return nil, ErrIncomplete
	}
	return l.files.Read(reference)
}

func (l *Ledger) BeginPublication(ctx context.Context, requested Publication) (Publication, error) {
	if requested.validateIdentity() != nil || requested.State != "" || requested.InventoryDigest != "" || requested.ReceiptDigest != "" {
		return Publication{}, ErrInvalid
	}
	tx, err := l.begin(ctx)
	if err != nil {
		return Publication{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = loadBinding(ctx, tx, requested.BindingID); err != nil {
		return Publication{}, err
	}
	existing, err := loadPublication(ctx, tx, requested.BindingID, requested.ID)
	if err == nil {
		if existing.RootDigest != requested.RootDigest || existing.ObjectCount != requested.ObjectCount {
			return Publication{}, ErrConflict
		}
		return existing, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Publication{}, err
	}
	if err = l.admit(ctx, tx, storagecapacity.MutationMetadataAllowance); err != nil {
		return Publication{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO immutable_custody_publications (binding_id,publication_id,root_digest,object_count,state) VALUES ($1,$2,$3,$4,'open')`,
		requested.BindingID, requested.ID, requested.RootDigest, requested.ObjectCount); err != nil {
		return Publication{}, ErrUnavailable
	}
	requested.State = "open"
	return requested, l.commit(ctx, tx)
}

func (l *Ledger) AddPins(ctx context.Context, bindingID, publicationID uuid.UUID, references []objectcustodywire.Reference) error {
	if len(references) == 0 || len(references) > MaximumPinBatch {
		return ErrInvalid
	}
	tx, err := l.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	publication, err := loadPublication(ctx, tx, bindingID, publicationID)
	if err != nil {
		return err
	}
	var currentCount int64
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM immutable_custody_pins WHERE binding_id=$1 AND publication_id=$2`, bindingID, publicationID).Scan(&currentCount); err != nil {
		return ErrUnavailable
	}
	var added int64
	for _, reference := range references {
		if reference.Validate() != nil || matchBinding(ctx, tx, bindingID, reference) != nil {
			return ErrInvalid
		}
		if _, err = loadObject(ctx, tx, reference); err != nil {
			return err
		}
		var exists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM immutable_custody_pins WHERE binding_id=$1 AND publication_id=$2 AND ciphertext_id=$3)`, bindingID, publicationID, reference.CiphertextID).Scan(&exists); err != nil {
			return ErrUnavailable
		}
		if exists {
			continue
		}
		if publication.State != "open" {
			return ErrConflict
		}
		if currentCount >= publication.ObjectCount {
			return ErrConflict
		}
		added++
		if err = l.admit(ctx, tx, added*storagecapacity.MutationMetadataAllowance); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO immutable_custody_pins VALUES ($1,$2,$3)`, bindingID, publicationID, reference.CiphertextID); err != nil {
			return ErrUnavailable
		}
		currentCount++
	}
	return l.commit(ctx, tx)
}

// Prepare verifies a streamed opaque closure without holding the global pool
// transaction across a whole resource. Finalization rechecks the exact inventory
// under the pool lock. Pins cannot be removed and file deletion is not exposed.
func (l *Ledger) Prepare(ctx context.Context, bindingID, publicationID uuid.UUID) (Publication, error) {
	if l == nil || ctx == nil || l.pool == nil {
		return Publication{}, ErrInvalid
	}
	initial, err := loadPublication(ctx, l.pool, bindingID, publicationID)
	if err != nil {
		return Publication{}, err
	}
	digest, err := l.inventory(ctx, l.pool, initial, true)
	if err != nil {
		return Publication{}, err
	}
	tx, err := l.begin(ctx)
	if err != nil {
		return Publication{}, err
	}
	defer tx.Rollback(ctx)
	current, err := loadPublication(ctx, tx, bindingID, publicationID)
	if err != nil {
		return Publication{}, err
	}
	if current.RootDigest != initial.RootDigest || current.ObjectCount != initial.ObjectCount {
		return Publication{}, ErrConflict
	}
	currentDigest, err := l.inventory(ctx, tx, current, false)
	if err != nil {
		return Publication{}, err
	}
	if currentDigest != digest {
		return Publication{}, ErrConflict
	}
	if current.State != "open" {
		if current.InventoryDigest != digest {
			return Publication{}, ErrConflict
		}
		return current, nil
	}
	if err = l.admit(ctx, tx, storagecapacity.MutationMetadataAllowance); err != nil {
		return Publication{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE immutable_custody_publications SET state='prepared',inventory_digest=$3 WHERE binding_id=$1 AND publication_id=$2`, bindingID, publicationID, digest); err != nil {
		return Publication{}, ErrUnavailable
	}
	current.State = "prepared"
	current.InventoryDigest = digest
	return current, l.commit(ctx, tx)
}

// Confirm is a trusted-owner persistence seam. The production adapter must
// authenticate the service's exact durable root receipt before invoking it.
func (l *Ledger) Confirm(ctx context.Context, bindingID, publicationID uuid.UUID, rootDigest, inventoryDigest, receiptDigest string) (Publication, error) {
	if !validDigest(rootDigest) || !validDigest(inventoryDigest) || !validDigest(receiptDigest) {
		return Publication{}, ErrInvalid
	}
	tx, err := l.begin(ctx)
	if err != nil {
		return Publication{}, err
	}
	defer tx.Rollback(ctx)
	current, err := loadPublication(ctx, tx, bindingID, publicationID)
	if err != nil {
		return Publication{}, err
	}
	if current.State == "open" {
		return Publication{}, ErrIncomplete
	}
	if current.RootDigest != rootDigest || current.InventoryDigest != inventoryDigest {
		return Publication{}, ErrConflict
	}
	if current.State == "committed" {
		if current.ReceiptDigest != receiptDigest {
			return Publication{}, ErrConflict
		}
		return current, nil
	}
	if err = l.admit(ctx, tx, storagecapacity.MutationMetadataAllowance); err != nil {
		return Publication{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE immutable_custody_publications SET state='committed',receipt_digest=$3 WHERE binding_id=$1 AND publication_id=$2`, bindingID, publicationID, receiptDigest); err != nil {
		return Publication{}, ErrUnavailable
	}
	current.State = "committed"
	current.ReceiptDigest = receiptDigest
	return current, l.commit(ctx, tx)
}

func (l *Ledger) Publication(ctx context.Context, bindingID, publicationID uuid.UUID) (Publication, error) {
	if l == nil || ctx == nil {
		return Publication{}, ErrInvalid
	}
	return loadPublication(ctx, l.pool, bindingID, publicationID)
}

type querier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (l *Ledger) begin(ctx context.Context) (pgx.Tx, error) {
	if l == nil || ctx == nil || l.pool == nil || l.files == nil || l.capacity == nil {
		return nil, ErrInvalid
	}
	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return nil, ErrUnavailable
	}
	var poolID uuid.UUID
	var version int
	if err = tx.QueryRow(ctx, `SELECT pool_id,version FROM immutable_custody_pool WHERE singleton FOR UPDATE`).Scan(&poolID, &version); err != nil || poolID != l.poolID || version != 1 {
		tx.Rollback(ctx)
		return nil, ErrInvalid
	}
	return tx, nil
}

func (l *Ledger) admit(ctx context.Context, tx pgx.Tx, additional int64) error {
	outstanding, err := reservations(ctx, tx)
	if err != nil {
		return err
	}
	snapshot, err := l.capacity.Snapshot(ctx)
	if err != nil {
		return err
	}
	return storagecapacity.Check(snapshot, outstanding, additional)
}

func reservations(ctx context.Context, q querier) (int64, error) {
	var value int64
	if err := q.QueryRow(ctx, `SELECT COALESCE(sum(2::numeric*wire_bytes+$1::bigint),0)::bigint FROM immutable_custody_objects WHERE state='reserved'`, storagecapacity.UploadMetadataAllowance).Scan(&value); err != nil || value < 0 {
		return 0, ErrInvalid
	}
	return value, nil
}

func loadBinding(ctx context.Context, q querier, id uuid.UUID) (Binding, error) {
	if id == uuid.Nil {
		return Binding{}, ErrInvalid
	}
	var binding Binding
	var epoch string
	err := q.QueryRow(ctx, `SELECT binding_id,service_kind,service_scope_id,resource_id,content_scope_id,content_epoch FROM immutable_custody_bindings WHERE binding_id=$1`, id).Scan(
		&binding.ID, &binding.ServiceKind, &binding.ServiceScopeID, &binding.ResourceID, &binding.ContentScopeID, &epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return Binding{}, err
	}
	if err != nil {
		return Binding{}, ErrUnavailable
	}
	binding.ContentEpoch, err = strconv.ParseUint(epoch, 10, 64)
	if err != nil || strconv.FormatUint(binding.ContentEpoch, 10) != epoch || binding.Validate() != nil {
		return Binding{}, ErrInvalid
	}
	return binding, nil
}

func matchBinding(ctx context.Context, q querier, id uuid.UUID, r objectcustodywire.Reference) error {
	if r.Validate() != nil {
		return ErrInvalid
	}
	binding, err := loadBinding(ctx, q, id)
	if err != nil {
		return err
	}
	if binding.ContentScopeID != r.Header.ScopeID || binding.ContentEpoch != r.Header.ContentEpoch {
		return ErrInvalid
	}
	return nil
}

func loadObject(ctx context.Context, q querier, r objectcustodywire.Reference) (string, error) {
	var header []byte
	var count int64
	var state string
	err := q.QueryRow(ctx, `SELECT wire_header,wire_bytes,state FROM immutable_custody_objects WHERE ciphertext_id=$1`, r.CiphertextID).Scan(&header, &count, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	if err != nil {
		return "", ErrUnavailable
	}
	expected, headerErr := r.Header.Encode()
	if headerErr != nil || !bytes.Equal(expected, header) || count != wireBytes(r) || (state != "reserved" && state != "retained") {
		return "", ErrInvalid
	}
	return state, nil
}

func loadPublication(ctx context.Context, q querier, bindingID, id uuid.UUID) (Publication, error) {
	if bindingID == uuid.Nil || id == uuid.Nil {
		return Publication{}, ErrInvalid
	}
	var p Publication
	err := q.QueryRow(ctx, `SELECT binding_id,publication_id,root_digest,object_count,state,COALESCE(inventory_digest,''),COALESCE(receipt_digest,'') FROM immutable_custody_publications WHERE binding_id=$1 AND publication_id=$2`, bindingID, id).Scan(
		&p.BindingID, &p.ID, &p.RootDigest, &p.ObjectCount, &p.State, &p.InventoryDigest, &p.ReceiptDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return Publication{}, err
	}
	if err != nil {
		return Publication{}, ErrUnavailable
	}
	if p.validateState() != nil {
		return Publication{}, ErrInvalid
	}
	return p, nil
}

func (l *Ledger) inventory(ctx context.Context, q querier, p Publication, verifyFiles bool) (string, error) {
	binding, err := loadBinding(ctx, q, p.BindingID)
	if err != nil {
		return "", err
	}
	digest := inventoryHasher(p, binding)
	rows, err := q.Query(ctx, `SELECT o.ciphertext_id,o.wire_header,o.wire_bytes,o.state FROM immutable_custody_pins p JOIN immutable_custody_objects o USING (ciphertext_id) WHERE p.binding_id=$1 AND p.publication_id=$2 ORDER BY o.ciphertext_id COLLATE "C"`, p.BindingID, p.ID)
	if err != nil {
		return "", ErrUnavailable
	}
	defer rows.Close()
	var count int64
	for rows.Next() {
		var id, state string
		var header []byte
		var length int64
		if rows.Scan(&id, &header, &length, &state) != nil {
			return "", ErrUnavailable
		}
		if count >= p.ObjectCount || state != "retained" {
			return "", ErrIncomplete
		}
		reference, err := decodeReference(header, id, length)
		if err != nil || reference.Header.ScopeID != binding.ContentScopeID || reference.Header.ContentEpoch != binding.ContentEpoch {
			return "", ErrInvalid
		}
		if verifyFiles {
			if _, err = l.files.Read(reference); err != nil {
				return "", err
			}
		}
		idBytes, _ := hex.DecodeString(id)
		_, _ = digest.Write(idBytes)
		count++
	}
	if rows.Err() != nil {
		return "", ErrUnavailable
	}
	if count != p.ObjectCount {
		return "", ErrIncomplete
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func inventoryHasher(p Publication, b Binding) hash.Hash {
	digest := sha256.New()
	_, _ = digest.Write([]byte("Facets immutable custody publication inventory v1\x00"))
	for _, id := range []uuid.UUID{p.BindingID, p.ID, b.ContentScopeID} {
		_, _ = digest.Write(id[:])
	}
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], b.ContentEpoch)
	_, _ = digest.Write(number[:])
	binary.BigEndian.PutUint64(number[:], uint64(p.ObjectCount))
	_, _ = digest.Write(number[:])
	root, _ := hex.DecodeString(p.RootDigest)
	_, _ = digest.Write(root)
	return digest
}

func decodeReference(header []byte, id string, length int64) (objectcustodywire.Reference, error) {
	if len(header) != objectcustodywire.HeaderBytes || !validDigest(id) || length < objectcustodywire.WireOverhead || length > objectcustodywire.WireOverhead+objectcustodywire.MaximumPlaintextBytes {
		return objectcustodywire.Reference{}, ErrInvalid
	}
	var h objectcustodywire.Header
	copy(h.ScopeID[:], header[4:20])
	h.ContentEpoch = binary.BigEndian.Uint64(header[20:28])
	copy(h.IncarnationID[:], header[28:44])
	h.PlaintextBytes = binary.BigEndian.Uint64(header[46:54])
	encoded, err := h.Encode()
	if err != nil || !bytes.Equal(encoded, header) || h.PlaintextBytes > math.MaxInt64-uint64(objectcustodywire.WireOverhead) || int64(h.PlaintextBytes)+objectcustodywire.WireOverhead != length {
		return objectcustodywire.Reference{}, ErrInvalid
	}
	return objectcustodywire.Reference{Header: h, CiphertextID: id}, nil
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}
func wireBytes(r objectcustodywire.Reference) int64 {
	return int64(r.Header.PlaintextBytes) + objectcustodywire.WireOverhead
}
func (l *Ledger) checkpoint(point string) error {
	if l.fault != nil {
		return l.fault(point)
	}
	return nil
}
func (l *Ledger) commit(ctx context.Context, tx pgx.Tx) error {
	if err := l.checkpoint("before_database_commit"); err != nil {
		return err
	}
	if tx.Commit(ctx) != nil {
		return ErrUnavailable
	}
	return l.checkpoint("after_database_commit")
}

package objectcustodyledger

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/robreuss/FacetsNode/internal/objectcustodywire"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

const RestoreLeaseLifetime = time.Hour

// RestoreLease describes a durable result, not a transferable read credential.
// Every operation must be authenticated by the service adapter before calling
// this isolated persistence component. Reads check current database state.
type RestoreLease struct {
	BindingID, PublicationID, ID    uuid.UUID
	Revision, ExpiresAtMilliseconds int64
	Closed                          bool
}

func (lease RestoreLease) validate() error {
	if lease.BindingID == uuid.Nil || lease.PublicationID == uuid.Nil || lease.ID == uuid.Nil ||
		lease.Revision <= 0 || lease.ExpiresAtMilliseconds <= 0 {
		return ErrInvalid
	}
	return nil
}

// RetentionObligations is a read-only diagnostic snapshot, NEVER a deletion
// permit. Future collection must recheck all references and holds while fencing
// new references at the actual physical deletion boundary.
type RetentionObligations struct {
	PendingUpload                     bool
	Publications, ActiveRestoreLeases int64
}

// Retire is a trusted-owner persistence seam, not authority to prune history.
// The future adapter must authenticate an explicit service retirement decision
// for this exact committed root. Open/prepared/uncertain roots are not retired.
// Pin metadata remains; active restore leases and other publications still hold
// independent byte-retention obligations. No physical file is removed here.
func (l *Ledger) Retire(ctx context.Context, expected Publication, decisionDigest string) (Publication, error) {
	if expected.validateState() != nil || expected.State != "committed" || !validDigest(decisionDigest) {
		return Publication{}, ErrInvalid
	}
	tx, err := l.begin(ctx)
	if err != nil {
		return Publication{}, err
	}
	defer tx.Rollback(ctx)
	current, err := loadPublication(ctx, tx, expected.BindingID, expected.ID)
	if err != nil {
		return Publication{}, err
	}
	if !matchesCommittedIdentity(current, expected) {
		return Publication{}, ErrConflict
	}
	if current.State == "retired" {
		if current.RetirementDigest != decisionDigest {
			return Publication{}, ErrConflict
		}
		return current, nil
	}
	if _, err = tx.Exec(ctx, `UPDATE immutable_custody_publications SET state='retired',retirement_digest=$3 WHERE binding_id=$1 AND publication_id=$2`, current.BindingID, current.ID, decisionDigest); err != nil {
		return Publication{}, ErrUnavailable
	}
	current.State, current.RetirementDigest = "retired", decisionDigest
	return current, l.commit(ctx, tx)
}

func matchesCommittedIdentity(current, expected Publication) bool {
	if current.validateState() != nil || expected.validateState() != nil || expected.State != "committed" ||
		(current.State != "committed" && current.State != "retired") {
		return false
	}
	current.State, current.RetirementDigest = "committed", ""
	return current == expected
}

// AcquireLease pins one exact committed publication for an authenticated
// restore. The caller retains leaseID before sending. Database time alone sets
// the deadline; replay returns the original receipt without extending it.
func (l *Ledger) AcquireLease(ctx context.Context, expected Publication, leaseID uuid.UUID) (RestoreLease, error) {
	if expected.validateState() != nil || expected.State != "committed" || leaseID == uuid.Nil {
		return RestoreLease{}, ErrInvalid
	}
	tx, err := l.begin(ctx)
	if err != nil {
		return RestoreLease{}, err
	}
	defer tx.Rollback(ctx)
	current, err := loadPublication(ctx, tx, expected.BindingID, expected.ID)
	if err != nil {
		return RestoreLease{}, err
	}
	if !matchesCommittedIdentity(current, expected) {
		return RestoreLease{}, ErrConflict
	}
	result := RestoreLease{BindingID: expected.BindingID, PublicationID: expected.ID, ID: leaseID}
	if prior, err := loadLeaseOperation(ctx, tx, result, leaseID, "acquire", 0); err == nil {
		if _, err = loadLease(ctx, tx, result.BindingID, result.PublicationID, result.ID); err != nil {
			return RestoreLease{}, err
		}
		return prior, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return RestoreLease{}, err
	}
	if current.State != "committed" {
		return RestoreLease{}, ErrConflict
	}
	if _, err = loadLease(ctx, tx, result.BindingID, result.PublicationID, result.ID); err == nil {
		return RestoreLease{}, ErrConflict
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return RestoreLease{}, err
	}
	now, err := databaseNow(ctx, tx)
	if err != nil {
		return RestoreLease{}, err
	}
	if err = l.admit(ctx, tx, 2*storagecapacity.MutationMetadataAllowance); err != nil {
		return RestoreLease{}, err
	}
	result.Revision, result.ExpiresAtMilliseconds = 1, now+RestoreLeaseLifetime.Milliseconds()
	if _, err = tx.Exec(ctx, `INSERT INTO immutable_custody_leases VALUES ($1,$2,$3,$4,$5,false)`, result.BindingID, result.PublicationID, result.ID, result.Revision, result.ExpiresAtMilliseconds); err != nil {
		return RestoreLease{}, ErrUnavailable
	}
	if err = recordLeaseOperation(ctx, tx, result, leaseID, "acquire", 0); err != nil {
		return RestoreLease{}, err
	}
	return result, l.commit(ctx, tx)
}

// RenewLease extends an active lease, including an in-progress restore of a
// subsequently retired root. It does not grant permission to start a new one.
func (l *Ledger) RenewLease(ctx context.Context, bindingID, publicationID, leaseID, operationID uuid.UUID, expectedRevision int64) (RestoreLease, error) {
	return l.changeLease(ctx, bindingID, publicationID, leaseID, operationID, expectedRevision, "renew")
}

// CloseLease is terminal and remains available under storage pressure.
func (l *Ledger) CloseLease(ctx context.Context, bindingID, publicationID, leaseID, operationID uuid.UUID, expectedRevision int64) (RestoreLease, error) {
	return l.changeLease(ctx, bindingID, publicationID, leaseID, operationID, expectedRevision, "close")
}

func (l *Ledger) changeLease(ctx context.Context, bindingID, publicationID, leaseID, operationID uuid.UUID, expectedRevision int64, kind string) (RestoreLease, error) {
	if bindingID == uuid.Nil || publicationID == uuid.Nil || leaseID == uuid.Nil || operationID == uuid.Nil ||
		expectedRevision <= 0 || expectedRevision == math.MaxInt64 || (kind != "renew" && kind != "close") {
		return RestoreLease{}, ErrInvalid
	}
	tx, err := l.begin(ctx)
	if err != nil {
		return RestoreLease{}, err
	}
	defer tx.Rollback(ctx)
	current, err := loadLease(ctx, tx, bindingID, publicationID, leaseID)
	if err != nil {
		return RestoreLease{}, err
	}
	if prior, err := loadLeaseOperation(ctx, tx, current, operationID, kind, expectedRevision); err == nil {
		return prior, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return RestoreLease{}, err
	}
	publication, err := loadPublication(ctx, tx, bindingID, publicationID)
	if err != nil {
		return RestoreLease{}, err
	}
	if current.Closed || current.Revision != expectedRevision || (publication.State != "committed" && publication.State != "retired") {
		return RestoreLease{}, ErrConflict
	}
	if kind == "renew" {
		now, err := databaseNow(ctx, tx)
		if err != nil {
			return RestoreLease{}, err
		}
		if current.ExpiresAtMilliseconds <= now {
			return RestoreLease{}, ErrConflict
		}
		if err = l.admit(ctx, tx, storagecapacity.MutationMetadataAllowance); err != nil {
			return RestoreLease{}, err
		}
		// A backward database-clock correction must not shorten a live lease.
		current.ExpiresAtMilliseconds = max(current.ExpiresAtMilliseconds, now+RestoreLeaseLifetime.Milliseconds())
	} else {
		current.Closed = true
	}
	current.Revision++
	if _, err = tx.Exec(ctx, `UPDATE immutable_custody_leases SET revision=$4,expires_at_milliseconds=$5,closed=$6 WHERE binding_id=$1 AND publication_id=$2 AND lease_id=$3`, bindingID, publicationID, leaseID, current.Revision, current.ExpiresAtMilliseconds, current.Closed); err != nil {
		return RestoreLease{}, ErrUnavailable
	}
	if err = recordLeaseOperation(ctx, tx, current, operationID, kind, expectedRevision); err != nil {
		return RestoreLease{}, err
	}
	return current, l.commit(ctx, tx)
}

// ReadLeased returns one verified bounded snapshot only while this exact live
// lease protects its publication and the reference is actually pinned there.
func (l *Ledger) ReadLeased(ctx context.Context, bindingID, publicationID, leaseID uuid.UUID, reference objectcustodywire.Reference) ([]byte, error) {
	if reference.Validate() != nil {
		return nil, ErrInvalid
	}
	tx, err := l.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	lease, err := loadLease(ctx, tx, bindingID, publicationID, leaseID)
	if err != nil {
		return nil, err
	}
	now, err := databaseNow(ctx, tx)
	if err != nil {
		return nil, err
	}
	if lease.Closed || lease.ExpiresAtMilliseconds <= now {
		return nil, ErrConflict
	}
	publication, err := loadPublication(ctx, tx, bindingID, publicationID)
	if err != nil {
		return nil, err
	}
	if publication.State != "committed" && publication.State != "retired" {
		return nil, ErrInvalid
	}
	if err = matchBinding(ctx, tx, bindingID, reference); err != nil {
		return nil, err
	}
	var pinned bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM immutable_custody_pins WHERE binding_id=$1 AND publication_id=$2 AND ciphertext_id=$3)`, bindingID, publicationID, reference.CiphertextID).Scan(&pinned); err != nil {
		return nil, ErrUnavailable
	}
	if !pinned {
		return nil, ErrInvalid
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

func (l *Ledger) Lease(ctx context.Context, bindingID, publicationID, leaseID uuid.UUID) (RestoreLease, error) {
	tx, err := l.begin(ctx)
	if err != nil {
		return RestoreLease{}, err
	}
	defer tx.Rollback(ctx)
	return loadLease(ctx, tx, bindingID, publicationID, leaseID)
}

func (l *Ledger) Retention(ctx context.Context, reference objectcustodywire.Reference) (RetentionObligations, error) {
	if reference.Validate() != nil {
		return RetentionObligations{}, ErrInvalid
	}
	tx, err := l.begin(ctx)
	if err != nil {
		return RetentionObligations{}, err
	}
	defer tx.Rollback(ctx)
	state, err := loadObject(ctx, tx, reference)
	if err != nil {
		return RetentionObligations{}, err
	}
	now, err := databaseNow(ctx, tx)
	if err != nil {
		return RetentionObligations{}, err
	}
	result := RetentionObligations{PendingUpload: state == "reserved"}
	if err = tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM immutable_custody_pins p JOIN immutable_custody_publications r USING(binding_id,publication_id) WHERE p.ciphertext_id=$1 AND r.state<>'retired'),
		(SELECT count(*) FROM immutable_custody_pins p JOIN immutable_custody_leases l USING(binding_id,publication_id) WHERE p.ciphertext_id=$1 AND NOT l.closed AND l.expires_at_milliseconds>$2)`, reference.CiphertextID, now).Scan(&result.Publications, &result.ActiveRestoreLeases); err != nil {
		return RetentionObligations{}, ErrUnavailable
	}
	return result, nil
}

func databaseNow(ctx context.Context, q querier) (int64, error) {
	var now int64
	if q.QueryRow(ctx, `SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint`).Scan(&now) != nil || now <= 0 || now > math.MaxInt64-RestoreLeaseLifetime.Milliseconds() {
		return 0, ErrUnavailable
	}
	return now, nil
}

func loadLease(ctx context.Context, q querier, bindingID, publicationID, leaseID uuid.UUID) (RestoreLease, error) {
	if bindingID == uuid.Nil || publicationID == uuid.Nil || leaseID == uuid.Nil {
		return RestoreLease{}, ErrInvalid
	}
	result := RestoreLease{BindingID: bindingID, PublicationID: publicationID, ID: leaseID}
	err := q.QueryRow(ctx, `SELECT revision,expires_at_milliseconds,closed FROM immutable_custody_leases WHERE binding_id=$1 AND publication_id=$2 AND lease_id=$3`, bindingID, publicationID, leaseID).Scan(&result.Revision, &result.ExpiresAtMilliseconds, &result.Closed)
	if errors.Is(err, pgx.ErrNoRows) {
		return RestoreLease{}, err
	}
	if err != nil {
		return RestoreLease{}, ErrUnavailable
	}
	if result.validate() != nil {
		return RestoreLease{}, ErrInvalid
	}
	// Current state and its durable outcome must agree. A partially corrupted
	// current row must not turn a closed/expired lease into live read authority.
	var matches bool
	if err = q.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM immutable_custody_lease_operations WHERE binding_id=$1 AND publication_id=$2 AND lease_id=$3 AND result_revision=$4 AND result_expires_at_milliseconds=$5 AND result_closed=$6)
		AND NOT EXISTS(SELECT 1 FROM immutable_custody_lease_operations WHERE binding_id=$1 AND publication_id=$2 AND lease_id=$3 AND result_revision>$4)`, result.BindingID, result.PublicationID, result.ID, result.Revision, result.ExpiresAtMilliseconds, result.Closed).Scan(&matches); err != nil {
		return RestoreLease{}, ErrUnavailable
	}
	if !matches {
		return RestoreLease{}, ErrInvalid
	}
	return result, nil
}

func loadLeaseOperation(ctx context.Context, q querier, lease RestoreLease, operationID uuid.UUID, kind string, baseRevision int64) (RestoreLease, error) {
	var storedKind string
	var storedBase int64
	result := RestoreLease{BindingID: lease.BindingID, PublicationID: lease.PublicationID, ID: lease.ID}
	err := q.QueryRow(ctx, `SELECT kind,base_revision,result_revision,result_expires_at_milliseconds,result_closed FROM immutable_custody_lease_operations WHERE binding_id=$1 AND publication_id=$2 AND lease_id=$3 AND operation_id=$4`, lease.BindingID, lease.PublicationID, lease.ID, operationID).Scan(&storedKind, &storedBase, &result.Revision, &result.ExpiresAtMilliseconds, &result.Closed)
	if errors.Is(err, pgx.ErrNoRows) {
		return RestoreLease{}, err
	}
	if err != nil {
		return RestoreLease{}, ErrUnavailable
	}
	if result.validate() != nil || storedBase < 0 || result.Revision-1 != storedBase ||
		(storedKind != "acquire" && storedKind != "renew" && storedKind != "close") ||
		(storedKind == "acquire") != (storedBase == 0) || (storedKind == "close") != result.Closed {
		return RestoreLease{}, ErrInvalid
	}
	if storedKind != kind || storedBase != baseRevision {
		return RestoreLease{}, ErrConflict
	}
	return result, nil
}

func recordLeaseOperation(ctx context.Context, tx pgx.Tx, result RestoreLease, operationID uuid.UUID, kind string, baseRevision int64) error {
	if result.validate() != nil || operationID == uuid.Nil || result.Revision-1 != baseRevision {
		return ErrInvalid
	}
	if _, err := tx.Exec(ctx, `INSERT INTO immutable_custody_lease_operations VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, result.BindingID, result.PublicationID, result.ID, operationID, kind, baseRevision, result.Revision, result.ExpiresAtMilliseconds, result.Closed); err != nil {
		return ErrUnavailable
	}
	return nil
}

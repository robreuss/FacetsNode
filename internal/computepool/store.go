package computepool

import (
	"context"
	"errors"
	"sort"
	"sync"

	"github.com/google/uuid"
)

var (
	ErrNotFound = errors.New("Facets Compute Pool record not found")
	ErrConflict = errors.New("Facets Compute Pool revision conflict")
)

type Store interface {
	CreatePool(context.Context, Pool) error
	UpdatePool(context.Context, uint64, Pool) error
	DeletePool(context.Context, uuid.UUID, uint64) error
	PutWorkerEnrollment(context.Context, uint64, WorkerEnrollment) error
	PutOffering(context.Context, uint64, Offering) error
	GetPoolStatus(context.Context, uuid.UUID) (Status, error)
}

type Status struct {
	Version           int                `json:"version"`
	Pool              Pool               `json:"pool"`
	WorkerEnrollments []WorkerEnrollment `json:"workerEnrollments"`
	Offerings         []Offering         `json:"offerings"`
}

func (status Status) Validate() error {
	if status.Version != SchemaVersion || status.Pool.Validate() != nil {
		return ErrInvalid
	}
	enrollments := make(map[uuid.UUID]struct{}, len(status.WorkerEnrollments))
	previousEnrollmentID := ""
	for _, enrollment := range status.WorkerEnrollments {
		if enrollment.Validate() != nil || enrollment.PoolID != status.Pool.PoolID ||
			enrollment.EnrollmentID.String() <= previousEnrollmentID {
			return ErrInvalid
		}
		enrollments[enrollment.EnrollmentID] = struct{}{}
		previousEnrollmentID = enrollment.EnrollmentID.String()
	}
	previousOfferingID := ""
	for _, offering := range status.Offerings {
		_, enrollmentFound := enrollments[offering.WorkerEnrollmentID]
		if offering.Validate() != nil || offering.PoolID != status.Pool.PoolID ||
			!enrollmentFound || offering.OfferingID.String() <= previousOfferingID {
			return ErrInvalid
		}
		previousOfferingID = offering.OfferingID.String()
	}
	return nil
}

type MemoryStore struct {
	mu          sync.RWMutex
	pools       map[uuid.UUID]Pool
	enrollments map[uuid.UUID]WorkerEnrollment
	offerings   map[uuid.UUID]Offering
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		pools:       make(map[uuid.UUID]Pool),
		enrollments: make(map[uuid.UUID]WorkerEnrollment),
		offerings:   make(map[uuid.UUID]Offering),
	}
}

func (store *MemoryStore) CreatePool(_ context.Context, pool Pool) error {
	if pool.Validate() != nil || pool.Revision != 1 {
		return ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, found := store.pools[pool.PoolID]; found {
		return ErrConflict
	}
	store.pools[pool.PoolID] = pool
	return nil
}

func (store *MemoryStore) UpdatePool(
	_ context.Context,
	previousRevision uint64,
	pool Pool,
) error {
	if pool.Validate() != nil || previousRevision == 0 || pool.Revision != previousRevision+1 {
		return ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	current, found := store.pools[pool.PoolID]
	if !found {
		return ErrNotFound
	}
	if current.Revision != previousRevision || current.OwnerAuthorityID != pool.OwnerAuthorityID ||
		current.CreatedAtMilliseconds != pool.CreatedAtMilliseconds ||
		pool.UpdatedAtMilliseconds < current.UpdatedAtMilliseconds ||
		pool.AuthorityRevision < current.AuthorityRevision ||
		(pool.AuthorityRevision == current.AuthorityRevision &&
			pool.AuthorityManifestDigest != current.AuthorityManifestDigest) {
		return ErrConflict
	}
	store.pools[pool.PoolID] = pool
	return nil
}

func (store *MemoryStore) DeletePool(
	_ context.Context,
	poolID uuid.UUID,
	expectedRevision uint64,
) error {
	if poolID == uuid.Nil || expectedRevision == 0 {
		return ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	pool, found := store.pools[poolID]
	if !found {
		return ErrNotFound
	}
	if pool.Revision != expectedRevision {
		return ErrConflict
	}
	delete(store.pools, poolID)
	for enrollmentID, enrollment := range store.enrollments {
		if enrollment.PoolID == poolID {
			delete(store.enrollments, enrollmentID)
		}
	}
	for offeringID, offering := range store.offerings {
		if offering.PoolID == poolID {
			delete(store.offerings, offeringID)
		}
	}
	return nil
}

func (store *MemoryStore) PutWorkerEnrollment(
	_ context.Context,
	previousRevision uint64,
	enrollment WorkerEnrollment,
) error {
	if enrollment.Validate() != nil || enrollment.Revision != previousRevision+1 {
		return ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, found := store.pools[enrollment.PoolID]; !found {
		return ErrNotFound
	}
	current, found := store.enrollments[enrollment.EnrollmentID]
	if !found {
		if previousRevision != 0 {
			return ErrNotFound
		}
	} else if current.Revision != previousRevision || current.PoolID != enrollment.PoolID ||
		current.WorkerID != enrollment.WorkerID ||
		current.WorkerOwnerAuthorityID != enrollment.WorkerOwnerAuthorityID ||
		current.CreatedAtMilliseconds != enrollment.CreatedAtMilliseconds ||
		enrollment.UpdatedAtMilliseconds < current.UpdatedAtMilliseconds ||
		enrollment.ConsentRevision < current.ConsentRevision ||
		(enrollment.ConsentRevision == current.ConsentRevision &&
			(enrollment.PublicSigningKeyEd25519 != current.PublicSigningKeyEd25519 ||
				enrollment.SigningKeyFingerprint != current.SigningKeyFingerprint)) {
		return ErrConflict
	}
	store.enrollments[enrollment.EnrollmentID] = enrollment
	return nil
}

func (store *MemoryStore) PutOffering(
	_ context.Context,
	previousRevision uint64,
	offering Offering,
) error {
	if offering.Validate() != nil || offering.Revision != previousRevision+1 {
		return ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, found := store.pools[offering.PoolID]; !found {
		return ErrNotFound
	}
	enrollment, found := store.enrollments[offering.WorkerEnrollmentID]
	if !found || enrollment.PoolID != offering.PoolID {
		return ErrNotFound
	}
	current, found := store.offerings[offering.OfferingID]
	if !found {
		if previousRevision != 0 {
			return ErrNotFound
		}
	} else if current.Revision != previousRevision || current.PoolID != offering.PoolID ||
		current.WorkerEnrollmentID != offering.WorkerEnrollmentID ||
		current.CreatedAtMilliseconds != offering.CreatedAtMilliseconds ||
		offering.UpdatedAtMilliseconds < current.UpdatedAtMilliseconds ||
		offering.PricingRevision < current.PricingRevision {
		return ErrConflict
	}
	store.offerings[offering.OfferingID] = cloneOffering(offering)
	return nil
}

func (store *MemoryStore) GetPoolStatus(
	_ context.Context,
	poolID uuid.UUID,
) (Status, error) {
	if poolID == uuid.Nil {
		return Status{}, ErrInvalid
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	pool, found := store.pools[poolID]
	if !found {
		return Status{}, ErrNotFound
	}
	enrollments := make([]WorkerEnrollment, 0)
	for _, enrollment := range store.enrollments {
		if enrollment.PoolID == poolID {
			enrollments = append(enrollments, enrollment)
		}
	}
	sort.Slice(enrollments, func(left, right int) bool {
		return enrollments[left].EnrollmentID.String() < enrollments[right].EnrollmentID.String()
	})
	offerings := make([]Offering, 0)
	for _, offering := range store.offerings {
		if offering.PoolID == poolID {
			offerings = append(offerings, cloneOffering(offering))
		}
	}
	sort.Slice(offerings, func(left, right int) bool {
		return offerings[left].OfferingID.String() < offerings[right].OfferingID.String()
	})
	status := Status{
		Version: SchemaVersion, Pool: pool,
		WorkerEnrollments: enrollments, Offerings: offerings,
	}
	if err := status.Validate(); err != nil {
		return Status{}, err
	}
	return status, nil
}

func cloneOffering(offering Offering) Offering {
	offering.ModelIdentifiers = append([]string(nil), offering.ModelIdentifiers...)
	offering.AllowedOperations = append([]string(nil), offering.AllowedOperations...)
	return offering
}

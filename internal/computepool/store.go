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
	PutWorkerCard(context.Context, uint64, WorkerCard) error
	PutOffering(context.Context, uint64, Offering) error
	GetPoolStatus(context.Context, uuid.UUID) (Status, error)
}

type Status struct {
	Version           int                `json:"version"`
	Pool              Pool               `json:"pool"`
	WorkerEnrollments []WorkerEnrollment `json:"workerEnrollments"`
	WorkerCards       []WorkerCard       `json:"workerCards"`
	Offerings         []Offering         `json:"offerings"`
}

func (status Status) Validate() error {
	if status.Version != SchemaVersion || status.Pool.Validate() != nil {
		return ErrInvalid
	}
	enrollments := make(map[uuid.UUID]struct{}, len(status.WorkerEnrollments))
	enrollmentOwners := make(map[uuid.UUID]uuid.UUID, len(status.WorkerEnrollments))
	previousEnrollmentID := ""
	for _, enrollment := range status.WorkerEnrollments {
		if enrollment.Validate() != nil || enrollment.PoolID != status.Pool.PoolID ||
			enrollment.EnrollmentID.String() <= previousEnrollmentID {
			return ErrInvalid
		}
		enrollments[enrollment.EnrollmentID] = struct{}{}
		enrollmentOwners[enrollment.EnrollmentID] = enrollment.WorkerOwnerAuthorityID
		previousEnrollmentID = enrollment.EnrollmentID.String()
	}
	cards := make(map[uuid.UUID]WorkerCard, len(status.WorkerCards))
	previousCardID := ""
	for _, card := range status.WorkerCards {
		owner, enrollmentFound := enrollmentOwners[card.WorkerEnrollmentID]
		if card.Validate() != nil || card.PoolID != status.Pool.PoolID || !enrollmentFound ||
			card.WorkerOwnerAuthorityID != owner || card.WorkerCardID.String() <= previousCardID {
			return ErrInvalid
		}
		cards[card.WorkerCardID] = card
		previousCardID = card.WorkerCardID.String()
	}
	previousOfferingID := ""
	for _, offering := range status.Offerings {
		_, enrollmentFound := enrollments[offering.WorkerEnrollmentID]
		card, cardFound := cards[offering.WorkerCardID]
		cardDigest, digestError := card.Digest()
		if offering.Validate() != nil || offering.PoolID != status.Pool.PoolID ||
			!enrollmentFound || !cardFound || card.WorkerEnrollmentID != offering.WorkerEnrollmentID ||
			offering.WorkerCardRevision != card.Revision || digestError != nil ||
			offering.WorkerCardDigest != cardDigest || offering.OfferingID.String() <= previousOfferingID {
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
	cards       map[uuid.UUID]WorkerCard
	offerings   map[uuid.UUID]Offering
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		pools:       make(map[uuid.UUID]Pool),
		enrollments: make(map[uuid.UUID]WorkerEnrollment),
		cards:       make(map[uuid.UUID]WorkerCard),
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
	for cardID, card := range store.cards {
		if card.PoolID == poolID {
			delete(store.cards, cardID)
		}
	}
	return nil
}

func (store *MemoryStore) PutWorkerCard(
	_ context.Context,
	previousRevision uint64,
	card WorkerCard,
) error {
	if card.Validate() != nil || card.Revision != previousRevision+1 {
		return ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	enrollment, found := store.enrollments[card.WorkerEnrollmentID]
	if !found || enrollment.PoolID != card.PoolID ||
		enrollment.WorkerOwnerAuthorityID != card.WorkerOwnerAuthorityID {
		return ErrNotFound
	}
	current, found := store.cards[card.WorkerCardID]
	if !found {
		if previousRevision != 0 {
			return ErrNotFound
		}
	} else if current.Revision != previousRevision || current.PoolID != card.PoolID ||
		current.WorkerEnrollmentID != card.WorkerEnrollmentID ||
		current.WorkerOwnerAuthorityID != card.WorkerOwnerAuthorityID ||
		current.CreatedAtMilliseconds != card.CreatedAtMilliseconds ||
		card.UpdatedAtMilliseconds < current.UpdatedAtMilliseconds {
		return ErrConflict
	}
	store.cards[card.WorkerCardID] = cloneWorkerCard(card)
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
	card, found := store.cards[offering.WorkerCardID]
	cardDigest, digestError := card.Digest()
	if !found || card.PoolID != offering.PoolID || card.WorkerEnrollmentID != offering.WorkerEnrollmentID ||
		offering.WorkerCardRevision != card.Revision || digestError != nil ||
		offering.WorkerCardDigest != cardDigest {
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
	cards := make([]WorkerCard, 0)
	for _, card := range store.cards {
		if card.PoolID == poolID {
			cards = append(cards, cloneWorkerCard(card))
		}
	}
	sort.Slice(cards, func(left, right int) bool {
		return cards[left].WorkerCardID.String() < cards[right].WorkerCardID.String()
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
		WorkerEnrollments: enrollments, WorkerCards: cards, Offerings: offerings,
	}
	if err := status.Validate(); err != nil {
		return Status{}, err
	}
	return status, nil
}

func cloneOffering(offering Offering) Offering {
	offering.ModelIdentifiers = append([]string(nil), offering.ModelIdentifiers...)
	offering.AllowedOperations = append([]string(nil), offering.AllowedOperations...)
	offering.InteractionModes = append([]InteractionMode(nil), offering.InteractionModes...)
	return offering
}

func cloneWorkerCard(card WorkerCard) WorkerCard {
	card.Claims = append([]AssuranceClaim(nil), card.Claims...)
	return card
}

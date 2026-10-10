package storageauthority

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

// InitializePhysicalPool explicitly binds a new dedicated authority schema to
// the durable identity marker on its physical root. A missing marker is created
// only while the configured schema is still empty; existing authority state can
// never silently acquire a replacement filesystem identity.
func InitializePhysicalPool(
	ctx context.Context,
	pool *pgxpool.Pool,
	root string,
	poolID uuid.UUID,
) error {
	if ctx == nil || pool == nil || poolID == uuid.Nil {
		return ErrInvalid
	}
	identity, err := storagecapacity.LoadPhysicalPoolIdentity(root)
	if err == nil {
		if identity.PoolID != poolID {
			return ErrInvalid
		}
		return Initialize(ctx, pool, poolID)
	}
	if !errors.Is(err, storagecapacity.ErrPoolIdentityUnavailable) {
		return ErrInvalid
	}
	var count int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN ('r','v','m','f','p')`).Scan(&count); err != nil {
		return ErrUnavailable
	}
	if count != 0 {
		return ErrInvalid
	}
	identity, err = storagecapacity.CreatePhysicalPoolIdentity(root, poolID)
	if err != nil || identity.PoolID != poolID {
		return ErrInvalid
	}
	return Initialize(ctx, pool, poolID)
}

// OpenPhysicalPool requires the retained filesystem identity and database
// identity to agree before exposing admission operations.
func OpenPhysicalPool(
	ctx context.Context,
	pool *pgxpool.Pool,
	root string,
	capacity storagecapacity.Provider,
) (*Ledger, error) {
	if ctx == nil || pool == nil || capacity == nil {
		return nil, ErrInvalid
	}
	identity, err := storagecapacity.LoadPhysicalPoolIdentity(root)
	if err != nil {
		return nil, ErrInvalid
	}
	return Open(ctx, pool, identity.PoolID, capacity)
}

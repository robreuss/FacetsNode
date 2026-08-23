package postgres

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed compute_pool_migrations/*.sql
var computePoolMigrationFiles embed.FS

const computePoolMigrationLockID int64 = 0x464143455443504f

// MigrateComputePool applies only Compute Pool Service state. It intentionally
// does not create Device Sync, Shared Spaces, membership, or Space-content
// tables in the Pool database.
func MigrateComputePool(ctx context.Context, pool *pgxpool.Pool) error {
	connection, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire Compute Pool migration connection: %w", err)
	}
	defer connection.Release()
	if _, err := connection.Exec(
		ctx,
		"SELECT pg_advisory_lock($1)",
		computePoolMigrationLockID,
	); err != nil {
		return fmt.Errorf("acquire Compute Pool migration lock: %w", err)
	}
	defer func() {
		_, _ = connection.Exec(
			context.Background(),
			"SELECT pg_advisory_unlock($1)",
			computePoolMigrationLockID,
		)
	}()

	if _, err := connection.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS facets_compute_pool_schema_migrations (
			name text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("create Compute Pool migration table: %w", err)
	}

	entries, err := fs.ReadDir(computePoolMigrationFiles, "compute_pool_migrations")
	if err != nil {
		return fmt.Errorf("read embedded Compute Pool migrations: %w", err)
	}
	sort.Slice(entries, func(left, right int) bool {
		return entries[left].Name() < entries[right].Name()
	})
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		var alreadyApplied bool
		if err := connection.QueryRow(
			ctx,
			"SELECT EXISTS (SELECT 1 FROM facets_compute_pool_schema_migrations WHERE name=$1)",
			entry.Name(),
		).Scan(&alreadyApplied); err != nil {
			return fmt.Errorf("check Compute Pool migration %s: %w", entry.Name(), err)
		}
		if alreadyApplied {
			continue
		}
		contents, err := computePoolMigrationFiles.ReadFile(
			"compute_pool_migrations/" + entry.Name(),
		)
		if err != nil {
			return fmt.Errorf("read Compute Pool migration %s: %w", entry.Name(), err)
		}
		transaction, err := connection.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin Compute Pool migration %s: %w", entry.Name(), err)
		}
		if _, err := transaction.Exec(ctx, string(contents)); err != nil {
			_ = transaction.Rollback(ctx)
			return fmt.Errorf("apply Compute Pool migration %s: %w", entry.Name(), err)
		}
		if _, err := transaction.Exec(
			ctx,
			"INSERT INTO facets_compute_pool_schema_migrations (name) VALUES ($1)",
			entry.Name(),
		); err != nil {
			_ = transaction.Rollback(ctx)
			return fmt.Errorf("record Compute Pool migration %s: %w", entry.Name(), err)
		}
		if err := transaction.Commit(ctx); err != nil {
			return fmt.Errorf("commit Compute Pool migration %s: %w", entry.Name(), err)
		}
	}
	return nil
}

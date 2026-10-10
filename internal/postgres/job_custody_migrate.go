package postgres

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed job_custody_migrations/*.sql
var jobCustodyMigrationFiles embed.FS

const jobCustodyMigrationLockID int64 = 0x46414345544a4355

func MigrateJobCustody(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return fmt.Errorf("Job Custody migration pool is missing")
	}
	connection, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire Job Custody migration connection: %w", err)
	}
	defer connection.Release()
	if _, err := connection.Exec(ctx, "SELECT pg_advisory_lock($1)", jobCustodyMigrationLockID); err != nil {
		return fmt.Errorf("acquire Job Custody migration lock: %w", err)
	}
	defer func() {
		_, _ = connection.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", jobCustodyMigrationLockID)
	}()
	if _, err := connection.Exec(ctx, `CREATE TABLE IF NOT EXISTS facets_job_custody_schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("create Job Custody migration table: %w", err)
	}
	entries, err := fs.ReadDir(jobCustodyMigrationFiles, "job_custody_migrations")
	if err != nil {
		return fmt.Errorf("read Job Custody migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		var exists bool
		if err := connection.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM facets_job_custody_schema_migrations WHERE name=$1)`, entry.Name()).Scan(&exists); err != nil {
			return fmt.Errorf("inspect Job Custody migration %s: %w", entry.Name(), err)
		}
		if exists {
			continue
		}
		body, err := jobCustodyMigrationFiles.ReadFile("job_custody_migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("read Job Custody migration %s: %w", entry.Name(), err)
		}
		tx, err := connection.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin Job Custody migration %s: %w", entry.Name(), err)
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply Job Custody migration %s: %w", entry.Name(), err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO facets_job_custody_schema_migrations(name) VALUES($1)`, entry.Name()); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record Job Custody migration %s: %w", entry.Name(), err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit Job Custody migration %s: %w", entry.Name(), err)
		}
	}
	return nil
}

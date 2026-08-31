package postgres

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed backup_custody_migrations/*.sql
var backupCustodyMigrationFiles embed.FS

const backupCustodyMigrationLockID int64 = 0x4641434554424355

func MigrateBackupCustody(ctx context.Context, pool *pgxpool.Pool) error {
	connection, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire Backup custody migration connection: %w", err)
	}
	defer connection.Release()
	if _, err := connection.Exec(ctx, "SELECT pg_advisory_lock($1)", backupCustodyMigrationLockID); err != nil {
		return fmt.Errorf("acquire Backup custody migration lock: %w", err)
	}
	defer func() {
		_, _ = connection.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", backupCustodyMigrationLockID)
	}()
	if _, err := connection.Exec(ctx, `CREATE TABLE IF NOT EXISTS facets_backup_custody_schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("create Backup custody migration table: %w", err)
	}
	entries, err := fs.ReadDir(backupCustodyMigrationFiles, "backup_custody_migrations")
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		var exists bool
		if err := connection.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM facets_backup_custody_schema_migrations WHERE name=$1)", entry.Name()).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		body, err := backupCustodyMigrationFiles.ReadFile("backup_custody_migrations/" + entry.Name())
		if err != nil {
			return err
		}
		tx, err := connection.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply Backup custody migration %s: %w", entry.Name(), err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO facets_backup_custody_schema_migrations(name) VALUES($1)", entry.Name()); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

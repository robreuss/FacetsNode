// Package testpostgres contains shared infrastructure for destructive tests
// that target the same explicitly disposable PostgreSQL database.
package testpostgres

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// This repository-wide key serializes reset/migrate/test lifecycles even when
// `go test ./...` runs different package binaries concurrently.
const disposableDatabaseLockKey int64 = 0x4661636574734e64

type DisposableDatabaseLock struct {
	connection *pgx.Conn
	closeOnce  sync.Once
	closeError error
}

func AcquireDisposableDatabaseLock(
	ctx context.Context,
	databaseURL string,
) (*DisposableDatabaseLock, error) {
	connection, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if _, err := connection.Exec(
		ctx, `SELECT pg_advisory_lock($1)`, disposableDatabaseLockKey,
	); err != nil {
		_ = connection.Close(context.Background())
		return nil, err
	}
	return &DisposableDatabaseLock{connection: connection}, nil
}

func (l *DisposableDatabaseLock) Close() error {
	if l == nil || l.connection == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, unlockError := l.connection.Exec(
			ctx, `SELECT pg_advisory_unlock($1)`, disposableDatabaseLockKey,
		)
		closeError := l.connection.Close(ctx)
		l.closeError = errors.Join(unlockError, closeError)
	})
	return l.closeError
}

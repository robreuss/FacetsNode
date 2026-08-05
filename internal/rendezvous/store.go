package rendezvous

import (
	"context"

	"github.com/google/uuid"
)

type Store interface {
	CreateRoute(
		ctx context.Context,
		registration Registration,
		sponsorToken string,
		nowMilliseconds int64,
	) (Acceptance, error)
	Publish(
		ctx context.Context,
		credential Credential,
		envelope Envelope,
		nowMilliseconds int64,
	) (Acceptance, error)
	Fetch(
		ctx context.Context,
		credential Credential,
		nowMilliseconds int64,
	) ([]Envelope, error)
	Acknowledge(
		ctx context.Context,
		credential Credential,
		messageID uuid.UUID,
		nowMilliseconds int64,
	) error
	Close(
		ctx context.Context,
		credential Credential,
		nowMilliseconds int64,
	) error
	PurgeExpired(ctx context.Context, nowMilliseconds int64) error
	Ready(ctx context.Context) error
}

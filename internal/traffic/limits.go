package traffic

import "fmt"

type Surface uint8

const (
	SurfaceRendezvous Surface = iota
	SurfaceRelayMessage
	SurfaceStorage
	SurfaceCheckpointAdmin
	SurfaceManagement
	SurfaceCount
)

const (
	MaximumRequestsPerMinute = 60_000
	MaximumBurst             = 10_000
	MaximumConcurrency       = 1_024
	MaximumLimiterEntries    = 2_048
)

var allSurfaces = [...]Surface{
	SurfaceRendezvous,
	SurfaceRelayMessage,
	SurfaceStorage,
	SurfaceCheckpointAdmin,
	SurfaceManagement,
}

func Surfaces() [SurfaceCount]Surface { return allSurfaces }

func (s Surface) Name() string {
	switch s {
	case SurfaceRendezvous:
		return "rendezvous"
	case SurfaceRelayMessage:
		return "relay_message"
	case SurfaceStorage:
		return "storage"
	case SurfaceCheckpointAdmin:
		return "checkpoint_admin"
	case SurfaceManagement:
		return "management"
	default:
		return "invalid"
	}
}

type Limit struct {
	RequestsPerMinute           int
	Burst                       int
	ConnectionRequestsPerMinute int
	ConnectionBurst             int
	Concurrency                 int
}

type Limits [SurfaceCount]Limit

func DefaultLimits() Limits {
	var limits Limits
	limits[SurfaceRendezvous] = Limit{RequestsPerMinute: 300, Burst: 100, ConnectionRequestsPerMinute: 2_400, ConnectionBurst: 400, Concurrency: 32}
	limits[SurfaceRelayMessage] = Limit{RequestsPerMinute: 3_000, Burst: 500, ConnectionRequestsPerMinute: 24_000, ConnectionBurst: 2_000, Concurrency: 128}
	limits[SurfaceStorage] = Limit{RequestsPerMinute: 1_200, Burst: 200, ConnectionRequestsPerMinute: 4_800, ConnectionBurst: 800, Concurrency: 32}
	limits[SurfaceCheckpointAdmin] = Limit{RequestsPerMinute: 600, Burst: 200, ConnectionRequestsPerMinute: 4_800, ConnectionBurst: 800, Concurrency: 32}
	limits[SurfaceManagement] = Limit{RequestsPerMinute: 300, Burst: 100, ConnectionRequestsPerMinute: 600, ConnectionBurst: 200, Concurrency: 8}
	return limits
}

func ValidateLimits(limits Limits) error {
	for _, surface := range allSurfaces {
		limit := limits[surface]
		if limit.RequestsPerMinute < 1 || limit.RequestsPerMinute > MaximumRequestsPerMinute {
			return fmt.Errorf("%s requests per minute must be between 1 and %d", surface.Name(), MaximumRequestsPerMinute)
		}
		if limit.Burst < 1 || limit.Burst > MaximumBurst {
			return fmt.Errorf("%s burst must be between 1 and %d", surface.Name(), MaximumBurst)
		}
		if limit.ConnectionRequestsPerMinute < 1 || limit.ConnectionRequestsPerMinute > MaximumRequestsPerMinute {
			return fmt.Errorf("%s connection requests per minute must be between 1 and %d", surface.Name(), MaximumRequestsPerMinute)
		}
		if limit.ConnectionBurst < 1 || limit.ConnectionBurst > MaximumBurst {
			return fmt.Errorf("%s connection burst must be between 1 and %d", surface.Name(), MaximumBurst)
		}
		if limit.Concurrency < 1 || limit.Concurrency > MaximumConcurrency {
			return fmt.Errorf("%s concurrency must be between 1 and %d", surface.Name(), MaximumConcurrency)
		}
	}
	return nil
}

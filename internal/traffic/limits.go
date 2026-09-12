package traffic

import "fmt"

type Surface uint8

const (
	SurfaceRendezvous Surface = iota
	SurfaceRelayMessage
	SurfaceStorage
	SurfaceCheckpointAdmin
	SurfaceManagement
	SurfaceDeploymentProof
	SurfaceBulkGrant
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
	SurfaceDeploymentProof,
	SurfaceBulkGrant,
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
	case SurfaceDeploymentProof:
		return "deployment_proof"
	case SurfaceBulkGrant:
		return "bulk_grant"
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
	limits[SurfaceStorage] = Limit{RequestsPerMinute: 6_000, Burst: 200, ConnectionRequestsPerMinute: 12_000, ConnectionBurst: 800, Concurrency: 32}
	limits[SurfaceCheckpointAdmin] = Limit{RequestsPerMinute: 600, Burst: 200, ConnectionRequestsPerMinute: 4_800, ConnectionBurst: 800, Concurrency: 32}
	limits[SurfaceManagement] = Limit{RequestsPerMinute: 300, Burst: 100, ConnectionRequestsPerMinute: 600, ConnectionBurst: 200, Concurrency: 8}
	// Each authenticated bulk operation needs a fresh proof both for its grant
	// and for its dispatch. Two clients with four upload slots must not compete
	// with interactive administration for that admission budget. This admits
	// 200 proofs/second per observed peer/route (not client-supplied identity),
	// while retaining a small burst and a separate hard signing-work bound.
	limits[SurfaceDeploymentProof] = Limit{RequestsPerMinute: 12_000, Burst: 400, ConnectionRequestsPerMinute: 24_000, ConnectionBurst: 800, Concurrency: 16}
	// One resource-scoped grant per bulk operation. Grants remain authenticated
	// control traffic, but must not exhaust checkpoint administration. Storage
	// admission is sized for the same 100-operation/s tested protocol workload;
	// request sizes, signing validation and hard concurrency remain bounded.
	limits[SurfaceBulkGrant] = Limit{RequestsPerMinute: 6_000, Burst: 200, ConnectionRequestsPerMinute: 12_000, ConnectionBurst: 400, Concurrency: 16}
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

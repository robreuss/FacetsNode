package boxcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	maximumWorkerCapabilitiesBytes = 16 * 1024
	maximumWorkerAdvertisementAge  = int64(5 * 60 * 1000)
)

var ErrSharedWorkerAuthority = errors.New("BOX-SHARED-WORKER-AUTHORITY: shared Worker identity, owner, revision, or availability is invalid")

type BoxSharedWorkerAvailability string

const (
	SharedWorkerAvailable   BoxSharedWorkerAvailability = "available"
	SharedWorkerBusy        BoxSharedWorkerAvailability = "busy"
	SharedWorkerUnavailable BoxSharedWorkerAvailability = "unavailable"
	SharedWorkerPaused      BoxSharedWorkerAvailability = "paused"
)

func (availability BoxSharedWorkerAvailability) valid() bool {
	switch availability {
	case SharedWorkerAvailable, SharedWorkerBusy, SharedWorkerUnavailable, SharedWorkerPaused:
		return true
	default:
		return false
	}
}

// BoxSharedWorkerAdvertisement is the content-blind Box directory record for
// one exact Worker. Capabilities are a bounded opaque canonical payload whose
// digest is verified by the Box and interpreted by Facets clients.
type BoxSharedWorkerAdvertisement struct {
	Version               int                         `json:"version"`
	BoxID                 uuid.UUID                   `json:"boxID"`
	WorkerID              uuid.UUID                   `json:"workerID"`
	OwnerParticipantID    uuid.UUID                   `json:"ownerParticipantID"`
	OwnerDeviceID         uuid.UUID                   `json:"ownerDeviceID"`
	DisplayName           string                      `json:"displayName"`
	Availability          BoxSharedWorkerAvailability `json:"availability"`
	Revision              uint64                      `json:"revision"`
	Capabilities          []byte                      `json:"capabilities"`
	CapabilitiesDigest    string                      `json:"capabilitiesDigest"`
	UpdatedAtMilliseconds int64                       `json:"updatedAtMilliseconds"`
	ExpiresAtMilliseconds int64                       `json:"expiresAtMilliseconds"`
}

func SharedWorkerCapabilitiesDigest(capabilities []byte) string {
	digest := sha256.Sum256(capabilities)
	return hex.EncodeToString(digest[:])
}

func (advertisement BoxSharedWorkerAdvertisement) validAt(nowMilliseconds int64) bool {
	if advertisement.Version != 1 || advertisement.BoxID == uuid.Nil ||
		advertisement.WorkerID == uuid.Nil || advertisement.OwnerParticipantID == uuid.Nil ||
		advertisement.OwnerDeviceID == uuid.Nil || advertisement.Revision == 0 ||
		advertisement.Revision > math.MaxInt64 ||
		!advertisement.Availability.valid() || !utf8.ValidString(advertisement.DisplayName) ||
		advertisement.DisplayName == "" || len(advertisement.DisplayName) > 128 ||
		strings.TrimSpace(advertisement.DisplayName) != advertisement.DisplayName ||
		strings.IndexFunc(advertisement.DisplayName, unicode.IsControl) >= 0 ||
		len(advertisement.Capabilities) == 0 ||
		len(advertisement.Capabilities) > maximumWorkerCapabilitiesBytes ||
		!validParticipantRequestDigest(advertisement.CapabilitiesDigest) ||
		advertisement.CapabilitiesDigest != SharedWorkerCapabilitiesDigest(advertisement.Capabilities) ||
		advertisement.UpdatedAtMilliseconds <= 0 || advertisement.UpdatedAtMilliseconds > nowMilliseconds ||
		advertisement.ExpiresAtMilliseconds <= nowMilliseconds ||
		advertisement.ExpiresAtMilliseconds-advertisement.UpdatedAtMilliseconds > maximumWorkerAdvertisementAge {
		return false
	}
	return true
}

func cloneSharedWorker(value BoxSharedWorkerAdvertisement) BoxSharedWorkerAdvertisement {
	value.Capabilities = bytes.Clone(value.Capabilities)
	return value
}

func (store *MemoryStore) UpsertSharedWorker(
	_ context.Context,
	advertisement BoxSharedWorkerAdvertisement,
	nowMilliseconds int64,
) error {
	if !advertisement.validAt(nowMilliseconds) {
		return ErrSharedWorkerAuthority
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state == nil || !store.state.Claimed() || store.state.BoxID != advertisement.BoxID {
		return ErrSharedWorkerAuthority
	}
	enrollment, present := store.participantEnrollments[advertisement.OwnerParticipantID]
	if !present || enrollment.Device.DeviceID != advertisement.OwnerDeviceID ||
		!enrollment.validInitialAt(nowMilliseconds) {
		return ErrSharedWorkerAuthority
	}
	if existing, present := store.sharedWorkers[advertisement.WorkerID]; present {
		if existing.OwnerParticipantID != advertisement.OwnerParticipantID ||
			existing.OwnerDeviceID != advertisement.OwnerDeviceID ||
			advertisement.Revision <= existing.Revision {
			return ErrSharedWorkerAuthority
		}
	}
	store.sharedWorkers[advertisement.WorkerID] = cloneSharedWorker(advertisement)
	return nil
}

func (store *MemoryStore) ListSharedWorkers(
	_ context.Context,
	boxID uuid.UUID,
	nowMilliseconds int64,
) ([]BoxSharedWorkerAdvertisement, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state == nil || !store.state.Claimed() || store.state.BoxID != boxID {
		return nil, ErrSharedWorkerAuthority
	}
	results := make([]BoxSharedWorkerAdvertisement, 0, len(store.sharedWorkers))
	for _, advertisement := range store.sharedWorkers {
		enrollment, present := store.participantEnrollments[advertisement.OwnerParticipantID]
		if advertisement.BoxID == boxID && advertisement.ExpiresAtMilliseconds > nowMilliseconds &&
			present && enrollment.Device.DeviceID == advertisement.OwnerDeviceID &&
			enrollment.validInitialAt(nowMilliseconds) {
			results = append(results, cloneSharedWorker(advertisement))
		}
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].WorkerID.String() < results[j].WorkerID.String()
	})
	return results, nil
}

func (store *MemoryStore) WithdrawSharedWorker(
	_ context.Context,
	boxID, workerID, participantID, deviceID uuid.UUID,
	revision uint64,
	nowMilliseconds int64,
) error {
	if boxID == uuid.Nil || workerID == uuid.Nil || participantID == uuid.Nil ||
		deviceID == uuid.Nil || revision == 0 || nowMilliseconds <= 0 {
		return ErrSharedWorkerAuthority
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	existing, present := store.sharedWorkers[workerID]
	enrollment, enrolled := store.participantEnrollments[participantID]
	if !present || !enrolled || store.state == nil || !store.state.Claimed() ||
		store.state.BoxID != boxID || existing.BoxID != boxID ||
		existing.OwnerParticipantID != participantID || existing.OwnerDeviceID != deviceID ||
		enrollment.Device.DeviceID != deviceID || !enrollment.validInitialAt(nowMilliseconds) ||
		revision <= existing.Revision {
		return ErrSharedWorkerAuthority
	}
	delete(store.sharedWorkers, workerID)
	return nil
}

func (store *PostgresStore) UpsertSharedWorker(
	ctx context.Context,
	advertisement BoxSharedWorkerAdvertisement,
	nowMilliseconds int64,
) error {
	if !advertisement.validAt(nowMilliseconds) {
		return ErrSharedWorkerAuthority
	}
	result, err := store.pool.Exec(ctx, `
		INSERT INTO box_shared_workers
			(worker_id, box_id, owner_participant_id, owner_device_id, display_name,
			 availability, revision, capabilities, capabilities_digest,
			 updated_at_milliseconds, expires_at_milliseconds)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		FROM box_state s
		JOIN box_participants p ON p.box_id = s.box_id AND p.participant_id = $3
		JOIN box_participant_devices d ON d.participant_id = p.participant_id AND d.device_id = $4
		WHERE s.box_id = $2 AND s.owner_verifier <> ''
		  AND p.revoked_at_milliseconds = 0
		  AND d.revoked_through_generation < d.device_generation
		ON CONFLICT (worker_id) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			availability = EXCLUDED.availability,
			revision = EXCLUDED.revision,
			capabilities = EXCLUDED.capabilities,
			capabilities_digest = EXCLUDED.capabilities_digest,
			updated_at_milliseconds = EXCLUDED.updated_at_milliseconds,
			expires_at_milliseconds = EXCLUDED.expires_at_milliseconds
		WHERE box_shared_workers.box_id = EXCLUDED.box_id
		  AND box_shared_workers.owner_participant_id = EXCLUDED.owner_participant_id
		  AND box_shared_workers.owner_device_id = EXCLUDED.owner_device_id
		  AND box_shared_workers.revision < EXCLUDED.revision`,
		advertisement.WorkerID, advertisement.BoxID, advertisement.OwnerParticipantID,
		advertisement.OwnerDeviceID, advertisement.DisplayName, advertisement.Availability,
		int64(advertisement.Revision), advertisement.Capabilities,
		advertisement.CapabilitiesDigest, advertisement.UpdatedAtMilliseconds,
		advertisement.ExpiresAtMilliseconds)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrSharedWorkerAuthority
	}
	return nil
}

func (store *PostgresStore) ListSharedWorkers(
	ctx context.Context,
	boxID uuid.UUID,
	nowMilliseconds int64,
) ([]BoxSharedWorkerAdvertisement, error) {
	rows, err := store.pool.Query(ctx, `
		SELECT w.worker_id, w.box_id, w.owner_participant_id, w.owner_device_id,
		       w.display_name, w.availability, w.revision, w.capabilities,
		       w.capabilities_digest, w.updated_at_milliseconds, w.expires_at_milliseconds
		FROM box_shared_workers w
		JOIN box_state s ON s.box_id = w.box_id AND s.owner_verifier <> ''
		JOIN box_participants p ON p.box_id = w.box_id AND p.participant_id = w.owner_participant_id
		JOIN box_participant_devices d ON d.participant_id = p.participant_id AND d.device_id = w.owner_device_id
		WHERE w.box_id = $1 AND w.expires_at_milliseconds > $2
		  AND p.revoked_at_milliseconds = 0
		  AND d.revoked_through_generation < d.device_generation
		ORDER BY w.worker_id`, boxID, nowMilliseconds)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []BoxSharedWorkerAdvertisement
	for rows.Next() {
		var value BoxSharedWorkerAdvertisement
		var revision int64
		value.Version = 1
		if err := rows.Scan(&value.WorkerID, &value.BoxID, &value.OwnerParticipantID,
			&value.OwnerDeviceID, &value.DisplayName, &value.Availability, &revision,
			&value.Capabilities, &value.CapabilitiesDigest, &value.UpdatedAtMilliseconds,
			&value.ExpiresAtMilliseconds); err != nil {
			return nil, err
		}
		if revision <= 0 {
			return nil, ErrSharedWorkerAuthority
		}
		value.Revision = uint64(revision)
		results = append(results, value)
	}
	return results, rows.Err()
}

func (store *PostgresStore) WithdrawSharedWorker(
	ctx context.Context,
	boxID, workerID, participantID, deviceID uuid.UUID,
	revision uint64,
	nowMilliseconds int64,
) error {
	if boxID == uuid.Nil || workerID == uuid.Nil || participantID == uuid.Nil ||
		deviceID == uuid.Nil || revision == 0 || revision > math.MaxInt64 ||
		nowMilliseconds <= 0 {
		return ErrSharedWorkerAuthority
	}
	result, err := store.pool.Exec(ctx, `
		DELETE FROM box_shared_workers w
		USING box_state s, box_participants p, box_participant_devices d
		WHERE w.worker_id = $2 AND w.box_id = $1
		  AND w.owner_participant_id = $3 AND w.owner_device_id = $4
		  AND w.revision < $5
		  AND s.box_id = w.box_id AND s.owner_verifier <> ''
		  AND p.box_id = s.box_id AND p.participant_id = w.owner_participant_id
		  AND p.revoked_at_milliseconds = 0
		  AND d.participant_id = p.participant_id AND d.device_id = w.owner_device_id
		  AND d.revoked_through_generation < d.device_generation`,
		boxID, workerID, participantID, deviceID, int64(revision))
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrSharedWorkerAuthority
	}
	return nil
}

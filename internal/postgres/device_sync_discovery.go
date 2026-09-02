package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
)

func (s *RelayStore) PublishDiscoveryProfile(
	ctx context.Context,
	credential relay.TenantCredential,
	profile devicesync.DiscoveryProfile,
) error {
	if err := profile.Validate(); err != nil {
		return err
	}
	if credential.TenantID != profile.PrincipalID {
		return devicesync.NewProtocolError(
			devicesync.CodeWrongScope, "discovery profile belongs to another principal",
		)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin Device Sync discovery profile: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tenant, err := loadRelayTenant(ctx, tx, credential.TenantID, "FOR UPDATE")
	if err != nil {
		return err
	}
	if err := tenant.Authorize(credential); err != nil {
		return err
	}
	if _, err := loadDeviceSyncPrincipalAuthority(ctx, tx, profile.PrincipalID, "FOR UPDATE"); err != nil {
		return err
	}
	var existingRevision uint64
	err = tx.QueryRow(ctx, `
		SELECT revision FROM device_sync_discovery_profiles WHERE principal_id=$1 FOR UPDATE
	`, profile.PrincipalID).Scan(&existingRevision)
	if err != nil && err != pgx.ErrNoRows {
		return fmt.Errorf("load Device Sync discovery profile: %w", err)
	}
	if err == nil && profile.Revision < existingRevision {
		return devicesync.NewProtocolError(
			devicesync.CodePrincipalCollision, "discovery profile revision moved backwards",
		)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_sync_discovery_profiles (
			principal_id,version,set_discriminator,display_name,revision,updated_at_milliseconds
		) VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (principal_id) DO UPDATE SET
			version=EXCLUDED.version,
			set_discriminator=EXCLUDED.set_discriminator,
			display_name=EXCLUDED.display_name,
			revision=EXCLUDED.revision,
			updated_at_milliseconds=EXCLUDED.updated_at_milliseconds,
			stored_at=now()
	`, profile.PrincipalID, profile.Version, profile.SetDiscriminator,
		profile.DisplayName, profile.Revision, profile.UpdatedMilliseconds); err != nil {
		return fmt.Errorf("store Device Sync discovery profile: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit Device Sync discovery profile: %w", err)
	}
	return nil
}

func (s *RelayStore) ListDiscoveryProfiles(
	ctx context.Context,
) ([]devicesync.DiscoveryProfile, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT version,principal_id,set_discriminator,display_name,revision,updated_at_milliseconds
		FROM device_sync_discovery_profiles
		ORDER BY display_name,set_discriminator
		LIMIT $1
	`, devicesync.MaximumDiscoveryProfiles+1)
	if err != nil {
		return nil, fmt.Errorf("query Device Sync discovery profiles: %w", err)
	}
	defer rows.Close()
	profiles := make([]devicesync.DiscoveryProfile, 0)
	for rows.Next() {
		var profile devicesync.DiscoveryProfile
		if err := rows.Scan(&profile.Version, &profile.PrincipalID,
			&profile.SetDiscriminator, &profile.DisplayName, &profile.Revision,
			&profile.UpdatedMilliseconds); err != nil {
			return nil, fmt.Errorf("scan Device Sync discovery profile: %w", err)
		}
		if err := profile.Validate(); err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(profiles) > devicesync.MaximumDiscoveryProfiles {
		return nil, fmt.Errorf("Device Sync discovery profile limit exceeded")
	}
	return profiles, nil
}

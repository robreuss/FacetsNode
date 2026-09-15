package objectcustodyledger

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

// ReconcilePeerAuthority takes authority only from the receiver's independently
// provisioned persistent registry, never a peer's request fields. The durable
// head protects all this service scope's bindings and operations from an older
// process. It does not authenticate a client, link resources, or run an effect.
func (l *Ledger) ReconcilePeerAuthority(ctx context.Context, registry *serviceauthority.BindingRegistry, scope serviceauthority.Scope) error {
	if registry == nil || ctx == nil {
		return ErrInvalid
	}
	lease, err := registry.AcquireMutationLease(ctx, scope)
	if err != nil {
		return err
	}
	defer lease.Release()
	tx, err := l.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	now, err := databaseNow(ctx, tx)
	if err != nil {
		return err
	}
	next, err := registry.CurrentCustodyPeerIdentityAt(scope, time.UnixMilli(now))
	if err != nil || validatePeerIdentity(next) != nil {
		return ErrInvalid
	}
	prior, err := loadPeerAuthority(ctx, tx, scope)
	exists := err == nil
	if exists {
		if err = validatePeerAuthorityAdvance(prior, next); err != nil {
			return err
		}
		if prior == next {
			return nil
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	// Replacing an existing row cannot grow the bounded identity materially and
	// must remain possible under pressure, especially to make a fence stricter.
	if !exists {
		if err = l.admit(ctx, tx, storagecapacity.MutationMetadataAllowance); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO immutable_custody_peer_authorities
		(service_kind,service_scope_id,authority_revision,manifest_digest,deployment_id,write_fenced)
		VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (service_kind,service_scope_id) DO UPDATE SET
		authority_revision=EXCLUDED.authority_revision,manifest_digest=EXCLUDED.manifest_digest,
		deployment_id=EXCLUDED.deployment_id,write_fenced=EXCLUDED.write_fenced`,
		string(scope.Kind), scope.ScopeID, strconv.FormatUint(next.Revision, 10), next.Digest, next.DeploymentID, next.WriteFenced)
	if err != nil {
		return ErrUnavailable
	}
	if err = l.checkpoint("peer_authority_staged"); err != nil {
		return err
	}
	now, err = databaseNow(ctx, tx)
	if err != nil {
		return err
	}
	current, err := registry.CurrentCustodyPeerIdentityAt(scope, time.UnixMilli(now))
	if err != nil || current != next {
		return ErrConflict
	}
	return l.commit(ctx, tx)
}

func validatePeerIdentity(identity serviceauthority.BindingIdentity) error {
	if identity.Scope.Validate() != nil ||
		(identity.Scope.Kind != serviceauthority.ScopeDeviceSync && identity.Scope.Kind != serviceauthority.ScopeBackupCustody) ||
		identity.Revision == 0 || !validDigest(identity.Digest) || identity.DeploymentID == uuid.Nil || identity.TransitionEvidenceDigest != nil {
		return ErrInvalid
	}
	return nil
}

func validatePeerAuthorityAdvance(prior, next serviceauthority.BindingIdentity) error {
	if validatePeerIdentity(prior) != nil || validatePeerIdentity(next) != nil || prior.Scope != next.Scope {
		return ErrInvalid
	}
	if next.Revision < prior.Revision || (next.Revision == prior.Revision &&
		(next.Digest != prior.Digest || next.DeploymentID != prior.DeploymentID || (prior.WriteFenced && !next.WriteFenced))) {
		return ErrConflict
	}
	return nil
}

func loadPeerAuthority(ctx context.Context, q querier, scope serviceauthority.Scope) (serviceauthority.BindingIdentity, error) {
	var revision string
	identity := serviceauthority.BindingIdentity{Scope: scope}
	err := q.QueryRow(ctx, `SELECT authority_revision,manifest_digest,deployment_id,write_fenced
		FROM immutable_custody_peer_authorities WHERE service_kind=$1 AND service_scope_id=$2`,
		string(scope.Kind), scope.ScopeID).Scan(&revision, &identity.Digest, &identity.DeploymentID, &identity.WriteFenced)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity, err
	}
	if err != nil {
		return identity, ErrUnavailable
	}
	identity.Revision, err = strconv.ParseUint(revision, 10, 64)
	if err != nil || strconv.FormatUint(identity.Revision, 10) != revision || validatePeerIdentity(identity) != nil {
		return identity, ErrInvalid
	}
	return identity, nil
}

// Called only with the custody pool transaction lock held. The future effect
// dispatcher MUST repeat this check inside its effect transaction, not assume
// an earlier challenge decision remains current after releasing that lock.
func checkPeerAuthority(ctx context.Context, q querier, payload serviceauthority.CustodyPeerPayload) error {
	head, err := loadPeerAuthority(ctx, q, payload.Source.Scope)
	if err != nil {
		return err
	}
	if head.Revision != payload.Source.AuthorityRevision || head.Digest != payload.Source.AuthorityManifestDigest ||
		head.DeploymentID != payload.Source.DeploymentID || (head.WriteFenced && payload.Request.Operation != serviceauthority.CustodyReadObject) {
		return ErrConflict
	}
	return nil
}

package objectcustodyledger

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/robreuss/FacetsNode/internal/objectcustodywire"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

const PeerChallengeLifetime = 5 * time.Minute
const MaximumPendingPeerChallenges = 64

// PeerChallenge is durable freshness state, not client/link authority or an
// effect receipt. Consumed means verification committed, NOT effect completion.
type PeerChallenge struct {
	Payload                                     serviceauthority.CustodyPeerPayload
	IssuedAtMilliseconds, ExpiresAtMilliseconds int64
	Consumed                                    bool
}

func (c PeerChallenge) validate() error {
	if c.Payload.Version != 1 || c.Payload.Request.Validate() != nil || !validPeerSource(c.Payload.Source, c.Payload.Request.Operation) ||
		c.IssuedAtMilliseconds <= 0 || c.ExpiresAtMilliseconds <= c.IssuedAtMilliseconds ||
		c.ExpiresAtMilliseconds-c.IssuedAtMilliseconds != PeerChallengeLifetime.Milliseconds() {
		return ErrInvalid
	}
	return nil
}

// IssuePeerChallenge is a trusted adapter seam. Before exposing this operation,
// authenticate the caller and current client/dual-service resource link; source
// structure and matching UUIDs below are not proof of those permissions. The
// intent's Challenge must be empty. Receiver pool/ledger IDs must match this
// owner. An operation identity cannot be reassigned to different content.
func (l *Ledger) IssuePeerChallenge(ctx context.Context, source serviceauthority.RequestBinding, intent serviceauthority.CustodyPeerRequest) (PeerChallenge, error) {
	if intent.Challenge != "" {
		return PeerChallenge{}, ErrInvalid
	}
	// Validate the intent before generating or persisting a real receiver nonce.
	intent.Challenge = strings.Repeat("A", 43)
	requested := serviceauthority.CustodyPeerPayload{Request: intent, Source: peerSource(source), Version: 1}
	if intent.Validate() != nil || !validPeerSource(requested.Source, intent.Operation) {
		return PeerChallenge{}, ErrInvalid
	}
	tx, err := l.begin(ctx)
	if err != nil {
		return PeerChallenge{}, err
	}
	defer tx.Rollback(ctx)
	if err = l.matchPeerBinding(ctx, tx, requested); err != nil {
		return PeerChallenge{}, err
	}
	now, err := databaseNow(ctx, tx)
	if err != nil {
		return PeerChallenge{}, err
	}
	prior, err := loadPeerChallenge(ctx, tx, intent.Target.BindingID, intent.OperationID)
	exists := err == nil
	if exists {
		oldIntent := prior.Payload.Request
		oldIntent.Challenge = intent.Challenge
		if oldIntent != intent || prior.Payload.Source.Scope != requested.Source.Scope ||
			requested.Source.AuthorityRevision < prior.Payload.Source.AuthorityRevision ||
			(requested.Source.AuthorityRevision == prior.Payload.Source.AuthorityRevision && requested.Source.AuthorityManifestDigest != prior.Payload.Source.AuthorityManifestDigest) {
			return PeerChallenge{}, ErrConflict
		}
		if now < prior.IssuedAtMilliseconds {
			return PeerChallenge{}, ErrUnavailable
		}
		if now < prior.ExpiresAtMilliseconds && prior.Payload.Source == requested.Source {
			return prior, nil
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return PeerChallenge{}, err
	}
	var pending int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM immutable_custody_peer_challenges WHERE binding_id=$1 AND NOT consumed AND expires_at_milliseconds>$2 AND operation_id<>$3`, intent.Target.BindingID, now, intent.OperationID).Scan(&pending); err != nil {
		return PeerChallenge{}, ErrUnavailable
	}
	if pending >= MaximumPendingPeerChallenges {
		return PeerChallenge{}, ErrConflict
	}
	if err = l.admit(ctx, tx, storagecapacity.MutationMetadataAllowance); err != nil {
		return PeerChallenge{}, err
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return PeerChallenge{}, ErrUnavailable
	}
	requested.Request.Challenge = base64.RawURLEncoding.EncodeToString(nonce[:])
	result := PeerChallenge{Payload: requested, IssuedAtMilliseconds: now, ExpiresAtMilliseconds: now + PeerChallengeLifetime.Milliseconds()}
	if result.validate() != nil {
		return PeerChallenge{}, ErrInvalid
	}
	encoded, err := json.Marshal(requested)
	if err != nil || len(encoded) > serviceauthority.MaximumCustodyPeerPayloadBytes {
		return PeerChallenge{}, ErrInvalid
	}
	if exists {
		_, err = tx.Exec(ctx, `UPDATE immutable_custody_peer_challenges SET payload=$3,challenge=$4,issued_at_milliseconds=$5,expires_at_milliseconds=$6,consumed=false WHERE binding_id=$1 AND operation_id=$2`, intent.Target.BindingID, intent.OperationID, encoded, requested.Request.Challenge, now, result.ExpiresAtMilliseconds)
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO immutable_custody_peer_challenges VALUES ($1,$2,$3,$4,$5,$6,false)`, intent.Target.BindingID, intent.OperationID, encoded, requested.Request.Challenge, now, result.ExpiresAtMilliseconds)
	}
	if err != nil {
		return PeerChallenge{}, ErrUnavailable
	}
	return result, l.commit(ctx, tx)
}

// VerifyPeerChallenge loads expected bytes from receiving custody, never from
// the supplied proof. The adapter must retain its source scope lease and current
// client/link permission across this call and its idempotent durable effect.
// A retry always rechecks freshness and current pinned source authority, even
// when Consumed is true. No effect is executed or authorized by this method.
func (l *Ledger) VerifyPeerChallenge(ctx context.Context, registry *serviceauthority.BindingRegistry, bindingID, operationID uuid.UUID, proof serviceauthority.CustodyPeerProof, body []byte) (serviceauthority.VerifiedCustodyPeerRequest, error) {
	if registry == nil || len(proof.Payload) > serviceauthority.MaximumCustodyPeerPayloadBytes ||
		len(body) > objectcustodywire.MaximumPlaintextBytes+objectcustodywire.WireOverhead {
		return serviceauthority.VerifiedCustodyPeerRequest{}, ErrInvalid
	}
	tx, err := l.begin(ctx)
	if err != nil {
		return serviceauthority.VerifiedCustodyPeerRequest{}, err
	}
	defer tx.Rollback(ctx)
	challenge, err := loadPeerChallenge(ctx, tx, bindingID, operationID)
	if err != nil {
		return serviceauthority.VerifiedCustodyPeerRequest{}, err
	}
	if err = l.matchPeerBinding(ctx, tx, challenge.Payload); err != nil {
		return serviceauthority.VerifiedCustodyPeerRequest{}, err
	}
	now, err := databaseNow(ctx, tx)
	if err != nil {
		return serviceauthority.VerifiedCustodyPeerRequest{}, err
	}
	if now < challenge.IssuedAtMilliseconds || now >= challenge.ExpiresAtMilliseconds {
		return serviceauthority.VerifiedCustodyPeerRequest{}, ErrConflict
	}
	verified, err := registry.VerifyCustodyPeerRequestAt(proof, challenge.Payload.Request, body, time.UnixMilli(now))
	if err != nil || peerSource(verified.Source()) != challenge.Payload.Source {
		return serviceauthority.VerifiedCustodyPeerRequest{}, ErrInvalid
	}
	if challenge.Consumed {
		return verified, nil
	}
	if _, err = tx.Exec(ctx, `UPDATE immutable_custody_peer_challenges SET consumed=true WHERE binding_id=$1 AND operation_id=$2`, bindingID, operationID); err != nil {
		return serviceauthority.VerifiedCustodyPeerRequest{}, ErrUnavailable
	}
	if err = l.commit(ctx, tx); err != nil {
		return serviceauthority.VerifiedCustodyPeerRequest{}, err
	}
	return verified, nil
}

func (l *Ledger) matchPeerBinding(ctx context.Context, q querier, payload serviceauthority.CustodyPeerPayload) error {
	target := payload.Request.Target
	if target.PoolID != l.poolID || target.LedgerID != l.ledgerID {
		return ErrInvalid
	}
	binding, err := loadBinding(ctx, q, target.BindingID)
	if err != nil {
		return err
	}
	if binding.ServiceKind != string(payload.Source.Scope.Kind) || binding.ServiceScopeID != payload.Source.Scope.ScopeID ||
		binding.ContentScopeID != target.ContentScopeID || binding.ContentEpoch != target.ContentEpoch {
		return ErrInvalid
	}
	return nil
}

func loadPeerChallenge(ctx context.Context, q querier, bindingID, operationID uuid.UUID) (PeerChallenge, error) {
	if bindingID == uuid.Nil || operationID == uuid.Nil {
		return PeerChallenge{}, ErrInvalid
	}
	var encoded []byte
	var nonce string
	var c PeerChallenge
	err := q.QueryRow(ctx, `SELECT payload,challenge,issued_at_milliseconds,expires_at_milliseconds,consumed FROM immutable_custody_peer_challenges WHERE binding_id=$1 AND operation_id=$2`, bindingID, operationID).Scan(&encoded, &nonce, &c.IssuedAtMilliseconds, &c.ExpiresAtMilliseconds, &c.Consumed)
	if errors.Is(err, pgx.ErrNoRows) {
		return PeerChallenge{}, err
	}
	if err != nil {
		return PeerChallenge{}, ErrUnavailable
	}
	if len(encoded) == 0 || len(encoded) > serviceauthority.MaximumCustodyPeerPayloadBytes || json.Unmarshal(encoded, &c.Payload) != nil || c.validate() != nil {
		return PeerChallenge{}, ErrInvalid
	}
	canonical, err := json.Marshal(c.Payload)
	if err != nil || !bytes.Equal(canonical, encoded) || c.Payload.Request.Target.BindingID != bindingID || c.Payload.Request.OperationID != operationID || c.Payload.Request.Challenge != nonce {
		return PeerChallenge{}, ErrInvalid
	}
	return c, nil
}

func peerSource(b serviceauthority.RequestBinding) serviceauthority.CustodyPeerSource {
	return serviceauthority.CustodyPeerSource{AuthorityManifestDigest: b.AuthorityDigest, AuthorityRevision: b.AuthorityRevision, DeploymentID: b.DeploymentID, RouteID: b.RouteID, Scope: b.Scope, TrafficClass: b.TrafficClass}
}

func validPeerSource(s serviceauthority.CustodyPeerSource, operation serviceauthority.CustodyPeerOperation) bool {
	class := serviceauthority.TrafficControl
	if operation == serviceauthority.CustodyPutObject || operation == serviceauthority.CustodyReadObject {
		class = serviceauthority.TrafficBulk
	}
	return s.Scope.Validate() == nil && (s.Scope.Kind == serviceauthority.ScopeDeviceSync || s.Scope.Kind == serviceauthority.ScopeBackupCustody) &&
		s.AuthorityRevision > 0 && len(s.AuthorityManifestDigest) == 64 && validDigest(s.AuthorityManifestDigest) && s.DeploymentID != uuid.Nil && s.RouteID != uuid.Nil && s.TrafficClass == class
}

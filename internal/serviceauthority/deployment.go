package serviceauthority

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	SchemaVersion                               = 1
	MaximumProofLifetime                        = 5 * time.Minute
	deploymentProofSignatureDomain              = "Facets server deployment proof v1\x00"
	HeaderScopeKind                             = "X-Facets-Service-Scope-Kind"
	HeaderScopeID                               = "X-Facets-Service-Scope-ID"
	HeaderAuthorityRevision                     = "X-Facets-Authority-Revision"
	HeaderAuthorityDigest                       = "X-Facets-Authority-Digest"
	HeaderDeploymentID                          = "X-Facets-Deployment-ID"
	HeaderRouteID                               = "X-Facets-Route-ID"
	HeaderTrafficClass                          = "X-Facets-Traffic-Class"
	TrafficControl                 TrafficClass = "control"
	TrafficMessage                 TrafficClass = "message"
	TrafficBulk                    TrafficClass = "bulk"
	ScopeDeviceSync                ScopeKind    = "device_sync"
	ScopeSharedSpace               ScopeKind    = "shared_space"
	ScopeComputePool               ScopeKind    = "compute_pool"
)

var ErrInvalid = errors.New("invalid Facets service authority value")

type ScopeKind string

func (kind ScopeKind) Valid() bool {
	return kind == ScopeDeviceSync || kind == ScopeSharedSpace || kind == ScopeComputePool
}

type TrafficClass string

func (class TrafficClass) Valid() bool {
	return class == TrafficControl || class == TrafficMessage || class == TrafficBulk
}

type Scope struct {
	Kind    ScopeKind `json:"kind"`
	ScopeID uuid.UUID `json:"scopeID"`
}

func (scope Scope) Validate() error {
	if !scope.Kind.Valid() || scope.ScopeID == uuid.Nil {
		return ErrInvalid
	}
	return nil
}

// ProofRequest field order is canonical sorted-key JSON and must remain in
// lockstep with Swift's sorted-key encoder.
type ProofRequest struct {
	AuthorityManifestDigest string       `json:"authorityManifestDigest"`
	AuthorityRevision       uint64       `json:"authorityRevision"`
	Challenge               string       `json:"challenge"`
	DeploymentID            uuid.UUID    `json:"deploymentID"`
	RouteID                 uuid.UUID    `json:"routeID"`
	Scope                   Scope        `json:"scope"`
	TrafficClass            TrafficClass `json:"trafficClass"`
	Version                 int          `json:"version"`
}

func (request ProofRequest) Validate(expectedDeploymentID uuid.UUID) error {
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(request.Challenge)
	if err != nil || len(challenge) != 32 ||
		base64.RawURLEncoding.EncodeToString(challenge) != request.Challenge ||
		request.Version != SchemaVersion || request.AuthorityRevision == 0 ||
		!validDigest(request.AuthorityManifestDigest) ||
		request.DeploymentID == uuid.Nil || request.DeploymentID != expectedDeploymentID ||
		request.RouteID == uuid.Nil || !request.TrafficClass.Valid() ||
		request.Scope.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

// ProofPayload field order is canonical sorted-key JSON.
type ProofPayload struct {
	ExpiresAtMilliseconds int64        `json:"expiresAtMilliseconds"`
	IssuedAtMilliseconds  int64        `json:"issuedAtMilliseconds"`
	Request               ProofRequest `json:"request"`
	Version               int          `json:"version"`
}

type Signature struct {
	Algorithm             string    `json:"algorithm"`
	PublicSigningKeyX963  string    `json:"publicSigningKeyX963"`
	Signature             string    `json:"signature"`
	SignerID              uuid.UUID `json:"signerID"`
	SigningKeyFingerprint string    `json:"signingKeyFingerprint"`
}

type DeploymentProof struct {
	Payload   []byte    `json:"payload"`
	Signature Signature `json:"signature"`
}

type DeploymentSigner struct {
	deploymentID uuid.UUID
	privateKey   *ecdsa.PrivateKey
	publicX963   []byte
	fingerprint  string
}

func NewDeploymentSigner(deploymentID uuid.UUID, privateScalar []byte) (*DeploymentSigner, error) {
	curve := elliptic.P256()
	d := new(big.Int).SetBytes(privateScalar)
	if deploymentID == uuid.Nil || len(privateScalar) != 32 || d.Sign() <= 0 ||
		d.Cmp(curve.Params().N) >= 0 {
		return nil, ErrInvalid
	}
	x, y := curve.ScalarBaseMult(privateScalar)
	key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}
	publicX963 := elliptic.Marshal(curve, x, y)
	fingerprint := sha256.Sum256(publicX963)
	return &DeploymentSigner{
		deploymentID: deploymentID,
		privateKey:   key,
		publicX963:   publicX963,
		fingerprint:  hex.EncodeToString(fingerprint[:]),
	}, nil
}

func LoadDeploymentSigner(
	deploymentID uuid.UUID,
	path string,
) (*DeploymentSigner, error) {
	encoded, err := readProtectedRegularFile(path, 128, 0o077)
	if err != nil || len(encoded) == 0 {
		return nil, ErrInvalid
	}
	text := strings.TrimSuffix(string(encoded), "\n")
	if strings.ContainsAny(text, "\r\n\t ") {
		return nil, ErrInvalid
	}
	seed, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || base64.RawURLEncoding.EncodeToString(seed) != text {
		return nil, ErrInvalid
	}
	return NewDeploymentSigner(deploymentID, seed)
}

func (signer *DeploymentSigner) DeploymentID() uuid.UUID { return signer.deploymentID }

func (signer *DeploymentSigner) PublicSigningKeyX963() string {
	return base64.RawURLEncoding.EncodeToString(signer.publicX963)
}

func (signer *DeploymentSigner) SigningKeyFingerprint() string { return signer.fingerprint }

func (signer *DeploymentSigner) SignProof(
	request ProofRequest,
	now time.Time,
) (DeploymentProof, error) {
	if signer == nil || request.Validate(signer.deploymentID) != nil {
		return DeploymentProof{}, ErrInvalid
	}
	issued := now.UnixMilli()
	payload := ProofPayload{
		ExpiresAtMilliseconds: issued + MaximumProofLifetime.Milliseconds(),
		IssuedAtMilliseconds:  issued,
		Request:               request,
		Version:               SchemaVersion,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return DeploymentProof{}, fmt.Errorf("encode deployment proof: %w", err)
	}
	digest := sha256.Sum256(append([]byte(deploymentProofSignatureDomain), encoded...))
	r, s, err := ecdsa.Sign(rand.Reader, signer.privateKey, digest[:])
	if err != nil {
		return DeploymentProof{}, fmt.Errorf("sign deployment proof: %w", err)
	}
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)) > 0 {
		s.Sub(elliptic.P256().Params().N, s)
	}
	rawSignature := make([]byte, 64)
	r.FillBytes(rawSignature[:32])
	s.FillBytes(rawSignature[32:])
	return DeploymentProof{
		Payload: encoded,
		Signature: Signature{
			Algorithm:             "ES256",
			PublicSigningKeyX963:  signer.PublicSigningKeyX963(),
			Signature:             base64.RawURLEncoding.EncodeToString(rawSignature),
			SignerID:              signer.deploymentID,
			SigningKeyFingerprint: signer.fingerprint,
		},
	}, nil
}

type RequestBinding struct {
	Scope             Scope
	AuthorityRevision uint64
	AuthorityDigest   string
	DeploymentID      uuid.UUID
	RouteID           uuid.UUID
	TrafficClass      TrafficClass
}

func ParseRequestBinding(
	header http.Header,
	expectedDeploymentID uuid.UUID,
	expectedTrafficClass TrafficClass,
) (RequestBinding, error) {
	scopeKindValue, scopeKindErr := singleHeaderValue(header, HeaderScopeKind)
	scopeIDValue, scopeIDHeaderErr := singleHeaderValue(header, HeaderScopeID)
	revisionValue, revisionHeaderErr := singleHeaderValue(header, HeaderAuthorityRevision)
	digestValue, digestHeaderErr := singleHeaderValue(header, HeaderAuthorityDigest)
	deploymentValue, deploymentHeaderErr := singleHeaderValue(header, HeaderDeploymentID)
	routeValue, routeHeaderErr := singleHeaderValue(header, HeaderRouteID)
	trafficClassValue, trafficClassErr := singleHeaderValue(header, HeaderTrafficClass)
	revision, err := strconv.ParseUint(revisionValue, 10, 64)
	scopeID, scopeErr := uuid.Parse(scopeIDValue)
	deploymentID, deploymentErr := uuid.Parse(deploymentValue)
	routeID, routeErr := uuid.Parse(routeValue)
	binding := RequestBinding{
		Scope: Scope{
			Kind:    ScopeKind(scopeKindValue),
			ScopeID: scopeID,
		},
		AuthorityRevision: revision,
		AuthorityDigest:   digestValue,
		DeploymentID:      deploymentID,
		RouteID:           routeID,
		TrafficClass:      TrafficClass(trafficClassValue),
	}
	if scopeKindErr != nil || scopeIDHeaderErr != nil || revisionHeaderErr != nil ||
		digestHeaderErr != nil || deploymentHeaderErr != nil || routeHeaderErr != nil ||
		trafficClassErr != nil || err != nil || scopeErr != nil || deploymentErr != nil ||
		routeErr != nil ||
		binding.Scope.Validate() != nil || revision == 0 ||
		!validDigest(binding.AuthorityDigest) || deploymentID != expectedDeploymentID ||
		routeID == uuid.Nil || binding.TrafficClass != expectedTrafficClass ||
		!expectedTrafficClass.Valid() {
		return RequestBinding{}, ErrInvalid
	}
	return binding, nil
}

func singleHeaderValue(header http.Header, name string) (string, error) {
	values := header.Values(name)
	if len(values) != 1 || values[0] == "" {
		return "", ErrInvalid
	}
	return values[0], nil
}

type CurrentBinding struct {
	Revision                 uint64
	Digest                   string
	DeploymentID             uuid.UUID
	Manifest                 *Manifest
	TransitionEvidenceDigest *string
	WriteFence               *MigrationWriteFence
}

// MigrationWriteFence is the durable public evidence that this deployment
// stopped accepting writes for one exact service scope before signing a
// migration snapshot. The service state store must commit the named fence and
// state commitment atomically before the deployment signs the snapshot; this
// registry then makes the fence fail-closed at the HTTP authority boundary.
type MigrationWriteFence struct {
	AuthorityManifestDigest string             `json:"authorityManifestDigest"`
	AuthorityRevision       uint64             `json:"authorityRevision"`
	Snapshot                *MigrationSnapshot `json:"snapshot,omitempty"`
	SnapshotPayload         []byte             `json:"snapshotPayload"`
	SnapshotReferenceDigest *string            `json:"snapshotReferenceDigest,omitempty"`
}

type BindingRegistry struct {
	mu                   sync.RWMutex
	bindings             map[Scope]CurrentBinding
	persistencePath      string
	expectedDeploymentID uuid.UUID
}

type BindingFile struct {
	Bindings []BindingFileEntry `json:"bindings"`
	Version  int                `json:"version"`
}

type BindingFileEntry struct {
	DeploymentID             uuid.UUID            `json:"deploymentID"`
	Digest                   string               `json:"digest"`
	Manifest                 *Manifest            `json:"manifest,omitempty"`
	Revision                 uint64               `json:"revision"`
	Scope                    Scope                `json:"scope"`
	TransitionEvidenceDigest *string              `json:"transitionEvidenceDigest,omitempty"`
	WriteFence               *MigrationWriteFence `json:"writeFence,omitempty"`
}

func NewBindingRegistry() *BindingRegistry {
	return &BindingRegistry{bindings: make(map[Scope]CurrentBinding)}
}

func LoadBindingRegistry(
	path string,
	expectedDeploymentID uuid.UUID,
) (*BindingRegistry, error) {
	if strings.TrimSpace(path) == "" || expectedDeploymentID == uuid.Nil {
		return nil, ErrInvalid
	}
	// Bindings are not secret, but only the service owner may modify them.
	data, err := readProtectedRegularFile(path, 1024*1024, 0o022)
	if err != nil {
		return nil, fmt.Errorf("read service authority bindings: %w", err)
	}
	if len(data) == 0 {
		return nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var file BindingFile
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("decode service authority bindings: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrInvalid
	}
	if file.Version != SchemaVersion {
		return nil, ErrInvalid
	}
	registry := &BindingRegistry{
		bindings:             make(map[Scope]CurrentBinding),
		persistencePath:      path,
		expectedDeploymentID: expectedDeploymentID,
	}
	seen := make(map[Scope]struct{}, len(file.Bindings))
	for _, entry := range file.Bindings {
		if _, exists := seen[entry.Scope]; exists {
			return nil, ErrInvalid
		}
		seen[entry.Scope] = struct{}{}
		binding := CurrentBinding{
			Revision:                 entry.Revision,
			Digest:                   entry.Digest,
			DeploymentID:             entry.DeploymentID,
			Manifest:                 entry.Manifest,
			TransitionEvidenceDigest: entry.TransitionEvidenceDigest,
			WriteFence:               entry.WriteFence,
		}
		if entry.Scope.Validate() != nil ||
			validateCurrentBinding(entry.Scope, binding, expectedDeploymentID) != nil {
			return nil, ErrInvalid
		}
		registry.bindings[entry.Scope] = binding
	}
	return registry, nil
}

// Activate is intentionally limited to initial activation and is not exposed
// over HTTP. Persistent registries require the exact signed manifest; later
// successors use the transition- or evidence-specific methods.
func (registry *BindingRegistry) Activate(scope Scope, binding CurrentBinding) error {
	if registry == nil || scope.Validate() != nil ||
		validateCurrentBinding(scope, binding, registry.expectedDeploymentID) != nil {
		return ErrInvalid
	}
	if binding.Manifest != nil {
		payload, err := binding.Manifest.VerifiedPayload()
		if err != nil || payload.Transition != TransitionInitialActivation {
			return ErrInvalid
		}
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if current, exists := registry.bindings[scope]; exists {
		if binding.Revision < current.Revision ||
			(binding.Revision == current.Revision &&
				(subtle.ConstantTimeCompare([]byte(binding.Digest), []byte(current.Digest)) != 1 ||
					binding.DeploymentID != current.DeploymentID)) {
			return ErrInvalid
		}
		if binding.Revision > current.Revision && binding.Revision != current.Revision+1 {
			return ErrInvalid
		}
	}
	next := make(map[Scope]CurrentBinding, len(registry.bindings)+1)
	for existingScope, existingBinding := range registry.bindings {
		next[existingScope] = existingBinding
	}
	next[scope] = binding
	if registry.persistencePath != "" {
		if err := persistBindingFile(
			registry.persistencePath,
			registry.expectedDeploymentID,
			next,
		); err != nil {
			return err
		}
	}
	registry.bindings = next
	return nil
}

func persistBindingFile(
	path string,
	expectedDeploymentID uuid.UUID,
	bindings map[Scope]CurrentBinding,
) error {
	if strings.TrimSpace(path) == "" || expectedDeploymentID == uuid.Nil {
		return ErrInvalid
	}
	entries := make([]BindingFileEntry, 0, len(bindings))
	for scope, binding := range bindings {
		if scope.Validate() != nil ||
			validateCurrentBinding(scope, binding, expectedDeploymentID) != nil {
			return ErrInvalid
		}
		entries = append(entries, BindingFileEntry{
			DeploymentID:             binding.DeploymentID,
			Digest:                   binding.Digest,
			Manifest:                 binding.Manifest,
			Revision:                 binding.Revision,
			Scope:                    scope,
			TransitionEvidenceDigest: binding.TransitionEvidenceDigest,
			WriteFence:               binding.WriteFence,
		})
	}
	sort.Slice(entries, func(left, right int) bool {
		if entries[left].Scope.Kind != entries[right].Scope.Kind {
			return entries[left].Scope.Kind < entries[right].Scope.Kind
		}
		return bytes.Compare(
			entries[left].Scope.ScopeID[:],
			entries[right].Scope.ScopeID[:],
		) < 0
	})
	encoded, err := json.Marshal(BindingFile{
		Bindings: entries,
		Version:  SchemaVersion,
	})
	if err != nil {
		return fmt.Errorf("encode service authority bindings: %w", err)
	}
	encoded = append(encoded, '\n')
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".facets-service-authority-bindings-*")
	if err != nil {
		return fmt.Errorf("create service authority binding update: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("protect service authority binding update: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		return fmt.Errorf("write service authority binding update: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync service authority binding update: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close service authority binding update: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("activate service authority binding update: %w", err)
	}
	committed = true
	directoryFile, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open service authority binding directory: %w", err)
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return fmt.Errorf("sync service authority binding directory: %w", err)
	}
	return nil
}

func validateCurrentBinding(
	scope Scope,
	binding CurrentBinding,
	expectedDeploymentID uuid.UUID,
) error {
	if binding.Revision == 0 || !validDigest(binding.Digest) || binding.DeploymentID == uuid.Nil {
		return ErrInvalid
	}
	if binding.Manifest == nil {
		if binding.TransitionEvidenceDigest != nil || binding.WriteFence != nil ||
			expectedDeploymentID != uuid.Nil {
			return ErrInvalid
		}
		return nil
	}
	payload, err := binding.Manifest.VerifiedPayload()
	digest, digestErr := binding.Manifest.ReferenceDigest()
	if err != nil || digestErr != nil || payload.Scope != scope || payload.Revision != binding.Revision ||
		digest != binding.Digest || payload.ActiveDeployment.DeploymentID != binding.DeploymentID {
		return ErrInvalid
	}
	if expectedDeploymentID != uuid.Nil && !manifestNamesDeployment(payload, expectedDeploymentID) {
		return ErrInvalid
	}
	requiresEvidence := payload.Transition == TransitionMigrationPreparation ||
		payload.Transition == TransitionMigrationActivation ||
		payload.Transition == TransitionMigrationRollback
	if requiresEvidence != (binding.TransitionEvidenceDigest != nil) ||
		(binding.TransitionEvidenceDigest != nil && !validDigest(*binding.TransitionEvidenceDigest)) {
		return ErrInvalid
	}
	if binding.WriteFence != nil &&
		binding.WriteFence.validate(scope, binding, expectedDeploymentID) != nil {
		return ErrInvalid
	}
	return nil
}

func manifestNamesDeployment(payload ManifestPayload, deploymentID uuid.UUID) bool {
	if payload.ActiveDeployment.DeploymentID == deploymentID {
		return true
	}
	for _, deployment := range payload.PreparedDeployments {
		if deployment.DeploymentID == deploymentID {
			return true
		}
	}
	return payload.Migration != nil &&
		(payload.Migration.SourceDeploymentID == deploymentID ||
			payload.Migration.TargetDeploymentID == deploymentID)
}

func (fence MigrationWriteFence) validate(
	scope Scope,
	binding CurrentBinding,
	expectedDeploymentID uuid.UUID,
) error {
	var payload MigrationSnapshotPayload
	if decodeCanonical(fence.SnapshotPayload, &payload) != nil || payload.Validate(nil) != nil ||
		!validDigest(fence.AuthorityManifestDigest) ||
		fence.AuthorityRevision == 0 || fence.AuthorityRevision > binding.Revision ||
		payload.Scope != scope || payload.AuthorityManifestDigest != fence.AuthorityManifestDigest ||
		(expectedDeploymentID != uuid.Nil && payload.ExportingDeploymentID != expectedDeploymentID) {
		return ErrInvalid
	}
	if fence.Snapshot == nil {
		if fence.SnapshotReferenceDigest != nil {
			return ErrInvalid
		}
	} else {
		verified, err := fence.Snapshot.VerifiedPayload(nil)
		digest, digestErr := fence.Snapshot.ReferenceDigest()
		if err != nil || digestErr != nil || !canonicalEqual(verified, payload) ||
			!bytes.Equal(fence.Snapshot.Payload, fence.SnapshotPayload) ||
			fence.SnapshotReferenceDigest == nil || digest != *fence.SnapshotReferenceDigest {
			return ErrInvalid
		}
	}
	if binding.Manifest != nil {
		manifest, err := binding.Manifest.VerifiedPayload()
		if err != nil || manifest.Migration == nil ||
			manifest.Migration.MigrationID != payload.MigrationID {
			return ErrInvalid
		}
	}
	return nil
}

func (registry *BindingRegistry) Authorize(binding RequestBinding) error {
	if registry == nil {
		return ErrInvalid
	}
	registry.mu.RLock()
	current, exists := registry.bindings[binding.Scope]
	registry.mu.RUnlock()
	if !exists || current.Revision != binding.AuthorityRevision ||
		current.DeploymentID != binding.DeploymentID ||
		subtle.ConstantTimeCompare([]byte(current.Digest), []byte(binding.AuthorityDigest)) != 1 {
		return ErrInvalid
	}
	return nil
}

// AuthorizeRequest additionally enforces a durable migration write fence.
// Read-only requests may continue during attended transfer; any method that
// can mutate service state fails closed until evidence-specific activation or
// rollback clears the local fence.
func (registry *BindingRegistry) AuthorizeRequest(binding RequestBinding, method string) error {
	if registry == nil {
		return ErrInvalid
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	current, exists := registry.bindings[binding.Scope]
	if !exists || current.Revision != binding.AuthorityRevision ||
		current.DeploymentID != binding.DeploymentID ||
		subtle.ConstantTimeCompare([]byte(current.Digest), []byte(binding.AuthorityDigest)) != 1 {
		return ErrInvalid
	}
	if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
		return nil
	}
	if current.WriteFence != nil {
		return ErrInvalid
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func readProtectedRegularFile(
	path string,
	maximumByteCount int64,
	disallowedPermissions os.FileMode,
) ([]byte, error) {
	if strings.TrimSpace(path) == "" || maximumByteCount <= 0 {
		return nil, ErrInvalid
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() ||
		pathInfo.Mode().Perm()&disallowedPermissions != 0 {
		return nil, ErrInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalid
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() ||
		openedInfo.Mode().Perm()&disallowedPermissions != 0 ||
		!os.SameFile(pathInfo, openedInfo) {
		return nil, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumByteCount+1))
	if err != nil || int64(len(data)) > maximumByteCount {
		return nil, ErrInvalid
	}
	return data, nil
}

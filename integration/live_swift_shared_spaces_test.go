package integration_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/httpapi"
	"github.com/robreuss/FacetsNode/internal/relay"
	"github.com/robreuss/FacetsNode/internal/rendezvous"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
	"github.com/robreuss/FacetsNode/internal/sharedspaces"
)

type swiftSharedSpacesLiveAccess struct {
	DeploymentOffer            serviceauthority.DeploymentOffer `json:"deploymentOffer"`
	Endpoint                   string                           `json:"endpoint"`
	OperatorAuthorizationToken string                           `json:"operatorAuthorizationToken"`
	ResultPath                 string                           `json:"resultPath"`
}

type swiftSharedSpacesLiveResult struct {
	AuthorityManifestDigest string    `json:"authorityManifestDigest"`
	RouteID                 uuid.UUID `json:"routeID"`
	SpaceID                 uuid.UUID `json:"spaceID"`
}

// TestLiveServeSwiftSharedSpacesAuthority is an opt-in cross-language gate.
// It exposes an in-process FacetsNode handler over pinned TLS, gives Swift only
// a short-lived deployment offer plus the disposable operator bearer, and
// waits for Swift to prove both initial authority activation and an ordinary
// authority-bound request. PostgreSQL durability is covered by the separate
// Shared Spaces store integration gate; this test owns wire/runtime parity.
func TestLiveServeSwiftSharedSpacesAuthority(t *testing.T) {
	accessPath := os.Getenv("FACETS_SERVER_TEST_SWIFT_SHARED_SPACES_ACCESS_OUTPUT_PATH")
	resultPath := os.Getenv("FACETS_SERVER_TEST_SWIFT_SHARED_SPACES_RESULT_PATH")
	if accessPath == "" || resultPath == "" {
		t.Skip("FACETS_SERVER_TEST_SWIFT_SHARED_SPACES_ACCESS_OUTPUT_PATH and FACETS_SERVER_TEST_SWIFT_SHARED_SPACES_RESULT_PATH are required")
	}
	validateHighVolumeStatePath(t, accessPath)
	validateHighVolumeStatePath(t, resultPath)
	if filepath.Clean(accessPath) == filepath.Clean(resultPath) {
		t.Fatal("Shared Spaces live access and result paths must differ")
	}

	operatorToken := encodedBytes(0xd1)
	relayStore := relay.NewMemoryStore()
	blobRoot := t.TempDir()
	blobStore, err := relay.NewFileBlobContentStore(blobRoot)
	if err != nil {
		t.Fatal(err)
	}
	uploadStore, err := relay.NewFileBlobUploadContentStore(blobRoot, blobStore)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	api, err := httpapi.NewWithRelay(
		rendezvous.NewMemoryStore(), relayStore, blobStore, logger,
		operatorToken, uploadStore,
	)
	if err != nil {
		t.Fatal(err)
	}
	api.SetServiceIdentity("facets-shared-spaces-server")
	api.SetSharedSpacesStore(sharedspaces.NewMemoryStore(relayStore))

	deploymentID := uuid.New()
	routeID := uuid.New()
	seed := make([]byte, 32)
	seed[31] = 2
	signer, err := serviceauthority.NewDeploymentSigner(deploymentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	bindings := serviceauthority.NewBindingRegistry()
	api.SetServiceAuthorityDeployment(
		signer, bindings, serviceauthority.ScopeSharedSpace,
	)

	server := httptest.NewUnstartedServer(api.Handler())
	server.StartTLS()
	defer server.Close()
	certificate := server.Certificate()
	if certificate == nil || len(certificate.RawSubjectPublicKeyInfo) == 0 {
		t.Fatal("live Shared Spaces TLS server has no SPKI")
	}
	pin := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	pinText := hex.EncodeToString(pin[:])
	now := time.Now()
	route := serviceauthority.TransportRoute{
		Endpoint:     server.URL,
		Kind:         serviceauthority.RouteDirectHTTPS,
		NetworkScope: serviceauthority.NetworkTrustedLAN,
		RouteID:      routeID,
		ServerAuthentication: serviceauthority.ServerAuthentication{
			Kind:             "pinned_spki_sha256",
			PinnedSPKISHA256: &pinText,
		},
	}
	policy := serviceauthority.TransportPolicy{
		AllowsPublicDirectBulkTransfer: false,
		BulkRouteIDs:                   []uuid.UUID{routeID},
		ControlRouteIDs:                []uuid.UUID{routeID},
		MessageRouteIDs:                []uuid.UUID{routeID},
		Version:                        serviceauthority.SchemaVersion,
	}
	offer, err := signer.SignDeploymentOffer(
		serviceauthority.DeploymentOfferPayload{
			Deployment: serviceauthority.DeploymentDescriptor{
				CreatedAtMilliseconds: now.Add(-time.Minute).UnixMilli(),
				DeploymentID:          deploymentID,
				PublicSigningKeyX963:  signer.PublicSigningKeyX963(),
				Routes:                []serviceauthority.TransportRoute{route},
				SigningKeyFingerprint: signer.SigningKeyFingerprint(),
				Version:               serviceauthority.SchemaVersion,
			},
			ExpiresAtMilliseconds: now.Add(10 * time.Minute).UnixMilli(),
			IssuedAtMilliseconds:  now.Add(-time.Second).UnixMilli(),
			TransportPolicy:       policy,
			Version:               serviceauthority.SchemaVersion,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	writeSwiftLiveAccess(t, accessPath, swiftSharedSpacesLiveAccess{
		DeploymentOffer:            offer,
		Endpoint:                   server.URL,
		OperatorAuthorizationToken: operatorToken,
		ResultPath:                 resultPath,
	})

	deadline := time.NewTimer(3 * time.Minute)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("timed out waiting for the Swift Shared Spaces live result")
		case <-ticker.C:
			data, readErr := os.ReadFile(resultPath)
			if os.IsNotExist(readErr) {
				continue
			}
			if readErr != nil {
				t.Fatal(readErr)
			}
			info, statErr := os.Stat(resultPath)
			if statErr != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("Swift Shared Spaces result permissions are not 0600: info=%v err=%v", info, statErr)
			}
			var result swiftSharedSpacesLiveResult
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&result); err != nil {
				t.Fatal(err)
			}
			if result.SpaceID == uuid.Nil || result.RouteID != routeID {
				t.Fatalf("unexpected Swift Shared Spaces live result: %+v", result)
			}
			if err := bindings.Authorize(serviceauthority.RequestBinding{
				Scope: serviceauthority.Scope{
					Kind: serviceauthority.ScopeSharedSpace, ScopeID: result.SpaceID,
				},
				AuthorityRevision: 1,
				AuthorityDigest:   result.AuthorityManifestDigest,
				DeploymentID:      deploymentID,
				RouteID:           routeID,
				TrafficClass:      serviceauthority.TrafficControl,
			}); err != nil {
				t.Fatalf("Swift did not activate the exact Shared Space binding: %v", err)
			}
			return
		}
	}
}

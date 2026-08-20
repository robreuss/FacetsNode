package testfixture

import (
	_ "embed"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/devicesync"
)

//go:embed device-sync-join-request-portable-v1.json
var deviceSyncJoinRequestFixture []byte

// DeviceSyncJoinRequestRequest contains the candidate-held secret material
// only for this synthetic portable fixture. Production clients must keep the
// private key, polling token, and PIN in platform-protected storage.
type DeviceSyncJoinRequestRequest struct {
	Version                      int       `json:"version"`
	RetryID                      uuid.UUID `json:"retryID"`
	RequestID                    uuid.UUID `json:"requestID"`
	CandidateDeviceID            uuid.UUID `json:"candidateDeviceID"`
	CandidateBootstrapPrivateKey string    `json:"candidateBootstrapPrivateKey"`
	CandidateBootstrapPublicKey  string    `json:"candidateBootstrapPublicKey"`
	PollingAuthorizationToken    string    `json:"pollingAuthorizationToken"`
	PIN                          string    `json:"pin"`
	CreatedAtMilliseconds        int64     `json:"createdAtMilliseconds"`
	ExpiresAtMilliseconds        int64     `json:"expiresAtMilliseconds"`
}

type DeviceSyncJoinRequestFixture struct {
	Format              string                                    `json:"format"`
	Request             DeviceSyncJoinRequestRequest              `json:"request"`
	CreateResult        devicesync.JoinRequestCreateResult        `json:"createResult"`
	SponsorPresentation devicesync.JoinRequestSponsorPresentation `json:"sponsorPresentation"`
	Bootstrap           devicesync.JoinBootstrapEnvelope          `json:"bootstrap"`
}

func LoadDeviceSyncJoinRequestFixture() (DeviceSyncJoinRequestFixture, error) {
	var fixture DeviceSyncJoinRequestFixture
	err := json.Unmarshal(deviceSyncJoinRequestFixture, &fixture)
	return fixture, err
}

func (r DeviceSyncJoinRequestRequest) JoinRequest() (devicesync.JoinRequest, error) {
	pollingDigest, err := devicesync.JoinRequestPollingAuthorizationDigest(
		devicesync.JoinRequestCredential{RequestID: r.RequestID, Token: r.PollingAuthorizationToken},
	)
	if err != nil {
		return devicesync.JoinRequest{}, err
	}
	pinDigest, err := devicesync.JoinRequestPINAuthorizationDigest(r.PIN)
	if err != nil {
		return devicesync.JoinRequest{}, err
	}
	return devicesync.JoinRequest{
		Version: r.Version, RetryID: r.RetryID, RequestID: r.RequestID,
		CandidateDeviceID:           r.CandidateDeviceID,
		CandidateBootstrapPublicKey: r.CandidateBootstrapPublicKey,
		PollingAuthorizationDigest:  pollingDigest, PINAuthorizationDigest: pinDigest,
		CreatedAtMilliseconds: r.CreatedAtMilliseconds,
		ExpiresAtMilliseconds: r.ExpiresAtMilliseconds,
	}, nil
}

package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"time"
)

const boxControllerAdmissionLifetime = 15 * time.Minute

func (s *Server) authorizeBoxController(request *http.Request) bool {
	if !s.boxControllerEnabled {
		return false
	}
	value := request.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(value) <= len(prefix) || value[:len(prefix)] != prefix {
		return false
	}
	token, err := base64.RawURLEncoding.Strict().DecodeString(value[len(prefix):])
	if err != nil || len(token) != 32 ||
		base64.RawURLEncoding.EncodeToString(token) != value[len(prefix):] {
		return false
	}
	digest := sha256.Sum256(append(
		[]byte("facets-device-sync-box-controller-v1\x00"),
		token...,
	))
	return subtle.ConstantTimeCompare(
		digest[:],
		s.boxControllerTokenDigest[:],
	) == 1
}

func (s *Server) handleBoxControllerDeviceSyncGroups(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if !s.authorizeBoxController(request) {
		http.Error(writer, "Not found.", http.StatusNotFound)
		return
	}
	profiles, err := s.deviceSyncStore.ListDiscoveryProfiles(request.Context())
	if err != nil {
		s.writeError(writer, err)
		return
	}
	groups := make([]facetsBoxDeviceSyncGroup, 0, len(profiles))
	for _, profile := range profiles {
		groups = append(groups, facetsBoxDeviceSyncGroup{
			SetDiscriminator: profile.SetDiscriminator,
			DisplayName:      profile.DisplayName,
			Revision:         profile.Revision,
		})
	}
	writeJSON(writer, http.StatusOK, struct {
		Groups []facetsBoxDeviceSyncGroup `json:"groups"`
	}{Groups: groups})
}

func (s *Server) handleBoxControllerDeviceSyncAccountAdmission(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if !s.authorizeBoxController(request) {
		http.Error(writer, "Not found.", http.StatusNotFound)
		return
	}
	issued, err := s.deviceSyncAccountBootstrapIssuer(
		request.Context(),
		boxControllerAdmissionLifetime,
		s.now(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, struct {
		Bootstrap any `json:"bootstrap"`
	}{Bootstrap: issued.Bootstrap})
}

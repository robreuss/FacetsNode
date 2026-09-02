package httpapi

import (
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/relay"
)

type facetsBoxServiceDescriptor struct {
	Kind     string `json:"kind"`
	Endpoint string `json:"endpoint"`
}

type facetsBoxDeviceSyncGroup struct {
	SetDiscriminator string `json:"setDiscriminator"`
	DisplayName      string `json:"displayName"`
	Revision         uint64 `json:"revision"`
}

type facetsBoxManifest struct {
	Version          int                          `json:"version"`
	BoxID            uuid.UUID                    `json:"boxID"`
	DisplayName      string                       `json:"displayName"`
	Services         []facetsBoxServiceDescriptor `json:"services"`
	DeviceSyncGroups []facetsBoxDeviceSyncGroup   `json:"deviceSyncGroups"`
}

func (s *Server) handleFacetsBoxManifest(writer http.ResponseWriter, request *http.Request) {
	if s.boxID == uuid.Nil || s.publicURL == "" {
		http.Error(writer, "Facets Box manifest is unavailable.", http.StatusServiceUnavailable)
		return
	}
	kind := ""
	switch s.serviceIdentity {
	case "facets-device-sync-server":
		kind = "device-sync"
	case "facets-shared-spaces-server":
		kind = "shared-spaces"
	case "facets-backup-custody-server":
		kind = "backup"
	case "facets-compute-pool-server":
		kind = "compute"
	default:
		http.Error(writer, "Facets Box manifest is unavailable.", http.StatusServiceUnavailable)
		return
	}
	services := append([]facetsBoxServiceDescriptor(nil), s.facetsBoxServices...)
	if len(services) == 0 {
		services = []facetsBoxServiceDescriptor{{Kind: kind, Endpoint: s.publicURL}}
	}
	manifest := facetsBoxManifest{
		Version:          1,
		BoxID:            s.boxID,
		DisplayName:      "Facets Box",
		Services:         services,
		DeviceSyncGroups: []facetsBoxDeviceSyncGroup{},
	}
	if s.deviceSyncStore != nil {
		profiles, err := s.deviceSyncStore.ListDiscoveryProfiles(request.Context())
		if err != nil {
			s.writeError(writer, err)
			return
		}
		for _, profile := range profiles {
			manifest.DeviceSyncGroups = append(manifest.DeviceSyncGroups, facetsBoxDeviceSyncGroup{
				SetDiscriminator: profile.SetDiscriminator,
				DisplayName:      profile.DisplayName,
				Revision:         profile.Revision,
			})
		}
	}
	writeJSON(writer, http.StatusOK, manifest)
}

func (s *Server) handlePublishDeviceSyncDiscoveryProfile(writer http.ResponseWriter, request *http.Request) {
	principalID, err := parseUUID(request.PathValue("principalID"))
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeInvalidPrincipal, err.Error()))
		return
	}
	token, err := bearerToken(request)
	if err != nil {
		s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeUnauthorized, "Device Sync principal credential is missing"))
		return
	}
	var input facetsBoxDeviceSyncGroup
	if err := readRelayJSON(writer, request, &input, 4*1024); err != nil {
		return
	}
	profile := devicesync.DiscoveryProfile{
		Version:             devicesync.SchemaVersion,
		PrincipalID:         principalID,
		SetDiscriminator:    strings.ToLower(input.SetDiscriminator),
		DisplayName:         strings.TrimSpace(input.DisplayName),
		Revision:            input.Revision,
		UpdatedMilliseconds: s.nowMilliseconds(),
	}
	if err := s.deviceSyncStore.PublishDiscoveryProfile(
		request.Context(),
		relay.TenantCredential{TenantID: principalID, Token: token},
		profile,
	); err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, input)
}

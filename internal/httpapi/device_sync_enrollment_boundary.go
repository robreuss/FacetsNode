package httpapi

import (
	"net/http"

	"github.com/robreuss/FacetsNode/internal/devicesync"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

// A Spaces Sync service must not offer a second, generic path which accepts
// shared administration custody or an admission bearer without rechecking the
// current sponsor and target. Generic relay and Group Spaces retain their own
// enrollment protocols; ordinary data and rebootstrap operations are unchanged.
func (s *Server) rejectGenericDeviceSyncEnrollment(writer http.ResponseWriter) bool {
	if s.serviceAuthorityScopeKind != serviceauthority.ScopeDeviceSync {
		return false
	}
	s.writeError(writer, devicesync.NewProtocolError(devicesync.CodeWrongScope,
		"Spaces Sync enrollment requires its participant-authorized protocol"))
	return true
}

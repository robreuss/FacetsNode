package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/relay"
)

const maximumRelayRequestByteCount = ((relay.MaximumCiphertextByteCount + 2) / 3 * 4) + 32_768

var allRelayCapabilities = []relay.Capability{
	relay.CapabilityFetchBlob,
	relay.CapabilityPublishBlob,
	relay.CapabilityPublishCheckpoint,
	relay.CapabilityAcknowledgeMessage,
	relay.CapabilityFetchMessage,
	relay.CapabilityPublishMessage,
}

type relayAdministrationCredential struct {
	TenantID           uuid.UUID `json:"tenantID"`
	DomainID           uuid.UUID `json:"domainID"`
	AuthorizationToken string    `json:"authorizationToken"`
}

type relayMemberCredential struct {
	TenantID           uuid.UUID `json:"tenantID"`
	DomainID           uuid.UUID `json:"domainID"`
	MemberID           uuid.UUID `json:"memberID"`
	AuthorizationToken string    `json:"authorizationToken"`
}

type relayAdmissionCredential struct {
	TenantID           uuid.UUID `json:"tenantID"`
	DomainID           uuid.UUID `json:"domainID"`
	AdmissionID        uuid.UUID `json:"admissionID"`
	AuthorizationToken string    `json:"authorizationToken"`
}

func (s *Server) handleCreateRelayDomain(writer http.ResponseWriter, request *http.Request) {
	if err := s.authorizeOperator(request); err != nil {
		s.writeError(writer, err)
		return
	}
	var input struct {
		AdministrationCredential relayAdministrationCredential `json:"administrationCredential"`
		MemberCredential         relayMemberCredential         `json:"memberCredential"`
		MemberCapabilities       []relay.Capability            `json:"memberCapabilities"`
		CreatedAtMilliseconds    int64                         `json:"createdAtMilliseconds"`
	}
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	if input.AdministrationCredential.TenantID != input.MemberCredential.TenantID ||
		input.AdministrationCredential.DomainID != input.MemberCredential.DomainID {
		s.writeError(writer, relay.NewProtocolError(
			relay.CodeWrongScope,
			"initial member belongs to another domain",
		))
		return
	}
	capabilities, err := normalizedCapabilities(input.MemberCapabilities)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	administrationCredential := relay.AdministrationCredential{
		TenantID: input.AdministrationCredential.TenantID,
		DomainID: input.AdministrationCredential.DomainID,
		Token:    input.AdministrationCredential.AuthorizationToken,
	}
	administrationDigest, err := relay.AdministrationDigest(administrationCredential)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	memberCredential := relay.Credential{
		TenantID: input.MemberCredential.TenantID,
		DomainID: input.MemberCredential.DomainID,
		MemberID: input.MemberCredential.MemberID,
		Token:    input.MemberCredential.AuthorizationToken,
	}
	memberDigest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	domain := relay.DomainRegistration{
		Version:                relay.SchemaVersion,
		TenantID:               administrationCredential.TenantID,
		DomainID:               administrationCredential.DomainID,
		AdministrationDigest:   administrationDigest,
		CreatedAtMilliseconds:  input.CreatedAtMilliseconds,
		MaximumMessageCount:    relay.DefaultMaximumMessageCount,
		MaximumBlobCount:       relay.DefaultMaximumBlobCount,
		MaximumStoredByteCount: relay.DefaultMaximumStoredByteCount,
	}
	member := relay.MemberRegistration{
		Version:               relay.SchemaVersion,
		TenantID:              memberCredential.TenantID,
		DomainID:              memberCredential.DomainID,
		MemberID:              memberCredential.MemberID,
		AuthorizationDigest:   memberDigest,
		Capabilities:          capabilities,
		CreatedAtMilliseconds: input.CreatedAtMilliseconds,
	}
	acceptance, err := s.relayStore.CreateDomain(request.Context(), domain, member)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(string(acceptance))
	writeJSON(writer, relayAcceptanceStatus(acceptance), struct {
		Acceptance               relay.Acceptance              `json:"acceptance"`
		Domain                   relay.DomainRegistration      `json:"domain"`
		AdministrationCredential relayAdministrationCredential `json:"administrationCredential"`
		Member                   relay.MemberRegistration      `json:"member"`
		MemberCredential         relayMemberCredential         `json:"memberCredential"`
	}{
		Acceptance:               acceptance,
		Domain:                   domain,
		AdministrationCredential: input.AdministrationCredential,
		Member:                   member,
		MemberCredential:         input.MemberCredential,
	})
}

func (s *Server) handleCreateRelayMember(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(
		request, tenantID, domainID,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var input struct {
		Capabilities          []relay.Capability `json:"capabilities"`
		ExpiresAtMilliseconds *int64             `json:"expiresAtMilliseconds,omitempty"`
	}
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	capabilities, err := normalizedCapabilities(input.Capabilities)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	memberID := uuid.New()
	token, err := randomToken()
	if err != nil {
		s.writeError(writer, err)
		return
	}
	memberCredential := relay.Credential{
		TenantID: tenantID,
		DomainID: domainID,
		MemberID: memberID,
		Token:    token,
	}
	digest, err := relay.AuthorizationDigest(memberCredential)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	now := s.nowMilliseconds()
	registration := relay.MemberRegistration{
		Version:               relay.SchemaVersion,
		TenantID:              tenantID,
		DomainID:              domainID,
		MemberID:              memberID,
		AuthorizationDigest:   digest,
		Capabilities:          capabilities,
		CreatedAtMilliseconds: now,
		ExpiresAtMilliseconds: input.ExpiresAtMilliseconds,
	}
	acceptance, err := s.relayStore.CreateMember(
		request.Context(), credential, registration, now,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(string(acceptance))
	writeJSON(writer, http.StatusCreated, struct {
		Member     relay.MemberRegistration `json:"member"`
		Credential relayMemberCredential    `json:"credential"`
	}{
		Member: registration,
		Credential: relayMemberCredential{
			TenantID:           tenantID,
			DomainID:           domainID,
			MemberID:           memberID,
			AuthorizationToken: token,
		},
	})
}

func (s *Server) handleRotateRelayAdministrationCredential(
	writer http.ResponseWriter,
	request *http.Request,
) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	rotationID, err := parseRelayUUID(request.PathValue("rotationID"))
	if err != nil {
		s.writeError(writer, relay.NewProtocolError(
			relay.CodeInvalidCredentialRotation,
			"credential rotation identifier is invalid",
		))
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(
		request, tenantID, domainID,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	rotation, err := relayCredentialRotationFromRequest(writer, request, rotationID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	result, err := s.relayStore.RotateAdministrationCredential(
		request.Context(), credential, rotation, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func (s *Server) handleRotateRelayMemberCredential(
	writer http.ResponseWriter,
	request *http.Request,
) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	memberID, err := parseRelayUUID(request.PathValue("memberID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	rotationID, err := parseRelayUUID(request.PathValue("rotationID"))
	if err != nil {
		s.writeError(writer, relay.NewProtocolError(
			relay.CodeInvalidCredentialRotation,
			"credential rotation identifier is invalid",
		))
		return
	}
	credential, err := relayCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	if credential.MemberID != memberID {
		s.writeError(writer, relay.NewProtocolError(
			relay.CodeWrongScope,
			"member credential and path identifiers differ",
		))
		return
	}
	rotation, err := relayCredentialRotationFromRequest(writer, request, rotationID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	result, err := s.relayStore.RotateMemberCredential(
		request.Context(), credential, rotation, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(string(result.Acceptance))
	writeJSON(writer, relayAcceptanceStatus(result.Acceptance), result)
}

func relayCredentialRotationFromRequest(
	writer http.ResponseWriter,
	request *http.Request,
	rotationID uuid.UUID,
) (relay.CredentialRotation, error) {
	var input struct {
		AuthorizationDigest string `json:"authorizationDigest"`
	}
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		return relay.CredentialRotation{}, err
	}
	rotation := relay.CredentialRotation{
		RotationID:          rotationID,
		AuthorizationDigest: input.AuthorizationDigest,
	}
	if err := rotation.Validate(); err != nil {
		return relay.CredentialRotation{}, err
	}
	return rotation, nil
}

func relayAcceptanceStatus(acceptance relay.Acceptance) int {
	if acceptance == relay.AcceptanceDuplicate {
		return http.StatusOK
	}
	return http.StatusCreated
}

func (s *Server) handleCreateRelayAdmission(
	writer http.ResponseWriter,
	request *http.Request,
) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(
		request, tenantID, domainID,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var input struct {
		AdmissionID                 uuid.UUID          `json:"admissionID"`
		AuthorizationDigest         string             `json:"authorizationDigest"`
		Capabilities                []relay.Capability `json:"capabilities"`
		ExpiresAtMilliseconds       int64              `json:"expiresAtMilliseconds"`
		MemberExpiresAtMilliseconds *int64             `json:"memberExpiresAtMilliseconds,omitempty"`
	}
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	capabilities, err := normalizedCapabilities(input.Capabilities)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	now := s.nowMilliseconds()
	registration := relay.MemberAdmission{
		Version:                     relay.SchemaVersion,
		TenantID:                    tenantID,
		DomainID:                    domainID,
		AdmissionID:                 input.AdmissionID,
		AuthorizationDigest:         input.AuthorizationDigest,
		Capabilities:                capabilities,
		CreatedAtMilliseconds:       now,
		ExpiresAtMilliseconds:       input.ExpiresAtMilliseconds,
		MemberExpiresAtMilliseconds: input.MemberExpiresAtMilliseconds,
	}
	result, err := s.relayStore.CreateAdmission(
		request.Context(), credential, registration, now,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(string(result.Acceptance))
	status := http.StatusCreated
	if result.Acceptance == relay.AcceptanceDuplicate {
		status = http.StatusOK
	}
	writeJSON(writer, status, result)
}

func (s *Server) handleCollectRelayAdmissions(
	writer http.ResponseWriter,
	request *http.Request,
) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(
		request, tenantID, domainID,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	result, err := s.relayStore.CollectAdmissions(
		request.Context(), credential, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) handleClaimRelayAdmission(
	writer http.ResponseWriter,
	request *http.Request,
) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	admissionID, err := parseRelayUUID(request.PathValue("admissionID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdmissionCredentialFromRequest(
		request, tenantID, domainID, admissionID,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var claim relay.MemberAdmissionClaim
	if err := readRelayJSON(writer, request, &claim, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	result, err := s.relayStore.ClaimAdmission(
		request.Context(), credential, claim, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(string(result.Acceptance))
	status := http.StatusCreated
	if result.Acceptance == relay.AcceptanceDuplicate {
		status = http.StatusOK
	}
	writeJSON(writer, status, result)
}

func (s *Server) handleRevokeRelayAdmission(
	writer http.ResponseWriter,
	request *http.Request,
) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	admissionID, err := parseRelayUUID(request.PathValue("admissionID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(
		request, tenantID, domainID,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	acceptance, err := s.relayStore.RevokeAdmission(
		request.Context(), credential, admissionID, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(string(acceptance))
	writeJSON(writer, http.StatusOK, map[string]string{
		"acceptance": string(acceptance),
	})
}

func (s *Server) handleRevokeRelayMember(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	memberID, err := parseRelayUUID(request.PathValue("memberID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayAdministrationCredentialFromRequest(
		request, tenantID, domainID,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	acceptance, err := s.relayStore.RevokeMember(
		request.Context(), credential, memberID, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(string(acceptance))
	writeJSON(writer, http.StatusOK, map[string]string{
		"acceptance": string(acceptance),
	})
}

func (s *Server) handlePublishRelayMessage(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	messageID, err := parseRelayUUID(request.PathValue("messageID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var envelope relay.Envelope
	if err := readRelayJSON(
		writer, request, &envelope, maximumRelayRequestByteCount,
	); err != nil {
		s.writeError(writer, err)
		return
	}
	if envelope.TenantID != tenantID || envelope.DomainID != domainID ||
		envelope.MessageID != messageID {
		s.writeError(writer, relay.NewProtocolError(
			relay.CodeWrongScope,
			"path and envelope identifiers differ",
		))
		return
	}
	result, err := s.relayStore.Publish(
		request.Context(), credential, envelope, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(string(result.Acceptance))
	status := http.StatusCreated
	if result.Acceptance == relay.AcceptanceDuplicate {
		status = http.StatusOK
	}
	writeJSON(writer, status, result)
}

func (s *Server) handleFetchRelayMessages(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	after, err := relay.DecodeCursor(request.URL.Query().Get("cursor"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	limit := relay.MaximumPageSize
	if rawLimit := request.URL.Query().Get("limit"); rawLimit != "" {
		limit, err = strconv.Atoi(rawLimit)
		if err != nil || limit <= 0 || limit > relay.MaximumPageSize {
			s.writeError(writer, relay.NewProtocolError(
				relay.CodeInvalidCursor,
				"page limit is invalid",
			))
			return
		}
	}
	result, err := s.relayStore.Fetch(
		request.Context(), credential, after, limit, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		Messages []relay.Message `json:"messages"`
		Cursor   string          `json:"cursor"`
	}{
		Messages: result.Messages,
		Cursor:   relay.EncodeCursor(result.NextSequence),
	})
}

func (s *Server) handleAcknowledgeRelayMessage(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	messageID, err := parseRelayUUID(request.PathValue("messageID"))
	if err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	var input struct {
		Stage relay.AcknowledgmentStage `json:"stage"`
	}
	if err := readRelayJSON(writer, request, &input, maximumRequestByteCount); err != nil {
		s.writeError(writer, err)
		return
	}
	result, err := s.relayStore.Acknowledge(
		request.Context(), credential, messageID, input.Stage, s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(string(result.Acceptance))
	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) handlePublishRelayBlob(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	blobID := request.PathValue("blobID")
	if err := relay.ValidateBlobID(blobID); err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/octet-stream" {
		s.writeError(writer, relay.NewProtocolError(
			relay.CodeInvalidBlob,
			"blob content type must be application/octet-stream",
		))
		return
	}
	if request.ContentLength < 0 || request.ContentLength > relay.MaximumBlobByteCount {
		s.writeError(writer, relay.NewProtocolError(
			relay.CodeInvalidBlob,
			"blob Content-Length is required and outside the supported range",
		))
		return
	}
	now := s.nowMilliseconds()
	if err := s.relayStore.PrepareBlobPublish(
		request.Context(),
		credential,
		blobID,
		request.ContentLength,
		now,
	); err != nil {
		s.writeError(writer, err)
		return
	}
	request.Body = http.MaxBytesReader(
		writer,
		request.Body,
		relay.MaximumBlobByteCount+1,
	)
	stored, err := s.blobContentStore.Put(
		request.Context(),
		relay.BlobScope{TenantID: tenantID, DomainID: domainID},
		blobID,
		request.Body,
		request.ContentLength,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	result, err := s.relayStore.CommitBlobPublish(
		request.Context(),
		credential,
		blobID,
		stored.ByteCount,
		s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	s.metrics.ObserveAcceptance(string(result.Acceptance))
	status := http.StatusCreated
	if result.Acceptance == relay.AcceptanceDuplicate {
		status = http.StatusOK
	}
	writeJSON(writer, status, result)
}

func (s *Server) handleFetchRelayBlob(writer http.ResponseWriter, request *http.Request) {
	tenantID, domainID, err := relayScopeFromPath(request)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	blobID := request.PathValue("blobID")
	if err := relay.ValidateBlobID(blobID); err != nil {
		s.writeError(writer, err)
		return
	}
	credential, err := relayCredentialFromRequest(request, tenantID, domainID)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	metadata, err := s.relayStore.GetBlobMetadata(
		request.Context(),
		credential,
		blobID,
		s.nowMilliseconds(),
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	content, err := s.blobContentStore.Open(
		request.Context(),
		relay.BlobScope{TenantID: tenantID, DomainID: domainID},
		blobID,
	)
	if err != nil {
		s.writeError(writer, err)
		return
	}
	defer content.Reader.Close()
	if content.ByteCount != metadata.ByteCount {
		s.writeError(writer, fmt.Errorf("stored blob content length differs from metadata"))
		return
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("ETag", `"`+blobID+`"`)
	http.ServeContent(writer, request, blobID, time.Time{}, content.Reader)
}

func (s *Server) authorizeOperator(request *http.Request) error {
	if !s.operatorProvisioningOn {
		return relay.NewProtocolError(relay.CodeUnauthorized, "operator provisioning is disabled")
	}
	token, err := bearerToken(request)
	if err != nil {
		return err
	}
	digest, err := operatorDigest(token)
	if err != nil || subtle.ConstantTimeCompare(
		digest[:], s.operatorTokenDigest[:],
	) != 1 {
		return relay.NewProtocolError(relay.CodeUnauthorized, "operator credential is invalid")
	}
	return nil
}

func operatorDigest(token string) ([32]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != 32 ||
		base64.RawURLEncoding.EncodeToString(decoded) != token {
		return [32]byte{}, fmt.Errorf("operator token must be 32-byte unpadded base64url")
	}
	return sha256.Sum256(decoded), nil
}

func randomToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate authorization token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func normalizedCapabilities(input []relay.Capability) ([]relay.Capability, error) {
	set := make(map[relay.Capability]struct{}, len(input))
	for _, capability := range input {
		if !capability.Valid() {
			return nil, relay.NewProtocolError(
				relay.CodeInvalidMember,
				"member capability is invalid",
			)
		}
		set[capability] = struct{}{}
	}
	if len(set) == 0 {
		return nil, relay.NewProtocolError(
			relay.CodeInvalidMember,
			"at least one member capability is required",
		)
	}
	result := make([]relay.Capability, 0, len(set))
	for capability := range set {
		result = append(result, capability)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, nil
}

func readRelayJSON(
	writer http.ResponseWriter,
	request *http.Request,
	destination any,
	maximumByteCount int,
) error {
	return decodeJSONWithLimit(
		writer,
		request,
		destination,
		maximumByteCount,
		func(message string) error {
			return relay.NewProtocolError(relay.CodeInvalidEnvelope, message)
		},
	)
}

func relayScopeFromPath(request *http.Request) (uuid.UUID, uuid.UUID, error) {
	tenantID, err := parseRelayUUID(request.PathValue("tenantID"))
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	domainID, err := parseRelayUUID(request.PathValue("domainID"))
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return tenantID, domainID, nil
}

func parseRelayUUID(value string) (uuid.UUID, error) {
	identifier, err := uuid.Parse(value)
	if err != nil || identifier == uuid.Nil {
		return uuid.Nil, relay.NewProtocolError(
			relay.CodeWrongScope,
			"identifier is invalid",
		)
	}
	return identifier, nil
}

func relayAdministrationCredentialFromRequest(
	request *http.Request,
	tenantID uuid.UUID,
	domainID uuid.UUID,
) (relay.AdministrationCredential, error) {
	token, err := bearerToken(request)
	if err != nil {
		return relay.AdministrationCredential{}, err
	}
	return relay.AdministrationCredential{
		TenantID: tenantID,
		DomainID: domainID,
		Token:    token,
	}, nil
}

func relayCredentialFromRequest(
	request *http.Request,
	tenantID uuid.UUID,
	domainID uuid.UUID,
) (relay.Credential, error) {
	token, err := bearerToken(request)
	if err != nil {
		return relay.Credential{}, err
	}
	memberID, err := parseRelayUUID(request.Header.Get("X-Facets-Member-ID"))
	if err != nil {
		return relay.Credential{}, relay.NewProtocolError(
			relay.CodeUnauthorized,
			"member identifier is required",
		)
	}
	return relay.Credential{
		TenantID: tenantID,
		DomainID: domainID,
		MemberID: memberID,
		Token:    token,
	}, nil
}

func relayAdmissionCredentialFromRequest(
	request *http.Request,
	tenantID uuid.UUID,
	domainID uuid.UUID,
	admissionID uuid.UUID,
) (relay.AdmissionCredential, error) {
	authorization := request.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") ||
		strings.TrimPrefix(authorization, "Bearer ") == "" {
		return relay.AdmissionCredential{}, relay.NewProtocolError(
			relay.CodeUnauthorized,
			"admission credential is required",
		)
	}
	return relay.AdmissionCredential{
		TenantID:    tenantID,
		DomainID:    domainID,
		AdmissionID: admissionID,
		Token:       strings.TrimPrefix(authorization, "Bearer "),
	}, nil
}

func bearerToken(request *http.Request) (string, error) {
	authorization := request.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") ||
		len(authorization) <= len("Bearer ") {
		return "", relay.NewProtocolError(
			relay.CodeUnauthorized,
			"bearer credential is required",
		)
	}
	return strings.TrimPrefix(authorization, "Bearer "), nil
}

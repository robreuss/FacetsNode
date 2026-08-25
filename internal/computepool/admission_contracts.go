package computepool

import "github.com/google/uuid"

const (
	consentReceiptDomain          = "Facets disclosure consent receipt v1\x00"
	invocationAuthorizationDomain = "Facets Compute invocation authorization v1\x00"
	poolAdmissionDomain           = "Facets Compute Pool admission v1\x00"
	poolJobTransitionDomain       = "Facets Compute Pool job transition v1\x00"
	workerExecutionDomain         = "Facets Compute Worker execution receipt v1\x00"
	resultApplicationDomain       = "Facets Compute result application receipt v1\x00"
	maximumConsentLifetimeMillis  = int64(30 * 24 * 60 * 60 * 1_000)
)

type P256SigningAuthority struct {
	SignerID              uuid.UUID
	SigningKeyFingerprint string
}

func (authority P256SigningAuthority) Validate() error {
	if authority.SignerID == uuid.Nil || !validSHA256Hex(authority.SigningKeyFingerprint) {
		return ErrInvalid
	}
	return nil
}

func (authority P256SigningAuthority) authorizes(signature ES256Signature) bool {
	return authority.SignerID == signature.SignerID &&
		authority.SigningKeyFingerprint == signature.SigningKeyFingerprint
}

type ConsentReceipt struct {
	Version                 int            `json:"version"`
	ReceiptID               uuid.UUID      `json:"receiptID"`
	PlanID                  uuid.UUID      `json:"planID"`
	PlanDigest              string         `json:"planDigest"`
	ConsentingDeviceID      uuid.UUID      `json:"consentingDeviceID"`
	ConsentedAtMilliseconds int64          `json:"consentedAtMilliseconds"`
	Signature               ES256Signature `json:"signature"`
}

func (receipt ConsentReceipt) signingPayload() any {
	return struct {
		Version                 int       `json:"version"`
		ReceiptID               uuid.UUID `json:"receiptID"`
		PlanID                  uuid.UUID `json:"planID"`
		PlanDigest              string    `json:"planDigest"`
		ConsentingDeviceID      uuid.UUID `json:"consentingDeviceID"`
		ConsentedAtMilliseconds int64     `json:"consentedAtMilliseconds"`
	}{receipt.Version, receipt.ReceiptID, receipt.PlanID, receipt.PlanDigest, receipt.ConsentingDeviceID, receipt.ConsentedAtMilliseconds}
}

func (receipt ConsentReceipt) Validate() error {
	if receipt.Version != 1 || receipt.ReceiptID == uuid.Nil || receipt.PlanID == uuid.Nil ||
		receipt.ConsentingDeviceID == uuid.Nil || receipt.Signature.SignerID != receipt.ConsentingDeviceID ||
		!validSHA256Hex(receipt.PlanDigest) || receipt.ConsentedAtMilliseconds < 0 {
		return ErrInvalid
	}
	return verifyES256(receipt.Signature, receipt.signingPayload(), consentReceiptDomain)
}

func (receipt ConsentReceipt) Digest() (string, error) { return canonicalDigest(receipt) }

func (receipt ConsentReceipt) ValidatePlan(plan DisclosurePlan, consentingDeviceAuthority P256SigningAuthority) error {
	if receipt.Validate() != nil || plan.Validate() != nil ||
		!consentingDeviceAuthority.authorizes(receipt.Signature) || receipt.PlanID != plan.PlanID ||
		plan.Decision != DecisionConsentRequired || receipt.ConsentedAtMilliseconds < plan.CreatedAtMilliseconds ||
		receipt.ConsentedAtMilliseconds >= plan.ExpiresAtMilliseconds {
		return ErrInvalid
	}
	digest, err := plan.Digest()
	if err != nil || digest != receipt.PlanDigest {
		return ErrInvalid
	}
	return nil
}

type DisclosureAction string

const (
	DisclosureShare      DisclosureAction = "share"
	DisclosureProcess    DisclosureAction = "process"
	DisclosureExportCopy DisclosureAction = "export_copy"
)

func (value DisclosureAction) Valid() bool {
	return value == DisclosureShare || value == DisclosureProcess || value == DisclosureExportCopy
}

type DisclosureDestinationKind string

const (
	DestinationSpace           DisclosureDestinationKind = "space"
	DestinationPublicAudience  DisclosureDestinationKind = "public_audience"
	DestinationComputeOffering DisclosureDestinationKind = "compute_offering"
)

type DisclosureDestination struct {
	Kind                  DisclosureDestinationKind `json:"kind"`
	DestinationIdentifier string                    `json:"destinationIdentifier"`
	ProviderIdentifier    *string                   `json:"providerIdentifier,omitempty"`
}

func (destination DisclosureDestination) Validate() error {
	isCompute := destination.Kind == DestinationComputeOffering
	if (destination.Kind != DestinationSpace && destination.Kind != DestinationPublicAudience && !isCompute) ||
		!validIdentifier(destination.DestinationIdentifier) || isCompute != (destination.ProviderIdentifier != nil) ||
		destination.ProviderIdentifier != nil && !validIdentifier(*destination.ProviderIdentifier) {
		return ErrInvalid
	}
	return nil
}

type ConsentRule struct {
	Version               int                   `json:"version"`
	RuleID                uuid.UUID             `json:"ruleID"`
	Action                DisclosureAction      `json:"action"`
	Destination           DisclosureDestination `json:"destination"`
	ObjectScopeDigest     string                `json:"objectScopeDigest"`
	SelectedFields        []string              `json:"selectedFields"`
	MaximumPrivacyClass   PrivacyClass          `json:"maximumPrivacyClass"`
	SourceSpaceID         *uuid.UUID            `json:"sourceSpaceID,omitempty"`
	SpacePolicyRevision   *uint64               `json:"spacePolicyRevision,omitempty"`
	SpacePolicyDigest     *string               `json:"spacePolicyDigest,omitempty"`
	RosterAudienceDigest  *string               `json:"rosterAudienceDigest,omitempty"`
	WorkerCardID          *uuid.UUID            `json:"workerCardID,omitempty"`
	WorkerCardRevision    *uint64               `json:"workerCardRevision,omitempty"`
	WorkerCardDigest      *string               `json:"workerCardDigest,omitempty"`
	OfferingID            *uuid.UUID            `json:"offeringID,omitempty"`
	OfferingRevision      *uint64               `json:"offeringRevision,omitempty"`
	ProviderIdentifier    *string               `json:"providerIdentifier,omitempty"`
	CreatedAtMilliseconds int64                 `json:"createdAtMilliseconds"`
	ExpiresAtMilliseconds int64                 `json:"expiresAtMilliseconds"`
}

func (rule ConsentRule) Validate() error {
	spaceScoped := rule.SourceSpaceID != nil
	computeScoped := rule.Destination.Kind == DestinationComputeOffering
	if rule.Version != 1 || rule.RuleID == uuid.Nil || !rule.Action.Valid() || rule.Destination.Validate() != nil ||
		!validSHA256Hex(rule.ObjectScopeDigest) || !validIdentifiers(rule.SelectedFields, true) ||
		(rule.MaximumPrivacyClass != PrivacyPublic && rule.MaximumPrivacyClass != PrivacyPersonal) ||
		spaceScoped != (rule.SpacePolicyRevision != nil) || spaceScoped != (rule.SpacePolicyDigest != nil) ||
		spaceScoped != (rule.RosterAudienceDigest != nil) || computeScoped != (rule.WorkerCardID != nil) ||
		computeScoped != (rule.WorkerCardRevision != nil) || computeScoped != (rule.WorkerCardDigest != nil) ||
		computeScoped != (rule.OfferingID != nil) || computeScoped != (rule.OfferingRevision != nil) ||
		computeScoped != (rule.ProviderIdentifier != nil) || rule.SourceSpaceID != nil && *rule.SourceSpaceID == uuid.Nil ||
		rule.WorkerCardID != nil && *rule.WorkerCardID == uuid.Nil || rule.OfferingID != nil && *rule.OfferingID == uuid.Nil ||
		rule.SpacePolicyRevision != nil && *rule.SpacePolicyRevision == 0 ||
		rule.WorkerCardRevision != nil && *rule.WorkerCardRevision == 0 || rule.OfferingRevision != nil && *rule.OfferingRevision == 0 ||
		rule.SpacePolicyDigest != nil && !validSHA256Hex(*rule.SpacePolicyDigest) ||
		rule.RosterAudienceDigest != nil && !validSHA256Hex(*rule.RosterAudienceDigest) ||
		rule.WorkerCardDigest != nil && !validSHA256Hex(*rule.WorkerCardDigest) ||
		rule.ProviderIdentifier != nil && !validIdentifier(*rule.ProviderIdentifier) || rule.CreatedAtMilliseconds < 0 ||
		rule.ExpiresAtMilliseconds <= rule.CreatedAtMilliseconds ||
		rule.ExpiresAtMilliseconds-rule.CreatedAtMilliseconds > maximumConsentLifetimeMillis {
		return ErrInvalid
	}
	return nil
}

type InvocationAuthorization struct {
	Version                  int            `json:"version"`
	AuthorizationID          uuid.UUID      `json:"authorizationID"`
	RequestID                uuid.UUID      `json:"requestID"`
	PoolID                   uuid.UUID      `json:"poolID"`
	WorkerCardID             uuid.UUID      `json:"workerCardID"`
	WorkerCardRevision       uint64         `json:"workerCardRevision"`
	WorkerCardDigest         string         `json:"workerCardDigest"`
	OfferingID               uuid.UUID      `json:"offeringID"`
	OfferingRevision         uint64         `json:"offeringRevision"`
	RequestDigest            string         `json:"requestDigest"`
	PayloadDigest            string         `json:"payloadDigest"`
	DisclosurePlanDigest     string         `json:"disclosurePlanDigest"`
	ConsentReceiptDigest     *string        `json:"consentReceiptDigest,omitempty"`
	AuthorizedPrivacyClass   PrivacyClass   `json:"authorizedPrivacyClass"`
	AuthorizedAtMilliseconds int64          `json:"authorizedAtMilliseconds"`
	ExpiresAtMilliseconds    int64          `json:"expiresAtMilliseconds"`
	Signature                ES256Signature `json:"signature"`
}

func (authorization InvocationAuthorization) signingPayload() any {
	return struct {
		Version                  int          `json:"version"`
		AuthorizationID          uuid.UUID    `json:"authorizationID"`
		RequestID                uuid.UUID    `json:"requestID"`
		PoolID                   uuid.UUID    `json:"poolID"`
		WorkerCardID             uuid.UUID    `json:"workerCardID"`
		WorkerCardRevision       uint64       `json:"workerCardRevision"`
		WorkerCardDigest         string       `json:"workerCardDigest"`
		OfferingID               uuid.UUID    `json:"offeringID"`
		OfferingRevision         uint64       `json:"offeringRevision"`
		RequestDigest            string       `json:"requestDigest"`
		PayloadDigest            string       `json:"payloadDigest"`
		DisclosurePlanDigest     string       `json:"disclosurePlanDigest"`
		ConsentReceiptDigest     *string      `json:"consentReceiptDigest,omitempty"`
		AuthorizedPrivacyClass   PrivacyClass `json:"authorizedPrivacyClass"`
		AuthorizedAtMilliseconds int64        `json:"authorizedAtMilliseconds"`
		ExpiresAtMilliseconds    int64        `json:"expiresAtMilliseconds"`
	}{authorization.Version, authorization.AuthorizationID, authorization.RequestID, authorization.PoolID, authorization.WorkerCardID, authorization.WorkerCardRevision, authorization.WorkerCardDigest, authorization.OfferingID, authorization.OfferingRevision, authorization.RequestDigest, authorization.PayloadDigest, authorization.DisclosurePlanDigest, authorization.ConsentReceiptDigest, authorization.AuthorizedPrivacyClass, authorization.AuthorizedAtMilliseconds, authorization.ExpiresAtMilliseconds}
}

func (authorization InvocationAuthorization) Validate() error {
	if authorization.Version != 1 || authorization.AuthorizationID == uuid.Nil || authorization.RequestID == uuid.Nil ||
		authorization.PoolID == uuid.Nil || authorization.WorkerCardID == uuid.Nil || authorization.OfferingID == uuid.Nil ||
		authorization.WorkerCardRevision == 0 || authorization.OfferingRevision == 0 ||
		!validSHA256Hex(authorization.WorkerCardDigest) || !validSHA256Hex(authorization.RequestDigest) ||
		!validSHA256Hex(authorization.PayloadDigest) || !validSHA256Hex(authorization.DisclosurePlanDigest) ||
		authorization.ConsentReceiptDigest != nil && !validSHA256Hex(*authorization.ConsentReceiptDigest) ||
		!authorization.AuthorizedPrivacyClass.Valid() || authorization.AuthorizedAtMilliseconds < 0 ||
		authorization.ExpiresAtMilliseconds <= authorization.AuthorizedAtMilliseconds {
		return ErrInvalid
	}
	return verifyES256(authorization.Signature, authorization.signingPayload(), invocationAuthorizationDomain)
}

func (authorization InvocationAuthorization) Digest() (string, error) {
	return canonicalDigest(authorization)
}

type PoolAdmission struct {
	Version                       int             `json:"version"`
	AdmissionID                   uuid.UUID       `json:"admissionID"`
	JobID                         uuid.UUID       `json:"jobID"`
	PoolID                        uuid.UUID       `json:"poolID"`
	InvocationAuthorizationID     uuid.UUID       `json:"invocationAuthorizationID"`
	InvocationAuthorizationDigest string          `json:"invocationAuthorizationDigest"`
	WorkerEnrollmentID            uuid.UUID       `json:"workerEnrollmentID"`
	WorkerCardID                  uuid.UUID       `json:"workerCardID"`
	WorkerCardRevision            uint64          `json:"workerCardRevision"`
	WorkerCardDigest              string          `json:"workerCardDigest"`
	OfferingID                    uuid.UUID       `json:"offeringID"`
	OfferingRevision              uint64          `json:"offeringRevision"`
	ResourceCeiling               ResourceCeiling `json:"resourceCeiling"`
	BudgetCeiling                 BudgetCeiling   `json:"budgetCeiling"`
	AdmittedAtMilliseconds        int64           `json:"admittedAtMilliseconds"`
	ExpiresAtMilliseconds         int64           `json:"expiresAtMilliseconds"`
	LeaseExpiresAtMilliseconds    int64           `json:"leaseExpiresAtMilliseconds"`
	Signature                     ES256Signature  `json:"signature"`
}

func (admission PoolAdmission) signingPayload() any {
	return struct {
		Version                       int             `json:"version"`
		AdmissionID                   uuid.UUID       `json:"admissionID"`
		JobID                         uuid.UUID       `json:"jobID"`
		PoolID                        uuid.UUID       `json:"poolID"`
		InvocationAuthorizationID     uuid.UUID       `json:"invocationAuthorizationID"`
		InvocationAuthorizationDigest string          `json:"invocationAuthorizationDigest"`
		WorkerEnrollmentID            uuid.UUID       `json:"workerEnrollmentID"`
		WorkerCardID                  uuid.UUID       `json:"workerCardID"`
		WorkerCardRevision            uint64          `json:"workerCardRevision"`
		WorkerCardDigest              string          `json:"workerCardDigest"`
		OfferingID                    uuid.UUID       `json:"offeringID"`
		OfferingRevision              uint64          `json:"offeringRevision"`
		ResourceCeiling               ResourceCeiling `json:"resourceCeiling"`
		BudgetCeiling                 BudgetCeiling   `json:"budgetCeiling"`
		AdmittedAtMilliseconds        int64           `json:"admittedAtMilliseconds"`
		ExpiresAtMilliseconds         int64           `json:"expiresAtMilliseconds"`
		LeaseExpiresAtMilliseconds    int64           `json:"leaseExpiresAtMilliseconds"`
	}{admission.Version, admission.AdmissionID, admission.JobID, admission.PoolID, admission.InvocationAuthorizationID, admission.InvocationAuthorizationDigest, admission.WorkerEnrollmentID, admission.WorkerCardID, admission.WorkerCardRevision, admission.WorkerCardDigest, admission.OfferingID, admission.OfferingRevision, admission.ResourceCeiling, admission.BudgetCeiling, admission.AdmittedAtMilliseconds, admission.ExpiresAtMilliseconds, admission.LeaseExpiresAtMilliseconds}
}

func (admission PoolAdmission) Validate() error {
	if admission.Version != 1 || admission.AdmissionID == uuid.Nil || admission.JobID == uuid.Nil || admission.PoolID == uuid.Nil ||
		admission.InvocationAuthorizationID == uuid.Nil || admission.WorkerEnrollmentID == uuid.Nil || admission.WorkerCardID == uuid.Nil ||
		admission.OfferingID == uuid.Nil || admission.WorkerCardRevision == 0 || admission.OfferingRevision == 0 ||
		!validSHA256Hex(admission.InvocationAuthorizationDigest) || !validSHA256Hex(admission.WorkerCardDigest) ||
		admission.ResourceCeiling.Validate() != nil || admission.BudgetCeiling.Validate() != nil || admission.AdmittedAtMilliseconds < 0 ||
		admission.ExpiresAtMilliseconds <= admission.AdmittedAtMilliseconds || admission.LeaseExpiresAtMilliseconds <= admission.AdmittedAtMilliseconds ||
		admission.LeaseExpiresAtMilliseconds > admission.ExpiresAtMilliseconds {
		return ErrInvalid
	}
	return verifyES256(admission.Signature, admission.signingPayload(), poolAdmissionDomain)
}

func (admission PoolAdmission) Digest() (string, error) { return canonicalDigest(admission) }

func (admission PoolAdmission) ValidateAuthorization(authorization InvocationAuthorization) error {
	if admission.Validate() != nil || authorization.Validate() != nil || authorization.AuthorizationID != admission.InvocationAuthorizationID ||
		authorization.PoolID != admission.PoolID || authorization.WorkerCardID != admission.WorkerCardID ||
		authorization.WorkerCardRevision != admission.WorkerCardRevision || authorization.WorkerCardDigest != admission.WorkerCardDigest ||
		authorization.OfferingID != admission.OfferingID || authorization.OfferingRevision != admission.OfferingRevision ||
		admission.AdmittedAtMilliseconds < authorization.AuthorizedAtMilliseconds ||
		admission.ExpiresAtMilliseconds > authorization.ExpiresAtMilliseconds {
		return ErrInvalid
	}
	digest, err := authorization.Digest()
	if err != nil || digest != admission.InvocationAuthorizationDigest {
		return ErrInvalid
	}
	return nil
}

func (admission PoolAdmission) ValidateInputRelease(
	authorization InvocationAuthorization,
	signedWorkerCard SignedWorkerCard,
	enrollment WorkerEnrollment,
	offering Offering,
	expectedPoolAuthority P256SigningAuthority,
	permittedInvocationAuthorities []P256SigningAuthority,
	evaluatedAtMilliseconds int64,
) error {
	if admission.ValidateAuthorization(authorization) != nil ||
		signedWorkerCard.Validate(enrollment) != nil || expectedPoolAuthority.Validate() != nil ||
		!expectedPoolAuthority.authorizes(admission.Signature) ||
		!anyP256AuthorityAuthorizes(permittedInvocationAuthorities, authorization.Signature) ||
		evaluatedAtMilliseconds < admission.AdmittedAtMilliseconds ||
		evaluatedAtMilliseconds < authorization.AuthorizedAtMilliseconds ||
		evaluatedAtMilliseconds >= admission.LeaseExpiresAtMilliseconds ||
		evaluatedAtMilliseconds >= admission.ExpiresAtMilliseconds ||
		evaluatedAtMilliseconds >= authorization.ExpiresAtMilliseconds {
		return ErrInvalid
	}
	card := signedWorkerCard.Card
	cardDigest, err := card.Digest()
	if err != nil || enrollment.EnrollmentID != admission.WorkerEnrollmentID ||
		enrollment.PoolID != admission.PoolID || !enrollment.Enabled ||
		card.WorkerCardID != admission.WorkerCardID || card.Revision != admission.WorkerCardRevision ||
		cardDigest != admission.WorkerCardDigest || offering.OfferingID != admission.OfferingID ||
		offering.PoolID != admission.PoolID || offering.WorkerEnrollmentID != admission.WorkerEnrollmentID ||
		offering.WorkerCardID != admission.WorkerCardID || offering.WorkerCardRevision != admission.WorkerCardRevision ||
		offering.WorkerCardDigest != admission.WorkerCardDigest || offering.Revision != admission.OfferingRevision ||
		!offering.Enabled {
		return ErrInvalid
	}
	return nil
}

func anyP256AuthorityAuthorizes(authorities []P256SigningAuthority, signature ES256Signature) bool {
	for _, authority := range authorities {
		if authority.Validate() == nil && authority.authorizes(signature) {
			return true
		}
	}
	return false
}

type JobState string

const (
	JobAuthorized      JobState = "authorized"
	JobAdmitted        JobState = "admitted"
	JobQueued          JobState = "queued"
	JobLeased          JobState = "leased"
	JobExecuting       JobState = "executing"
	JobRetryWait       JobState = "retry_wait"
	JobResultStaged    JobState = "result_staged"
	JobResultDelivered JobState = "result_delivered"
	JobResultApplied   JobState = "result_applied"
	JobCompleted       JobState = "completed"
	JobCancelRequested JobState = "cancel_requested"
	JobCancelled       JobState = "cancelled"
	JobPaused          JobState = "paused"
	JobFailed          JobState = "failed"
	JobExpired         JobState = "expired"
)

func (state JobState) Valid() bool {
	switch state {
	case JobAuthorized, JobAdmitted, JobQueued, JobLeased, JobExecuting, JobRetryWait, JobResultStaged, JobResultDelivered, JobResultApplied, JobCompleted, JobCancelRequested, JobCancelled, JobPaused, JobFailed, JobExpired:
		return true
	}
	return false
}

type PoolJobTransition struct {
	Version                int            `json:"version"`
	TransitionID           uuid.UUID      `json:"transitionID"`
	JobID                  uuid.UUID      `json:"jobID"`
	PoolID                 uuid.UUID      `json:"poolID"`
	Sequence               uint64         `json:"sequence"`
	PredecessorDigest      *string        `json:"predecessorDigest,omitempty"`
	State                  JobState       `json:"state"`
	EvidenceDigest         *string        `json:"evidenceDigest,omitempty"`
	OccurredAtMilliseconds int64          `json:"occurredAtMilliseconds"`
	Signature              ES256Signature `json:"signature"`
}

func (transition PoolJobTransition) signingPayload() any {
	return struct {
		Version                int       `json:"version"`
		TransitionID           uuid.UUID `json:"transitionID"`
		JobID                  uuid.UUID `json:"jobID"`
		PoolID                 uuid.UUID `json:"poolID"`
		Sequence               uint64    `json:"sequence"`
		PredecessorDigest      *string   `json:"predecessorDigest,omitempty"`
		State                  JobState  `json:"state"`
		EvidenceDigest         *string   `json:"evidenceDigest,omitempty"`
		OccurredAtMilliseconds int64     `json:"occurredAtMilliseconds"`
	}{transition.Version, transition.TransitionID, transition.JobID, transition.PoolID, transition.Sequence, transition.PredecessorDigest, transition.State, transition.EvidenceDigest, transition.OccurredAtMilliseconds}
}

func (transition PoolJobTransition) Validate() error {
	if transition.Version != 1 || transition.TransitionID == uuid.Nil || transition.JobID == uuid.Nil || transition.PoolID == uuid.Nil || transition.Sequence == 0 ||
		(transition.Sequence == 1) != (transition.PredecessorDigest == nil) || transition.PredecessorDigest != nil && !validSHA256Hex(*transition.PredecessorDigest) ||
		!transition.State.Valid() || transition.EvidenceDigest != nil && !validSHA256Hex(*transition.EvidenceDigest) || transition.OccurredAtMilliseconds < 0 {
		return ErrInvalid
	}
	return verifyES256(transition.Signature, transition.signingPayload(), poolJobTransitionDomain)
}

func (transition PoolJobTransition) Digest() (string, error) { return canonicalDigest(transition) }

type WorkerExecutionReceipt struct {
	Version                int              `json:"version"`
	ReceiptID              uuid.UUID        `json:"receiptID"`
	JobID                  uuid.UUID        `json:"jobID"`
	AdmissionID            uuid.UUID        `json:"admissionID"`
	AdmissionDigest        string           `json:"admissionDigest"`
	WorkerEnrollmentID     uuid.UUID        `json:"workerEnrollmentID"`
	Attempt                uint64           `json:"attempt"`
	RequestDigest          string           `json:"requestDigest"`
	ResultDigest           string           `json:"resultDigest"`
	StartedAtMilliseconds  int64            `json:"startedAtMilliseconds"`
	FinishedAtMilliseconds int64            `json:"finishedAtMilliseconds"`
	Signature              Ed25519Signature `json:"signature"`
}

func (receipt WorkerExecutionReceipt) signingPayload() any {
	return struct {
		Version                int       `json:"version"`
		ReceiptID              uuid.UUID `json:"receiptID"`
		JobID                  uuid.UUID `json:"jobID"`
		AdmissionID            uuid.UUID `json:"admissionID"`
		AdmissionDigest        string    `json:"admissionDigest"`
		WorkerEnrollmentID     uuid.UUID `json:"workerEnrollmentID"`
		Attempt                uint64    `json:"attempt"`
		RequestDigest          string    `json:"requestDigest"`
		ResultDigest           string    `json:"resultDigest"`
		StartedAtMilliseconds  int64     `json:"startedAtMilliseconds"`
		FinishedAtMilliseconds int64     `json:"finishedAtMilliseconds"`
	}{receipt.Version, receipt.ReceiptID, receipt.JobID, receipt.AdmissionID, receipt.AdmissionDigest, receipt.WorkerEnrollmentID, receipt.Attempt, receipt.RequestDigest, receipt.ResultDigest, receipt.StartedAtMilliseconds, receipt.FinishedAtMilliseconds}
}

func (receipt WorkerExecutionReceipt) Validate() error {
	if receipt.Version != 1 || receipt.ReceiptID == uuid.Nil || receipt.JobID == uuid.Nil || receipt.AdmissionID == uuid.Nil || receipt.WorkerEnrollmentID == uuid.Nil || receipt.Signature.SignerID != receipt.WorkerEnrollmentID || receipt.Attempt == 0 || !validSHA256Hex(receipt.AdmissionDigest) || !validSHA256Hex(receipt.RequestDigest) || !validSHA256Hex(receipt.ResultDigest) || receipt.StartedAtMilliseconds < 0 || receipt.FinishedAtMilliseconds < receipt.StartedAtMilliseconds {
		return ErrInvalid
	}
	return verifyEd25519(receipt.Signature, receipt.signingPayload(), workerExecutionDomain)
}

func (receipt WorkerExecutionReceipt) Digest() (string, error) { return canonicalDigest(receipt) }

func (receipt WorkerExecutionReceipt) ValidateAdmission(admission PoolAdmission, authorization InvocationAuthorization, enrollment WorkerEnrollment) error {
	if receipt.Validate() != nil || receipt.JobID != admission.JobID || receipt.AdmissionID != admission.AdmissionID ||
		receipt.WorkerEnrollmentID != admission.WorkerEnrollmentID || receipt.RequestDigest != authorization.RequestDigest ||
		enrollment.Validate() != nil || enrollment.EnrollmentID != receipt.WorkerEnrollmentID || enrollment.PoolID != admission.PoolID ||
		enrollment.PublicSigningKeyEd25519 != receipt.Signature.PublicSigningKeyEd25519 ||
		enrollment.SigningKeyFingerprint != receipt.Signature.SigningKeyFingerprint || !enrollment.Enabled {
		return ErrInvalid
	}
	digest, err := admission.Digest()
	if err != nil || digest != receipt.AdmissionDigest || admission.ValidateAuthorization(authorization) != nil {
		return ErrInvalid
	}
	return nil
}

type ResultApplicationReceipt struct {
	Version                int            `json:"version"`
	ReceiptID              uuid.UUID      `json:"receiptID"`
	JobID                  uuid.UUID      `json:"jobID"`
	ExecutionReceiptID     uuid.UUID      `json:"executionReceiptID"`
	ExecutionReceiptDigest string         `json:"executionReceiptDigest"`
	ResultDigest           string         `json:"resultDigest"`
	ApplicationDigest      string         `json:"applicationDigest"`
	ApplyingDeviceID       uuid.UUID      `json:"applyingDeviceID"`
	AppliedAtMilliseconds  int64          `json:"appliedAtMilliseconds"`
	Signature              ES256Signature `json:"signature"`
}

func (receipt ResultApplicationReceipt) signingPayload() any {
	return struct {
		Version                int       `json:"version"`
		ReceiptID              uuid.UUID `json:"receiptID"`
		JobID                  uuid.UUID `json:"jobID"`
		ExecutionReceiptID     uuid.UUID `json:"executionReceiptID"`
		ExecutionReceiptDigest string    `json:"executionReceiptDigest"`
		ResultDigest           string    `json:"resultDigest"`
		ApplicationDigest      string    `json:"applicationDigest"`
		ApplyingDeviceID       uuid.UUID `json:"applyingDeviceID"`
		AppliedAtMilliseconds  int64     `json:"appliedAtMilliseconds"`
	}{receipt.Version, receipt.ReceiptID, receipt.JobID, receipt.ExecutionReceiptID, receipt.ExecutionReceiptDigest, receipt.ResultDigest, receipt.ApplicationDigest, receipt.ApplyingDeviceID, receipt.AppliedAtMilliseconds}
}

func (receipt ResultApplicationReceipt) Validate() error {
	if receipt.Version != 1 || receipt.ReceiptID == uuid.Nil || receipt.JobID == uuid.Nil || receipt.ExecutionReceiptID == uuid.Nil || receipt.ApplyingDeviceID == uuid.Nil || receipt.Signature.SignerID != receipt.ApplyingDeviceID || !validSHA256Hex(receipt.ExecutionReceiptDigest) || !validSHA256Hex(receipt.ResultDigest) || !validSHA256Hex(receipt.ApplicationDigest) || receipt.AppliedAtMilliseconds < 0 {
		return ErrInvalid
	}
	return verifyES256(receipt.Signature, receipt.signingPayload(), resultApplicationDomain)
}

func (receipt ResultApplicationReceipt) Digest() (string, error) { return canonicalDigest(receipt) }

func (receipt ResultApplicationReceipt) ValidateExecution(execution WorkerExecutionReceipt) error {
	if execution.Validate() != nil || receipt.JobID != execution.JobID || receipt.ExecutionReceiptID != execution.ReceiptID || receipt.ResultDigest != execution.ResultDigest || receipt.AppliedAtMilliseconds < execution.FinishedAtMilliseconds {
		return ErrInvalid
	}
	digest, err := execution.Digest()
	if err != nil || digest != receipt.ExecutionReceiptDigest {
		return ErrInvalid
	}
	return nil
}

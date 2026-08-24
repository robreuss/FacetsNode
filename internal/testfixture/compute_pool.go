package testfixture

import (
	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/computepool"
)

func ComputeBudgetCeiling() computepool.BudgetCeiling {
	return computepool.BudgetCeiling{
		MaximumCostMinorUnits: 2_500,
		CurrencyIdentifier:    "USD",
	}
}

func ComputeWorkerCard(
	cardID uuid.UUID,
	poolID uuid.UUID,
	enrollmentID uuid.UUID,
	ownerID uuid.UUID,
	providerIdentifier string,
) computepool.WorkerCard {
	dimensions := []string{
		"diagnostic_retention", "execution_isolation", "network_egress", "plaintext_location",
		"provider_identity", "request_retention", "result_retention", "runtime_integrity",
		"tool_access", "training_use",
	}
	claims := make([]computepool.AssuranceClaim, 0, len(dimensions))
	for _, dimension := range dimensions {
		claims = append(claims, computepool.AssuranceClaim{
			DimensionIdentifier:   dimension,
			Value:                 "test_value",
			EvidenceKind:          computepool.EvidenceConfigurationVerified,
			IssuerIdentifier:      "test.runtime",
			ValidFromMilliseconds: 1_000,
			Revision:              1,
		})
	}
	return computepool.WorkerCard{
		Version:      computepool.WorkerCardSchemaVersion,
		WorkerCardID: cardID, PoolID: poolID, WorkerEnrollmentID: enrollmentID,
		WorkerOwnerAuthorityID: ownerID, DisplayName: "Test Worker",
		RuntimeIdentifier: "test.runtime", BuildIdentifier: "test.build",
		Claims: claims, Revision: 1, CreatedAtMilliseconds: 1_000, UpdatedAtMilliseconds: 1_000,
	}
}

func ComputeDataUseConstraints(providerIdentifier string) []computepool.DataUseConstraint {
	classes := []computepool.PrivacyClass{
		computepool.PrivacyPublic,
		computepool.PrivacyPersonal,
		computepool.PrivacyConfidential,
		computepool.PrivacyRestricted,
	}
	constraints := make([]computepool.DataUseConstraint, 0, len(classes))
	for _, privacyClass := range classes {
		constraints = append(constraints, computepool.DataUseConstraint{
			PrivacyClass:                 privacyClass,
			Audience:                     computepool.AudiencePrivateInvoker,
			MaximumPlaintextBoundary:     computepool.PlaintextBoundaryPrivateInfrastructure,
			PermittedProviderIdentifiers: []string{providerIdentifier},
			PermittedNetworkEgress:       []computepool.NetworkEgress{computepool.NetworkEgressNone},
			PermittedTrainingUse:         []computepool.TrainingUse{computepool.TrainingProhibited},
			PermittedToolAccess:          []computepool.ToolAccess{computepool.ToolAccessNone},
			ResultPolicy:                 computepool.ResultPrivateToInvoker,
			OverrideControl:              computepool.ControlProhibited,
		})
	}
	return constraints
}

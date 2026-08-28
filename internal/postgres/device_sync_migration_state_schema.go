package postgres

import "fmt"

// Device Sync migration state is a logical, one-principal export. Database
// custody/authority rows, migration bookkeeping, wall-clock storage metadata,
// global pairing state, unclaimed account admissions, and unassociated join
// requests are deliberately outside this artifact.

type deviceSyncMigrationScalarKind uint8

const (
	deviceSyncMigrationScalarNull deviceSyncMigrationScalarKind = iota
	deviceSyncMigrationScalarUUID
	deviceSyncMigrationScalarText
	deviceSyncMigrationScalarInt
	deviceSyncMigrationScalarBool
	deviceSyncMigrationScalarTextArray
	deviceSyncMigrationScalarBytes
	deviceSyncMigrationScalarCanonicalJSON
)

type deviceSyncMigrationColumnSpec struct {
	name             string
	kind             deviceSyncMigrationScalarKind
	databaseType     string
	nullable         bool
	virtual          bool
	sourceExpression string
}

type deviceSyncMigrationTableSpec struct {
	name              string
	columns           []deviceSyncMigrationColumnSpec
	keyColumnIndexes  []int
	scopeColumnIndex  int
	allowMultiplicity bool
}

func migrationUUID(name string, nullable ...bool) deviceSyncMigrationColumnSpec {
	return migrationColumn(name, deviceSyncMigrationScalarUUID, "uuid", nullable...)
}

func migrationText(name string, nullable ...bool) deviceSyncMigrationColumnSpec {
	return migrationColumn(name, deviceSyncMigrationScalarText, "text", nullable...)
}

func migrationInt16(name string, nullable ...bool) deviceSyncMigrationColumnSpec {
	return migrationColumn(name, deviceSyncMigrationScalarInt, "int2", nullable...)
}

func migrationInt32(name string, nullable ...bool) deviceSyncMigrationColumnSpec {
	return migrationColumn(name, deviceSyncMigrationScalarInt, "int4", nullable...)
}

func migrationInt64(name string, nullable ...bool) deviceSyncMigrationColumnSpec {
	return migrationColumn(name, deviceSyncMigrationScalarInt, "int8", nullable...)
}

func migrationVirtualInt64(name string, sourceExpression string) deviceSyncMigrationColumnSpec {
	return deviceSyncMigrationColumnSpec{
		name: name, kind: deviceSyncMigrationScalarInt, databaseType: "int8",
		virtual: true, sourceExpression: sourceExpression,
	}
}

func migrationBool(name string, nullable ...bool) deviceSyncMigrationColumnSpec {
	return migrationColumn(name, deviceSyncMigrationScalarBool, "bool", nullable...)
}

func migrationTextArray(name string, nullable ...bool) deviceSyncMigrationColumnSpec {
	return migrationColumn(name, deviceSyncMigrationScalarTextArray, "_text", nullable...)
}

func migrationJSON(name string, nullable ...bool) deviceSyncMigrationColumnSpec {
	return migrationColumn(name, deviceSyncMigrationScalarCanonicalJSON, "jsonb", nullable...)
}

func migrationColumn(
	name string,
	kind deviceSyncMigrationScalarKind,
	databaseType string,
	nullable ...bool,
) deviceSyncMigrationColumnSpec {
	isNullable := false
	if len(nullable) > 0 {
		isNullable = nullable[0]
	}
	return deviceSyncMigrationColumnSpec{
		name: name, kind: kind, databaseType: databaseType, nullable: isNullable,
	}
}

func migrationTable(
	name string,
	scopeColumn string,
	keyColumns []string,
	columns ...deviceSyncMigrationColumnSpec,
) deviceSyncMigrationTableSpec {
	columnIndexes := make(map[string]int, len(columns))
	for index, column := range columns {
		if _, exists := columnIndexes[column.name]; exists {
			panic("duplicate Device Sync migration column " + name + "." + column.name)
		}
		columnIndexes[column.name] = index
	}
	keyIndexes := make([]int, len(keyColumns))
	for index, keyColumn := range keyColumns {
		columnIndex, exists := columnIndexes[keyColumn]
		if !exists {
			panic("missing Device Sync migration key column " + name + "." + keyColumn)
		}
		keyIndexes[index] = columnIndex
	}
	scopeIndex, exists := columnIndexes[scopeColumn]
	if !exists {
		panic("missing Device Sync migration scope column " + name + "." + scopeColumn)
	}
	return deviceSyncMigrationTableSpec{
		name: name, columns: columns, keyColumnIndexes: keyIndexes,
		scopeColumnIndex: scopeIndex,
	}
}

func migrationAuditTable(columns ...deviceSyncMigrationColumnSpec) deviceSyncMigrationTableSpec {
	columns = append(columns, migrationVirtualInt64(
		"source_event_ordinal",
		"(row_number() OVER (ORDER BY event_sequence) - 1)::bigint",
	))
	return migrationTable(
		"relay_audit_events", "tenant_id", []string{"source_event_ordinal"}, columns...,
	)
}

var deviceSyncMigrationTableSpecs = []deviceSyncMigrationTableSpec{
	migrationTable("device_sync_account_admissions", "claimed_principal_id", []string{"admission_id"},
		migrationUUID("admission_id"), migrationUUID("retry_id"), migrationInt16("version"),
		migrationText("authorization_digest"), migrationInt64("created_at_milliseconds"),
		migrationInt64("expires_at_milliseconds"), migrationInt64("claimed_at_milliseconds", true),
		migrationUUID("claimed_principal_id", true), migrationInt16("entitlement_version"),
		migrationText("entitlement_plan_id"), migrationInt32("maximum_domain_count"),
		migrationInt32("maximum_aggregate_message_count"),
		migrationInt64("maximum_aggregate_message_byte_count"),
		migrationInt32("maximum_aggregate_blob_count"),
		migrationInt64("maximum_aggregate_blob_byte_count")),
	migrationTable("relay_tenants", "tenant_id", []string{"tenant_id"},
		migrationUUID("tenant_id"), migrationInt16("version"), migrationUUID("provisioning_retry_id"),
		migrationText("provisioning_authorization_digest"), migrationInt64("created_at_milliseconds"),
		migrationInt32("maximum_domain_count"), migrationInt32("maximum_aggregate_message_count"),
		migrationInt64("maximum_aggregate_message_byte_count"),
		migrationInt32("maximum_aggregate_blob_count"),
		migrationInt64("maximum_aggregate_blob_byte_count"), migrationInt32("domain_count"),
		migrationInt32("message_count"), migrationInt32("blob_count"),
		migrationInt64("aggregate_message_byte_count"), migrationInt64("aggregate_blob_byte_count"),
		migrationInt32("reserved_blob_count"), migrationInt64("reserved_blob_byte_count")),
	migrationTable("relay_domains", "tenant_id", []string{"tenant_id", "domain_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("provisioning_retry_id"),
		migrationInt16("version"), migrationText("administration_digest"),
		migrationInt64("created_at_milliseconds"), migrationInt32("maximum_message_count"),
		migrationInt64("maximum_message_byte_count"), migrationInt32("maximum_blob_count"),
		migrationInt64("maximum_blob_byte_count"), migrationInt32("message_count"),
		migrationInt32("blob_count"), migrationInt64("message_byte_count"),
		migrationInt64("blob_byte_count"), migrationInt64("last_sequence"),
		migrationInt64("checkpoint_activation_ordinal"), migrationInt32("reserved_blob_count"),
		migrationInt64("reserved_blob_byte_count")),
	migrationTable("relay_subscriptions", "tenant_id", []string{"tenant_id", "domain_id", "subscription_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("subscription_id"),
		migrationUUID("create_retry_id"), migrationInt16("version"), migrationText("status"),
		migrationInt64("start_sequence", true), migrationInt64("created_at_milliseconds"),
		migrationInt64("updated_at_milliseconds")),
	migrationTable("relay_subscription_status_changes", "tenant_id", []string{"tenant_id", "domain_id", "retry_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("retry_id"),
		migrationUUID("subscription_id"), migrationText("status"),
		migrationInt64("changed_at_milliseconds"), migrationInt64("result_start_sequence", true)),
	migrationTable("relay_members", "tenant_id", []string{"tenant_id", "domain_id", "member_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("member_id"),
		migrationUUID("subscription_id"), migrationInt16("version"),
		migrationText("authorization_digest"), migrationTextArray("capabilities"),
		migrationInt64("created_at_milliseconds"), migrationInt64("expires_at_milliseconds", true),
		migrationInt64("revoked_at_milliseconds", true)),
	migrationTable("relay_member_admissions", "tenant_id", []string{"tenant_id", "domain_id", "admission_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("admission_id"),
		migrationUUID("subscription_id"), migrationInt16("version"),
		migrationText("authorization_digest"), migrationTextArray("capabilities"),
		migrationInt64("created_at_milliseconds"), migrationInt64("expires_at_milliseconds"),
		migrationInt64("member_expires_at_milliseconds", true),
		migrationInt64("revoked_at_milliseconds", true), migrationInt64("claimed_at_milliseconds", true),
		migrationUUID("claimed_member_id", true)),
	migrationTable("relay_checkpoint_fences", "tenant_id", []string{"tenant_id", "domain_id", "fence_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("fence_id"),
		migrationUUID("create_retry_id"), migrationUUID("holder_subscription_id"),
		migrationText("status"), migrationInt64("boundary_sequence"),
		migrationInt64("requested_at_milliseconds"), migrationInt64("acquired_at_milliseconds"),
		migrationInt64("expires_at_milliseconds"), migrationUUID("abort_retry_id", true),
		migrationInt64("aborted_at_milliseconds", true)),
	migrationTable("relay_messages", "tenant_id", []string{"tenant_id", "domain_id", "message_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationInt64("domain_sequence"),
		migrationUUID("message_id"), migrationUUID("publisher_member_id"),
		migrationUUID("publisher_subscription_id"), migrationInt16("version"),
		migrationText("algorithm"), migrationInt64("key_epoch"),
		migrationInt64("created_at_milliseconds"), migrationText("nonce"),
		migrationText("ciphertext"), migrationText("authentication_tag"),
		migrationInt32("ciphertext_byte_count"), migrationUUID("checkpoint_fence_id", true),
		migrationText("envelope_digest")),
	migrationTable("relay_acknowledgments", "tenant_id", []string{"tenant_id", "domain_id", "message_id", "subscription_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("message_id"),
		migrationUUID("subscription_id"), migrationText("stage"),
		migrationInt64("accepted_at_milliseconds"), migrationInt64("applied_at_milliseconds", true)),
	migrationTable("relay_blobs", "tenant_id", []string{"tenant_id", "domain_id", "blob_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationText("blob_id"),
		migrationUUID("publisher_member_id"), migrationInt64("byte_count"),
		migrationInt64("created_at_milliseconds"), migrationUUID("checkpoint_fence_id", true)),
	migrationTable("relay_credential_rotations", "tenant_id", []string{"tenant_id", "domain_id", "rotation_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("rotation_id"),
		migrationText("subject_type"), migrationUUID("subject_id"),
		migrationText("previous_authorization_digest"), migrationText("new_authorization_digest"),
		migrationInt64("rotated_at_milliseconds")),
	migrationTable("relay_tenant_credential_rotations", "tenant_id", []string{"tenant_id", "rotation_id"},
		migrationUUID("tenant_id"), migrationUUID("rotation_id"),
		migrationText("previous_authorization_digest"), migrationText("new_authorization_digest"),
		migrationInt64("rotated_at_milliseconds")),
	migrationTable("relay_checkpoints", "tenant_id", []string{"tenant_id", "domain_id", "checkpoint_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("checkpoint_id"),
		migrationUUID("stage_retry_id"), migrationText("candidate_digest"), migrationInt16("version"),
		migrationUUID("publisher_subscription_id"), migrationUUID("publisher_member_id"),
		migrationInt64("covered_through_sequence"), migrationInt64("created_at_milliseconds"),
		migrationText("state"), migrationUUID("activation_retry_id", true),
		migrationInt64("activation_ordinal", true), migrationInt64("activated_at_milliseconds", true),
		migrationInt64("start_sequence", true), migrationUUID("fence_id"), migrationInt64("key_epoch")),
	migrationTable("relay_checkpoint_retained_messages", "tenant_id", []string{"tenant_id", "domain_id", "checkpoint_id", "message_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("checkpoint_id"),
		migrationUUID("message_id")),
	migrationTable("relay_checkpoint_retained_blobs", "tenant_id", []string{"tenant_id", "domain_id", "checkpoint_id", "blob_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("checkpoint_id"),
		migrationText("blob_id")),
	migrationTable("relay_checkpoint_required_subscriptions", "tenant_id", []string{"tenant_id", "domain_id", "checkpoint_id", "subscription_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("checkpoint_id"),
		migrationUUID("subscription_id")),
	migrationTable("relay_checkpoint_deletion_messages", "tenant_id", []string{"tenant_id", "domain_id", "checkpoint_id", "message_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("checkpoint_id"),
		migrationUUID("message_id"), migrationInt64("domain_sequence"), migrationInt64("byte_count"),
		migrationInt64("collected_at_milliseconds", true)),
	migrationTable("relay_checkpoint_deletion_blobs", "tenant_id", []string{"tenant_id", "domain_id", "checkpoint_id", "blob_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("checkpoint_id"),
		migrationText("blob_id"), migrationInt64("byte_count"),
		migrationInt64("collected_at_milliseconds", true)),
	migrationTable("relay_checkpoint_collections", "tenant_id", []string{"tenant_id", "domain_id", "retry_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("retry_id"),
		migrationUUID("checkpoint_id"), migrationText("plan_digest"),
		migrationInt64("maximum_message_count"), migrationInt64("maximum_blob_count"),
		migrationInt64("requested_at_milliseconds"), migrationInt64("deleted_message_count"),
		migrationInt64("deleted_message_byte_count"), migrationInt64("deleted_blob_count"),
		migrationInt64("deleted_blob_byte_count"), migrationBool("completed")),
	migrationTable("relay_collected_blob_deletions", "tenant_id", []string{"tenant_id", "domain_id", "blob_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationText("blob_id"),
		migrationInt64("collected_at_milliseconds")),
	migrationTable("relay_blob_uploads", "tenant_id", []string{"tenant_id", "domain_id", "upload_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("upload_id"),
		migrationUUID("create_retry_id"), migrationUUID("subscription_id"),
		migrationUUID("publisher_member_id"), migrationText("relay_blob_id"),
		migrationInt64("byte_count"), migrationInt64("committed_offset"), migrationText("state"),
		migrationInt64("created_at_milliseconds"), migrationInt64("updated_at_milliseconds"),
		migrationInt64("expires_at_milliseconds"), migrationInt64("finalized_at_milliseconds", true)),
	migrationTable("relay_blob_upload_chunks", "tenant_id", []string{"tenant_id", "domain_id", "upload_id", "chunk_offset"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("upload_id"),
		migrationInt64("chunk_offset"), migrationInt64("byte_count"), migrationText("chunk_sha256"),
		migrationInt64("committed_at_milliseconds")),
	migrationTable("relay_blob_upload_finalizations", "tenant_id", []string{"tenant_id", "domain_id", "retry_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("retry_id"),
		migrationUUID("upload_id"), migrationText("relay_blob_id"), migrationInt64("byte_count"),
		migrationInt64("finalized_at_milliseconds")),
	migrationTable("relay_blob_upload_deletions", "tenant_id", []string{"tenant_id", "domain_id", "upload_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("upload_id"),
		migrationInt64("eligible_at_milliseconds")),
	migrationTable("relay_checkpoint_fence_message_tombstones", "tenant_id", []string{"tenant_id", "domain_id", "message_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("message_id"),
		migrationUUID("fence_id"), migrationUUID("publisher_member_id"),
		migrationText("envelope_digest"), migrationInt64("domain_sequence"),
		migrationInt64("ciphertext_byte_count")),
	migrationTable("relay_tenant_membership_revocations", "tenant_id", []string{"tenant_id", "retry_id"},
		migrationUUID("tenant_id"), migrationUUID("retry_id"), migrationInt16("version"),
		migrationInt64("revoked_at_milliseconds")),
	migrationTable("relay_tenant_membership_revocation_items", "tenant_id", []string{"tenant_id", "retry_id", "ordinal"},
		migrationUUID("tenant_id"), migrationUUID("retry_id"), migrationInt32("ordinal"),
		migrationUUID("domain_id"), migrationUUID("subscription_id"), migrationUUID("member_id")),
	migrationTable("relay_member_capability_changes", "tenant_id", []string{"tenant_id", "domain_id", "retry_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("retry_id"),
		migrationUUID("member_id"), migrationInt16("version"),
		migrationTextArray("previous_capabilities"), migrationTextArray("next_capabilities"),
		migrationInt64("changed_at_milliseconds")),
	migrationTable("relay_subscription_rebootstrap_requests", "tenant_id", []string{"tenant_id", "domain_id", "retry_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("retry_id"),
		migrationUUID("subscription_id"), migrationUUID("checkpoint_id"),
		migrationUUID("root_message_id"), migrationInt64("requested_at_milliseconds"),
		migrationInt64("lease_duration_milliseconds"),
		migrationInt64("lease_expires_at_milliseconds"),
		migrationInt64("result_start_sequence"), migrationInt64("result_updated_at_milliseconds")),
	migrationTable("relay_subscription_rebootstrap_renewals", "tenant_id", []string{"tenant_id", "domain_id", "retry_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("retry_id"),
		migrationUUID("subscription_id"), migrationUUID("request_retry_id"),
		migrationUUID("checkpoint_id"), migrationUUID("root_message_id"),
		migrationInt64("expected_lease_expires_at_milliseconds"),
		migrationInt64("requested_at_milliseconds"), migrationInt64("lease_duration_milliseconds"),
		migrationInt64("previous_lease_expires_at_milliseconds"),
		migrationInt64("lease_expires_at_milliseconds"), migrationInt64("result_start_sequence"),
		migrationInt64("result_updated_at_milliseconds")),
	migrationTable("relay_subscription_rebootstrap_cancellations", "tenant_id", []string{"tenant_id", "domain_id", "retry_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("retry_id"),
		migrationUUID("subscription_id"), migrationUUID("request_retry_id"),
		migrationUUID("checkpoint_id"), migrationUUID("root_message_id"),
		migrationInt64("cancelled_at_milliseconds"), migrationInt64("result_updated_at_milliseconds")),
	migrationTable("relay_subscription_rebootstrap_completions", "tenant_id", []string{"tenant_id", "domain_id", "retry_id"},
		migrationUUID("tenant_id"), migrationUUID("domain_id"), migrationUUID("retry_id"),
		migrationUUID("subscription_id"), migrationUUID("request_retry_id"),
		migrationUUID("checkpoint_id"), migrationUUID("root_message_id"),
		migrationInt64("recovery_start_sequence"),
		migrationInt64("completed_through_sequence"), migrationInt64("completed_at_milliseconds"),
		migrationInt64("result_updated_at_milliseconds")),
	migrationAuditTable(
		migrationUUID("tenant_id"), migrationUUID("domain_id", true),
		migrationUUID("subscription_id", true), migrationUUID("member_id", true),
		migrationUUID("admission_id", true), migrationUUID("message_id", true),
		migrationText("blob_id", true), migrationUUID("credential_rotation_id", true),
		migrationText("event_type"), migrationInt64("occurred_at_milliseconds"),
		migrationUUID("checkpoint_id", true)),
	migrationTable("device_sync_principals", "principal_id", []string{"principal_id"},
		migrationUUID("principal_id"), migrationUUID("claim_retry_id"),
		migrationUUID("account_admission_id"), migrationUUID("tenant_id"),
		migrationUUID("control_domain_id"), migrationUUID("initial_device_id"),
		migrationInt64("created_at_milliseconds")),
	migrationTable("device_sync_devices", "principal_id", []string{"principal_id", "device_id"},
		migrationUUID("principal_id"), migrationUUID("device_id"), migrationUUID("tenant_id"),
		migrationUUID("control_domain_id"), migrationUUID("control_member_id"),
		migrationInt64("created_at_milliseconds")),
	migrationTable("device_sync_device_admissions", "principal_id", []string{"principal_id", "admission_id"},
		migrationUUID("principal_id"), migrationUUID("retry_id"), migrationUUID("device_id"),
		migrationUUID("control_domain_id"), migrationUUID("subscription_id"),
		migrationUUID("admission_id"), migrationInt16("version"),
		migrationInt64("created_at_milliseconds"), migrationInt64("claimed_at_milliseconds", true),
		migrationUUID("claimed_member_id", true)),
	migrationTable("device_sync_spaces", "principal_id", []string{"principal_id", "space_id"},
		migrationUUID("principal_id"), migrationUUID("space_id"), migrationUUID("provisioning_retry_id"),
		migrationUUID("domain_id"), migrationUUID("subscription_id"),
		migrationUUID("initial_device_id"), migrationInt16("version"),
		migrationInt64("created_at_milliseconds")),
	migrationTable("device_sync_space_devices", "principal_id", []string{"principal_id", "space_id", "device_id"},
		migrationUUID("principal_id"), migrationUUID("space_id"), migrationUUID("device_id"),
		migrationUUID("domain_id"), migrationUUID("subscription_id"), migrationUUID("member_id"),
		migrationInt64("created_at_milliseconds")),
	migrationTable("device_sync_space_device_admissions", "principal_id", []string{"principal_id", "space_id", "admission_id"},
		migrationUUID("principal_id"), migrationUUID("space_id"), migrationUUID("retry_id"),
		migrationUUID("device_id"), migrationUUID("domain_id"), migrationUUID("subscription_id"),
		migrationUUID("admission_id"), migrationInt16("version"),
		migrationInt64("created_at_milliseconds"), migrationInt64("claimed_at_milliseconds", true),
		migrationUUID("claimed_member_id", true)),
	migrationTable("device_sync_device_revocations", "principal_id", []string{"principal_id", "retry_id"},
		migrationUUID("principal_id"), migrationUUID("retry_id"), migrationUUID("device_id"),
		migrationInt16("version"), migrationInt64("revoked_at_milliseconds")),
	migrationTable("device_sync_join_requests", "principal_id", []string{"request_id"},
		migrationUUID("request_id"), migrationUUID("retry_id"), migrationInt32("version"),
		migrationUUID("candidate_device_id"), migrationText("candidate_bootstrap_public_key"),
		migrationText("polling_authorization_digest"), migrationText("pin_authorization_digest"),
		migrationInt64("created_at_milliseconds"), migrationInt64("expires_at_milliseconds"),
		migrationUUID("principal_id", true), migrationJSON("bootstrap", true)),
}

var deviceSyncMigrationExcludedTables = map[string]string{
	"device_sync_scope_enforcement":          "deployment authority and write fencing are installed separately",
	"device_sync_migration_exports":          "source-side migration evidence is not logical Device Sync state",
	"device_sync_migration_imports":          "target-side migration evidence is not logical Device Sync state",
	"device_sync_migration_rollback_imports": "reverse-import evidence is not logical Device Sync state",
}

var deviceSyncMigrationOmittedColumns = map[string]map[string]string{
	"device_sync_account_admissions":               {"stored_at": "timestamptz", "updated_at": "timestamptz"},
	"device_sync_device_admissions":                {"stored_at": "timestamptz", "updated_at": "timestamptz"},
	"device_sync_device_revocations":               {"stored_at": "timestamptz"},
	"device_sync_devices":                          {"stored_at": "timestamptz"},
	"device_sync_principals":                       {"stored_at": "timestamptz"},
	"device_sync_space_device_admissions":          {"stored_at": "timestamptz", "updated_at": "timestamptz"},
	"device_sync_space_devices":                    {"stored_at": "timestamptz"},
	"device_sync_spaces":                           {"stored_at": "timestamptz"},
	"relay_acknowledgments":                        {"updated_at": "timestamptz"},
	"relay_audit_events":                           {"event_sequence": "int8", "stored_at": "timestamptz"},
	"relay_blob_upload_finalizations":              {"stored_at": "timestamptz"},
	"relay_blob_uploads":                           {"stored_at": "timestamptz", "updated_at": "timestamptz"},
	"relay_blobs":                                  {"stored_at": "timestamptz"},
	"relay_checkpoint_collections":                 {"stored_at": "timestamptz"},
	"relay_checkpoint_fence_message_tombstones":    {"stored_at": "timestamptz"},
	"relay_checkpoint_fences":                      {"stored_at": "timestamptz", "updated_at": "timestamptz"},
	"relay_checkpoints":                            {"stored_at": "timestamptz", "updated_at": "timestamptz"},
	"relay_credential_rotations":                   {"stored_at": "timestamptz"},
	"relay_domains":                                {"stored_at": "timestamptz", "updated_at": "timestamptz"},
	"relay_member_admissions":                      {"stored_at": "timestamptz", "updated_at": "timestamptz"},
	"relay_member_capability_changes":              {"stored_at": "timestamptz"},
	"relay_members":                                {"stored_at": "timestamptz", "updated_at": "timestamptz"},
	"relay_messages":                               {"stored_at": "timestamptz"},
	"relay_subscription_rebootstrap_completions":   {"stored_at": "timestamptz"},
	"relay_subscription_rebootstrap_cancellations": {"stored_at": "timestamptz"},
	"relay_subscription_rebootstrap_renewals":      {"stored_at": "timestamptz"},
	"relay_subscription_rebootstrap_requests":      {"stored_at": "timestamptz"},
	"relay_subscription_status_changes":            {"stored_at": "timestamptz"},
	"relay_subscriptions":                          {"stored_at": "timestamptz", "updated_at": "timestamptz"},
	"relay_tenant_credential_rotations":            {"stored_at": "timestamptz"},
	"relay_tenant_membership_revocations":          {"stored_at": "timestamptz"},
	"relay_tenants":                                {"stored_at": "timestamptz", "updated_at": "timestamptz"},
}

func init() {
	seen := make(map[string]struct{}, len(deviceSyncMigrationTableSpecs))
	for _, spec := range deviceSyncMigrationTableSpecs {
		if _, exists := seen[spec.name]; exists {
			panic("duplicate Device Sync migration table " + spec.name)
		}
		seen[spec.name] = struct{}{}
		if _, excluded := deviceSyncMigrationExcludedTables[spec.name]; excluded {
			panic(fmt.Sprintf("Device Sync migration table %s is both included and excluded", spec.name))
		}
	}
}

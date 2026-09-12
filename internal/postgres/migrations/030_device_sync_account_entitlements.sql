-- Operator-issued Device Sync account admissions carry an immutable service
-- entitlement snapshot. A bootstrap holder can create its content-blind relay
-- tenant, but cannot choose or enlarge the service capacity it receives.
ALTER TABLE device_sync_account_admissions
    ADD COLUMN entitlement_version smallint NOT NULL DEFAULT 1 CHECK (entitlement_version = 1),
    ADD COLUMN entitlement_plan_id text NOT NULL DEFAULT 'self-hosted'
        CHECK (entitlement_plan_id ~ '^[A-Za-z0-9._-]{1,64}$'),
    ADD COLUMN maximum_domain_count integer NOT NULL DEFAULT 0
        CHECK (maximum_domain_count >= 0),
    ADD COLUMN maximum_aggregate_message_count integer NOT NULL DEFAULT 0
        CHECK (maximum_aggregate_message_count >= 0),
    ADD COLUMN maximum_aggregate_message_byte_count bigint NOT NULL DEFAULT 0
        CHECK (maximum_aggregate_message_byte_count >= 0),
    ADD COLUMN maximum_aggregate_blob_count integer NOT NULL DEFAULT 0
        CHECK (maximum_aggregate_blob_count >= 0),
    ADD COLUMN maximum_aggregate_blob_byte_count bigint NOT NULL DEFAULT 0
        CHECK (maximum_aggregate_blob_byte_count >= 0),
    ADD CHECK ((entitlement_plan_id='self-hosted' AND maximum_domain_count=0 AND maximum_aggregate_message_count=0
            AND maximum_aggregate_message_byte_count=0 AND maximum_aggregate_blob_count=0 AND maximum_aggregate_blob_byte_count=0)
        OR (maximum_domain_count>0 AND maximum_aggregate_message_count>0 AND maximum_aggregate_message_byte_count>0
            AND maximum_aggregate_blob_count>0 AND maximum_aggregate_blob_byte_count>0));

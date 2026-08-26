-- Durable, per-principal Device Sync write authority. This migration adds no
-- compatibility rows: every new principal is created with a standby row by
-- the current account-claim transaction.
CREATE TABLE device_sync_scope_enforcement (
    principal_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL UNIQUE,
    initial_claim_transaction_id xid8 NOT NULL,
    state text NOT NULL CHECK (
        state IN (
            'standby', 'writable', 'export_fenced',
            'rollback_standby', 'retired'
        )
    ),
    local_deployment_id uuid,
    initial_deployment_id uuid,
    initial_authority_validated_at_milliseconds bigint CHECK (
        initial_authority_validated_at_milliseconds >= 0
    ),
    initial_authority_manifest_digest text CHECK (
        initial_authority_manifest_digest ~ '^[0-9a-f]{64}$'
    ),
    initial_authority_manifest_record bytea CHECK (
        initial_authority_manifest_record IS NULL OR
        (octet_length(initial_authority_manifest_record) > 0 AND
            octet_length(initial_authority_manifest_record) <= 1048576)
    ),
    authority_validated_at_milliseconds bigint CHECK (
        authority_validated_at_milliseconds >= 0
    ),
    authority_revision bigint CHECK (authority_revision > 0),
    authority_manifest_digest text CHECK (
        authority_manifest_digest ~ '^[0-9a-f]{64}$'
    ),
    authority_manifest_record bytea CHECK (
        authority_manifest_record IS NULL OR
        (octet_length(authority_manifest_record) > 0 AND
            octet_length(authority_manifest_record) <= 1048576)
    ),
    active_deployment_id uuid,
    transition_evidence_digest text CHECK (
        transition_evidence_digest ~ '^[0-9a-f]{64}$'
    ),
    active_export_write_fence_id uuid,
    active_migration_import_id uuid,
    active_rollback_import_id uuid,
    stored_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (principal_id, tenant_id),
    CHECK (principal_id = tenant_id),
    FOREIGN KEY (principal_id)
        REFERENCES device_sync_principals(principal_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id)
        REFERENCES relay_tenants(tenant_id) ON DELETE CASCADE,
    CHECK (
        (local_deployment_id IS NULL AND
            initial_deployment_id IS NULL AND
            initial_authority_validated_at_milliseconds IS NULL AND
            initial_authority_manifest_digest IS NULL AND
            initial_authority_manifest_record IS NULL AND
            authority_validated_at_milliseconds IS NULL AND
            authority_revision IS NULL AND
            authority_manifest_digest IS NULL AND
            authority_manifest_record IS NULL AND active_deployment_id IS NULL AND
            transition_evidence_digest IS NULL) OR
        (local_deployment_id IS NOT NULL AND
            initial_deployment_id IS NOT NULL AND
            initial_authority_validated_at_milliseconds IS NOT NULL AND
            initial_authority_manifest_digest IS NOT NULL AND
            initial_authority_manifest_record IS NOT NULL AND
            authority_validated_at_milliseconds IS NOT NULL AND
            authority_revision IS NOT NULL AND
            authority_manifest_digest IS NOT NULL AND
            authority_manifest_record IS NOT NULL AND active_deployment_id IS NOT NULL)
    ),
    CHECK (
        (state = 'standby' AND active_export_write_fence_id IS NULL AND
            active_rollback_import_id IS NULL AND (
            (local_deployment_id IS NULL AND authority_revision IS NULL AND
                active_migration_import_id IS NULL) OR
            (local_deployment_id = active_deployment_id AND
                authority_revision IS NOT NULL AND
                active_migration_import_id IS NULL) OR
            (local_deployment_id <> active_deployment_id AND
                authority_revision IS NOT NULL AND
                active_migration_import_id IS NOT NULL)
        )) OR
        (state = 'writable' AND local_deployment_id = active_deployment_id AND
            authority_revision IS NOT NULL AND active_export_write_fence_id IS NULL AND
            active_migration_import_id IS NULL AND active_rollback_import_id IS NULL) OR
        (state = 'export_fenced' AND local_deployment_id = active_deployment_id AND
            authority_revision IS NOT NULL AND active_export_write_fence_id IS NOT NULL AND
            active_migration_import_id IS NULL AND active_rollback_import_id IS NULL) OR
        (state = 'rollback_standby' AND
            local_deployment_id <> active_deployment_id AND
            authority_revision IS NOT NULL AND active_export_write_fence_id IS NULL AND
            active_migration_import_id IS NULL AND active_rollback_import_id IS NOT NULL) OR
        (state = 'retired' AND authority_revision IS NOT NULL AND
            active_export_write_fence_id IS NULL AND active_migration_import_id IS NULL AND
            active_rollback_import_id IS NULL)
    )
);

-- The initial-claim exception is valid only inside the transaction that
-- actually creates the enforcement row. A BEFORE trigger, rather than a
-- caller-supplied default, prevents direct SQL from planting an identity for a
-- later transaction. The value is protected from every subsequent update by
-- preserve_device_sync_initial_authority below.
CREATE FUNCTION bind_device_sync_initial_claim_transaction()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.initial_claim_transaction_id := pg_current_xact_id();
    RETURN NEW;
END;
$$;

CREATE TRIGGER device_sync_initial_claim_transaction_is_bound
BEFORE INSERT ON device_sync_scope_enforcement
FOR EACH ROW
EXECUTE FUNCTION bind_device_sync_initial_claim_transaction();

CREATE TABLE device_sync_migration_exports (
    principal_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    migration_id uuid NOT NULL,
    export_write_fence_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    authority_revision bigint NOT NULL CHECK (authority_revision > 0),
    authority_manifest_digest text NOT NULL CHECK (
        authority_manifest_digest ~ '^[0-9a-f]{64}$'
    ),
    exporting_deployment_id uuid NOT NULL,
    importing_deployment_id uuid NOT NULL,
    canonical_snapshot_payload bytea NOT NULL CHECK (
        octet_length(canonical_snapshot_payload) > 0 AND
        octet_length(canonical_snapshot_payload) <= 262144
    ),
    snapshot_payload_sha256 text NOT NULL CHECK (
        snapshot_payload_sha256 ~ '^[0-9a-f]{64}$'
    ),
    state_commitment_digest text NOT NULL CHECK (
        state_commitment_digest ~ '^[0-9a-f]{64}$'
    ),
    captured_at_milliseconds bigint NOT NULL CHECK (
        captured_at_milliseconds >= 0
    ),
    expires_at_milliseconds bigint NOT NULL CHECK (
        expires_at_milliseconds > captured_at_milliseconds
    ),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (principal_id, export_write_fence_id),
    UNIQUE (principal_id, migration_id, exporting_deployment_id),
    UNIQUE (principal_id, snapshot_id),
    UNIQUE (principal_id, tenant_id, export_write_fence_id),
    CHECK (principal_id = tenant_id),
    CHECK (exporting_deployment_id <> importing_deployment_id),
    FOREIGN KEY (principal_id, tenant_id)
        REFERENCES device_sync_scope_enforcement(principal_id, tenant_id)
        ON DELETE CASCADE
);

-- A target import is immutable evidence that one exact authenticated source
-- snapshot populated one exact target-local standby scope. The service rows
-- themselves are materialized in the same transaction. This table deliberately
-- stores only signed/canonical evidence and artifact descriptors; artifact bytes
-- and production migration orchestration remain separate checkpoints.
CREATE TABLE device_sync_migration_imports (
    principal_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    migration_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    export_write_fence_id uuid NOT NULL,
    authority_revision bigint NOT NULL CHECK (authority_revision > 0),
    authority_manifest_digest text NOT NULL CHECK (
        authority_manifest_digest ~ '^[0-9a-f]{64}$'
    ),
    preparation_reference_digest text NOT NULL CHECK (
        preparation_reference_digest ~ '^[0-9a-f]{64}$'
    ),
    exporting_deployment_id uuid NOT NULL,
    importing_deployment_id uuid NOT NULL,
    canonical_preparation_record bytea NOT NULL CHECK (
        octet_length(canonical_preparation_record) > 0 AND
        octet_length(canonical_preparation_record) <= 8388608
    ),
    preparation_record_sha256 text NOT NULL CHECK (
        preparation_record_sha256 ~ '^[0-9a-f]{64}$'
    ),
    canonical_snapshot_record bytea NOT NULL CHECK (
        octet_length(canonical_snapshot_record) > 0 AND
        octet_length(canonical_snapshot_record) <= 8388608
    ),
    snapshot_record_sha256 text NOT NULL CHECK (
        snapshot_record_sha256 ~ '^[0-9a-f]{64}$'
    ),
    snapshot_reference_digest text NOT NULL CHECK (
        snapshot_reference_digest ~ '^[0-9a-f]{64}$'
    ),
    snapshot_payload_sha256 text NOT NULL CHECK (
        snapshot_payload_sha256 ~ '^[0-9a-f]{64}$'
    ),
    state_commitment_digest text NOT NULL CHECK (
        state_commitment_digest ~ '^[0-9a-f]{64}$'
    ),
    canonical_artifact_descriptors bytea NOT NULL CHECK (
        octet_length(canonical_artifact_descriptors) > 0 AND
        octet_length(canonical_artifact_descriptors) <= 262144
    ),
    artifact_descriptors_sha256 text NOT NULL CHECK (
        artifact_descriptors_sha256 ~ '^[0-9a-f]{64}$'
    ),
    artifact_count integer NOT NULL CHECK (artifact_count > 0),
    service_state_artifact_id uuid NOT NULL,
    service_state_artifact_byte_count bigint NOT NULL CHECK (
        service_state_artifact_byte_count >= 0
    ),
    service_state_artifact_transfer_digest text NOT NULL CHECK (
        service_state_artifact_transfer_digest ~ '^[0-9a-f]{64}$'
    ),
    captured_at_milliseconds bigint NOT NULL CHECK (
        captured_at_milliseconds >= 0
    ),
    expires_at_milliseconds bigint NOT NULL CHECK (
        expires_at_milliseconds > captured_at_milliseconds
    ),
    imported_at_milliseconds bigint NOT NULL CHECK (
        imported_at_milliseconds >= captured_at_milliseconds AND
        imported_at_milliseconds < expires_at_milliseconds
    ),
    initial_deployment_id uuid NOT NULL,
    initial_authority_validated_at_milliseconds bigint NOT NULL CHECK (
        initial_authority_validated_at_milliseconds >= 0
    ),
    initial_authority_manifest_digest text NOT NULL CHECK (
        initial_authority_manifest_digest ~ '^[0-9a-f]{64}$'
    ),
    initial_authority_manifest_record bytea NOT NULL CHECK (
        octet_length(initial_authority_manifest_record) > 0 AND
        octet_length(initial_authority_manifest_record) <= 1048576
    ),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (principal_id, migration_id, importing_deployment_id),
    UNIQUE (principal_id, snapshot_id, importing_deployment_id),
    UNIQUE (
        principal_id, tenant_id, migration_id, importing_deployment_id,
        exporting_deployment_id, authority_revision, authority_manifest_digest,
        preparation_reference_digest, initial_deployment_id,
        initial_authority_validated_at_milliseconds,
        initial_authority_manifest_digest
    ),
    CHECK (principal_id = tenant_id),
    CHECK (exporting_deployment_id <> importing_deployment_id),
    FOREIGN KEY (principal_id, tenant_id)
        REFERENCES device_sync_scope_enforcement(principal_id, tenant_id)
        DEFERRABLE INITIALLY DEFERRED
);

-- Reverse import evidence is deliberately distinct from a fresh target
-- preparation. It binds the activation-authorized target-to-source snapshot
-- that replaced the retired source's stale semantic rows while the target
-- remained authoritative. The source stays non-writable until a complete
-- rollback successor is installed.
CREATE TABLE device_sync_migration_rollback_imports (
    principal_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    migration_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    export_write_fence_id uuid NOT NULL,
    authority_revision bigint NOT NULL CHECK (authority_revision > 0),
    authority_manifest_digest text NOT NULL CHECK (
        authority_manifest_digest ~ '^[0-9a-f]{64}$'
    ),
    activation_evidence_digest text NOT NULL CHECK (
        activation_evidence_digest ~ '^[0-9a-f]{64}$'
    ),
    exporting_deployment_id uuid NOT NULL,
    importing_deployment_id uuid NOT NULL,
    canonical_activation_evidence_record bytea NOT NULL CHECK (
        octet_length(canonical_activation_evidence_record) > 0 AND
        octet_length(canonical_activation_evidence_record) <= 8388608
    ),
    activation_evidence_record_sha256 text NOT NULL CHECK (
        activation_evidence_record_sha256 ~ '^[0-9a-f]{64}$'
    ),
    canonical_snapshot_record bytea NOT NULL CHECK (
        octet_length(canonical_snapshot_record) > 0 AND
        octet_length(canonical_snapshot_record) <= 8388608
    ),
    snapshot_record_sha256 text NOT NULL CHECK (
        snapshot_record_sha256 ~ '^[0-9a-f]{64}$'
    ),
    snapshot_reference_digest text NOT NULL CHECK (
        snapshot_reference_digest ~ '^[0-9a-f]{64}$'
    ),
    snapshot_payload_sha256 text NOT NULL CHECK (
        snapshot_payload_sha256 ~ '^[0-9a-f]{64}$'
    ),
    state_commitment_digest text NOT NULL CHECK (
        state_commitment_digest ~ '^[0-9a-f]{64}$'
    ),
    canonical_artifact_descriptors bytea NOT NULL CHECK (
        octet_length(canonical_artifact_descriptors) > 0 AND
        octet_length(canonical_artifact_descriptors) <= 262144
    ),
    artifact_descriptors_sha256 text NOT NULL CHECK (
        artifact_descriptors_sha256 ~ '^[0-9a-f]{64}$'
    ),
    artifact_count integer NOT NULL CHECK (artifact_count > 0),
    service_state_artifact_id uuid NOT NULL,
    service_state_artifact_byte_count bigint NOT NULL CHECK (
        service_state_artifact_byte_count >= 0
    ),
    service_state_artifact_transfer_digest text NOT NULL CHECK (
        service_state_artifact_transfer_digest ~ '^[0-9a-f]{64}$'
    ),
    captured_at_milliseconds bigint NOT NULL CHECK (
        captured_at_milliseconds >= 0
    ),
    expires_at_milliseconds bigint NOT NULL CHECK (
        expires_at_milliseconds > captured_at_milliseconds
    ),
    imported_at_milliseconds bigint NOT NULL CHECK (
        imported_at_milliseconds >= captured_at_milliseconds AND
        imported_at_milliseconds < expires_at_milliseconds
    ),
    initial_deployment_id uuid NOT NULL,
    initial_authority_validated_at_milliseconds bigint NOT NULL CHECK (
        initial_authority_validated_at_milliseconds >= 0
    ),
    initial_authority_manifest_digest text NOT NULL CHECK (
        initial_authority_manifest_digest ~ '^[0-9a-f]{64}$'
    ),
    initial_authority_manifest_record bytea NOT NULL CHECK (
        octet_length(initial_authority_manifest_record) > 0 AND
        octet_length(initial_authority_manifest_record) <= 1048576
    ),
	import_transaction_id xid8 NOT NULL,
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (principal_id, migration_id, importing_deployment_id),
    UNIQUE (principal_id, snapshot_id, importing_deployment_id),
    UNIQUE (
        principal_id, tenant_id, migration_id, importing_deployment_id,
        exporting_deployment_id, authority_revision, authority_manifest_digest,
        activation_evidence_digest, initial_deployment_id,
        initial_authority_validated_at_milliseconds,
        initial_authority_manifest_digest
    ),
    CHECK (principal_id = tenant_id),
    CHECK (exporting_deployment_id <> importing_deployment_id),
    FOREIGN KEY (principal_id, tenant_id)
        REFERENCES device_sync_scope_enforcement(principal_id, tenant_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE FUNCTION bind_device_sync_rollback_import_transaction()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.import_transaction_id := pg_current_xact_id();
    RETURN NEW;
END;
$$;

CREATE TRIGGER device_sync_rollback_import_transaction_is_bound
BEFORE INSERT ON device_sync_migration_rollback_imports
FOR EACH ROW
EXECUTE FUNCTION bind_device_sync_rollback_import_transaction();

ALTER TABLE device_sync_scope_enforcement
    ADD CONSTRAINT device_sync_scope_enforcement_active_fence_fk
    FOREIGN KEY (principal_id, tenant_id, active_export_write_fence_id)
    REFERENCES device_sync_migration_exports(
        principal_id, tenant_id, export_write_fence_id
    ) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE device_sync_scope_enforcement
    ADD CONSTRAINT device_sync_scope_enforcement_active_rollback_import_fk
    FOREIGN KEY (
        principal_id, tenant_id, active_rollback_import_id,
        local_deployment_id, active_deployment_id,
        authority_revision, authority_manifest_digest,
        transition_evidence_digest, initial_deployment_id,
        initial_authority_validated_at_milliseconds,
        initial_authority_manifest_digest
    ) REFERENCES device_sync_migration_rollback_imports (
        principal_id, tenant_id, migration_id,
        importing_deployment_id, exporting_deployment_id,
        authority_revision, authority_manifest_digest,
        activation_evidence_digest, initial_deployment_id,
        initial_authority_validated_at_milliseconds,
        initial_authority_manifest_digest
    ) DEFERRABLE INITIALLY DEFERRED;

-- The composite reference makes the exceptional target standby shape exact at
-- the database boundary: its local deployment is the authenticated importer,
-- its still-active deployment is the exporter, and its authority revision and
-- digest are the exact preparation committed by the immutable import record.
ALTER TABLE device_sync_scope_enforcement
    ADD CONSTRAINT device_sync_scope_enforcement_active_import_fk
    FOREIGN KEY (
        principal_id, tenant_id, active_migration_import_id,
        local_deployment_id, active_deployment_id,
        authority_revision, authority_manifest_digest,
        transition_evidence_digest, initial_deployment_id,
        initial_authority_validated_at_milliseconds,
        initial_authority_manifest_digest
    ) REFERENCES device_sync_migration_imports (
        principal_id, tenant_id, migration_id,
        importing_deployment_id, exporting_deployment_id,
        authority_revision, authority_manifest_digest,
        preparation_reference_digest, initial_deployment_id,
        initial_authority_validated_at_milliseconds,
        initial_authority_manifest_digest
    ) DEFERRABLE INITIALLY DEFERRED;

-- Exactly one enforcement row must exist for every principal created after
-- this unreleased schema checkpoint. Deferred checks let the account-claim
-- transaction insert the principal before its standby enforcement row, while
-- still making that row permanent for the lifetime of the principal.
CREATE FUNCTION require_device_sync_principal_enforcement_row()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM device_sync_principals
        WHERE principal_id = NEW.principal_id
          AND tenant_id = NEW.tenant_id
    ) AND NOT EXISTS (
        SELECT 1
        FROM device_sync_scope_enforcement
        WHERE principal_id = NEW.principal_id
          AND tenant_id = NEW.tenant_id
    ) THEN
        RAISE EXCEPTION
            'Device Sync principal % lacks its scope enforcement row',
            NEW.principal_id;
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER device_sync_principal_requires_enforcement
AFTER INSERT OR UPDATE ON device_sync_principals
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION require_device_sync_principal_enforcement_row();

CREATE FUNCTION preserve_device_sync_principal_enforcement_row()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'Device Sync principal % scope enforcement row cannot be deleted',
        OLD.principal_id
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER device_sync_principal_enforcement_is_permanent
BEFORE DELETE ON device_sync_scope_enforcement
FOR EACH ROW
EXECUTE FUNCTION preserve_device_sync_principal_enforcement_row();

CREATE FUNCTION preserve_device_sync_initial_authority()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.initial_claim_transaction_id IS DISTINCT FROM
            NEW.initial_claim_transaction_id OR
        OLD.initial_deployment_id IS DISTINCT FROM NEW.initial_deployment_id OR
        OLD.initial_authority_validated_at_milliseconds IS DISTINCT FROM
            NEW.initial_authority_validated_at_milliseconds OR
        OLD.initial_authority_manifest_digest IS DISTINCT FROM
            NEW.initial_authority_manifest_digest OR
        OLD.initial_authority_manifest_record IS DISTINCT FROM
            NEW.initial_authority_manifest_record THEN
        RAISE EXCEPTION
            'Device Sync principal % initial authority is immutable',
            OLD.principal_id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER device_sync_initial_authority_is_immutable
BEFORE UPDATE ON device_sync_scope_enforcement
FOR EACH ROW
EXECUTE FUNCTION preserve_device_sync_initial_authority();

CREATE FUNCTION preserve_device_sync_migration_export()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' OR EXISTS (
        SELECT 1
        FROM device_sync_principals
        WHERE principal_id = OLD.principal_id
          AND tenant_id = OLD.tenant_id
    ) THEN
        RAISE EXCEPTION
            'Device Sync migration export % is immutable',
            OLD.export_write_fence_id;
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER device_sync_migration_export_is_immutable
AFTER UPDATE OR DELETE ON device_sync_migration_exports
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION preserve_device_sync_migration_export();

CREATE FUNCTION preserve_device_sync_migration_import()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'Device Sync migration import % is immutable',
        OLD.migration_id
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER device_sync_migration_import_is_immutable
BEFORE UPDATE OR DELETE ON device_sync_migration_imports
FOR EACH ROW
EXECUTE FUNCTION preserve_device_sync_migration_import();

CREATE TRIGGER device_sync_migration_rollback_import_is_immutable
BEFORE UPDATE OR DELETE ON device_sync_migration_rollback_imports
FOR EACH ROW
EXECUTE FUNCTION preserve_device_sync_migration_import();

-- A Device Sync principal is permanent in this unreleased authority model.
-- Rejecting the principal row deletion also rejects a relay-tenant deletion
-- that would otherwise cascade through it, while relay tenants belonging only
-- to Shared Spaces remain deletable.
CREATE FUNCTION prohibit_device_sync_principal_deletion()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'Device Sync principal % cannot be deleted',
        OLD.principal_id
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER device_sync_principal_is_permanent
BEFORE DELETE ON device_sync_principals
FOR EACH ROW
EXECUTE FUNCTION prohibit_device_sync_principal_deletion();

-- This unreleased checkpoint deliberately has no legacy backfill. Refuse to
-- mark the migration applied if an older database already contains a Device
-- Sync principal, because silently leaving it without an enforcement row would
-- violate the invariant and permit fail-open behavior on later code paths.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM device_sync_principals p
        LEFT JOIN device_sync_scope_enforcement e
          ON e.principal_id = p.principal_id AND e.tenant_id = p.tenant_id
        WHERE e.principal_id IS NULL
    ) THEN
        RAISE EXCEPTION
            'preexisting Device Sync principals require an unreleased database reset';
    END IF;
END;
$$;

-- A request-level lock transaction authenticates the exact authority and
-- drains ordinary writers, but PostgreSQL must still reject a write atomically
-- if that separate lock session disappears. These deferred row triggers run in
-- the mutation's own transaction. Their first check takes a shared lock on the
-- enforcement row and is therefore ordered against export's FOR UPDATE lock.
-- Shared Spaces reuse relay tables but have no Device Sync enforcement row, so
-- the function leaves those tenants unchanged.
CREATE FUNCTION require_device_sync_scope_writable(scope_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    scope_state text;
    stored_initial_claim_transaction_id xid8;
	active_rollback_import_id uuid;
	rollback_import_transaction_id xid8;
    current_transaction_id xid8;
BEGIN
    IF scope_id IS NULL THEN
        RETURN;
    END IF;

    SELECT enforcement.state, enforcement.initial_claim_transaction_id,
		enforcement.active_rollback_import_id
    INTO scope_state, stored_initial_claim_transaction_id,
		active_rollback_import_id
    FROM device_sync_scope_enforcement AS enforcement
    WHERE enforcement.principal_id = scope_id
      AND enforcement.tenant_id = scope_id
    FOR SHARE;

    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF scope_state = 'writable' THEN
        RETURN;
    END IF;

    -- Initial account claim creates the complete principal and its standby
    -- enforcement row atomically. Permit only that row's creating transaction;
    -- an older standby row remains non-writable even for direct store callers.
    current_transaction_id := pg_current_xact_id();
    IF scope_state = 'standby' AND
        stored_initial_claim_transaction_id = current_transaction_id THEN
        RETURN;
    END IF;

	-- A reverse import may replace semantic rows only in the transaction that
	-- created the immutable evidence named by the non-writable standby. The
	-- transaction identity is database-authored, so later callers cannot reuse
	-- rollback_standby as a general mutation bypass.
	IF scope_state = 'rollback_standby' AND
		active_rollback_import_id IS NOT NULL THEN
		SELECT import_transaction_id
		INTO rollback_import_transaction_id
		FROM device_sync_migration_rollback_imports
		WHERE principal_id = scope_id
		  AND tenant_id = scope_id
		  AND migration_id = active_rollback_import_id;
		IF FOUND AND rollback_import_transaction_id = current_transaction_id THEN
			RETURN;
		END IF;
	END IF;

    RAISE EXCEPTION
        'Device Sync scope % is not writable in this transaction',
        scope_id
        USING ERRCODE = '55000';
END;
$$;

CREATE FUNCTION enforce_device_sync_scope_writable_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    old_scope_id uuid;
    new_scope_id uuid;
BEGIN
    IF TG_NARGS <> 1 THEN
        RAISE EXCEPTION 'Device Sync scope trigger lacks its scope column';
    END IF;
    IF TG_OP <> 'INSERT' THEN
        old_scope_id := NULLIF(to_jsonb(OLD) ->> TG_ARGV[0], '')::uuid;
        PERFORM require_device_sync_scope_writable(old_scope_id);
    END IF;
    IF TG_OP <> 'DELETE' THEN
        new_scope_id := NULLIF(to_jsonb(NEW) ->> TG_ARGV[0], '')::uuid;
        IF old_scope_id IS NULL OR new_scope_id IS DISTINCT FROM old_scope_id THEN
            PERFORM require_device_sync_scope_writable(new_scope_id);
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

DO $$
DECLARE
    target record;
BEGIN
    FOR target IN
        SELECT table_name,
            CASE
                WHEN bool_or(column_name = 'principal_id') THEN 'principal_id'
                ELSE 'tenant_id'
            END AS scope_column
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND (table_name LIKE 'relay\_%' ESCAPE '\' OR
               table_name LIKE 'device\_sync\_%' ESCAPE '\')
          AND column_name IN ('principal_id', 'tenant_id')
          AND table_name NOT IN (
              'device_sync_scope_enforcement',
              'device_sync_migration_exports',
			  'device_sync_migration_imports',
			  'device_sync_migration_rollback_imports'
          )
        GROUP BY table_name
        ORDER BY table_name
    LOOP
        EXECUTE format(
            'CREATE CONSTRAINT TRIGGER %I '
            'AFTER INSERT OR UPDATE OR DELETE ON %I '
            'DEFERRABLE INITIALLY DEFERRED FOR EACH ROW '
            'EXECUTE FUNCTION enforce_device_sync_scope_writable_mutation(%L)',
            'ds_writable_' || target.table_name,
            target.table_name,
            target.scope_column
        );
    END LOOP;
END;
$$;

CREATE CONSTRAINT TRIGGER ds_writable_device_sync_account_admissions
AFTER INSERT OR UPDATE OR DELETE ON device_sync_account_admissions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION enforce_device_sync_scope_writable_mutation(
    'claimed_principal_id'
);

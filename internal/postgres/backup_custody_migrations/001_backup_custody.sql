CREATE TABLE backup_custody_accounts (
    account_id uuid PRIMARY KEY,
    claim_id uuid NOT NULL UNIQUE,
    admission_id uuid NOT NULL UNIQUE,
    admission_record bytea NOT NULL,
    admission_authorization_digest text NOT NULL CHECK (admission_authorization_digest ~ '^[0-9a-f]{64}$'),
    authority_revision bigint NOT NULL CHECK (authority_revision > 0),
    authority_manifest_digest text NOT NULL CHECK (authority_manifest_digest ~ '^[0-9a-f]{64}$'),
    deployment_id uuid NOT NULL,
    initial_anchor_record bytea NOT NULL,
    initial_manifest_record bytea NOT NULL,
    initial_enrollment_record bytea NOT NULL,
    server_time_high_water_milliseconds bigint NOT NULL CHECK (server_time_high_water_milliseconds >= 0),
    state text NOT NULL CHECK (state IN ('standby','writable')),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE backup_custody_requests (
    request_id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES backup_custody_accounts(account_id),
    operation text NOT NULL CHECK (operation IN ('account_claim','begin_upload','retention')),
    request_record bytea NOT NULL,
    stored_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id,request_id)
);

CREATE TABLE backup_custody_account_control (
    account_id uuid PRIMARY KEY REFERENCES backup_custody_accounts(account_id),
    initial_anchor_record bytea NOT NULL,
    initial_anchor_reference_digest text NOT NULL CHECK (initial_anchor_reference_digest ~ '^[0-9a-f]{64}$'),
    current_anchor_record bytea NOT NULL,
    current_anchor_reference_digest text NOT NULL CHECK (current_anchor_reference_digest ~ '^[0-9a-f]{64}$'),
    head_sequence bigint NOT NULL CHECK (head_sequence >= 0),
    head_reference_digest text NOT NULL CHECK (head_reference_digest ~ '^[0-9a-f]{64}$'),
    control_generation bigint NOT NULL CHECK (control_generation > 0),
    control_key_id uuid NOT NULL,
    stored_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((head_sequence = 0 AND head_reference_digest = initial_anchor_reference_digest) OR head_sequence > 0)
);

CREATE TABLE backup_custody_control_commands (
    account_id uuid NOT NULL REFERENCES backup_custody_accounts(account_id),
    sequence bigint NOT NULL CHECK (sequence > 0),
    command_id uuid NOT NULL,
    predecessor_reference_digest text NOT NULL CHECK (predecessor_reference_digest ~ '^[0-9a-f]{64}$'),
    command_reference_digest text NOT NULL CHECK (command_reference_digest ~ '^[0-9a-f]{64}$'),
    command_record bytea NOT NULL,
    acceptance_record bytea NOT NULL,
    effect_kind text NOT NULL CHECK (effect_kind IN ('create_target_with_initial_grant','grant','supersede','revoke','rotate_control_key')),
    accepted_at_milliseconds bigint NOT NULL CHECK (accepted_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id,sequence),
    UNIQUE (account_id,command_id),
    UNIQUE (command_reference_digest)
);

CREATE TABLE backup_custody_authority_history (
    account_id uuid NOT NULL REFERENCES backup_custody_accounts(account_id),
    authority_revision bigint NOT NULL CHECK (authority_revision > 0),
    authority_manifest_digest text NOT NULL CHECK (authority_manifest_digest ~ '^[0-9a-f]{64}$'),
    deployment_id uuid NOT NULL,
    anchor_record bytea NOT NULL,
    manifest_record bytea NOT NULL,
    accepted_at_milliseconds bigint NOT NULL CHECK (accepted_at_milliseconds >= 0),
    PRIMARY KEY (account_id,authority_revision),
    UNIQUE (account_id,authority_manifest_digest)
);

CREATE TABLE backup_custody_targets (
    account_id uuid NOT NULL REFERENCES backup_custody_accounts(account_id),
    target_id uuid NOT NULL,
    backup_set_id uuid NOT NULL,
    create_control_command_reference_digest text NOT NULL UNIQUE CHECK (create_control_command_reference_digest ~ '^[0-9a-f]{64}$'),
    head_generation bigint,
    head_generation_reference_digest text CHECK (head_generation_reference_digest ~ '^[0-9a-f]{64}$'),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id,target_id),
    UNIQUE (account_id,backup_set_id),
    UNIQUE (account_id,target_id,backup_set_id),
    CHECK ((head_generation IS NULL) = (head_generation_reference_digest IS NULL)),
    CHECK (head_generation IS NULL OR head_generation > 0),
    FOREIGN KEY (create_control_command_reference_digest) REFERENCES backup_custody_control_commands(command_reference_digest)
);

CREATE TABLE backup_custody_credential_grants (
    account_id uuid NOT NULL REFERENCES backup_custody_accounts(account_id),
    credential_id uuid NOT NULL,
    target_id uuid NOT NULL,
    backup_set_id uuid NOT NULL,
    grant_reference_digest text NOT NULL CHECK (grant_reference_digest ~ '^[0-9a-f]{64}$'),
    grant_record bytea NOT NULL,
    authorization_digest text NOT NULL CHECK (authorization_digest ~ '^[0-9a-f]{64}$'),
    accepted_control_command_reference_digest text NOT NULL CHECK (accepted_control_command_reference_digest ~ '^[0-9a-f]{64}$'),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id,grant_reference_digest),
    UNIQUE (account_id,credential_id),
    FOREIGN KEY (account_id,target_id,backup_set_id) REFERENCES backup_custody_targets(account_id,target_id,backup_set_id),
    FOREIGN KEY (accepted_control_command_reference_digest) REFERENCES backup_custody_control_commands(command_reference_digest)
);

CREATE TABLE backup_custody_credential_grant_transitions (
    account_id uuid NOT NULL REFERENCES backup_custody_accounts(account_id),
    prior_grant_reference_digest text NOT NULL,
    transition_kind text NOT NULL CHECK (transition_kind IN ('supersede','revoke')),
    replacement_grant_reference_digest text,
    accepted_control_command_reference_digest text NOT NULL UNIQUE,
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id,prior_grant_reference_digest),
    FOREIGN KEY (account_id,prior_grant_reference_digest) REFERENCES backup_custody_credential_grants(account_id,grant_reference_digest),
    FOREIGN KEY (account_id,replacement_grant_reference_digest) REFERENCES backup_custody_credential_grants(account_id,grant_reference_digest),
    FOREIGN KEY (accepted_control_command_reference_digest) REFERENCES backup_custody_control_commands(command_reference_digest),
    CHECK ((transition_kind='supersede') = (replacement_grant_reference_digest IS NOT NULL))
);

CREATE TABLE backup_custody_uploads (
    account_id uuid NOT NULL,
    upload_id uuid NOT NULL,
    target_id uuid NOT NULL,
    backup_set_id uuid NOT NULL,
    publish_request_id uuid NOT NULL UNIQUE,
    request_record bytea NOT NULL,
    committed_bytes bigint NOT NULL CHECK (committed_bytes >= 0),
    maximum_chunk_count integer NOT NULL CHECK (maximum_chunk_count > 0),
    state text NOT NULL CHECK (state IN ('uploading','committed')),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id,upload_id),
    FOREIGN KEY (account_id,target_id,backup_set_id) REFERENCES backup_custody_targets(account_id,target_id,backup_set_id),
    UNIQUE (account_id,target_id,upload_id),
    UNIQUE (account_id,target_id,backup_set_id,upload_id),
    FOREIGN KEY (account_id,publish_request_id) REFERENCES backup_custody_requests(account_id,request_id)
);

CREATE TABLE backup_custody_generations (
    account_id uuid NOT NULL,
    target_id uuid NOT NULL,
    backup_set_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    upload_id uuid NOT NULL,
    generation_record bytea NOT NULL,
    generation_reference_digest text NOT NULL UNIQUE CHECK (generation_reference_digest ~ '^[0-9a-f]{64}$'),
    object_path text NOT NULL,
    custody_receipt_record bytea NOT NULL,
    custody_receipt_reference_digest text NOT NULL UNIQUE CHECK (custody_receipt_reference_digest ~ '^[0-9a-f]{64}$'),
    credential_grant_reference_digest text NOT NULL CHECK (credential_grant_reference_digest ~ '^[0-9a-f]{64}$'),
    control_head_reference_digest text NOT NULL CHECK (control_head_reference_digest ~ '^[0-9a-f]{64}$'),
    outer_byte_count bigint NOT NULL CHECK (outer_byte_count > 0),
    outer_digest text NOT NULL CHECK (outer_digest ~ '^[A-Za-z0-9_-]{43}$'),
    committed_at_milliseconds bigint NOT NULL CHECK (committed_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id,target_id,generation),
    FOREIGN KEY (account_id,target_id,backup_set_id) REFERENCES backup_custody_targets(account_id,target_id,backup_set_id),
    FOREIGN KEY (account_id,target_id,backup_set_id,upload_id) REFERENCES backup_custody_uploads(account_id,target_id,backup_set_id,upload_id),
    UNIQUE (account_id,upload_id)
);

CREATE TABLE backup_custody_upload_chunks (
    account_id uuid NOT NULL,
    upload_id uuid NOT NULL,
    chunk_offset bigint NOT NULL CHECK (chunk_offset >= 0),
    chunk_byte_count bigint NOT NULL CHECK (chunk_byte_count > 0),
    chunk_sha256 text NOT NULL CHECK (chunk_sha256 ~ '^[0-9a-f]{64}$'),
    next_offset bigint NOT NULL CHECK (next_offset > chunk_offset),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id,upload_id,chunk_offset),
    FOREIGN KEY (account_id,upload_id) REFERENCES backup_custody_uploads(account_id,upload_id),
    CHECK (chunk_offset <= 9223372036854775807 - chunk_byte_count),
    CHECK (next_offset = chunk_offset + chunk_byte_count)
);

ALTER TABLE backup_custody_targets
    ADD CONSTRAINT backup_custody_target_head_fk
    FOREIGN KEY (account_id,target_id,head_generation)
    REFERENCES backup_custody_generations(account_id,target_id,generation)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE backup_custody_retention_receipts (
    account_id uuid NOT NULL REFERENCES backup_custody_accounts(account_id),
    request_id uuid NOT NULL UNIQUE,
    request_record bytea NOT NULL,
    receipt_record bytea NOT NULL,
    receipt_reference_digest text NOT NULL UNIQUE CHECK (receipt_reference_digest ~ '^[0-9a-f]{64}$'),
    credential_grant_reference_digest text NOT NULL CHECK (credential_grant_reference_digest ~ '^[0-9a-f]{64}$'),
    control_head_reference_digest text NOT NULL CHECK (control_head_reference_digest ~ '^[0-9a-f]{64}$'),
    issued_at_milliseconds bigint NOT NULL CHECK (issued_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id,request_id),
    FOREIGN KEY (account_id,request_id) REFERENCES backup_custody_requests(account_id,request_id)
);

CREATE INDEX backup_custody_upload_target_idx ON backup_custody_uploads(account_id,target_id,upload_id);
CREATE INDEX backup_custody_generation_lookup_idx ON backup_custody_generations(account_id,generation_reference_digest);

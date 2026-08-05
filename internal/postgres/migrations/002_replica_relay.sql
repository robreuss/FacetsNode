CREATE TABLE relay_domains (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    administration_digest text NOT NULL CHECK (
        administration_digest ~ '^[0-9a-f]{64}$'
    ),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    maximum_message_count integer NOT NULL CHECK (
        maximum_message_count > 0 AND maximum_message_count <= 1000000
    ),
    message_count integer NOT NULL DEFAULT 0 CHECK (message_count >= 0),
    last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id),
    CHECK (message_count <= maximum_message_count)
);

CREATE TABLE relay_members (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    member_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    authorization_digest text NOT NULL CHECK (
        authorization_digest ~ '^[0-9a-f]{64}$'
    ),
    capabilities text[] NOT NULL CHECK (
        cardinality(capabilities) > 0 AND
        capabilities <@ ARRAY[
            'blob_fetch',
            'blob_publish',
            'checkpoint_publish',
            'message_acknowledge',
            'message_fetch',
            'message_publish'
        ]::text[]
    ),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    expires_at_milliseconds bigint,
    revoked_at_milliseconds bigint,
    stored_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, member_id),
    FOREIGN KEY (tenant_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE,
    CHECK (
        expires_at_milliseconds IS NULL OR
        expires_at_milliseconds > created_at_milliseconds
    ),
    CHECK (
        revoked_at_milliseconds IS NULL OR
        revoked_at_milliseconds >= created_at_milliseconds
    )
);

CREATE TABLE relay_messages (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    domain_sequence bigint NOT NULL CHECK (domain_sequence > 0),
    message_id uuid NOT NULL,
    publisher_member_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    algorithm text NOT NULL CHECK (algorithm = 'HKDF-SHA256+A256GCM'),
    key_epoch bigint NOT NULL CHECK (key_epoch > 0),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    nonce text NOT NULL CHECK (char_length(nonce) = 16),
    ciphertext text NOT NULL CHECK (
        char_length(ciphertext) > 0 AND char_length(ciphertext) <= 22369624
    ),
    authentication_tag text NOT NULL CHECK (char_length(authentication_tag) = 22),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, message_id),
    UNIQUE (tenant_id, domain_id, domain_sequence),
    FOREIGN KEY (tenant_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, domain_id, publisher_member_id)
        REFERENCES relay_members(tenant_id, domain_id, member_id)
);

CREATE TABLE relay_acknowledgments (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    message_id uuid NOT NULL,
    member_id uuid NOT NULL,
    stage text NOT NULL CHECK (stage IN ('accepted', 'applied')),
    accepted_at_milliseconds bigint NOT NULL CHECK (accepted_at_milliseconds >= 0),
    applied_at_milliseconds bigint,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, message_id, member_id),
    FOREIGN KEY (tenant_id, domain_id, message_id)
        REFERENCES relay_messages(tenant_id, domain_id, message_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, domain_id, member_id)
        REFERENCES relay_members(tenant_id, domain_id, member_id),
    CHECK (
        (stage = 'accepted' AND applied_at_milliseconds IS NULL) OR
        (stage = 'applied' AND applied_at_milliseconds IS NOT NULL)
    )
);

CREATE TABLE relay_audit_events (
    event_sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    member_id uuid,
    message_id uuid,
    event_type text NOT NULL CHECK (event_type IN (
        'domain_created',
        'member_created',
        'member_revoked',
        'message_published',
        'message_accepted',
        'message_applied'
    )),
    occurred_at_milliseconds bigint NOT NULL CHECK (occurred_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE
);

CREATE INDEX relay_members_active_idx
    ON relay_members (tenant_id, domain_id, member_id)
    WHERE revoked_at_milliseconds IS NULL;

CREATE INDEX relay_messages_fetch_idx
    ON relay_messages (tenant_id, domain_id, domain_sequence);

CREATE INDEX relay_acknowledgments_member_idx
    ON relay_acknowledgments (tenant_id, domain_id, member_id, stage);

CREATE INDEX relay_audit_scope_idx
    ON relay_audit_events (tenant_id, domain_id, event_sequence);

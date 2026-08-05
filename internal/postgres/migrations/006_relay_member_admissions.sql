CREATE TABLE relay_member_admissions (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    admission_id uuid NOT NULL,
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
    created_at_milliseconds bigint NOT NULL CHECK (
        created_at_milliseconds >= 0
    ),
    expires_at_milliseconds bigint NOT NULL,
    member_expires_at_milliseconds bigint,
    revoked_at_milliseconds bigint,
    claimed_at_milliseconds bigint,
    claimed_member_id uuid,
    stored_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, admission_id),
    FOREIGN KEY (tenant_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, domain_id, claimed_member_id)
        REFERENCES relay_members(tenant_id, domain_id, member_id)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        expires_at_milliseconds > created_at_milliseconds AND
        expires_at_milliseconds - created_at_milliseconds <= 604800000
    ),
    CHECK (
        member_expires_at_milliseconds IS NULL OR
        member_expires_at_milliseconds > expires_at_milliseconds
    ),
    CHECK (
        revoked_at_milliseconds IS NULL OR
        revoked_at_milliseconds >= created_at_milliseconds
    ),
    CHECK (
        (claimed_at_milliseconds IS NULL) = (claimed_member_id IS NULL)
    ),
    CHECK (
        claimed_at_milliseconds IS NULL OR
        (claimed_at_milliseconds >= created_at_milliseconds AND
         claimed_at_milliseconds < expires_at_milliseconds)
    )
);

CREATE INDEX relay_member_admissions_active_idx
    ON relay_member_admissions (tenant_id, domain_id, expires_at_milliseconds)
    WHERE revoked_at_milliseconds IS NULL AND claimed_at_milliseconds IS NULL;

ALTER TABLE relay_audit_events
    ADD COLUMN admission_id uuid,
    DROP CONSTRAINT relay_audit_events_event_type_check,
    ADD CONSTRAINT relay_audit_events_event_type_check CHECK (event_type IN (
        'domain_created',
        'member_created',
        'member_revoked',
        'admission_created',
        'admission_claimed',
        'admission_revoked',
        'message_published',
        'message_accepted',
        'message_applied',
        'blob_published'
    )),
    ADD CONSTRAINT relay_audit_events_admission_event_check CHECK (
        (event_type IN (
            'admission_created',
            'admission_claimed',
            'admission_revoked'
        )) = (admission_id IS NOT NULL)
    );

CREATE INDEX relay_audit_admission_idx
    ON relay_audit_events (tenant_id, domain_id, admission_id)
    WHERE admission_id IS NOT NULL;

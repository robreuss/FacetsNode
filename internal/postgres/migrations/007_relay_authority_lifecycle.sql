CREATE TABLE relay_credential_rotations (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    rotation_id uuid NOT NULL,
    subject_type text NOT NULL CHECK (
        subject_type IN ('administration', 'member')
    ),
    subject_id uuid NOT NULL,
    previous_authorization_digest text NOT NULL CHECK (
        previous_authorization_digest ~ '^[0-9a-f]{64}$'
    ),
    new_authorization_digest text NOT NULL CHECK (
        new_authorization_digest ~ '^[0-9a-f]{64}$'
    ),
    rotated_at_milliseconds bigint NOT NULL CHECK (
        rotated_at_milliseconds >= 0
    ),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, rotation_id),
    FOREIGN KEY (tenant_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE,
    CHECK (
        previous_authorization_digest <> new_authorization_digest
    ),
    CHECK (
        subject_type <> 'administration' OR subject_id = domain_id
    )
);

CREATE INDEX relay_credential_rotations_subject_idx
    ON relay_credential_rotations (
        tenant_id, domain_id, subject_type, subject_id,
        rotated_at_milliseconds
    );

ALTER TABLE relay_audit_events
    ADD COLUMN credential_rotation_id uuid,
    DROP CONSTRAINT relay_audit_events_event_type_check,
    DROP CONSTRAINT relay_audit_events_admission_event_check,
    ADD CONSTRAINT relay_audit_events_event_type_check CHECK (event_type IN (
        'domain_created',
        'member_created',
        'member_revoked',
        'administration_credential_rotated',
        'member_credential_rotated',
        'admission_created',
        'admission_claimed',
        'admission_revoked',
        'admission_collected',
        'message_published',
        'message_accepted',
        'message_applied',
        'blob_published'
    )),
    ADD CONSTRAINT relay_audit_events_admission_event_check CHECK (
        (event_type IN (
            'admission_created',
            'admission_claimed',
            'admission_revoked',
            'admission_collected'
        )) = (admission_id IS NOT NULL)
    ),
    ADD CONSTRAINT relay_audit_events_rotation_event_check CHECK (
        (event_type IN (
            'administration_credential_rotated',
            'member_credential_rotated'
        )) = (credential_rotation_id IS NOT NULL)
    );

CREATE INDEX relay_audit_rotation_idx
    ON relay_audit_events (tenant_id, domain_id, credential_rotation_id)
    WHERE credential_rotation_id IS NOT NULL;

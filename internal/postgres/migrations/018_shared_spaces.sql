CREATE TABLE shared_space_provisioning_admissions (
    admission_id uuid PRIMARY KEY,
    retry_id uuid NOT NULL UNIQUE,
    version smallint NOT NULL CHECK (version = 1),
    authorization_digest text NOT NULL CHECK (
        authorization_digest ~ '^[0-9a-f]{64}$'
    ),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    expires_at_milliseconds bigint NOT NULL,
    claimed_at_milliseconds bigint,
    claimed_space_id uuid,
    claimed_request_digest text CHECK (
        claimed_request_digest ~ '^[0-9a-f]{64}$'
    ),
    stored_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (
        expires_at_milliseconds - created_at_milliseconds >= 300000 AND
        expires_at_milliseconds - created_at_milliseconds <= 604800000
    ),
    CHECK (
        (claimed_at_milliseconds IS NULL AND claimed_space_id IS NULL AND
            claimed_request_digest IS NULL) OR
        (claimed_at_milliseconds >= created_at_milliseconds AND
            claimed_at_milliseconds < expires_at_milliseconds AND
            claimed_space_id IS NOT NULL AND claimed_request_digest IS NOT NULL)
    )
);

CREATE TABLE shared_spaces (
    space_id uuid PRIMARY KEY REFERENCES relay_tenants(tenant_id) ON DELETE CASCADE,
    provisioning_retry_id uuid NOT NULL UNIQUE,
    version smallint NOT NULL CHECK (version = 1),
    security_mode text NOT NULL CHECK (security_mode IN ('private', 'secure', 'managed')),
    domain_id uuid NOT NULL UNIQUE,
    initial_participant_id uuid NOT NULL,
    initial_subscription_id uuid NOT NULL,
    initial_participant_kind text NOT NULL CHECK (initial_participant_kind IN ('person', 'nonhuman')),
    provisioning_payload jsonb NOT NULL,
    service_authority_state text NOT NULL DEFAULT 'unbound'
        CHECK (service_authority_state IN ('unbound', 'standby', 'active')),
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
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (space_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE,
    FOREIGN KEY (space_id, domain_id, initial_subscription_id)
        REFERENCES relay_subscriptions(tenant_id, domain_id, subscription_id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (space_id, domain_id, initial_participant_id)
        REFERENCES relay_members(tenant_id, domain_id, member_id)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (service_authority_state = 'unbound' AND
            initial_deployment_id IS NULL AND
            initial_authority_validated_at_milliseconds IS NULL AND
            initial_authority_manifest_digest IS NULL AND
            initial_authority_manifest_record IS NULL AND
            authority_revision IS NULL AND
            authority_manifest_digest IS NULL AND
            authority_manifest_record IS NULL AND
            active_deployment_id IS NULL) OR
        (service_authority_state = 'standby' AND
            initial_deployment_id IS NOT NULL AND
            initial_authority_validated_at_milliseconds IS NOT NULL AND
            initial_authority_manifest_digest IS NOT NULL AND
            initial_authority_manifest_record IS NOT NULL AND
            authority_revision = 1 AND
            authority_manifest_digest = initial_authority_manifest_digest AND
            authority_manifest_record = initial_authority_manifest_record AND
            active_deployment_id = initial_deployment_id) OR
        (service_authority_state = 'active' AND
            initial_deployment_id IS NOT NULL AND
            initial_authority_validated_at_milliseconds IS NOT NULL AND
            initial_authority_manifest_digest IS NOT NULL AND
            initial_authority_manifest_record IS NOT NULL AND
            authority_revision IS NOT NULL AND
            authority_manifest_digest IS NOT NULL AND
            authority_manifest_record IS NOT NULL AND
            active_deployment_id IS NOT NULL)
    )
);

CREATE FUNCTION preserve_shared_space_initial_authority()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.initial_deployment_id IS DISTINCT FROM NEW.initial_deployment_id OR
        OLD.initial_authority_validated_at_milliseconds IS DISTINCT FROM
            NEW.initial_authority_validated_at_milliseconds OR
        OLD.initial_authority_manifest_digest IS DISTINCT FROM
            NEW.initial_authority_manifest_digest OR
        OLD.initial_authority_manifest_record IS DISTINCT FROM
            NEW.initial_authority_manifest_record THEN
        RAISE EXCEPTION 'Shared Space initial service authority is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER shared_space_initial_authority_is_immutable
BEFORE UPDATE ON shared_spaces
FOR EACH ROW
EXECUTE FUNCTION preserve_shared_space_initial_authority();

CREATE TABLE shared_space_participants (
    space_id uuid NOT NULL REFERENCES shared_spaces(space_id) ON DELETE CASCADE,
    participant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    kind text NOT NULL CHECK (kind IN ('person', 'nonhuman')),
    role text NOT NULL CHECK (role IN ('host', 'moderator', 'participant', 'reader')),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    revoked_at_milliseconds bigint,
    stored_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (space_id, participant_id),
    FOREIGN KEY (space_id, domain_id, subscription_id)
        REFERENCES relay_subscriptions(tenant_id, domain_id, subscription_id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (space_id, domain_id, participant_id)
        REFERENCES relay_members(tenant_id, domain_id, member_id)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (revoked_at_milliseconds IS NULL OR revoked_at_milliseconds >= created_at_milliseconds)
);

CREATE TABLE shared_space_invitations (
    space_id uuid NOT NULL REFERENCES shared_spaces(space_id) ON DELETE CASCADE,
    invitation_id uuid NOT NULL,
    retry_id uuid NOT NULL UNIQUE,
    domain_id uuid NOT NULL,
    participant_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    kind text NOT NULL CHECK (kind IN ('person', 'nonhuman')),
    role text NOT NULL CHECK (role IN ('host', 'moderator', 'participant', 'reader')),
    invitation_payload jsonb NOT NULL,
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    claimed_at_milliseconds bigint,
    claimed_member_id uuid,
    stored_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (space_id, invitation_id),
    FOREIGN KEY (space_id, domain_id, subscription_id)
        REFERENCES relay_subscriptions(tenant_id, domain_id, subscription_id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (space_id, domain_id, invitation_id)
        REFERENCES relay_member_admissions(tenant_id, domain_id, admission_id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (space_id, domain_id, claimed_member_id)
        REFERENCES relay_members(tenant_id, domain_id, member_id)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK ((claimed_at_milliseconds IS NULL) = (claimed_member_id IS NULL))
);

CREATE TABLE shared_space_participant_revocations (
    space_id uuid NOT NULL REFERENCES shared_spaces(space_id) ON DELETE CASCADE,
    retry_id uuid NOT NULL,
    participant_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    revoked_at_milliseconds bigint NOT NULL CHECK (revoked_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (space_id, retry_id),
    UNIQUE (space_id, participant_id),
    FOREIGN KEY (space_id, participant_id)
        REFERENCES shared_space_participants(space_id, participant_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX shared_space_participants_status_idx
    ON shared_space_participants (space_id, revoked_at_milliseconds, participant_id);

CREATE INDEX shared_space_invitations_participant_idx
    ON shared_space_invitations (space_id, participant_id, claimed_at_milliseconds);

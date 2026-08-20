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
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (space_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE,
    FOREIGN KEY (space_id, domain_id, initial_subscription_id)
        REFERENCES relay_subscriptions(tenant_id, domain_id, subscription_id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (space_id, domain_id, initial_participant_id)
        REFERENCES relay_members(tenant_id, domain_id, member_id)
        DEFERRABLE INITIALLY DEFERRED
);

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

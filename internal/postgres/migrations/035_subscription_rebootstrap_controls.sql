-- A member may recover only its own replica from an exact client-authorized
-- root retained by the latest activated checkpoint. These records make the
-- control requests idempotent without giving a member administrative
-- authority over another subscription.

CREATE TABLE relay_subscription_rebootstrap_requests (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    retry_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    checkpoint_id uuid NOT NULL,
    root_message_id uuid NOT NULL,
    requested_at_milliseconds bigint NOT NULL CHECK (requested_at_milliseconds >= 0),
    lease_duration_milliseconds bigint NOT NULL CHECK (lease_duration_milliseconds >= 0),
    lease_expires_at_milliseconds bigint NOT NULL CHECK (lease_expires_at_milliseconds >= 0),
    result_start_sequence bigint NOT NULL CHECK (result_start_sequence >= 0),
    result_updated_at_milliseconds bigint NOT NULL CHECK (result_updated_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, retry_id),
    FOREIGN KEY (tenant_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, domain_id, subscription_id)
        REFERENCES relay_subscriptions(tenant_id, domain_id, subscription_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE relay_subscription_rebootstrap_cancellations (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    retry_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    request_retry_id uuid NOT NULL,
    checkpoint_id uuid NOT NULL,
    root_message_id uuid NOT NULL,
    cancelled_at_milliseconds bigint NOT NULL CHECK (cancelled_at_milliseconds >= 0),
    result_updated_at_milliseconds bigint NOT NULL CHECK (result_updated_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, retry_id),
    FOREIGN KEY (tenant_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, domain_id, subscription_id)
        REFERENCES relay_subscriptions(tenant_id, domain_id, subscription_id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, domain_id, request_retry_id)
        REFERENCES relay_subscription_rebootstrap_requests(tenant_id, domain_id, retry_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE relay_subscription_rebootstrap_renewals (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    retry_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    request_retry_id uuid NOT NULL,
    checkpoint_id uuid NOT NULL,
    root_message_id uuid NOT NULL,
    expected_lease_expires_at_milliseconds bigint NOT NULL CHECK (expected_lease_expires_at_milliseconds > 0),
    requested_at_milliseconds bigint NOT NULL CHECK (requested_at_milliseconds >= 0),
    lease_duration_milliseconds bigint NOT NULL CHECK (lease_duration_milliseconds >= 0),
    previous_lease_expires_at_milliseconds bigint NOT NULL CHECK (previous_lease_expires_at_milliseconds > 0),
    lease_expires_at_milliseconds bigint NOT NULL CHECK (lease_expires_at_milliseconds > 0),
    result_start_sequence bigint NOT NULL CHECK (result_start_sequence >= 0),
    result_updated_at_milliseconds bigint NOT NULL CHECK (result_updated_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, retry_id),
    FOREIGN KEY (tenant_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, domain_id, subscription_id)
        REFERENCES relay_subscriptions(tenant_id, domain_id, subscription_id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, domain_id, request_retry_id)
        REFERENCES relay_subscription_rebootstrap_requests(tenant_id, domain_id, retry_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE relay_subscription_rebootstrap_completions (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    retry_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    request_retry_id uuid NOT NULL,
    checkpoint_id uuid NOT NULL,
    root_message_id uuid NOT NULL,
    recovery_start_sequence bigint NOT NULL CHECK (recovery_start_sequence >= 0),
    completed_through_sequence bigint NOT NULL CHECK (completed_through_sequence >= 0),
    completed_at_milliseconds bigint NOT NULL CHECK (completed_at_milliseconds >= 0),
    result_updated_at_milliseconds bigint NOT NULL CHECK (result_updated_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, retry_id),
    FOREIGN KEY (tenant_id, domain_id)
        REFERENCES relay_domains(tenant_id, domain_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, domain_id, subscription_id)
        REFERENCES relay_subscriptions(tenant_id, domain_id, subscription_id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, domain_id, request_retry_id)
        REFERENCES relay_subscription_rebootstrap_requests(tenant_id, domain_id, retry_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX relay_subscription_rebootstrap_request_subscription_idx
    ON relay_subscription_rebootstrap_requests (tenant_id, domain_id, subscription_id);
CREATE INDEX relay_subscription_rebootstrap_renewal_subscription_idx
    ON relay_subscription_rebootstrap_renewals (tenant_id, domain_id, subscription_id);
CREATE INDEX relay_subscription_rebootstrap_cancellation_subscription_idx
    ON relay_subscription_rebootstrap_cancellations (tenant_id, domain_id, subscription_id);
CREATE INDEX relay_subscription_rebootstrap_completion_subscription_idx
    ON relay_subscription_rebootstrap_completions (tenant_id, domain_id, subscription_id);

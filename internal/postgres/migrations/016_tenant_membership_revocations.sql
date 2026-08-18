-- Tenant-authorized, atomic fencing of one logical client from several opaque
-- relay domains. The relay records only transport identifiers.
CREATE TABLE relay_tenant_membership_revocations (
    tenant_id uuid NOT NULL REFERENCES relay_tenants(tenant_id) ON DELETE CASCADE,
    retry_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    revoked_at_milliseconds bigint NOT NULL CHECK (revoked_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, retry_id)
);

CREATE TABLE relay_tenant_membership_revocation_items (
    tenant_id uuid NOT NULL,
    retry_id uuid NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    domain_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    member_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, retry_id, ordinal),
    UNIQUE (tenant_id, retry_id, domain_id),
    FOREIGN KEY (tenant_id, retry_id)
        REFERENCES relay_tenant_membership_revocations(tenant_id, retry_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, domain_id, subscription_id)
        REFERENCES relay_subscriptions(tenant_id, domain_id, subscription_id),
    FOREIGN KEY (tenant_id, domain_id, member_id)
        REFERENCES relay_members(tenant_id, domain_id, member_id)
);

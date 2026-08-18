CREATE TABLE relay_member_capability_changes (
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    retry_id uuid NOT NULL,
    member_id uuid NOT NULL,
    version smallint NOT NULL CHECK (version = 1),
    previous_capabilities text[] NOT NULL CHECK (cardinality(previous_capabilities) > 0),
    next_capabilities text[] NOT NULL CHECK (cardinality(next_capabilities) > 0),
    changed_at_milliseconds bigint NOT NULL CHECK (changed_at_milliseconds >= 0),
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain_id, retry_id),
    FOREIGN KEY (tenant_id, domain_id, member_id)
        REFERENCES relay_members(tenant_id, domain_id, member_id)
        ON DELETE CASCADE
);

CREATE INDEX relay_member_capability_changes_member_idx
    ON relay_member_capability_changes (tenant_id, domain_id, member_id, changed_at_milliseconds);

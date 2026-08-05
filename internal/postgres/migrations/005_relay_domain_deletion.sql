ALTER TABLE relay_messages
    DROP CONSTRAINT relay_messages_tenant_id_domain_id_publisher_member_id_fkey,
    ADD CONSTRAINT relay_messages_tenant_id_domain_id_publisher_member_id_fkey
        FOREIGN KEY (tenant_id, domain_id, publisher_member_id)
        REFERENCES relay_members(tenant_id, domain_id, member_id)
        DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE relay_acknowledgments
    DROP CONSTRAINT relay_acknowledgments_tenant_id_domain_id_member_id_fkey,
    ADD CONSTRAINT relay_acknowledgments_tenant_id_domain_id_member_id_fkey
        FOREIGN KEY (tenant_id, domain_id, member_id)
        REFERENCES relay_members(tenant_id, domain_id, member_id)
        DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE relay_blobs
    DROP CONSTRAINT relay_blobs_tenant_id_domain_id_publisher_member_id_fkey,
    ADD CONSTRAINT relay_blobs_tenant_id_domain_id_publisher_member_id_fkey
        FOREIGN KEY (tenant_id, domain_id, publisher_member_id)
        REFERENCES relay_members(tenant_id, domain_id, member_id)
        DEFERRABLE INITIALLY DEFERRED;

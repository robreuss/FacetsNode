ALTER TABLE relay_domains
    ADD COLUMN maximum_stored_byte_count bigint NOT NULL DEFAULT 1073741824
        CHECK (
            maximum_stored_byte_count > 0 AND
            maximum_stored_byte_count <= 1099511627776
        ),
    ADD COLUMN stored_byte_count bigint NOT NULL DEFAULT 0
        CHECK (stored_byte_count >= 0);

ALTER TABLE relay_messages
    ADD COLUMN ciphertext_byte_count integer;

UPDATE relay_messages
SET ciphertext_byte_count = char_length(ciphertext) * 3 / 4;

ALTER TABLE relay_messages
    ALTER COLUMN ciphertext_byte_count SET NOT NULL,
    ADD CONSTRAINT relay_messages_ciphertext_byte_count_check CHECK (
        ciphertext_byte_count > 0 AND ciphertext_byte_count <= 16777216
    );

UPDATE relay_domains AS domain
SET stored_byte_count = COALESCE((
    SELECT sum(message.ciphertext_byte_count)
    FROM relay_messages AS message
    WHERE message.tenant_id = domain.tenant_id
      AND message.domain_id = domain.domain_id
), 0);

ALTER TABLE relay_domains
    ADD CONSTRAINT relay_domains_stored_byte_count_limit_check CHECK (
        stored_byte_count <= maximum_stored_byte_count
    );

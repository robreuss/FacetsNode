CREATE TABLE pairing_routes (
    route_id uuid PRIMARY KEY,
    version smallint NOT NULL CHECK (version = 1),
    sponsor_authorization_digest char(64) NOT NULL,
    candidate_authorization_digest char(64) NOT NULL,
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    expires_at_milliseconds bigint NOT NULL,
    closed_at_milliseconds bigint,
    stored_at timestamptz NOT NULL DEFAULT now(),
    CHECK (expires_at_milliseconds > created_at_milliseconds),
    CHECK (closed_at_milliseconds IS NULL OR (
        closed_at_milliseconds >= created_at_milliseconds AND
        closed_at_milliseconds < expires_at_milliseconds
    )),
    CHECK (sponsor_authorization_digest <> candidate_authorization_digest)
);

CREATE TABLE pairing_messages (
    route_id uuid NOT NULL REFERENCES pairing_routes(route_id) ON DELETE CASCADE,
    message_id uuid NOT NULL,
    publisher_role text NOT NULL CHECK (publisher_role IN ('sponsor', 'candidate')),
    version smallint NOT NULL CHECK (version = 1),
    algorithm text NOT NULL CHECK (algorithm = 'HKDF-SHA256+A256GCM'),
    created_at_milliseconds bigint NOT NULL CHECK (created_at_milliseconds >= 0),
    expires_at_milliseconds bigint NOT NULL,
    nonce text NOT NULL,
    ciphertext text NOT NULL,
    authentication_tag text NOT NULL,
    acknowledged_by text CHECK (acknowledged_by IN ('sponsor', 'candidate')),
    acknowledged_at_milliseconds bigint,
    stored_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (route_id, message_id),
    CHECK (expires_at_milliseconds > created_at_milliseconds),
    CHECK (
        (acknowledged_by IS NULL AND acknowledged_at_milliseconds IS NULL) OR
        (acknowledged_by IS NOT NULL AND acknowledged_at_milliseconds IS NOT NULL)
    ),
    CHECK (acknowledged_by IS NULL OR acknowledged_by <> publisher_role)
);

CREATE INDEX pairing_routes_expiry_idx
    ON pairing_routes (expires_at_milliseconds);

CREATE INDEX pairing_messages_fetch_idx
    ON pairing_messages (
        route_id,
        publisher_role,
        created_at_milliseconds,
        message_id
    )
    WHERE acknowledged_by IS NULL;

CREATE INDEX pairing_messages_expiry_idx
    ON pairing_messages (expires_at_milliseconds);

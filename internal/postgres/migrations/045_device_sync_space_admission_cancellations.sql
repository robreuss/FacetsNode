-- Exact cancellation fences also cover requests not yet accepted by the Box.
-- This contains no bearer credentials and never revokes a claimed membership.
CREATE TABLE device_sync_space_admission_cancellations (
    principal_id uuid NOT NULL,
    space_id uuid NOT NULL,
    admission_id uuid NOT NULL,
    retry_id uuid NOT NULL,
    device_id uuid NOT NULL,
    sponsor_device_id uuid NOT NULL,
    PRIMARY KEY (principal_id, space_id, admission_id),
    UNIQUE (principal_id, space_id, retry_id),
    FOREIGN KEY (principal_id, space_id)
        REFERENCES device_sync_spaces(principal_id, space_id) ON DELETE CASCADE
);

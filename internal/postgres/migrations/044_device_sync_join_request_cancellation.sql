-- Keep request/retry identifiers and credential digests as a tombstone so an
-- uncertain create retry cannot resurrect a candidate-cancelled mailbox.
ALTER TABLE device_sync_join_requests ADD COLUMN cancelled BOOLEAN NOT NULL DEFAULT FALSE;

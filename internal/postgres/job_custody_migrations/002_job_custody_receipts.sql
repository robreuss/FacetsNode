ALTER TABLE job_custody_admissions
    ADD COLUMN admission_permit_digest text NOT NULL
        CHECK (admission_permit_digest ~ '^[0-9a-f]{64}$'),
    ADD COLUMN custody_receipt_record bytea,
    ADD COLUMN expiry_started_at_milliseconds bigint,
    ADD COLUMN expiry_receipt_record bytea;

ALTER TABLE job_custody_admissions
    ADD CHECK (
        (state = 'staging' AND custody_receipt_record IS NULL AND
         expiry_started_at_milliseconds IS NULL AND expiry_receipt_record IS NULL) OR
        (state = 'stagingExpiryPending' AND custody_receipt_record IS NULL AND
         expiry_started_at_milliseconds IS NOT NULL AND expiry_receipt_record IS NULL) OR
        (state = 'retained' AND custody_receipt_record IS NOT NULL AND
         octet_length(custody_receipt_record) BETWEEN 1 AND 40960 AND
         expiry_started_at_milliseconds IS NULL AND expiry_receipt_record IS NULL) OR
        (state = 'expiryPending' AND custody_receipt_record IS NOT NULL AND
         octet_length(custody_receipt_record) BETWEEN 1 AND 40960 AND
         expiry_started_at_milliseconds IS NOT NULL AND expiry_receipt_record IS NULL) OR
        (state = 'expired' AND expiry_started_at_milliseconds IS NOT NULL AND
         expiry_receipt_record IS NOT NULL AND
         octet_length(expiry_receipt_record) BETWEEN 1 AND 40960 AND
         (custody_receipt_record IS NULL OR
          (committed_bytes = protected_byte_count AND
           octet_length(custody_receipt_record) BETWEEN 1 AND 40960)))
    );

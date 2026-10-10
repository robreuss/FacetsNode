ALTER TABLE job_custody_admissions
    ADD COLUMN admission_permit_digest text NOT NULL
        CHECK (admission_permit_digest ~ '^[0-9a-f]{64}$'),
    ADD COLUMN custody_receipt_record bytea;

ALTER TABLE job_custody_admissions
    ADD CHECK (
        (state = 'staging' AND custody_receipt_record IS NULL) OR
        (state = 'retained' AND custody_receipt_record IS NOT NULL AND
         octet_length(custody_receipt_record) BETWEEN 1 AND 40960)
    );

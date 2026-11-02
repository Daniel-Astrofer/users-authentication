-- Epoch and optimistic locking share the credential rotation transaction.
-- Existing JWTs without an epoch remain valid only until the first recovery.
ALTER TABLE auth.users_credentials
    ADD COLUMN credential_epoch BIGINT NOT NULL DEFAULT 0 CHECK (credential_epoch >= 0),
    ADD COLUMN record_version BIGINT NOT NULL DEFAULT 0 CHECK (record_version >= 0);

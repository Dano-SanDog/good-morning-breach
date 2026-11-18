ALTER TABLE accounts
    ADD COLUMN totp_required boolean NOT NULL DEFAULT true;

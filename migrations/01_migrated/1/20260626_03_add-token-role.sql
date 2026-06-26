ALTER TABLE "01_vault"."11_fct_auth_tokens"
    ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'admin'
        CHECK (role IN ('admin','developer','reader'));

-- DOWN ==
ALTER TABLE "01_vault"."11_fct_auth_tokens" DROP COLUMN role;

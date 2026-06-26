-- UP: Add optional expiry timestamp to auth tokens
ALTER TABLE "01_vault"."11_fct_auth_tokens" ADD COLUMN expires_at TIMESTAMPTZ;

-- DOWN ==
ALTER TABLE "01_vault"."11_fct_auth_tokens" DROP COLUMN IF EXISTS expires_at;

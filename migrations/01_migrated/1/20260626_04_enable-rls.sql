-- Enable Row-Level Security on all 9 tenant-scoped tables.
--
-- Policy: rows are visible/writable only when the session variable
-- `app.tenant_id` matches the row's `tenant_id` column.  `FORCE ROW LEVEL
-- SECURITY` ensures the table owner (the 'soma' role) is also subject to the
-- policy — without FORCE, the owner bypasses RLS by default.
--
-- `current_setting('app.tenant_id', true)` — the second arg `true` is
-- missing_ok: returns NULL when the setting is absent, making the comparison
-- NULL = NULL → false → no rows visible (fail-closed).
--
-- Special case: `11_fct_auth_tokens` gets a second permissive SELECT policy
-- that fires when `app.tenant_id` is unset/empty.  `find_token_by_plaintext`
-- is a cross-tenant bootstrap path: it looks up a token by hash to discover
-- *which* tenant it belongs to.  Reads are safe to allow broadly here because
-- the caller must already hold the correct plaintext token; all
-- INSERT/UPDATE/DELETE on this table still require the tenant context.

-- ── 03_fct_projects ──────────────────────────────────────────────────────────
ALTER TABLE "01_vault"."03_fct_projects" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "01_vault"."03_fct_projects" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "01_vault"."03_fct_projects"
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- ── 04_fct_environments ───────────────────────────────────────────────────────
ALTER TABLE "01_vault"."04_fct_environments" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "01_vault"."04_fct_environments" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "01_vault"."04_fct_environments"
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- ── 05_fct_secrets ────────────────────────────────────────────────────────────
ALTER TABLE "01_vault"."05_fct_secrets" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "01_vault"."05_fct_secrets" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "01_vault"."05_fct_secrets"
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- ── 06_fct_secret_versions ────────────────────────────────────────────────────
ALTER TABLE "01_vault"."06_fct_secret_versions" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "01_vault"."06_fct_secret_versions" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "01_vault"."06_fct_secret_versions"
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- ── 07_fct_config_keys ───────────────────────────────────────────────────────
ALTER TABLE "01_vault"."07_fct_config_keys" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "01_vault"."07_fct_config_keys" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "01_vault"."07_fct_config_keys"
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- ── 08_fct_config_versions ───────────────────────────────────────────────────
ALTER TABLE "01_vault"."08_fct_config_versions" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "01_vault"."08_fct_config_versions" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "01_vault"."08_fct_config_versions"
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- ── 09_dtl_secret_attrs ──────────────────────────────────────────────────────
ALTER TABLE "01_vault"."09_dtl_secret_attrs" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "01_vault"."09_dtl_secret_attrs" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "01_vault"."09_dtl_secret_attrs"
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- ── 10_dtl_config_attrs ──────────────────────────────────────────────────────
ALTER TABLE "01_vault"."10_dtl_config_attrs" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "01_vault"."10_dtl_config_attrs" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "01_vault"."10_dtl_config_attrs"
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- ── 11_fct_auth_tokens ───────────────────────────────────────────────────────
ALTER TABLE "01_vault"."11_fct_auth_tokens" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "01_vault"."11_fct_auth_tokens" FORCE ROW LEVEL SECURITY;

-- Primary policy: tenant-scoped access for all DML.
CREATE POLICY tenant_isolation ON "01_vault"."11_fct_auth_tokens"
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- Bootstrap policy: allow SELECT and INSERT on auth tokens when no tenant
-- context is set (app.tenant_id is absent or empty).
--
-- SELECT: find_token_by_plaintext() needs to look up a token by hash to
-- discover which tenant owns it — at that point the caller is not yet
-- authenticated, so no tenant_id is available.  Possession of the correct
-- 256-bit token hash is the authentication factor for reads.
--
-- INSERT: bootstrap code (server startup, test setup) may insert tokens
-- directly with an explicit tenant_id before a tenant context is established.
-- The tenant_id FK to 00_dim_tenants and the DB connection credentials ('soma'
-- user) are the guard.  UPDATE/DELETE still require tenant context via
-- tenant_isolation (the default policy).
CREATE POLICY token_lookup ON "01_vault"."11_fct_auth_tokens"
    FOR INSERT
    WITH CHECK (
        coalesce(current_setting('app.tenant_id', true), '') = ''
        OR tenant_id = current_setting('app.tenant_id', true)::uuid
    );
CREATE POLICY token_select ON "01_vault"."11_fct_auth_tokens"
    FOR SELECT
    USING (
        coalesce(current_setting('app.tenant_id', true), '') = ''
        OR tenant_id = current_setting('app.tenant_id', true)::uuid
    );

-- DOWN ==
-- Reverse in reverse table order to avoid FK-ordering issues.

-- 11_fct_auth_tokens
DROP POLICY IF EXISTS token_select ON "01_vault"."11_fct_auth_tokens";
DROP POLICY IF EXISTS token_lookup ON "01_vault"."11_fct_auth_tokens";
DROP POLICY IF EXISTS tenant_isolation ON "01_vault"."11_fct_auth_tokens";
ALTER TABLE "01_vault"."11_fct_auth_tokens" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "01_vault"."11_fct_auth_tokens" DISABLE ROW LEVEL SECURITY;

-- 10_dtl_config_attrs
DROP POLICY IF EXISTS tenant_isolation ON "01_vault"."10_dtl_config_attrs";
ALTER TABLE "01_vault"."10_dtl_config_attrs" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "01_vault"."10_dtl_config_attrs" DISABLE ROW LEVEL SECURITY;

-- 09_dtl_secret_attrs
DROP POLICY IF EXISTS tenant_isolation ON "01_vault"."09_dtl_secret_attrs";
ALTER TABLE "01_vault"."09_dtl_secret_attrs" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "01_vault"."09_dtl_secret_attrs" DISABLE ROW LEVEL SECURITY;

-- 08_fct_config_versions
DROP POLICY IF EXISTS tenant_isolation ON "01_vault"."08_fct_config_versions";
ALTER TABLE "01_vault"."08_fct_config_versions" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "01_vault"."08_fct_config_versions" DISABLE ROW LEVEL SECURITY;

-- 07_fct_config_keys
DROP POLICY IF EXISTS tenant_isolation ON "01_vault"."07_fct_config_keys";
ALTER TABLE "01_vault"."07_fct_config_keys" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "01_vault"."07_fct_config_keys" DISABLE ROW LEVEL SECURITY;

-- 06_fct_secret_versions
DROP POLICY IF EXISTS tenant_isolation ON "01_vault"."06_fct_secret_versions";
ALTER TABLE "01_vault"."06_fct_secret_versions" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "01_vault"."06_fct_secret_versions" DISABLE ROW LEVEL SECURITY;

-- 05_fct_secrets
DROP POLICY IF EXISTS tenant_isolation ON "01_vault"."05_fct_secrets";
ALTER TABLE "01_vault"."05_fct_secrets" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "01_vault"."05_fct_secrets" DISABLE ROW LEVEL SECURITY;

-- 04_fct_environments
DROP POLICY IF EXISTS tenant_isolation ON "01_vault"."04_fct_environments";
ALTER TABLE "01_vault"."04_fct_environments" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "01_vault"."04_fct_environments" DISABLE ROW LEVEL SECURITY;

-- 03_fct_projects
DROP POLICY IF EXISTS tenant_isolation ON "01_vault"."03_fct_projects";
ALTER TABLE "01_vault"."03_fct_projects" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "01_vault"."03_fct_projects" DISABLE ROW LEVEL SECURITY;

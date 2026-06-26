# Data Model, Multi-tenancy & soma-iam Integration

soma-vault stores all mutable state in a single PostgreSQL database. This document is the authoritative Phase 1 data model reference: every table, column, constraint, index, role grant, and enforcement rule. It covers multi-tenant isolation, envelope encryption layout, the secrets-vs-config separation, RBAC, audit, KMS state, and the exact contract soma-vault requires from soma-iam. Implement this before writing any Rust.

---

## 1. Design Principles

### Tenancy strategy

**Shared schema, dual-layer enforcement.** Every table carries `tenant_id UUID NOT NULL` as a denormalized leading column. Isolation is enforced by two independent layers that must both be correct for a breach to occur.

**Layer 1 (primary) — application layer.** The Rust `TenantId(Uuid)` newtype is a required parameter on every repository function. Every SQL query includes `WHERE tenant_id = $1` supplied from the authenticated request context injected by the axum middleware tower. A query that compiles without a `TenantId` argument cannot reach the database. All repository functions additionally accept `&mut Transaction<'_, Postgres>` (not `&PgPool`) so that `SET LOCAL app.tenant_id = $1` fires inside an explicit transaction — see §1.1.

**Layer 2 (defense-in-depth) — Postgres RLS.** `FORCE ROW LEVEL SECURITY` is set on every table. The policy evaluates `tenant_id = current_setting('app.tenant_id', true)::uuid`. The setting is written as a transaction-scoped variable (`SET LOCAL app.tenant_id = $1`) as the first statement of every explicit transaction. This is safe with PgBouncer transaction-pooling mode because the setting resets at transaction end.

The `soma_vault_app` role is **not** the table owner — DDL is owned by `soma_vault_admin`. All views use `SECURITY INVOKER = true` (Postgres 15+).

**Why not RLS-only.** Connection-pool recycling can leak session-scoped variables; the application layer is always the primary gate.

**Why not schema-per-tenant.** O(N) migration complexity.

**Why not database-per-tenant.** Contradicts the single-binary self-host requirement.

### 1.1 Transaction wrapper type enforcement

Every repository function signature uses a `TenantTransaction<'_>` newtype:

```rust
// TenantTransaction wraps sqlx::Transaction and enforces SET LOCAL was called.
pub struct TenantTransaction<'c>(sqlx::Transaction<'c, sqlx::Postgres>);

impl<'c> TenantTransaction<'c> {
    pub async fn begin(pool: &PgPool, tid: TenantId) -> Result<Self> {
        let mut tx = pool.begin().await?;
        sqlx::query("SET LOCAL app.tenant_id = $1")
            .bind(tid.0)
            .execute(&mut *tx)
            .await?;
        Ok(Self(tx))
    }
}
```

A handler that calls any repository function without going through `TenantTransaction::begin` does not compile. This also ensures the RLS `SET LOCAL` always fires inside an explicit transaction, eliminating the autocommit footgun.

### Naming conventions

- `snake_case` everywhere.
- All primary keys are `UUID` generated at the application layer (`uuid::Uuid::new_v4()`).
- Every table has `created_at TIMESTAMPTZ NOT NULL DEFAULT now()` and, where rows are mutable, `updated_at TIMESTAMPTZ NOT NULL DEFAULT now()`.
- Unique constraints always include `tenant_id` as the leading column to prevent cross-tenant existence leaks via duplicate-key errors.
- Foreign keys always reference rows within the same tenant.

### Postgres roles

```sql
-- DDL owner (runs migrations, never used by the application)
CREATE ROLE soma_vault_admin;

-- Runtime application role (every connection in the sqlx pool)
CREATE ROLE soma_vault_app;

-- Read-only role for audit exports and compliance queries
CREATE ROLE soma_vault_audit_reader;
```

`soma_vault_app` is explicitly not the table owner. This is required for `FORCE ROW LEVEL SECURITY` to apply — table owners bypass RLS by default.

---

## 2. Hierarchy: Tenants → Workspaces → Projects → Environments

```sql
-- ============================================================
-- TENANTS
-- Maps 1:1 to a soma-iam org. tenant_id IS the soma-iam org_id UUID.
-- soma-vault does not own user identity; this is an opaque reference.
-- New rows are created by the POST /v1/admin/tenants endpoint (§11.1).
-- ============================================================
CREATE TABLE tenants (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    soma_iam_org_id  UUID        NOT NULL UNIQUE,
    display_name     TEXT        NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON COLUMN tenants.soma_iam_org_id IS
  'Opaque soma-iam org UUID. soma-vault does not own org identity.
   Inserted by POST /v1/admin/tenants on soma-iam org.created webhook.';

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenants
    USING (id = current_setting('app.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE ON tenants TO soma_vault_app;
-- No DELETE: tenant deletion is a soma_vault_admin DDL operation only.


-- ============================================================
-- WORKSPACES
-- ============================================================
CREATE TABLE workspaces (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL REFERENCES tenants(id),
    name        TEXT        NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_workspace_name UNIQUE (tenant_id, name)
);

CREATE INDEX idx_workspaces_tenant ON workspaces (tenant_id);

ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspaces FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON workspaces
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON workspaces TO soma_vault_app;


-- ============================================================
-- PROJECTS
-- ============================================================
CREATE TABLE projects (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID        NOT NULL REFERENCES tenants(id),
    workspace_id UUID        NOT NULL REFERENCES workspaces(id),
    name         TEXT        NOT NULL,
    description  TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_project_name UNIQUE (tenant_id, workspace_id, name)
);

CREATE INDEX idx_projects_workspace ON projects (tenant_id, workspace_id);

ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON projects
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON projects TO soma_vault_app;


-- ============================================================
-- ENVIRONMENTS
-- inherits_from: optional parent in the same project (config only).
-- Depth cap of 3 enforced at application write time.
-- Self-reference prevented by DB constraint.
-- Cycle detection required at application write time (see §2.1).
-- Secrets are NEVER inherited; only config values walk this chain.
-- ============================================================
CREATE TABLE environments (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL REFERENCES tenants(id),
    project_id    UUID        NOT NULL REFERENCES projects(id),
    name          TEXT        NOT NULL,
    description   TEXT,
    inherits_from UUID        REFERENCES environments(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_env_name UNIQUE (tenant_id, project_id, name),
    CONSTRAINT chk_no_self_inherit CHECK (inherits_from IS DISTINCT FROM id)
);

COMMENT ON COLUMN environments.inherits_from IS
  'Optional parent environment in the same project. Depth capped at 3 and
   cycle-free — enforced at write time by the application layer.
   Config resolution walks this chain; child values override parent.
   Secrets are always environment-specific and are never inherited.';

CREATE INDEX idx_environments_project ON environments (tenant_id, project_id);

ALTER TABLE environments ENABLE ROW LEVEL SECURITY;
ALTER TABLE environments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON environments
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON environments TO soma_vault_app;
```

### 2.1 Inheritance cycle detection (application layer)

Before writing any `inherits_from` update, the handler walks the chain upward (up to four steps) and rejects with `400 Cycle Detected` if the new environment ID appears. This is O(depth) and costs nothing at depth ≤ 3. The DB `chk_no_self_inherit` constraint is a backstop for direct self-reference only; the application check is the primary guard for indirect cycles.

Config resolution also tracks visited IDs in a `HashSet` and returns an error rather than looping, providing a second termination guarantee against any cycle that bypasses write-time detection.

---

## 3. KMS Bootstrap Table

This table persists the KMS-wrapped master KEK. It is infrastructure-plane state (no `tenant_id`) owned entirely by `soma_vault_admin`. It holds exactly one row per deployment.

```sql
-- ============================================================
-- KMS DEPLOYMENT KEYS
-- One row per deployment. Stores the wrapped master KEK.
-- Pods SELECT this row on boot and call KMS Decrypt to load the
-- master KEK into pod RAM. Never holds plaintext key material.
-- ============================================================
CREATE TABLE kms_deployment_keys (
    id                  UUID              PRIMARY KEY DEFAULT gen_random_uuid(),
    deployment_id       TEXT              NOT NULL UNIQUE, -- e.g. Helm release name
    kms_provider        TEXT              NOT NULL,        -- 'aws_kms' | 'software_age'
    kms_key_id          TEXT              NOT NULL,        -- ARN or 'env_var'
    wrapped_master_kek  BYTEA             NOT NULL,        -- KMS Encrypt output
    kms_key_version     INT               NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ       NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ       NOT NULL DEFAULT now()
);

COMMENT ON TABLE kms_deployment_keys IS
  'Stores the KMS-wrapped master KEK. Plaintext never appears here.
   Bootstrap: on first boot, pod calls KMS Encrypt on OsRng 32 bytes,
   writes with INSERT ... ON CONFLICT (deployment_id) DO NOTHING,
   then re-SELECTs and Decrypts whatever was committed. All pods
   converge on the same master KEK even under simultaneous first-boot
   races. The soma init-kms CLI command wraps this into one step.';

-- App role needs SELECT (boot) and INSERT (first-boot race).
-- UPDATE is for re-encryption during KMS key rotation only.
GRANT SELECT, INSERT, UPDATE ON kms_deployment_keys TO soma_vault_app;
```

**Boot sequence:**

1. Pod generates 32 bytes via `OsRng`.
2. Calls `KMS Encrypt(plaintext_key_bytes)` → `wrapped_bytes`.
3. `INSERT INTO kms_deployment_keys (deployment_id, ..., wrapped_master_kek) VALUES (...) ON CONFLICT (deployment_id) DO NOTHING`.
4. `SELECT wrapped_master_kek FROM kms_deployment_keys WHERE deployment_id = $1`.
5. Calls `KMS Decrypt(wrapped_master_kek)` → master KEK into `Zeroizing<[u8; 32]>` in pod RAM.
6. Readiness probe gates on step 5 success.

Steps 3–4 guarantee all pods in a simultaneous first-boot race converge on a single canonical master KEK.

**Software-KMS fallback:** For self-hosters without a cloud KMS, the `kms_provider = 'software_age'` path reads `SOMA_MASTER_KEK_HEX` (32 bytes, hex-encoded) from a Kubernetes Secret environment variable. This degrades to "master KEK protected by Kubernetes etcd encryption at rest and RBAC" — documented explicitly in the health endpoint (`seal_backend: software_kms`, severity `WARNING`). This is equivalent to Infisical's `ENCRYPTION_KEY` model. Operators who require full tenet 3 guarantees must use cloud KMS.

---

## 4. RBAC Tables

Principal identity, org-level roles, and group memberships live in soma-iam and arrive as JWT claims. soma-vault owns only two things in the authorization space: path-capability policies (secret-store-specific) and short-lived session tokens. Workspace-level roles are NOT stored redundantly in soma-vault — they arrive as `workspace_roles` claims in the soma-iam JWT (see §11).

```sql
-- ============================================================
-- PATH-CAPABILITY POLICIES
-- Fine-grained overlay on top of workspace roles.
-- path_glob: * = suffix wildcard, + = single-segment wildcard.
-- 'deny' capability always wins. Evaluated via in-memory radix trie.
-- Cache invalidated per-tenant via Postgres LISTEN/NOTIFY
-- on INSERT/UPDATE/DELETE (same infrastructure as config SSE).
-- ============================================================
CREATE TABLE policies (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL REFERENCES tenants(id),
    workspace_id   UUID        NOT NULL REFERENCES workspaces(id),
    name           TEXT        NOT NULL,
    path_glob      TEXT        NOT NULL,
    capabilities   TEXT[]      NOT NULL,   -- {read, write, list, delete, deny}
    principal_id   UUID,                   -- NULL = applies to all principals in workspace
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_policy_name UNIQUE (tenant_id, workspace_id, name),
    CONSTRAINT chk_capabilities CHECK (
        capabilities <@ ARRAY['read','write','list','delete','deny']
    )
);

CREATE INDEX idx_policies_workspace ON policies (tenant_id, workspace_id);

ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON policies
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON policies TO soma_vault_app;


-- ============================================================
-- SESSION TOKENS
-- Short-lived soma-vault opaque Bearer tokens, issued after
-- validating a soma-iam JWT. Hot-path requests validate against
-- this table only — no soma-iam call per secret read.
--
-- token_hash: HMAC-SHA256(server_token_signing_key, raw_token)
-- where server_token_signing_key is derived from the master KEK:
--   HKDF-SHA256(master_kek, salt=b"soma-vault-session-hmac-v1", info=b"")
-- This ties session token verification to the master KEK. A Postgres
-- dump alone cannot verify token candidates without KMS access.
-- ============================================================
CREATE TABLE session_tokens (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL REFERENCES tenants(id),
    principal_id  UUID        NOT NULL,   -- opaque soma-iam sub UUID
    soma_iam_jti  UUID        NOT NULL UNIQUE, -- JWT ID from the soma-iam JWT
    token_hash    TEXT        NOT NULL UNIQUE, -- HMAC-SHA256(signing_key, raw_token)
    expires_at    TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON COLUMN session_tokens.soma_iam_jti IS
  'JWT ID from the soma-iam JWT used to create this session.
   Used for replay prevention: a second login with the same jti is rejected.
   Also provides a cross-platform correlation key for audit (§11.4).';
COMMENT ON COLUMN session_tokens.token_hash IS
  'HMAC-SHA256(server_token_signing_key, raw_token).
   The signing key is HKDF-derived from the master KEK on pod boot.
   A Postgres dump cannot brute-force tokens without KMS access.';

CREATE INDEX idx_session_tokens_lookup ON session_tokens
    (token_hash, tenant_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_session_tokens_expiry ON session_tokens (expires_at)
    WHERE revoked_at IS NULL;
CREATE INDEX idx_session_tokens_jti ON session_tokens (soma_iam_jti);

ALTER TABLE session_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON session_tokens
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE ON session_tokens TO soma_vault_app;


-- ============================================================
-- JTI REPLAY CACHE
-- Prevents soma-iam JWT replay attacks. Every jti presented at
-- /v1/auth/login is recorded here. A second login with the same
-- jti (for the same or different session) is rejected with 401.
-- Rows are pruned by the expiry sweeper once expires_at passes.
-- ============================================================
CREATE TABLE jti_replay_cache (
    jti        UUID        PRIMARY KEY,
    tenant_id  UUID        NOT NULL REFERENCES tenants(id),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_jti_expiry ON jti_replay_cache (expires_at);

-- No RLS: jti is per-tenant but the lookup is by jti before tenant context
-- is established. Application layer enforces tenant scoping after lookup.
GRANT SELECT, INSERT ON jti_replay_cache TO soma_vault_app;


-- ============================================================
-- UNIVERSAL AUTH CREDENTIALS
-- client_id + Argon2id-hashed client_secret for machine identity
-- local dev / CI fallback. Production workloads should use
-- soma-iam machine identity OIDC (projected SA token exchange).
-- ============================================================
CREATE TABLE universal_auth_credentials (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID        NOT NULL REFERENCES tenants(id),
    workspace_id       UUID        NOT NULL REFERENCES workspaces(id),
    client_id          UUID        NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    client_secret_hash TEXT        NOT NULL,   -- Argon2id hash
    description        TEXT,
    revoked_at         TIMESTAMPTZ,
    last_used_at       TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_uac_client ON universal_auth_credentials
    (client_id) WHERE revoked_at IS NULL;

ALTER TABLE universal_auth_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE universal_auth_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON universal_auth_credentials
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE ON universal_auth_credentials TO soma_vault_app;
```

---

## 5. Encrypted Secrets

These tables store only encrypted blobs. No typed-value columns exist here. The column layout structurally prevents secret plaintext from appearing in config responses.

### Envelope encryption layout

Each `secret_versions` row stores:

| Column | Contains |
|---|---|
| `ciphertext` | AEAD output (AES-256-GCM or ChaCha20Poly1305) of the plaintext secret value |
| `nonce` | 96-bit random nonce for the plaintext AEAD — one per encryption call |
| `wrapped_dek` | Per-version 32-byte DEK, wrapped under the tenant KEK using **RFC 3394 AES Key Wrap** (`aes-kw` crate) — nonceless by design |
| `aad_context` | SHA-256(`secret_id_bytes` \|\| `version_id_bytes`) — a diagnostic structural binding check stored alongside the ciphertext |
| `kms_key_version` | Which generation of the master KEK wrapped this DEK (enables key rotation tracking) |

The actual AEAD additional data (AAD) passed to AES-256-GCM at both encrypt and decrypt time is the raw concatenation `secret_id_bytes || version_id_bytes` — this is what provides cryptographic binding. The `aad_context` column stores `SHA-256(secret_id_bytes || version_id_bytes)` as a secondary diagnostic check: on every decrypt the handler recomputes `SHA-256(secret_id || version_id)` and compares against the stored value using `subtle::ConstantTimeEq` before proceeding. This is not the primary AEAD mechanism; the AEAD tag is. The comparison provides defense against data-layer row tampering.

**DEK wrapping:** The per-version DEK is wrapped and unwrapped using RFC 3394 AES Key Wrap (`aes-kw` crate, `Aes256KW`). AES-KW is nonceless by design and is the correct algorithm for key wrapping. AES-256-GCM is used only for encrypting plaintext secret values, not for wrapping keys. These are distinct operations and must not be conflated.

**Rollback always generates a fresh DEK.** When `POST /v1/secrets/{id}/rollback?to_version=N` re-encrypts the source version's plaintext as a new current version, it generates a new 32-byte DEK from `OsRng` and a new 96-bit nonce. It never copies `wrapped_dek` or `nonce` from the source version row. This guarantees each version has exactly one DEK encryption event.

**Tenant KEK derivation:** `tenant_kek = HKDF-SHA256(master_kek, salt=b"soma-vault-tenant-kek-v1", info=tenant_id_bytes)`. The tenant KEK is never stored in Postgres. A Postgres dump is cryptographically useless without KMS access.

**Key hierarchy:**

```
Layer 0: External KMS key (lives in cloud HSM, never exported)
Layer 1: Master KEK (Zeroizing<[u8;32]> in pod RAM, loaded from KMS on boot)
Layer 2: Per-tenant KEK (HKDF-SHA256 derivation in pod RAM, 5-min TTL cache)
Layer 3: Per-secret-version DEK (32-byte OsRng, in-memory only during encrypt/decrypt)
```

One KMS call on boot yields all tenant KEKs via CPU-only HKDF. Zero additional KMS calls per request.

**Tenant KEK cache memory hygiene.** The cache is `Arc<RwLock<LruCache<TenantId, Box<Zeroizing<[u8; 32]>>>>>`. `Box` pins the key material at a stable heap address, preventing copies on LRU reallocation. `ZeroizeOnDrop` zeroes the fixed address on eviction. This mitigates (but cannot eliminate) the kernel-level unzeroed-memory concern; the `ponytail:` comment at the cache definition names this ceiling and the upgrade path (mlock + mlockall for sensitive memory pages).

```sql
-- ============================================================
-- SECRETS (metadata, no ciphertext)
-- ============================================================
CREATE TABLE secrets (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id),
    environment_id  UUID        NOT NULL REFERENCES environments(id),
    path            TEXT        NOT NULL,
    current_version INT         NOT NULL DEFAULT 0,
    max_versions    SMALLINT    NOT NULL DEFAULT 20 CHECK (max_versions > 0),
    cas_required    BOOLEAN     NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_secret_path UNIQUE (tenant_id, environment_id, path)
);

CREATE INDEX idx_secrets_env ON secrets (tenant_id, environment_id);

ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE secrets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON secrets
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE ON secrets TO soma_vault_app;


-- ============================================================
-- SECRET VERSIONS (envelope-encrypted ciphertext)
-- ============================================================
CREATE TABLE secret_versions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id       UUID        NOT NULL REFERENCES secrets(id),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id),
    version         INT         NOT NULL CHECK (version > 0),
    ciphertext      BYTEA       NOT NULL,   -- AES-256-GCM AEAD ciphertext
    nonce           BYTEA       NOT NULL,   -- 96-bit random nonce for AEAD
    wrapped_dek     BYTEA       NOT NULL,   -- RFC 3394 AES-KW output under tenant KEK
    aad_context     BYTEA       NOT NULL,   -- SHA-256(secret_id || version_id); diagnostic only
    kms_key_version INT         NOT NULL DEFAULT 1,
    is_deleted      BOOLEAN     NOT NULL DEFAULT false,
    deleted_at      TIMESTAMPTZ,
    is_destroyed    BOOLEAN     NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by_id   UUID        NOT NULL,   -- opaque soma-iam principal UUID

    CONSTRAINT uq_secret_version UNIQUE (secret_id, version),
    CONSTRAINT chk_destroyed_implies_deleted
        CHECK (NOT is_destroyed OR is_deleted)
);

COMMENT ON COLUMN secret_versions.wrapped_dek IS
  'Per-version DEK wrapped by RFC 3394 AES Key Wrap (aes-kw crate, Aes256KW).
   Set to zero bytes on destroy (is_destroyed=true). Never NULL.
   DO NOT use AES-GCM for key wrapping — AES-KW is nonceless by design
   and is the correct algorithm here.';
COMMENT ON COLUMN secret_versions.nonce IS
  '96-bit random nonce for AES-256-GCM encryption of the plaintext secret.
   Unrelated to DEK wrapping (RFC 3394 AES-KW is nonceless).';
COMMENT ON COLUMN secret_versions.aad_context IS
  'SHA-256(secret_id_bytes || version_id_bytes). Secondary diagnostic check.
   The primary cryptographic binding is the AEAD tag (secret_id || version_id
   passed as raw AAD to AES-256-GCM at encrypt/decrypt time).
   Verified at decrypt via subtle::ConstantTimeEq before proceeding.';
COMMENT ON COLUMN secret_versions.ciphertext IS
  'Set to zero bytes on destroy (is_destroyed=true). Never NULL.';

CREATE INDEX idx_sv_secret_version ON secret_versions
    (tenant_id, secret_id, version DESC);
CREATE INDEX idx_sv_current ON secret_versions
    (tenant_id, secret_id) WHERE NOT is_deleted AND NOT is_destroyed;

ALTER TABLE secret_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON secret_versions
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE ON secret_versions TO soma_vault_app;
```

---

## 6. Typed Config

Config values are typed, plaintext, indexable, and safe to log (when `is_sensitive = false`). The column layout contains **no** `ciphertext` or `wrapped_dek` columns — structural proof that config and secrets are separate tiers. The schema makes conflation architecturally impossible, not just policy-forbidden.

A config key with `value_type = 'secret_ref'` stores a UUID pointing to a row in `secrets`. The secret's plaintext is never stored in the config tables; it is resolved at API call time with a separate auth check and audit log entry.

`secret_ref` config keys reference secrets within the **same environment**. Cross-environment refs are not permitted: the application validates `secret.environment_id = config_key.environment_id` at write time, and the DB foreign key enforces referential integrity within the tenant. This eliminates cross-environment privilege escalation via `secret_ref`.

### Value type enum

```sql
CREATE TYPE config_value_type AS ENUM (
    'string',
    'int',
    'float',
    'bool',
    'json',
    'secret_ref'
);
```

### Config tables

```sql
-- ============================================================
-- CONFIG KEYS
-- ============================================================
CREATE TABLE config_keys (
    id              UUID                PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID                NOT NULL REFERENCES tenants(id),
    environment_id  UUID                NOT NULL REFERENCES environments(id),
    path            TEXT                NOT NULL,
    value_type      config_value_type   NOT NULL,
    schema_json     JSONB,              -- JSON Schema Draft 2020-12; only for json type
    is_sensitive    BOOLEAN             NOT NULL DEFAULT false,
    current_version INT                 NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ         NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ         NOT NULL DEFAULT now(),

    CONSTRAINT uq_config_path UNIQUE (tenant_id, environment_id, path),
    CONSTRAINT chk_schema_only_for_json
        CHECK (schema_json IS NULL OR value_type = 'json')
);

COMMENT ON COLUMN config_keys.is_sensitive IS
  'If true, the config value is redacted in audit log entries but the access
   event is still recorded. Secret plaintext never appears here regardless.';
COMMENT ON COLUMN config_keys.schema_json IS
  'JSON Schema Draft 2020-12. Validated at write time via the jsonschema crate
   (build-once, validate-many). Applicable only when value_type = ''json''.';

CREATE INDEX idx_ck_env ON config_keys (tenant_id, environment_id);

ALTER TABLE config_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE config_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON config_keys
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE ON config_keys TO soma_vault_app;


-- ============================================================
-- CONFIG VERSIONS
-- Typed values stored as plaintext. secret_ref stores only a UUID.
-- Exactly one value column is non-null (DB constraint + app layer).
-- ============================================================
CREATE TABLE config_versions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    config_key_id   UUID        NOT NULL REFERENCES config_keys(id),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id),
    version         INT         NOT NULL CHECK (version > 0),
    string_value    TEXT,
    int_value       BIGINT,
    float_value     DOUBLE PRECISION,
    bool_value      BOOLEAN,
    json_value      JSONB,
    secret_ref      UUID        REFERENCES secrets(id),
    is_deleted      BOOLEAN     NOT NULL DEFAULT false,
    deleted_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by_id   UUID        NOT NULL,

    CONSTRAINT uq_config_version UNIQUE (config_key_id, version),
    CONSTRAINT chk_single_value CHECK (
        (string_value IS NOT NULL)::int +
        (int_value    IS NOT NULL)::int +
        (float_value  IS NOT NULL)::int +
        (bool_value   IS NOT NULL)::int +
        (json_value   IS NOT NULL)::int +
        (secret_ref   IS NOT NULL)::int = 1
    )
);

COMMENT ON COLUMN config_versions.secret_ref IS
  'value_type=secret_ref: UUID of the referenced secret in the SAME environment.
   Resolved plaintext NEVER appears in this table. The API resolves the secret
   separately with its own auth check and audit log entry.
   Cross-environment refs are rejected at the application write layer.';

CREATE INDEX idx_cv_key_version ON config_versions
    (tenant_id, config_key_id, version DESC);
CREATE INDEX idx_cv_current ON config_versions
    (tenant_id, config_key_id) WHERE NOT is_deleted;

ALTER TABLE config_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE config_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON config_versions
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE ON config_versions TO soma_vault_app;
```

### Config resolution (environment inheritance)

At read time, the application walks the `environments.inherits_from` chain (depth cap 3, cycle detection via visited-ID `HashSet`) and merges: child values override parent. No JOIN magic — the handler fetches the ancestor chain explicitly and resolves in application code. Depth enforcement at write time prevents chains of length > 3 from being created.

### SSE cross-pod fan-out

After every committed `config_versions` INSERT or UPDATE, the handler sends:

```sql
NOTIFY config_changes, '<json_payload>';
```

Payload format:

```json
{
  "tenant_id": "<uuid>",
  "project_id": "<uuid>",
  "env_id": "<uuid>",
  "path": "server/port",
  "event_id": 42
}
```

The payload contains **only routing keys** — no config value, even for non-sensitive config. Receiving pods look up the current value from Postgres after receiving the notification. This eliminates the 8000-byte Postgres NOTIFY limit risk and ensures `is_sensitive` config values never appear in the WAL's NOTIFY payloads.

For `secret_ref` config keys, the payload omits the secret UUID entirely. The SSE client receives only the path and event ID, then fetches the current config key metadata (which returns `value_type: secret_ref`) via the REST API. The resolved plaintext requires a separate `secrets.get()` call with its own auth check.

Each pod maintains one dedicated non-pooled Postgres `LISTEN` connection for `config_changes`. This connection must have TCP keepalive configured (see §10 on advisory lock connections). If the LISTEN connection drops silently, the relay task detects the failure via a periodic `SELECT 1` heartbeat, reconnects with exponential backoff, and sends a synthetic `stream_interrupted` SSE event to all subscribers so they fall back to the 60-second polling path during the reconnect window.

Policy cache invalidation follows the same pattern: any `INSERT/UPDATE/DELETE` on `policies` sends `NOTIFY policy_changes, '{"tenant_id":"...", "workspace_id":"..."}'`, causing receiving pods to clear their in-memory radix trie for that tenant.

---

## 7. Rotation Infrastructure

```sql
CREATE TYPE rotation_status AS ENUM (
    'pending',
    'in_progress',
    'succeeded',
    'failed',
    'irrevocable'
);

CREATE TYPE rotation_stage AS ENUM (
    'create',
    'set',
    'test',
    'finish'
);

CREATE TABLE rotation_jobs (
    id               UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID            NOT NULL REFERENCES tenants(id),
    secret_id        UUID            NOT NULL REFERENCES secrets(id),
    status           rotation_status NOT NULL DEFAULT 'pending',
    stage            rotation_stage,
    rotation_version UUID            NOT NULL DEFAULT gen_random_uuid(),
    error            TEXT,
    next_attempt_at  TIMESTAMPTZ     NOT NULL DEFAULT now(),
    started_at       TIMESTAMPTZ,
    completed_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ     NOT NULL DEFAULT now()
);

COMMENT ON COLUMN rotation_jobs.rotation_version IS
  'Idempotency key. Workers re-enter any stage safely by checking whether
   the secret_version for this rotation_version already exists.';

-- Double-rotation guard: at most one active job per secret.
-- Partial index is the correct implementation — UNIQUE (secret_id, status)
-- would allow one pending AND one in_progress row simultaneously.
CREATE UNIQUE INDEX uq_rotation_active ON rotation_jobs (secret_id)
    WHERE status IN ('pending', 'in_progress');

CREATE INDEX idx_rj_pending ON rotation_jobs
    (tenant_id, next_attempt_at, status)
    WHERE status IN ('pending', 'failed');

ALTER TABLE rotation_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE rotation_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON rotation_jobs
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE ON rotation_jobs TO soma_vault_app;


CREATE TABLE rotation_schedules (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL REFERENCES tenants(id),
    secret_id   UUID        NOT NULL REFERENCES secrets(id) UNIQUE,
    cron_expr   TEXT        NOT NULL,
    next_run_at TIMESTAMPTZ NOT NULL,
    last_run_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE rotation_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE rotation_schedules FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON rotation_schedules
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE ON rotation_schedules TO soma_vault_app;
```

Workers claim jobs via:

```sql
SELECT * FROM rotation_jobs
WHERE status IN ('pending', 'failed')
  AND next_attempt_at <= now()
FOR UPDATE SKIP LOCKED
LIMIT 10;
```

The partial unique index `uq_rotation_active` is the database-level double-rotation guard. The `SKIP LOCKED` pattern prevents two workers from claiming the same job.

---

## 8. Audit Log

The audit table is **append-only**. `soma_vault_app` has `INSERT + SELECT` only; no `UPDATE` or `DELETE` is ever granted. The `entry_hash` HMAC chain provides tamper evidence.

### HMAC key source

The audit HMAC key is derived from a **separate root**, not from the master KEK. Using the master KEK as the sole root would mean a single KEK compromise simultaneously breaks secret confidentiality and audit integrity. Instead:

- **Encryption key hierarchy root:** `master_kek` (loaded from KMS on boot)
- **Audit HMAC key root:** A second KMS-wrapped key, stored in `kms_deployment_keys` as a second row with `kms_provider` suffix `_audit` — or wrapped in the same KMS call via `GenerateDataKey` with a distinct key spec and stored in a `wrapped_audit_hmac_root` column on the same row.

Per-tenant audit HMAC key: `HKDF-SHA256(audit_hmac_root, salt=b"soma-vault-audit-hmac-v1", info=tenant_id_bytes)`.

This key is never stored in Postgres. A DBA who modifies the table cannot forge valid hashes without KMS access for the audit key. A master KEK compromise does not invalidate audit integrity guarantees.

### Chaining algorithm

```
entry_hash = HMAC-SHA256(
    audit_hmac_key,
    "<schema_version>|<seq_num>|<tenant_id>|<event_type>|<actor_id>|
     <resource_id>|<outcome>|<created_at_unix_ms>|<prev_entry_hash>"
)
```

Genesis entry: `prev_entry_hash = "0" * 64`.

`seq_num` is assigned via `pg_advisory_xact_lock(hashtext('audit:' || tenant_id::text))` plus a `BIGSERIAL` Postgres sequence per tenant. The advisory lock serializes appends; the sequence guarantees monotonic assignment without relying on `MAX + 1` logic. A sequence increment is never rolled back even on transaction abort, but seq_num gaps from dropped best-effort read events are distinguishable from tampered entries by the presence of a `chain_epoch` column that increments on KMS key rotation.

### Audit correctness tiers

Secret creates, updates, deletes, rotates, and destroys write audit entries **synchronously within the same transaction** — these are guaranteed.

Secret reads write audit entries via a **bounded async channel** (capacity: 10,000 events). A filled channel emits a `CRITICAL` structured log entry but does not block the read path. The `seq_num` gap from a dropped read event is visible to `GET /v1/audit/verify` and produces a `WARN` response indicating a channel overflow rather than a `FAIL` indicating tampering — the `entry_hash` of the event following the gap references the last pre-gap hash, not a fabricated one.

KMS infrastructure events (`kms_unseal_success`, `kms_unseal_fail`, `kms_degraded_entry`, `kms_sealed`) are **not** stored in `audit_events`. They are pod-scoped infrastructure events that predate any tenant context. They belong in structured logs, Prometheus metrics, and the `/health/status` endpoint — not in the per-tenant tamper-evident chain.

```sql
-- Narrower audit_event_type set: app-data-layer events only.
-- KMS/infrastructure events are omitted; they belong in structured logs.
CREATE TYPE audit_event_type AS ENUM (
    'secret_read',
    'secret_create',
    'secret_update',
    'secret_delete',
    'secret_destroy',
    'secret_rollback',
    'secret_rotate_start',
    'secret_rotate_succeed',
    'secret_rotate_fail',
    'config_read',
    'config_create',
    'config_update',
    'config_delete',
    'policy_create',
    'policy_update',
    'policy_delete',
    'workspace_create',
    'workspace_delete',
    'project_create',
    'project_delete',
    'environment_create',
    'environment_delete',
    'service_account_create',
    'service_account_revoke',
    'session_token_issue',
    'session_token_revoke'
);

CREATE TYPE audit_actor_type    AS ENUM ('human', 'service_account', 'system');
CREATE TYPE audit_outcome       AS ENUM ('success', 'denied', 'error');
CREATE TYPE audit_resource_type AS ENUM (
    'secret', 'config', 'policy', 'workspace',
    'project', 'environment', 'service_account', 'session_token'
);

CREATE TABLE audit_events (
    id                  UUID                 PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID                 NOT NULL REFERENCES tenants(id),
    workspace_id        UUID,
    project_id          UUID,
    environment_id      UUID,
    seq_num             BIGINT               NOT NULL,
    chain_epoch         SMALLINT             NOT NULL DEFAULT 1,
    event_type          audit_event_type     NOT NULL,
    actor_type          audit_actor_type     NOT NULL,
    actor_id            UUID                 NOT NULL,
    soma_iam_jti        UUID,               -- JWT ID for cross-platform correlation
    actor_ip            INET,
    actor_user_agent    TEXT,
    resource_type       audit_resource_type  NOT NULL,
    resource_id         UUID                 NOT NULL,
    resource_name       TEXT,               -- SHA-256 of path; never plaintext
    outcome             audit_outcome        NOT NULL,
    reason              TEXT,               -- optional break-glass justification
    prev_entry_hash     TEXT                 NOT NULL,
    entry_hash          TEXT                 NOT NULL,
    hmac_schema_version SMALLINT             NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ          NOT NULL DEFAULT now(),

    CONSTRAINT uq_audit_seq UNIQUE (tenant_id, seq_num, chain_epoch)
);

COMMENT ON COLUMN audit_events.reason IS
  'Optional break-glass justification supplied by the caller.
   Absent from Vault, Infisical, and Doppler. NULL for routine access.';
COMMENT ON COLUMN audit_events.soma_iam_jti IS
  'JWT ID from the soma-iam token that initiated this session.
   Populated on session_token_issue events. Links soma-vault audit
   entries to soma-iam token issuance records for cross-platform correlation.';
COMMENT ON COLUMN audit_events.resource_name IS
  'SHA-256(resource_path) — safe to ship to SIEM without leaking secret names.';
COMMENT ON COLUMN audit_events.chain_epoch IS
  'Increments on KMS key rotation (audit HMAC root key change).
   Each epoch has its own genesis hash. The /v1/audit/verify endpoint
   walks epochs independently, so key rotation does not invalidate
   prior audit history.';
COMMENT ON TABLE audit_events IS
  'Secret values NEVER appear in any column of this table.
   App role: INSERT + SELECT only. No UPDATE. No DELETE. Ever.
   Superuser access bypasses RLS and must be treated as break-glass;
   envelope encryption (not RLS) is the cryptographic boundary against
   Postgres-level attackers — superusers see only ciphertext.';

CREATE INDEX idx_audit_tenant_time ON audit_events (tenant_id, created_at DESC);
CREATE INDEX idx_audit_tenant_seq  ON audit_events (tenant_id, chain_epoch, seq_num);
CREATE INDEX idx_audit_actor       ON audit_events (tenant_id, actor_id, created_at DESC);
CREATE INDEX idx_audit_resource    ON audit_events (tenant_id, resource_id, created_at DESC);

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_events
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- App role: INSERT + SELECT only. No UPDATE. No DELETE. Ever.
GRANT INSERT, SELECT ON audit_events TO soma_vault_app;
GRANT SELECT ON audit_events TO soma_vault_audit_reader;
```

---

## 9. Tables Not in Phase 1

The following are reserved for later phases. Namespace is set aside intentionally.

| Future table | Phase | Reason deferred |
|---|---|---|
| `certificate_authorities` | 2 | PKI engine |
| `dynamic_roles` / `leases` | 2 | Dynamic secrets |
| `transit_keys` | 2 | Transit EaaS |
| `audit_digests` | 2 | SOC 2 hourly signed digest export |
| `siem_stream_configs` | 2 | External SIEM streaming |
| `change_proposals` | 2 | Approval workflow |

---

## 10. Stateless Kubernetes Deployment and Singleton Workers

soma-vault runs as a Kubernetes `Deployment` (never `StatefulSet`). Zero `PersistentVolumeClaims`. No Raft. All mutable state in Postgres. HPA scales against CPU and RPS; any pod can serve any request.

### Advisory lock connections

Background singleton workers (rotation sweeper, expiry sweeper, audit flush) each acquire a Postgres **session-level** advisory lock on a **dedicated non-pooled connection** outside the sqlx pool. Dedicated connections prevent the zombie-lock bug from pool recycling.

**TCP keepalive is required on these dedicated connections.** An OOM-killed pod receives `SIGKILL`; the kernel does not immediately close the TCP connection. Without explicit keepalive, Postgres detects the dead session only after the OS-level default (7200 seconds on Linux). During this window, all other pods' `pg_try_advisory_lock` calls return `false`, stalling rotation and expiry workers for up to 2 hours.

All dedicated advisory lock connections must set:

```
keepalives=1 keepalives_idle=60 keepalives_interval=10 keepalives_count=3
```

Via the libpq connection string or `sqlx::ConnectOptions::tcp_keepalives`. This is required configuration, not optional — document it in the Helm chart's `DATABASE_URL` guidance.

Lock acquisition pattern:

```rust
// ponytail: ceiling ~50 pods polling DB simultaneously; Kubernetes Lease object
// is the upgrade path if lock poll becomes a measurable load contributor.
loop {
    if pg_try_advisory_lock(job_type_hash, &dedicated_conn).await? {
        run_work_loop().await;
        pg_advisory_unlock(job_type_hash, &dedicated_conn).await?;
    }
    tokio::time::sleep(Duration::from_secs(30)).await;
}
```

Pod crash → TCP close (detected within `keepalives_idle + keepalives_interval * keepalives_count` = 90 seconds) → automatic lock release → next pod acquires on next poll.

### Rolling deploy schema compatibility

Every Phase 1 migration is additive: new nullable columns or new tables only. No `DROP COLUMN`, no renames, no destructive changes.

Each migration must satisfy N-1 forward compatibility: old-pod code running against the new schema must not error or produce incorrect results. New columns must be nullable or have a constant default. New enum values are added before the code that uses them.

On pod startup, the application asserts that the count of applied migrations in `_sqlx_migrations` matches the compiled-in expected count. A mismatch fails the readiness probe immediately rather than allowing the pod to serve requests against an incompatible schema.

---

## 11. soma-iam Integration Boundary

### What soma-iam owns

| Data | Where it lives | How soma-vault sees it |
|---|---|---|
| User identity (email, name, MFA) | soma-iam | Never seen |
| Org-level RBAC (`org:admin`, `org:member`, `org:viewer`) | soma-iam | `org_role` claim in JWT |
| Workspace-level role bindings | soma-iam | `workspace_roles` claim in JWT |
| User sessions, password hashes, MFA tokens | soma-iam | Never seen |
| OIDC federation with CI providers | soma-iam | soma-iam exchanges; soma-vault sees only soma-iam JWT |
| Group memberships | soma-iam | `groups[]` claim in JWT (optional) |

Workspace role bindings (`ws_admin`, `ws_developer`, `ws_reader`) flow in the JWT — soma-vault does not store them redundantly. This ensures revocation in soma-iam propagates immediately on the next session token issuance, with no stale soma-vault role binding to purge.

### What soma-vault owns

| Data | Table |
|---|---|
| Path-capability policies | `policies` |
| Short-lived session tokens | `session_tokens` |
| JWT replay cache | `jti_replay_cache` |
| Universal Auth credentials | `universal_auth_credentials` |
| All secret/config/audit data | secrets / config / audit tables |

### 11.1 Tenant bootstrap

When a new soma-iam org is provisioned, soma-iam calls `POST /v1/internal/tenants` — an endpoint exposed only on the internal network interface (not through the public load balancer). The call carries a pre-shared HMAC-signed webhook secret. The handler performs an `INSERT ... ON CONFLICT (soma_iam_org_id) DO UPDATE SET display_name = EXCLUDED.display_name` (idempotent upsert). This is the **only** write path for tenant creation.

The `ADMIN_TOKEN` environment variable also gates a `POST /v1/admin/tenants` endpoint for CLI-driven bootstrap (`soma vault admin register-tenant --soma-iam-org-id <uuid> --name <name>`), usable during local development and Helm `post-install` hooks.

### Exact JWT contract soma-vault requires from soma-iam

```json
{
  "iss": "https://iam.soma-platform.com",
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "aud": ["soma-vault"],
  "iat": 1750000000,
  "exp": 1750000900,
  "jti": "unique-token-id-uuid",
  "tid": "org-uuid-here",
  "org_role": "member",
  "workspace_roles": [
    {"workspace_id": "ws-uuid-1", "role": "ws_developer"},
    {"workspace_id": "ws-uuid-2", "role": "ws_reader"}
  ],
  "groups": ["group-uuid-1"]
}
```

| Claim | Type | Required | Description |
|---|---|---|---|
| `iss` | string | yes | Must match `SOMA_IAM_ISSUER` config |
| `sub` | UUID string | yes | Principal UUID — opaque to soma-vault |
| `aud` | `["soma-vault"]` | yes | Must contain exactly `"soma-vault"` |
| `iat` / `exp` | unix timestamp | yes | Standard JWT lifetime |
| `jti` | UUID string | yes | Used for replay prevention and audit correlation |
| `tid` | UUID string | yes | Tenant (org) UUID. **Rejected without this claim.** |
| `org_role` | `"admin" \| "member" \| "viewer"` | yes | Coarse org-level role |
| `workspace_roles` | array of `{workspace_id, role}` | yes | Workspace-scoped role bindings |
| `groups` | UUID array | no | Group memberships for future policy templating |

**Required soma-iam endpoints:**

```
GET /.well-known/openid-configuration   → OIDC discovery (iss, jwks_uri)
GET /jwks                               → JSON Web Key Set (RS256 or ES256)
POST /introspect                        → Token introspection for high-privilege ops
```

soma-vault caches the JWKS in-process. On `kid` miss, exactly one re-fetch is in-flight per miss (singleflight pattern via `tokio::sync::OnceCell` per kid) — other concurrent miss-waiters block on the same future. Unknown `kid` values are negatively cached for 60 seconds. A circuit breaker stops re-fetching and rejects all unknown-kid tokens after N consecutive failed fetches.

### Authentication flow

```
1. Client → POST /v1/auth/login { soma_iam_jwt: "<JWT>" }

2. soma-vault:
   a. Decode JWT header, extract kid.
   b. Verify signature against JWKS cache (singleflight re-fetch on kid miss).
   c. Validate iss, aud==["soma-vault"], exp, iat.
   d. Check jti against jti_replay_cache; reject with 401 if found.
   e. Extract tid → look up tenants.soma_iam_org_id; reject if unknown.
   f. Extract sub (principal_id), org_role, workspace_roles, jti.
   g. org_role='admin' + no workspace_roles? Auto-provision ws_admin for all
      tenant workspaces. org_role='member'/'viewer'? workspace_roles claim
      governs; no auto-provisioning (explicit invitation required).
   h. Issue soma-vault session token (opaque 32-byte OsRng Bearer value).
   i. Compute token_hash = HMAC-SHA256(session_signing_key, raw_token).
   j. INSERT into session_tokens (token_hash, soma_iam_jti, expires_at=now()+15m).
   k. INSERT into jti_replay_cache (jti, expires_at=jwt.exp).
   l. Return raw_token to client (shown once, not stored).

3. Client → subsequent requests: Authorization: Bearer <soma-vault-session-token>

4. soma-vault hot path:
   a. Compute HMAC-SHA256(signing_key, raw_token); look up session_tokens by hash.
   b. Check expires_at, revoked_at.
   c. Load path-capability policies from in-memory radix trie (invalidated via LISTEN/NOTIFY).
   d. authz::check(tenant_id, principal_id, action, resource_path) → Ok/Err.
   e. Proceed to data layer.
   NO soma-iam call on this path.
```

### Authorization model

```
Layer 1 — Workspace role (from JWT workspace_roles claim):
  ws_admin     → all actions in the workspace
  ws_developer → read/write secrets and config; cannot manage policies or roles
  ws_reader    → read-only on secrets and config

Layer 2 — Path-capability overlay (policies table, in-memory radix trie):
  'deny' capability always wins, regardless of workspace role.
  No matching policy row → workspace role governs.
  Matching 'deny' policy → rejected, even for ws_admin.

Result: deny-by-default. No role binding + no policy match = Forbidden.
```

Rust type-state enforcement: handlers accept `Request<Authorized>` only. A handler that does not call `authz::check()` does not compile.

### Pod → KMS workload-identity plane

This plane authenticates **the pods themselves** to KMS for key unwrapping. It has zero intersection with the app-principal plane above. They share no code paths and no credentials.

```
Pod boot:
1. Kubernetes injects projected ServiceAccount OIDC JWT at
   /var/run/secrets/eks.amazonaws.com/serviceaccount/token  (IRSA)
2. Pod calls AWS STS AssumeRoleWithWebIdentity.
3. STS returns ephemeral credentials (no static credentials anywhere).
4. Pod calls KMS Decrypt on wrapped_master_kek from kms_deployment_keys.
5. Master KEK → Zeroizing<[u8;32]> in pod RAM. Never written to disk.
6. Readiness probe gates on step 4 success (60-second retry window with
   exponential backoff before the probe fails on boot).

KMS circuit-breaker (post-boot):
- Transient KMS error → pod extends tenant KEK cache TTL up to
  grace_period_minutes (default 30, max 240).
- Health endpoint returns HTTP 200 with degraded: true and
  active_alerts: [kms_unreachable]. Pod stays in Service Endpoints.
- Grace period expires → pod transitions to SEALED, stops serving.
- CRITICAL structured log emitted. Pod must be restarted to re-unseal.
```

---

## 12. Role Grants Summary

```sql
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;

-- soma_vault_app (runtime application role)
GRANT INSERT, SELECT                  ON audit_events                TO soma_vault_app;
GRANT SELECT, INSERT, UPDATE          ON session_tokens              TO soma_vault_app;
GRANT SELECT, INSERT                  ON jti_replay_cache            TO soma_vault_app;
GRANT SELECT, INSERT, UPDATE          ON universal_auth_credentials  TO soma_vault_app;
GRANT SELECT, INSERT, UPDATE          ON secrets                     TO soma_vault_app;
GRANT SELECT, INSERT, UPDATE          ON secret_versions             TO soma_vault_app;
GRANT SELECT, INSERT, UPDATE          ON config_keys                 TO soma_vault_app;
GRANT SELECT, INSERT, UPDATE          ON config_versions             TO soma_vault_app;
GRANT SELECT, INSERT, UPDATE          ON rotation_jobs               TO soma_vault_app;
GRANT SELECT, INSERT, UPDATE          ON rotation_schedules          TO soma_vault_app;
GRANT SELECT, INSERT, UPDATE          ON kms_deployment_keys         TO soma_vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE  ON policies                    TO soma_vault_app;
GRANT SELECT, INSERT, UPDATE          ON tenants                     TO soma_vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE  ON workspaces                  TO soma_vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE  ON projects                    TO soma_vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE  ON environments                TO soma_vault_app;

-- soma_vault_audit_reader (compliance queries)
GRANT SELECT ON audit_events TO soma_vault_audit_reader;
```

`soma_vault_app` has no `DELETE` on `tenants`. Tenant deletion requires `soma_vault_admin` intervention with explicit CASCADE handling.

**Superuser note:** Postgres superusers (including the RDS master user or Cloud SQL admin user) bypass `FORCE ROW LEVEL SECURITY` regardless of this configuration. Superuser access must be treated as break-glass only. The cryptographic boundary against Postgres-level attackers is envelope encryption — a superuser sees only ciphertext without KMS access. RLS provides defense against application-layer mistakes, not against superusers.

---

## 13. Schema Enforcement Summary

| Rule | Enforcement |
|---|---|
| Every query scoped to `tenant_id` | Rust `TenantId(Uuid)` newtype required on every repo fn |
| RLS always within an explicit transaction | `TenantTransaction<'_>` newtype — compile-time enforced |
| Cross-tenant data access impossible | RLS on every table + application `WHERE tenant_id = $1` |
| Secret plaintext never in config tables | Column layout: `config_versions` has no `ciphertext`/`wrapped_dek` |
| Config values never in secret tables | Column layout: `secret_versions` has no typed-value columns |
| Secret plaintext never in audit log | Audit column set: no value column; only `resource_id` |
| Audit rows unmodifiable | `soma_vault_app`: `INSERT + SELECT` only on `audit_events` |
| DEK wrapped with RFC 3394 AES-KW | `wrapped_dek` comment; `aes-kw` crate is the only wrap implementation |
| AAD fingerprint verified at decrypt | `subtle::ConstantTimeEq` check on `aad_context` before proceeding |
| Audit HMAC root separate from master KEK | Second KMS-wrapped key; master KEK compromise does not break audit |
| Session tokens HMAC-protected | `token_hash = HMAC-SHA256(session_signing_key, raw_token)` |
| JWT replay prevention | `jti_replay_cache` table; duplicate `jti` rejected with 401 |
| Policy revocation propagates immediately | `NOTIFY policy_changes` on every write; pods clear trie cache |
| secret_ref within same environment only | Application validates `secret.environment_id = config_key.environment_id` |
| Inheritance cycle detection | Application walks chain + visited-ID `HashSet`; 400 on cycle |
| Inheritance depth ≤ 3 | Application write-time check |
| Unique constraints always tenant-scoped | All `UNIQUE` constraints include `tenant_id` as leading column |
| RLS bypass prevention | `soma_vault_app` is not table owner; `FORCE ROW LEVEL SECURITY` |
| View RLS bypass prevention | All views use `SECURITY INVOKER = true` |
| Double-rotation guard | Partial unique index on `rotation_jobs (secret_id) WHERE status IN (...)` |
| Singleton worker liveness | TCP keepalive required on dedicated advisory lock connections |
| KMS events not in tenant audit | `kms_*` event types removed; belong in structured logs + Prometheus |
| workspace roles not stored locally | `workspace_roles` flows from soma-iam JWT; no `principal_workspace_roles` table |
| Tenant bootstrap single write path | `POST /v1/internal/tenants` webhook + upsert |

---

## 14. Migration Strategy

Migrations are embedded in the binary via `sqlx::migrate!()` and run on startup before the readiness probe passes. The migration runner connects as `soma_vault_admin`; the runtime pool connects as `soma_vault_app`.

All Phase 1 migrations are additive: no `DROP COLUMN`, no renames, no data-destructive changes. Each migration satisfies N-1 forward compatibility — old-pod code running against the new schema must not produce errors.

Migration files: `migrations/0001_init_roles.sql`, `0002_tenants.sql`, `0003_workspaces.sql`, etc., applied in order by sqlx's built-in runner.

On pod startup, a schema version assertion compares the count of applied migrations against the compiled-in expected count. Mismatch → readiness probe fails immediately.

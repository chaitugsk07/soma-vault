-- UP: Phase-1 vault schema — 11-table EAV star schema
-- Tables are created in FK-dependency order (dim first, then fct, then dtl).

-- 1. Entity type whitelist (dim, no FKs)
CREATE TABLE "01_vault"."01_dim_entity_types" (
    id          UUID         DEFAULT gen_random_uuid() NOT NULL,
    code        VARCHAR(50)  NOT NULL,
    name        VARCHAR(120) NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_01_dim_entity_types      PRIMARY KEY (id),
    CONSTRAINT uq_01_dim_entity_types_code UNIQUE      (code)
);

COMMENT ON TABLE  "01_vault"."01_dim_entity_types"             IS 'Whitelist of entity types for which EAV attribute definitions may be registered.';
COMMENT ON COLUMN "01_vault"."01_dim_entity_types".id          IS 'Surrogate primary key.';
COMMENT ON COLUMN "01_vault"."01_dim_entity_types".code        IS 'Stable machine code used as the FK target from 02_dim_attr_defs (e.g. ''secret'', ''config_key'').';
COMMENT ON COLUMN "01_vault"."01_dim_entity_types".name        IS 'Human-readable display name for the entity type.';
COMMENT ON COLUMN "01_vault"."01_dim_entity_types".description IS 'Optional longer description of the entity type.';
COMMENT ON COLUMN "01_vault"."01_dim_entity_types".created_at  IS 'Row creation timestamp (UTC).';
COMMENT ON COLUMN "01_vault"."01_dim_entity_types".updated_at  IS 'Row last-updated timestamp (UTC).';

-- 2. Attribute definition whitelist (dim, FK → 01_dim_entity_types.code)
CREATE TABLE "01_vault"."02_dim_attr_defs" (
    id          UUID         DEFAULT gen_random_uuid() NOT NULL,
    entity_type VARCHAR(50)  NOT NULL,
    code        VARCHAR(100) NOT NULL,
    name        VARCHAR(120) NOT NULL,
    data_type   VARCHAR(20)  NOT NULL,
    is_required BOOLEAN      NOT NULL DEFAULT false,
    is_pii      BOOLEAN      NOT NULL DEFAULT false,
    sort_order  INT          NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_02_dim_attr_defs                              PRIMARY KEY (id),
    CONSTRAINT uq_02_dim_attr_defs_entity_code                 UNIQUE      (entity_type, code),
    CONSTRAINT fk_02_dim_attr_defs_entity_type_01_dim_entity_types
        FOREIGN KEY (entity_type) REFERENCES "01_vault"."01_dim_entity_types" (code) ON DELETE RESTRICT,
    CONSTRAINT chk_02_dim_attr_defs_data_type
        CHECK (data_type IN ('text', 'int', 'float', 'bool', 'json'))
);

COMMENT ON TABLE  "01_vault"."02_dim_attr_defs"             IS 'Attribute definition whitelist per entity type. The (entity_type, code) pair is the composite-FK target for EAV detail tables.';
COMMENT ON COLUMN "01_vault"."02_dim_attr_defs".id          IS 'Surrogate primary key.';
COMMENT ON COLUMN "01_vault"."02_dim_attr_defs".entity_type IS 'FK to 01_dim_entity_types.code; partitions attribute definitions by entity type.';
COMMENT ON COLUMN "01_vault"."02_dim_attr_defs".code        IS 'Machine code for the attribute within its entity type (e.g. ''tags'', ''owner_team'').';
COMMENT ON COLUMN "01_vault"."02_dim_attr_defs".name        IS 'Human-readable display name for the attribute.';
COMMENT ON COLUMN "01_vault"."02_dim_attr_defs".data_type   IS 'Expected data type of the attribute value; one of text, int, float, bool, json.';
COMMENT ON COLUMN "01_vault"."02_dim_attr_defs".is_required IS 'Whether this attribute must be supplied when creating an entity of this type.';
COMMENT ON COLUMN "01_vault"."02_dim_attr_defs".is_pii      IS 'PII: indirect — marks attribute values that carry personally identifiable data.';
COMMENT ON COLUMN "01_vault"."02_dim_attr_defs".sort_order  IS 'Display ordering hint for UI; lower values appear first.';
COMMENT ON COLUMN "01_vault"."02_dim_attr_defs".created_at  IS 'Row creation timestamp (UTC).';
COMMENT ON COLUMN "01_vault"."02_dim_attr_defs".updated_at  IS 'Row last-updated timestamp (UTC).';

-- 3. Projects (fct, tenant-scoped)
CREATE TABLE "01_vault"."03_fct_projects" (
    id          UUID         DEFAULT gen_random_uuid() NOT NULL,
    tenant_key  VARCHAR(100) NOT NULL DEFAULT 'default',
    code        VARCHAR(100) NOT NULL,
    name        VARCHAR(255) NOT NULL,
    description TEXT,
    is_deleted  BOOLEAN      NOT NULL DEFAULT false,
    deleted_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_03_fct_projects             PRIMARY KEY (id),
    CONSTRAINT uq_03_fct_projects_tenant_code UNIQUE      (tenant_key, code),
    CONSTRAINT chk_03_fct_projects_deleted
        CHECK ((is_deleted = false AND deleted_at IS NULL) OR (is_deleted = true AND deleted_at IS NOT NULL))
);

COMMENT ON TABLE  "01_vault"."03_fct_projects"             IS 'Top-level project grouping scoped to a tenant. Projects contain environments.';
COMMENT ON COLUMN "01_vault"."03_fct_projects".id          IS 'Surrogate primary key.';
COMMENT ON COLUMN "01_vault"."03_fct_projects".tenant_key  IS 'Tenant identifier; every query must filter by this column.';
COMMENT ON COLUMN "01_vault"."03_fct_projects".code        IS 'Stable machine code for the project, unique within a tenant (used in URLs and API paths).';
COMMENT ON COLUMN "01_vault"."03_fct_projects".name        IS 'Human-readable project name.';
COMMENT ON COLUMN "01_vault"."03_fct_projects".description IS 'Optional description of the project.';
COMMENT ON COLUMN "01_vault"."03_fct_projects".is_deleted  IS 'Soft-delete flag; must be paired with deleted_at via chk_03_fct_projects_deleted.';
COMMENT ON COLUMN "01_vault"."03_fct_projects".deleted_at  IS 'Timestamp of soft deletion; NULL when is_deleted = false.';
COMMENT ON COLUMN "01_vault"."03_fct_projects".created_at  IS 'Row creation timestamp (UTC).';
COMMENT ON COLUMN "01_vault"."03_fct_projects".updated_at  IS 'Row last-updated timestamp (UTC).';

-- 4. Environments (fct, FK → projects)
CREATE TABLE "01_vault"."04_fct_environments" (
    id         UUID         DEFAULT gen_random_uuid() NOT NULL,
    tenant_key VARCHAR(100) NOT NULL DEFAULT 'default',
    project_id UUID         NOT NULL,
    code       VARCHAR(100) NOT NULL,
    name       VARCHAR(255) NOT NULL,
    is_deleted BOOLEAN      NOT NULL DEFAULT false,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_04_fct_environments                      PRIMARY KEY (id),
    CONSTRAINT uq_04_fct_environments_tenant_project_code  UNIQUE      (tenant_key, project_id, code),
    CONSTRAINT fk_04_fct_environments_project_id_03_fct_projects
        FOREIGN KEY (project_id) REFERENCES "01_vault"."03_fct_projects" (id) ON DELETE RESTRICT,
    CONSTRAINT chk_04_fct_environments_deleted
        CHECK ((is_deleted = false AND deleted_at IS NULL) OR (is_deleted = true AND deleted_at IS NOT NULL))
);

COMMENT ON TABLE  "01_vault"."04_fct_environments"            IS 'Environment within a project (e.g. production, staging, development).';
COMMENT ON COLUMN "01_vault"."04_fct_environments".id         IS 'Surrogate primary key.';
COMMENT ON COLUMN "01_vault"."04_fct_environments".tenant_key IS 'Tenant identifier; every query must filter by this column.';
COMMENT ON COLUMN "01_vault"."04_fct_environments".project_id IS 'FK to 03_fct_projects.id; the parent project.';
COMMENT ON COLUMN "01_vault"."04_fct_environments".code       IS 'Stable machine code for the environment, unique within a project (e.g. ''production'', ''staging'').';
COMMENT ON COLUMN "01_vault"."04_fct_environments".name       IS 'Human-readable environment name.';
COMMENT ON COLUMN "01_vault"."04_fct_environments".is_deleted IS 'Soft-delete flag; must be paired with deleted_at via chk_04_fct_environments_deleted.';
COMMENT ON COLUMN "01_vault"."04_fct_environments".deleted_at IS 'Timestamp of soft deletion; NULL when is_deleted = false.';
COMMENT ON COLUMN "01_vault"."04_fct_environments".created_at IS 'Row creation timestamp (UTC).';
COMMENT ON COLUMN "01_vault"."04_fct_environments".updated_at IS 'Row last-updated timestamp (UTC).';

CREATE INDEX ix_vault_04_fct_environments_project_id
    ON "01_vault"."04_fct_environments" USING btree (project_id);

-- 5. Secrets (fct, FK → environments)
CREATE TABLE "01_vault"."05_fct_secrets" (
    id              UUID         DEFAULT gen_random_uuid() NOT NULL,
    tenant_key      VARCHAR(100) NOT NULL DEFAULT 'default',
    environment_id  UUID         NOT NULL,
    path            VARCHAR(255) NOT NULL,
    current_version INT          NOT NULL DEFAULT 0,
    cas_required    BOOLEAN      NOT NULL DEFAULT false,
    max_versions    INT          NOT NULL DEFAULT 20,
    is_deleted      BOOLEAN      NOT NULL DEFAULT false,
    deleted_at      TIMESTAMPTZ,
    destroyed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_05_fct_secrets                      PRIMARY KEY (id),
    CONSTRAINT uq_05_fct_secrets_tenant_env_path      UNIQUE      (tenant_key, environment_id, path),
    CONSTRAINT fk_05_fct_secrets_environment_id_04_fct_environments
        FOREIGN KEY (environment_id) REFERENCES "01_vault"."04_fct_environments" (id) ON DELETE RESTRICT,
    CONSTRAINT chk_05_fct_secrets_max_versions
        CHECK (max_versions > 0),
    CONSTRAINT chk_05_fct_secrets_deleted
        CHECK ((is_deleted = false AND deleted_at IS NULL) OR (is_deleted = true AND deleted_at IS NOT NULL))
);

COMMENT ON TABLE  "01_vault"."05_fct_secrets"                 IS 'Secret entry per environment path. Versioned; crypto material lives in 06_fct_secret_versions.';
COMMENT ON COLUMN "01_vault"."05_fct_secrets".id              IS 'Surrogate primary key.';
COMMENT ON COLUMN "01_vault"."05_fct_secrets".tenant_key      IS 'Tenant identifier; every query must filter by this column.';
COMMENT ON COLUMN "01_vault"."05_fct_secrets".environment_id  IS 'FK to 04_fct_environments.id; the parent environment.';
COMMENT ON COLUMN "01_vault"."05_fct_secrets".path            IS 'Logical path of the secret within the environment (e.g. ''db/password'').';
COMMENT ON COLUMN "01_vault"."05_fct_secrets".current_version IS 'Latest active version number; 0 means no active version yet.';
COMMENT ON COLUMN "01_vault"."05_fct_secrets".cas_required    IS 'When true, writes must supply the expected current_version (check-and-set).';
COMMENT ON COLUMN "01_vault"."05_fct_secrets".max_versions    IS 'Maximum number of version rows to retain; older versions are pruned beyond this limit.';
COMMENT ON COLUMN "01_vault"."05_fct_secrets".is_deleted      IS 'Soft-delete flag; must be paired with deleted_at via chk_05_fct_secrets_deleted.';
COMMENT ON COLUMN "01_vault"."05_fct_secrets".deleted_at      IS 'Timestamp of soft deletion; NULL when is_deleted = false.';
COMMENT ON COLUMN "01_vault"."05_fct_secrets".destroyed_at    IS 'Timestamp of hard destroy (crypto-shred); NULL until explicitly destroyed.';
COMMENT ON COLUMN "01_vault"."05_fct_secrets".created_at      IS 'Row creation timestamp (UTC).';
COMMENT ON COLUMN "01_vault"."05_fct_secrets".updated_at      IS 'Row last-updated timestamp (UTC).';

CREATE INDEX ix_vault_05_fct_secrets_environment_id
    ON "01_vault"."05_fct_secrets" USING btree (environment_id);

-- 6. Secret versions — APPEND-ONLY (no updated_at), crypto ledger
CREATE TABLE "01_vault"."06_fct_secret_versions" (
    id            UUID         DEFAULT gen_random_uuid() NOT NULL,
    tenant_key    VARCHAR(100) NOT NULL DEFAULT 'default',
    secret_id     UUID         NOT NULL,
    version       INT          NOT NULL,
    ciphertext    BYTEA        NOT NULL,
    nonce         BYTEA        NOT NULL,
    wrapped_dek   BYTEA        NOT NULL,
    aad           BYTEA        NOT NULL,
    seal_provider VARCHAR(20)  NOT NULL DEFAULT 'software',
    seal_key_id   VARCHAR(255) NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_06_fct_secret_versions                     PRIMARY KEY (id),
    CONSTRAINT uq_06_fct_secret_versions_secret_version      UNIQUE      (secret_id, version),
    CONSTRAINT fk_06_fct_secret_versions_secret_id_05_fct_secrets
        FOREIGN KEY (secret_id) REFERENCES "01_vault"."05_fct_secrets" (id) ON DELETE RESTRICT,
    CONSTRAINT chk_06_fct_secret_versions_version
        CHECK (version > 0),
    CONSTRAINT chk_06_fct_secret_versions_nonce_len
        CHECK (octet_length(nonce) = 12),
    CONSTRAINT chk_06_fct_secret_versions_seal_provider
        CHECK (seal_provider IN ('software', 'aws_kms', 'gcp_kms', 'azure_kms'))
);

COMMENT ON TABLE  "01_vault"."06_fct_secret_versions"               IS 'Append-only crypto ledger for secret versions. Each row holds the AEAD ciphertext, nonce, wrapped DEK, and AAD. Never updated or deleted.';
COMMENT ON COLUMN "01_vault"."06_fct_secret_versions".id            IS 'Surrogate primary key.';
COMMENT ON COLUMN "01_vault"."06_fct_secret_versions".tenant_key    IS 'Tenant identifier; every query must filter by this column.';
COMMENT ON COLUMN "01_vault"."06_fct_secret_versions".secret_id     IS 'FK to 05_fct_secrets.id; the parent secret entry.';
COMMENT ON COLUMN "01_vault"."06_fct_secret_versions".version       IS 'Monotonically increasing version number; must be > 0.';
COMMENT ON COLUMN "01_vault"."06_fct_secret_versions".ciphertext    IS 'AEAD-encrypted secret ciphertext (ChaCha20-Poly1305 or AES-256-GCM). Crypto material — never log.';
COMMENT ON COLUMN "01_vault"."06_fct_secret_versions".nonce         IS 'AEAD nonce (12 bytes for GCM/ChaCha); uniqueness per DEK is caller-enforced. Crypto material — never log.';
COMMENT ON COLUMN "01_vault"."06_fct_secret_versions".wrapped_dek   IS 'Data encryption key (DEK) wrapped by the KMS or software seal. Crypto material — never log.';
COMMENT ON COLUMN "01_vault"."06_fct_secret_versions".aad           IS 'Additional authenticated data bound to this ciphertext; typically includes tenant_key, secret_id, version. Crypto material — never log.';
COMMENT ON COLUMN "01_vault"."06_fct_secret_versions".seal_provider IS 'KMS / seal provider used to wrap the DEK; one of software, aws_kms, gcp_kms, azure_kms.';
COMMENT ON COLUMN "01_vault"."06_fct_secret_versions".seal_key_id   IS 'Provider-specific key identifier used by the seal provider to unwrap the DEK.';
COMMENT ON COLUMN "01_vault"."06_fct_secret_versions".created_at    IS 'Row creation timestamp (UTC). Append-only; this column is never updated.';

CREATE INDEX ix_vault_06_fct_secret_versions_secret_id
    ON "01_vault"."06_fct_secret_versions" USING btree (secret_id);

-- 7. Config keys (fct, FK → environments)
CREATE TABLE "01_vault"."07_fct_config_keys" (
    id              UUID         DEFAULT gen_random_uuid() NOT NULL,
    tenant_key      VARCHAR(100) NOT NULL DEFAULT 'default',
    environment_id  UUID         NOT NULL,
    key             VARCHAR(255) NOT NULL,
    value_type      VARCHAR(20)  NOT NULL,
    current_version INT          NOT NULL DEFAULT 0,
    is_deleted      BOOLEAN      NOT NULL DEFAULT false,
    deleted_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_07_fct_config_keys                     PRIMARY KEY (id),
    CONSTRAINT uq_07_fct_config_keys_tenant_env_key      UNIQUE      (tenant_key, environment_id, key),
    CONSTRAINT fk_07_fct_config_keys_environment_id_04_fct_environments
        FOREIGN KEY (environment_id) REFERENCES "01_vault"."04_fct_environments" (id) ON DELETE RESTRICT,
    CONSTRAINT chk_07_fct_config_keys_value_type
        CHECK (value_type IN ('string', 'int', 'float', 'bool', 'json', 'secret_ref')),
    CONSTRAINT chk_07_fct_config_keys_deleted
        CHECK ((is_deleted = false AND deleted_at IS NULL) OR (is_deleted = true AND deleted_at IS NOT NULL))
);

COMMENT ON TABLE  "01_vault"."07_fct_config_keys"                IS 'Typed configuration key per environment. Versioned; actual values live in 08_fct_config_versions.';
COMMENT ON COLUMN "01_vault"."07_fct_config_keys".id             IS 'Surrogate primary key.';
COMMENT ON COLUMN "01_vault"."07_fct_config_keys".tenant_key     IS 'Tenant identifier; every query must filter by this column.';
COMMENT ON COLUMN "01_vault"."07_fct_config_keys".environment_id IS 'FK to 04_fct_environments.id; the parent environment.';
COMMENT ON COLUMN "01_vault"."07_fct_config_keys".key            IS 'Logical name of the config key within the environment.';
COMMENT ON COLUMN "01_vault"."07_fct_config_keys".value_type     IS 'Declared type for this key; one of string, int, float, bool, json, secret_ref.';
COMMENT ON COLUMN "01_vault"."07_fct_config_keys".current_version IS 'Latest active version number; 0 means no active version yet.';
COMMENT ON COLUMN "01_vault"."07_fct_config_keys".is_deleted     IS 'Soft-delete flag; must be paired with deleted_at via chk_07_fct_config_keys_deleted.';
COMMENT ON COLUMN "01_vault"."07_fct_config_keys".deleted_at     IS 'Timestamp of soft deletion; NULL when is_deleted = false.';
COMMENT ON COLUMN "01_vault"."07_fct_config_keys".created_at     IS 'Row creation timestamp (UTC).';
COMMENT ON COLUMN "01_vault"."07_fct_config_keys".updated_at     IS 'Row last-updated timestamp (UTC).';

CREATE INDEX ix_vault_07_fct_config_keys_environment_id
    ON "01_vault"."07_fct_config_keys" USING btree (environment_id);

-- 8. Config versions — APPEND-ONLY (no updated_at)
CREATE TABLE "01_vault"."08_fct_config_versions" (
    id            UUID         DEFAULT gen_random_uuid() NOT NULL,
    tenant_key    VARCHAR(100) NOT NULL DEFAULT 'default',
    config_key_id UUID         NOT NULL,
    version       INT          NOT NULL,
    value         TEXT,
    value_type    VARCHAR(20)  NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_08_fct_config_versions                      PRIMARY KEY (id),
    CONSTRAINT uq_08_fct_config_versions_key_version          UNIQUE      (config_key_id, version),
    CONSTRAINT fk_08_fct_config_versions_config_key_id_07_fct_config_keys
        FOREIGN KEY (config_key_id) REFERENCES "01_vault"."07_fct_config_keys" (id) ON DELETE RESTRICT,
    CONSTRAINT chk_08_fct_config_versions_version
        CHECK (version > 0)
);

COMMENT ON TABLE  "01_vault"."08_fct_config_versions"               IS 'Append-only version ledger for config key values.';
COMMENT ON COLUMN "01_vault"."08_fct_config_versions".id            IS 'Surrogate primary key.';
COMMENT ON COLUMN "01_vault"."08_fct_config_versions".tenant_key    IS 'Tenant identifier; every query must filter by this column.';
COMMENT ON COLUMN "01_vault"."08_fct_config_versions".config_key_id IS 'FK to 07_fct_config_keys.id; the parent config key.';
COMMENT ON COLUMN "01_vault"."08_fct_config_versions".version       IS 'Monotonically increasing version number; must be > 0.';
COMMENT ON COLUMN "01_vault"."08_fct_config_versions".value         IS 'Serialized value for this version; interpretation depends on value_type.';
COMMENT ON COLUMN "01_vault"."08_fct_config_versions".value_type    IS 'Snapshot of the declared type at version write time; one of string, int, float, bool, json, secret_ref.';
COMMENT ON COLUMN "01_vault"."08_fct_config_versions".created_at    IS 'Row creation timestamp (UTC). Append-only; this column is never updated.';

CREATE INDEX ix_vault_08_fct_config_versions_config_key_id
    ON "01_vault"."08_fct_config_versions" USING btree (config_key_id);

-- 9. Secret EAV attributes (dtl, FK → secrets + composite FK → attr whitelist)
CREATE TABLE "01_vault"."09_dtl_secret_attrs" (
    id             UUID         DEFAULT gen_random_uuid() NOT NULL,
    tenant_key     VARCHAR(100) NOT NULL DEFAULT 'default',
    secret_id      UUID         NOT NULL,
    entity_type    VARCHAR(50)  NOT NULL DEFAULT 'secret',
    property_key   VARCHAR(100) NOT NULL,
    property_value TEXT,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_09_dtl_secret_attrs                PRIMARY KEY (id),
    CONSTRAINT uq_09_dtl_secret_attrs_secret_key     UNIQUE      (secret_id, property_key),
    CONSTRAINT fk_09_dtl_secret_attrs_secret_id_05_fct_secrets
        FOREIGN KEY (secret_id) REFERENCES "01_vault"."05_fct_secrets" (id) ON DELETE CASCADE,
    CONSTRAINT chk_09_dtl_secret_attrs_entity_type
        CHECK (entity_type = 'secret'),
    CONSTRAINT fk_09_dtl_secret_attrs_whitelist
        FOREIGN KEY (entity_type, property_key) REFERENCES "01_vault"."02_dim_attr_defs" (entity_type, code) ON DELETE RESTRICT
);

COMMENT ON TABLE  "01_vault"."09_dtl_secret_attrs"                IS 'EAV attribute rows for secrets. property_key is whitelisted via composite FK to 02_dim_attr_defs.';
COMMENT ON COLUMN "01_vault"."09_dtl_secret_attrs".id             IS 'Surrogate primary key.';
COMMENT ON COLUMN "01_vault"."09_dtl_secret_attrs".tenant_key     IS 'Tenant identifier; every query must filter by this column.';
COMMENT ON COLUMN "01_vault"."09_dtl_secret_attrs".secret_id      IS 'FK to 05_fct_secrets.id; the owning secret (CASCADE on delete).';
COMMENT ON COLUMN "01_vault"."09_dtl_secret_attrs".entity_type    IS 'Discriminator column fixed to ''secret''; participates in composite FK whitelist check.';
COMMENT ON COLUMN "01_vault"."09_dtl_secret_attrs".property_key   IS 'Attribute code; must exist in 02_dim_attr_defs for entity_type = ''secret''.';
COMMENT ON COLUMN "01_vault"."09_dtl_secret_attrs".property_value IS 'Serialized attribute value; interpretation depends on the data_type defined in 02_dim_attr_defs.';
COMMENT ON COLUMN "01_vault"."09_dtl_secret_attrs".created_at     IS 'Row creation timestamp (UTC).';
COMMENT ON COLUMN "01_vault"."09_dtl_secret_attrs".updated_at     IS 'Row last-updated timestamp (UTC).';

CREATE INDEX ix_vault_09_dtl_secret_attrs_secret_id
    ON "01_vault"."09_dtl_secret_attrs" USING btree (secret_id);

-- 10. Config key EAV attributes (dtl, FK → config keys + composite FK → attr whitelist)
CREATE TABLE "01_vault"."10_dtl_config_attrs" (
    id             UUID         DEFAULT gen_random_uuid() NOT NULL,
    tenant_key     VARCHAR(100) NOT NULL DEFAULT 'default',
    config_key_id  UUID         NOT NULL,
    entity_type    VARCHAR(50)  NOT NULL DEFAULT 'config_key',
    property_key   VARCHAR(100) NOT NULL,
    property_value TEXT,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_10_dtl_config_attrs               PRIMARY KEY (id),
    CONSTRAINT uq_10_dtl_config_attrs_key           UNIQUE      (config_key_id, property_key),
    CONSTRAINT fk_10_dtl_config_attrs_config_key_id_07_fct_config_keys
        FOREIGN KEY (config_key_id) REFERENCES "01_vault"."07_fct_config_keys" (id) ON DELETE CASCADE,
    CONSTRAINT chk_10_dtl_config_attrs_entity_type
        CHECK (entity_type = 'config_key'),
    CONSTRAINT fk_10_dtl_config_attrs_whitelist
        FOREIGN KEY (entity_type, property_key) REFERENCES "01_vault"."02_dim_attr_defs" (entity_type, code) ON DELETE RESTRICT
);

COMMENT ON TABLE  "01_vault"."10_dtl_config_attrs"                IS 'EAV attribute rows for config keys. property_key is whitelisted via composite FK to 02_dim_attr_defs.';
COMMENT ON COLUMN "01_vault"."10_dtl_config_attrs".id             IS 'Surrogate primary key.';
COMMENT ON COLUMN "01_vault"."10_dtl_config_attrs".tenant_key     IS 'Tenant identifier; every query must filter by this column.';
COMMENT ON COLUMN "01_vault"."10_dtl_config_attrs".config_key_id  IS 'FK to 07_fct_config_keys.id; the owning config key (CASCADE on delete).';
COMMENT ON COLUMN "01_vault"."10_dtl_config_attrs".entity_type    IS 'Discriminator column fixed to ''config_key''; participates in composite FK whitelist check.';
COMMENT ON COLUMN "01_vault"."10_dtl_config_attrs".property_key   IS 'Attribute code; must exist in 02_dim_attr_defs for entity_type = ''config_key''.';
COMMENT ON COLUMN "01_vault"."10_dtl_config_attrs".property_value IS 'Serialized attribute value; interpretation depends on the data_type defined in 02_dim_attr_defs.';
COMMENT ON COLUMN "01_vault"."10_dtl_config_attrs".created_at     IS 'Row creation timestamp (UTC).';
COMMENT ON COLUMN "01_vault"."10_dtl_config_attrs".updated_at     IS 'Row last-updated timestamp (UTC).';

CREATE INDEX ix_vault_10_dtl_config_attrs_config_key_id
    ON "01_vault"."10_dtl_config_attrs" USING btree (config_key_id);

-- 11. Auth tokens (fct, stores hash only — never plaintext)
CREATE TABLE "01_vault"."11_fct_auth_tokens" (
    id           UUID         DEFAULT gen_random_uuid() NOT NULL,
    tenant_key   VARCHAR(100) NOT NULL DEFAULT 'default',
    name         VARCHAR(255) NOT NULL,
    token_hash   VARCHAR(64)  NOT NULL,
    last_used_at TIMESTAMPTZ,
    is_revoked   BOOLEAN      NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_11_fct_auth_tokens            PRIMARY KEY (id),
    CONSTRAINT uq_11_fct_auth_tokens_token_hash UNIQUE      (token_hash)
);

COMMENT ON TABLE  "01_vault"."11_fct_auth_tokens"              IS 'API bearer tokens for service-to-vault authentication. Stores sha256 hex hash only — never the plaintext token.';
COMMENT ON COLUMN "01_vault"."11_fct_auth_tokens".id           IS 'Surrogate primary key.';
COMMENT ON COLUMN "01_vault"."11_fct_auth_tokens".tenant_key   IS 'Tenant identifier; every query must filter by this column.';
COMMENT ON COLUMN "01_vault"."11_fct_auth_tokens".name         IS 'Human-readable label for this token (e.g. service name or purpose).';
COMMENT ON COLUMN "01_vault"."11_fct_auth_tokens".token_hash   IS 'PII: indirect — SHA-256 hex of the bearer token. Plaintext token is never stored.';
COMMENT ON COLUMN "01_vault"."11_fct_auth_tokens".last_used_at IS 'Timestamp of the most recent authenticated request using this token; NULL if never used.';
COMMENT ON COLUMN "01_vault"."11_fct_auth_tokens".is_revoked   IS 'When true the token is permanently disabled and must not be accepted.';
COMMENT ON COLUMN "01_vault"."11_fct_auth_tokens".created_at   IS 'Row creation timestamp (UTC).';

-- DOWN ==
DROP TABLE IF EXISTS "01_vault"."11_fct_auth_tokens";
DROP TABLE IF EXISTS "01_vault"."10_dtl_config_attrs";
DROP TABLE IF EXISTS "01_vault"."09_dtl_secret_attrs";
DROP TABLE IF EXISTS "01_vault"."08_fct_config_versions";
DROP TABLE IF EXISTS "01_vault"."07_fct_config_keys";
DROP TABLE IF EXISTS "01_vault"."06_fct_secret_versions";
DROP TABLE IF EXISTS "01_vault"."05_fct_secrets";
DROP TABLE IF EXISTS "01_vault"."04_fct_environments";
DROP TABLE IF EXISTS "01_vault"."03_fct_projects";
DROP TABLE IF EXISTS "01_vault"."02_dim_attr_defs";
DROP TABLE IF EXISTS "01_vault"."01_dim_entity_types";

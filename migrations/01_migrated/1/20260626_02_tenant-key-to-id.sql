-- UP: Replace tenant_key (VARCHAR) with tenant_id (UUID FK → 00_dim_tenants) on all 9 tenant-scoped tables.
-- No data safety ceremony needed: this is a pre-launch repo with no production data.
-- The single 'default' tenant is backfilled via the literal UUID seeded in 20260626_01.

-- 03_fct_projects
ALTER TABLE "01_vault"."03_fct_projects" ADD COLUMN tenant_id UUID;
UPDATE "01_vault"."03_fct_projects" SET tenant_id = '02e81b29-f150-54b9-9a08-ce75944f6889' WHERE tenant_id IS NULL;
ALTER TABLE "01_vault"."03_fct_projects" ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE "01_vault"."03_fct_projects"
    ADD CONSTRAINT fk_03_fct_projects_tenant_id_00_dim_tenants
        FOREIGN KEY (tenant_id) REFERENCES "01_vault"."00_dim_tenants" (id) ON DELETE RESTRICT;
ALTER TABLE "01_vault"."03_fct_projects" DROP CONSTRAINT uq_03_fct_projects_tenant_code;
ALTER TABLE "01_vault"."03_fct_projects"
    ADD CONSTRAINT uq_03_fct_projects_tenant_code UNIQUE (tenant_id, code);
ALTER TABLE "01_vault"."03_fct_projects" DROP COLUMN tenant_key;

-- 04_fct_environments
ALTER TABLE "01_vault"."04_fct_environments" ADD COLUMN tenant_id UUID;
UPDATE "01_vault"."04_fct_environments" SET tenant_id = '02e81b29-f150-54b9-9a08-ce75944f6889' WHERE tenant_id IS NULL;
ALTER TABLE "01_vault"."04_fct_environments" ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE "01_vault"."04_fct_environments"
    ADD CONSTRAINT fk_04_fct_environments_tenant_id_00_dim_tenants
        FOREIGN KEY (tenant_id) REFERENCES "01_vault"."00_dim_tenants" (id) ON DELETE RESTRICT;
ALTER TABLE "01_vault"."04_fct_environments" DROP CONSTRAINT uq_04_fct_environments_tenant_project_code;
ALTER TABLE "01_vault"."04_fct_environments"
    ADD CONSTRAINT uq_04_fct_environments_tenant_project_code UNIQUE (tenant_id, project_id, code);
ALTER TABLE "01_vault"."04_fct_environments" DROP COLUMN tenant_key;

-- 05_fct_secrets
ALTER TABLE "01_vault"."05_fct_secrets" ADD COLUMN tenant_id UUID;
UPDATE "01_vault"."05_fct_secrets" SET tenant_id = '02e81b29-f150-54b9-9a08-ce75944f6889' WHERE tenant_id IS NULL;
ALTER TABLE "01_vault"."05_fct_secrets" ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE "01_vault"."05_fct_secrets"
    ADD CONSTRAINT fk_05_fct_secrets_tenant_id_00_dim_tenants
        FOREIGN KEY (tenant_id) REFERENCES "01_vault"."00_dim_tenants" (id) ON DELETE RESTRICT;
ALTER TABLE "01_vault"."05_fct_secrets" DROP CONSTRAINT uq_05_fct_secrets_tenant_env_path;
ALTER TABLE "01_vault"."05_fct_secrets"
    ADD CONSTRAINT uq_05_fct_secrets_tenant_env_path UNIQUE (tenant_id, environment_id, path);
ALTER TABLE "01_vault"."05_fct_secrets" DROP COLUMN tenant_key;

-- 06_fct_secret_versions (no tenant_key-based unique constraint)
ALTER TABLE "01_vault"."06_fct_secret_versions" ADD COLUMN tenant_id UUID;
UPDATE "01_vault"."06_fct_secret_versions" SET tenant_id = '02e81b29-f150-54b9-9a08-ce75944f6889' WHERE tenant_id IS NULL;
ALTER TABLE "01_vault"."06_fct_secret_versions" ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE "01_vault"."06_fct_secret_versions"
    ADD CONSTRAINT fk_06_fct_secret_versions_tenant_id_00_dim_tenants
        FOREIGN KEY (tenant_id) REFERENCES "01_vault"."00_dim_tenants" (id) ON DELETE RESTRICT;
ALTER TABLE "01_vault"."06_fct_secret_versions" DROP COLUMN tenant_key;

-- 07_fct_config_keys
ALTER TABLE "01_vault"."07_fct_config_keys" ADD COLUMN tenant_id UUID;
UPDATE "01_vault"."07_fct_config_keys" SET tenant_id = '02e81b29-f150-54b9-9a08-ce75944f6889' WHERE tenant_id IS NULL;
ALTER TABLE "01_vault"."07_fct_config_keys" ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE "01_vault"."07_fct_config_keys"
    ADD CONSTRAINT fk_07_fct_config_keys_tenant_id_00_dim_tenants
        FOREIGN KEY (tenant_id) REFERENCES "01_vault"."00_dim_tenants" (id) ON DELETE RESTRICT;
ALTER TABLE "01_vault"."07_fct_config_keys" DROP CONSTRAINT uq_07_fct_config_keys_tenant_env_key;
ALTER TABLE "01_vault"."07_fct_config_keys"
    ADD CONSTRAINT uq_07_fct_config_keys_tenant_env_key UNIQUE (tenant_id, environment_id, key);
ALTER TABLE "01_vault"."07_fct_config_keys" DROP COLUMN tenant_key;

-- 08_fct_config_versions (no tenant_key-based unique constraint)
ALTER TABLE "01_vault"."08_fct_config_versions" ADD COLUMN tenant_id UUID;
UPDATE "01_vault"."08_fct_config_versions" SET tenant_id = '02e81b29-f150-54b9-9a08-ce75944f6889' WHERE tenant_id IS NULL;
ALTER TABLE "01_vault"."08_fct_config_versions" ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE "01_vault"."08_fct_config_versions"
    ADD CONSTRAINT fk_08_fct_config_versions_tenant_id_00_dim_tenants
        FOREIGN KEY (tenant_id) REFERENCES "01_vault"."00_dim_tenants" (id) ON DELETE RESTRICT;
ALTER TABLE "01_vault"."08_fct_config_versions" DROP COLUMN tenant_key;

-- 09_dtl_secret_attrs (no tenant_key-based unique constraint)
ALTER TABLE "01_vault"."09_dtl_secret_attrs" ADD COLUMN tenant_id UUID;
UPDATE "01_vault"."09_dtl_secret_attrs" SET tenant_id = '02e81b29-f150-54b9-9a08-ce75944f6889' WHERE tenant_id IS NULL;
ALTER TABLE "01_vault"."09_dtl_secret_attrs" ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE "01_vault"."09_dtl_secret_attrs"
    ADD CONSTRAINT fk_09_dtl_secret_attrs_tenant_id_00_dim_tenants
        FOREIGN KEY (tenant_id) REFERENCES "01_vault"."00_dim_tenants" (id) ON DELETE RESTRICT;
ALTER TABLE "01_vault"."09_dtl_secret_attrs" DROP COLUMN tenant_key;

-- 10_dtl_config_attrs (no tenant_key-based unique constraint)
ALTER TABLE "01_vault"."10_dtl_config_attrs" ADD COLUMN tenant_id UUID;
UPDATE "01_vault"."10_dtl_config_attrs" SET tenant_id = '02e81b29-f150-54b9-9a08-ce75944f6889' WHERE tenant_id IS NULL;
ALTER TABLE "01_vault"."10_dtl_config_attrs" ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE "01_vault"."10_dtl_config_attrs"
    ADD CONSTRAINT fk_10_dtl_config_attrs_tenant_id_00_dim_tenants
        FOREIGN KEY (tenant_id) REFERENCES "01_vault"."00_dim_tenants" (id) ON DELETE RESTRICT;
ALTER TABLE "01_vault"."10_dtl_config_attrs" DROP COLUMN tenant_key;

-- 11_fct_auth_tokens (no tenant_key-based unique constraint)
ALTER TABLE "01_vault"."11_fct_auth_tokens" ADD COLUMN tenant_id UUID;
UPDATE "01_vault"."11_fct_auth_tokens" SET tenant_id = '02e81b29-f150-54b9-9a08-ce75944f6889' WHERE tenant_id IS NULL;
ALTER TABLE "01_vault"."11_fct_auth_tokens" ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE "01_vault"."11_fct_auth_tokens"
    ADD CONSTRAINT fk_11_fct_auth_tokens_tenant_id_00_dim_tenants
        FOREIGN KEY (tenant_id) REFERENCES "01_vault"."00_dim_tenants" (id) ON DELETE RESTRICT;
ALTER TABLE "01_vault"."11_fct_auth_tokens" DROP COLUMN tenant_key;

-- DOWN ==
-- Reverse in reverse table order. Add tenant_key back, backfill 'default', drop tenant_id.

-- 11_fct_auth_tokens
ALTER TABLE "01_vault"."11_fct_auth_tokens" ADD COLUMN tenant_key VARCHAR(100) NOT NULL DEFAULT 'default';
ALTER TABLE "01_vault"."11_fct_auth_tokens" DROP CONSTRAINT fk_11_fct_auth_tokens_tenant_id_00_dim_tenants;
ALTER TABLE "01_vault"."11_fct_auth_tokens" DROP COLUMN tenant_id;

-- 10_dtl_config_attrs
ALTER TABLE "01_vault"."10_dtl_config_attrs" ADD COLUMN tenant_key VARCHAR(100) NOT NULL DEFAULT 'default';
ALTER TABLE "01_vault"."10_dtl_config_attrs" DROP CONSTRAINT fk_10_dtl_config_attrs_tenant_id_00_dim_tenants;
ALTER TABLE "01_vault"."10_dtl_config_attrs" DROP COLUMN tenant_id;

-- 09_dtl_secret_attrs
ALTER TABLE "01_vault"."09_dtl_secret_attrs" ADD COLUMN tenant_key VARCHAR(100) NOT NULL DEFAULT 'default';
ALTER TABLE "01_vault"."09_dtl_secret_attrs" DROP CONSTRAINT fk_09_dtl_secret_attrs_tenant_id_00_dim_tenants;
ALTER TABLE "01_vault"."09_dtl_secret_attrs" DROP COLUMN tenant_id;

-- 08_fct_config_versions
ALTER TABLE "01_vault"."08_fct_config_versions" ADD COLUMN tenant_key VARCHAR(100) NOT NULL DEFAULT 'default';
ALTER TABLE "01_vault"."08_fct_config_versions" DROP CONSTRAINT fk_08_fct_config_versions_tenant_id_00_dim_tenants;
ALTER TABLE "01_vault"."08_fct_config_versions" DROP COLUMN tenant_id;

-- 07_fct_config_keys
ALTER TABLE "01_vault"."07_fct_config_keys" ADD COLUMN tenant_key VARCHAR(100) NOT NULL DEFAULT 'default';
ALTER TABLE "01_vault"."07_fct_config_keys" DROP CONSTRAINT fk_07_fct_config_keys_tenant_id_00_dim_tenants;
ALTER TABLE "01_vault"."07_fct_config_keys" DROP CONSTRAINT uq_07_fct_config_keys_tenant_env_key;
ALTER TABLE "01_vault"."07_fct_config_keys"
    ADD CONSTRAINT uq_07_fct_config_keys_tenant_env_key UNIQUE (tenant_key, environment_id, key);
ALTER TABLE "01_vault"."07_fct_config_keys" DROP COLUMN tenant_id;

-- 06_fct_secret_versions
ALTER TABLE "01_vault"."06_fct_secret_versions" ADD COLUMN tenant_key VARCHAR(100) NOT NULL DEFAULT 'default';
ALTER TABLE "01_vault"."06_fct_secret_versions" DROP CONSTRAINT fk_06_fct_secret_versions_tenant_id_00_dim_tenants;
ALTER TABLE "01_vault"."06_fct_secret_versions" DROP COLUMN tenant_id;

-- 05_fct_secrets
ALTER TABLE "01_vault"."05_fct_secrets" ADD COLUMN tenant_key VARCHAR(100) NOT NULL DEFAULT 'default';
ALTER TABLE "01_vault"."05_fct_secrets" DROP CONSTRAINT fk_05_fct_secrets_tenant_id_00_dim_tenants;
ALTER TABLE "01_vault"."05_fct_secrets" DROP CONSTRAINT uq_05_fct_secrets_tenant_env_path;
ALTER TABLE "01_vault"."05_fct_secrets"
    ADD CONSTRAINT uq_05_fct_secrets_tenant_env_path UNIQUE (tenant_key, environment_id, path);
ALTER TABLE "01_vault"."05_fct_secrets" DROP COLUMN tenant_id;

-- 04_fct_environments
ALTER TABLE "01_vault"."04_fct_environments" ADD COLUMN tenant_key VARCHAR(100) NOT NULL DEFAULT 'default';
ALTER TABLE "01_vault"."04_fct_environments" DROP CONSTRAINT fk_04_fct_environments_tenant_id_00_dim_tenants;
ALTER TABLE "01_vault"."04_fct_environments" DROP CONSTRAINT uq_04_fct_environments_tenant_project_code;
ALTER TABLE "01_vault"."04_fct_environments"
    ADD CONSTRAINT uq_04_fct_environments_tenant_project_code UNIQUE (tenant_key, project_id, code);
ALTER TABLE "01_vault"."04_fct_environments" DROP COLUMN tenant_id;

-- 03_fct_projects
ALTER TABLE "01_vault"."03_fct_projects" ADD COLUMN tenant_key VARCHAR(100) NOT NULL DEFAULT 'default';
ALTER TABLE "01_vault"."03_fct_projects" DROP CONSTRAINT fk_03_fct_projects_tenant_id_00_dim_tenants;
ALTER TABLE "01_vault"."03_fct_projects" DROP CONSTRAINT uq_03_fct_projects_tenant_code;
ALTER TABLE "01_vault"."03_fct_projects"
    ADD CONSTRAINT uq_03_fct_projects_tenant_code UNIQUE (tenant_key, code);
ALTER TABLE "01_vault"."03_fct_projects" DROP COLUMN tenant_id;

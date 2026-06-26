-- UP: Add 00_dim_tenants table and seed the default tenant.

CREATE TABLE "01_vault"."00_dim_tenants" (
    id              UUID         NOT NULL DEFAULT gen_random_uuid(),
    code            VARCHAR(100) NOT NULL,
    name            VARCHAR(255) NOT NULL,
    soma_iam_org_id UUID,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_00_dim_tenants      PRIMARY KEY (id),
    CONSTRAINT uq_00_dim_tenants_code UNIQUE      (code),
    CONSTRAINT uq_00_dim_tenants_soma_iam_org_id UNIQUE (soma_iam_org_id)
);

COMMENT ON TABLE  "01_vault"."00_dim_tenants"                  IS 'Tenant registry. Every tenant-scoped row in fct/dtl tables references this table via tenant_id.';
COMMENT ON COLUMN "01_vault"."00_dim_tenants".id               IS 'Stable tenant UUID. Default tenant is seeded with a deterministic v5 UUID derived from the code ''default'' in the OID namespace.';
COMMENT ON COLUMN "01_vault"."00_dim_tenants".code             IS 'Human slug for the tenant (e.g. ''default'', ''acme''). Unique; used in CLI/config.';
COMMENT ON COLUMN "01_vault"."00_dim_tenants".name             IS 'Human-readable display name for the tenant.';
COMMENT ON COLUMN "01_vault"."00_dim_tenants".soma_iam_org_id  IS 'Future FK to soma-iam organisation UUID. NULL until soma-iam integration is wired.';
COMMENT ON COLUMN "01_vault"."00_dim_tenants".created_at       IS 'Row creation timestamp (UTC).';
COMMENT ON COLUMN "01_vault"."00_dim_tenants".updated_at       IS 'Row last-updated timestamp (UTC).';

-- Seed the default tenant with a deterministic v5 UUID (uuid5(NAMESPACE_OID, 'default')).
-- The Rust TenantId::default() derives the same UUID, so no sync is needed.
INSERT INTO "01_vault"."00_dim_tenants" (id, code, name, created_at, updated_at)
VALUES ('02e81b29-f150-54b9-9a08-ce75944f6889', 'default', 'Default', now(), now())
ON CONFLICT (code) DO NOTHING;

-- DOWN ==
DROP TABLE IF EXISTS "01_vault"."00_dim_tenants";

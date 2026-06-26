-- Append-only HMAC hash-chained audit log.
--
-- entry_hash = HMAC-SHA256(audit_hmac_key, canonical_msg) where:
--   canonical_msg = seq_num || "|" || tenant_id || "|" || event_type || "|"
--                   || coalesce(actor_token_id, "") || "|" || coalesce(resource_type, "") || "|"
--                   || coalesce(resource_id, "") || "|" || outcome || "|"
--                   || created_at_rfc3339 || "|" || coalesce(prev_hash, "")
--
-- This table is INSERT + SELECT only. No UPDATE or DELETE paths exist.

CREATE TABLE "01_vault"."12_fct_audit_events" (
    id              UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES "01_vault"."00_dim_tenants"(id),
    seq_num         BIGINT      NOT NULL,
    event_type      TEXT        NOT NULL,
    actor_token_id  UUID,
    actor_role      TEXT,
    resource_type   TEXT,
    resource_id     TEXT,
    outcome         TEXT        NOT NULL CHECK (outcome IN ('success','denied','error')),
    actor_ip        INET,
    prev_hash       TEXT,
    entry_hash      TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    UNIQUE (tenant_id, seq_num)
);

CREATE INDEX idx_audit_tenant_seq    ON "01_vault"."12_fct_audit_events" (tenant_id, seq_num);
CREATE INDEX idx_audit_tenant_ts     ON "01_vault"."12_fct_audit_events" (tenant_id, created_at);
CREATE INDEX idx_audit_tenant_type   ON "01_vault"."12_fct_audit_events" (tenant_id, event_type);

ALTER TABLE "01_vault"."12_fct_audit_events" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "01_vault"."12_fct_audit_events" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "01_vault"."12_fct_audit_events"
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- DOWN ==
DROP POLICY IF EXISTS tenant_isolation ON "01_vault"."12_fct_audit_events";
ALTER TABLE "01_vault"."12_fct_audit_events" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "01_vault"."12_fct_audit_events" DISABLE ROW LEVEL SECURITY;
DROP TABLE IF EXISTS "01_vault"."12_fct_audit_events";

-- Add parent_env_id to 04_fct_environments for environment inheritance.
-- A NULL parent means no inheritance (root environment).
-- A non-NULL parent means this environment inherits values from the parent when a
-- key is not set locally. The application enforces cycle prevention and depth limits.

ALTER TABLE "01_vault"."04_fct_environments"
    ADD COLUMN parent_env_id UUID
        REFERENCES "01_vault"."04_fct_environments"(id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT chk_04_fct_environments_no_self_parent
        CHECK (parent_env_id <> id);

COMMENT ON COLUMN "01_vault"."04_fct_environments".parent_env_id
    IS 'Optional FK to the parent environment in the same project/tenant. NULL = root; non-NULL = inherits unset keys from the parent chain (depth ≤ 5, no cycles).';

-- DOWN ==
ALTER TABLE "01_vault"."04_fct_environments"
    DROP CONSTRAINT IF EXISTS chk_04_fct_environments_no_self_parent;

ALTER TABLE "01_vault"."04_fct_environments"
    DROP COLUMN IF EXISTS parent_env_id;

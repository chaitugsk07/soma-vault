mod attrs;
mod audit;
mod ledger;

use std::collections::HashMap;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use soma_crypto::MasterKek;

use crate::error::map_sqlx;
use crate::store::DataStore;
use crate::types::{
    AttrDef, AuditEvent, AuditFilters, AuditVerifyResult, AuthToken, ConfigKey, ConfigVersion,
    EffectiveExportBundle, EntityRef, EntityType, Environment, ExportBundle, ExportEntry,
    InheritedSecret, ListParams, Page, Project, ResolvedConfig, RevealedSecret, Secret,
    SecretVersionMeta, TenantId, ValueType,
};
use crate::{Error, Result};

// ── sqlx row structs ──────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct ProjectRow {
    id: Uuid,
    tenant_id: Uuid,
    code: String,
    name: String,
    description: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<ProjectRow> for Project {
    fn from(r: ProjectRow) -> Self {
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            code: r.code,
            name: r.name,
            description: r.description,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct EnvironmentRow {
    id: Uuid,
    tenant_id: Uuid,
    project_id: Uuid,
    code: String,
    name: String,
    parent_env_id: Option<Uuid>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<EnvironmentRow> for Environment {
    fn from(r: EnvironmentRow) -> Self {
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            project_id: r.project_id,
            code: r.code,
            name: r.name,
            parent_env_id: r.parent_env_id,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct SecretRow {
    id: Uuid,
    tenant_id: Uuid,
    environment_id: Uuid,
    path: String,
    current_version: i32,
    cas_required: bool,
    max_versions: i32,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<SecretRow> for Secret {
    fn from(r: SecretRow) -> Self {
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            environment_id: r.environment_id,
            path: r.path,
            current_version: r.current_version,
            cas_required: r.cas_required,
            max_versions: r.max_versions,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct SecretVersionRow {
    #[allow(dead_code)]
    secret_id: Uuid,
    #[allow(dead_code)]
    version: i32,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    wrapped_dek: Vec<u8>,
    aad: Vec<u8>,
    seal_provider: String,
    seal_key_id: String,
    #[allow(dead_code)]
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow)]
struct ConfigKeyRow {
    id: Uuid,
    tenant_id: Uuid,
    environment_id: Uuid,
    key: String,
    value_type: String,
    current_version: i32,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<ConfigKeyRow> for ConfigKey {
    fn from(r: ConfigKeyRow) -> Self {
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            environment_id: r.environment_id,
            key: r.key,
            value_type: r.value_type,
            current_version: r.current_version,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct ConfigVersionRow {
    config_key_id: Uuid,
    version: i32,
    value: Option<String>,
    value_type: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<ConfigVersionRow> for ConfigVersion {
    fn from(r: ConfigVersionRow) -> Self {
        Self {
            config_key_id: r.config_key_id,
            version: r.version,
            value: r.value,
            value_type: r.value_type,
            created_at: r.created_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct AuthTokenRow {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    role: String,
    created_at: chrono::DateTime<chrono::Utc>,
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<AuthTokenRow> for AuthToken {
    fn from(r: AuthTokenRow) -> Self {
        use std::str::FromStr as _;
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            name: r.name,
            role: crate::types::Role::from_str(&r.role).unwrap_or(crate::types::Role::Admin),
            created_at: r.created_at,
            last_used_at: r.last_used_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct EntityTypeRow {
    id: Uuid,
    code: String,
    name: String,
    description: Option<String>,
}

impl From<EntityTypeRow> for EntityType {
    fn from(r: EntityTypeRow) -> Self {
        Self {
            id: r.id,
            code: r.code,
            name: r.name,
            description: r.description,
        }
    }
}

#[derive(sqlx::FromRow)]
struct AttrDefRow {
    id: Uuid,
    entity_type: String,
    code: String,
    name: String,
    data_type: String,
    is_required: bool,
    is_pii: bool,
    sort_order: i32,
}

impl From<AttrDefRow> for AttrDef {
    fn from(r: AttrDefRow) -> Self {
        Self {
            id: r.id,
            entity_type: r.entity_type,
            code: r.code,
            name: r.name,
            data_type: r.data_type,
            is_required: r.is_required,
            is_pii: r.is_pii,
            sort_order: r.sort_order,
        }
    }
}

// ── PgDataStore ───────────────────────────────────────────────────────────────

/// `DataStore` backed by `PostgreSQL` via `sqlx`.
pub struct PgDataStore {
    pub(crate) pool: PgPool,
    pub(crate) kek: MasterKek,
    audit_hmac_key: [u8; 32],
}

impl PgDataStore {
    /// Create a new store with the given pool and master KEK.
    ///
    /// Call [`DataStore::migrate`] before issuing any other operations.
    #[must_use]
    pub fn new(pool: PgPool, kek: MasterKek) -> Self {
        let audit_hmac_key = kek.derive_audit_hmac_key();
        Self { pool, kek, audit_hmac_key }
    }

    /// Return a reference to the underlying pool (e.g. for tests).
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Begin a transaction and immediately set `app.tenant_id` so that all
    /// tenant-scoped RLS policies in this transaction see the correct rows.
    ///
    /// `SET LOCAL` / `set_config(..., true)` scopes the setting to the
    /// transaction; it is automatically cleared on commit or rollback.
    ///
    /// Every method that queries a tenant-scoped table MUST obtain its executor
    /// through this helper (or through a transaction already initialized by it).
    async fn tenant_tx(&self, tenant: &TenantId) -> Result<Transaction<'_, Postgres>> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        // ponytail: set_config is the bindable form of SET LOCAL; SET LOCAL itself
        // cannot take a bind parameter.
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(tenant.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx)?;
        Ok(tx)
    }
}

// ── Pagination helper ─────────────────────────────────────────────────────────

fn decode_cursor(cursor: &str) -> Result<Uuid> {
    cursor
        .parse::<Uuid>()
        .map_err(|_| Error::Validation(format!("invalid pagination cursor: {cursor}")))
}

// ── Environment chain helpers ─────────────────────────────────────────────────

/// Walk the `parent_env_id` chain starting from `env_id` and return the depth (number
/// of ancestors, not counting `env_id` itself).  Returns an error if the chain would
/// cause a cycle (by checking against visited set) or the depth would exceed 5.
///
/// Called only inside an already-open tenant-tx so RLS is active.
async fn check_env_chain_depth(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    mut current_id: Uuid,
) -> Result<usize> {
    let mut depth: usize = 0;
    let mut visited = std::collections::HashSet::new();
    visited.insert(current_id);

    loop {
        let row: Option<(Option<Uuid>,)> = sqlx::query_as(
            r#"SELECT parent_env_id FROM "01_vault"."04_fct_environments"
               WHERE id = $1 AND tenant_id = $2 AND is_deleted = false"#,
        )
        .bind(current_id)
        .bind(tenant_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_sqlx)?;

        let parent = match row {
            None => break, // env not found → chain ends
            Some((p,)) => p,
        };

        let Some(pid) = parent else { break }; // NULL parent → root

        if visited.contains(&pid) {
            return Err(Error::Validation("cycle detected in environment inheritance chain".to_owned()));
        }

        visited.insert(pid);
        depth += 1;
        if depth >= 5 {
            return Err(Error::Validation(
                "environment inheritance chain exceeds maximum depth of 5".to_owned(),
            ));
        }
        current_id = pid;
    }

    Ok(depth)
}

/// Fetch just the `parent_env_id` for a given environment (tenant-scoped).
/// Returns `Ok(None)` when the env is a root or not found.
async fn get_parent_env_id(pool: &PgPool, tenant_id: Uuid, env_id: Uuid) -> Result<Option<Uuid>> {
    // ponytail: direct pool query; no tenant_tx needed since we only read the FK.
    // RLS on 04_fct_environments requires app.tenant_id to be set; because this helper
    // is called outside a tenant_tx we bypass RLS by also binding tenant_id in the WHERE
    // clause (defense-in-depth: the explicit filter is an additional guard).
    let row: Option<(Option<Uuid>,)> = sqlx::query_as(
        r#"SELECT parent_env_id FROM "01_vault"."04_fct_environments"
           WHERE id = $1 AND tenant_id = $2 AND is_deleted = false"#,
    )
    .bind(env_id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(map_sqlx)?;

    Ok(row.and_then(|(p,)| p))
}

/// Build an ordered chain starting with `env_id`, then its parent, then grandparent, …
/// up to depth 5.  Returns `[env_id, parent_id, grandparent_id, …]`.
async fn build_env_chain(pool: &PgPool, tenant_id: Uuid, env_id: Uuid) -> Result<Vec<Uuid>> {
    let mut chain = vec![env_id];
    let mut current = env_id;
    for _ in 0..5_u8 {
        match get_parent_env_id(pool, tenant_id, current).await? {
            Some(pid) => {
                if chain.contains(&pid) {
                    // Cycle guard (should be prevented at write time, but be safe).
                    break;
                }
                chain.push(pid);
                current = pid;
            }
            None => break,
        }
    }
    Ok(chain)
}

/// Try to fetch a config key+version from `env_id`, then walk the parent chain on miss.
/// Returns `(ConfigVersion, inherited_from)`.
async fn get_config_with_inheritance(
    store: &PgDataStore,
    tenant: &TenantId,
    env_id: Uuid,
    key: &str,
    version: Option<i32>,
) -> Result<(ConfigVersion, Option<Uuid>)> {
    match store.get_config(tenant, env_id, key, version).await {
        Ok(cv) => return Ok((cv, None)),
        Err(Error::NotFound) => {}
        Err(e) => return Err(e),
    }

    let mut current = env_id;
    for _ in 0..5_u8 {
        let parent_id = get_parent_env_id(&store.pool, tenant.0, current).await?;
        let Some(pid) = parent_id else { break };
        match store.get_config(tenant, pid, key, version).await {
            Ok(cv) => return Ok((cv, Some(pid))),
            Err(Error::NotFound) => {
                current = pid;
            }
            Err(e) => return Err(e),
        }
    }

    Err(Error::NotFound)
}

// ── DataStore impl ────────────────────────────────────────────────────────────

#[async_trait]
impl DataStore for PgDataStore {
    // ── Migrations ────────────────────────────────────────────────────────────

    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(map_sqlx)?;
        Ok(())
    }

    async fn migrate(&self) -> Result<()> {
        use soma_schema::{Migrator, PostgresConfig, PostgresDriver};

        let driver = PostgresDriver::new(
            self.pool.clone(),
            PostgresConfig {
                schema: Some("01_vault".into()),
                advisory_lock_key: 0x50A1_7A01_7017_i64,
                ..Default::default()
            },
        )
        .map_err(|e| Error::Migrate(e.to_string()))?;

        // Resolve migrations path relative to this crate at compile time so it
        // works regardless of the process working directory.
        // ponytail: CARGO_MANIFEST_DIR is set by cargo at build time; fine for all
        //           environments (tests, embedded startup, CLI). Ceiling: packaging
        //           without cargo (e.g. bazel) would need a different strategy.
        let migrations_root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations");

        Migrator::from_root(migrations_root)
            .up(&driver)
            .await
            .map_err(|e| Error::Migrate(e.to_string()))
    }

    // ── Projects ──────────────────────────────────────────────────────────────

    async fn create_project(
        &self,
        tenant: &TenantId,
        code: &str,
        name: &str,
        description: Option<&str>,
    ) -> Result<Project> {
        let mut tx = self.tenant_tx(tenant).await?;

        let row: ProjectRow = sqlx::query_as(
            r#"INSERT INTO "01_vault"."03_fct_projects"
               (id, tenant_id, code, name, description, is_deleted, created_at, updated_at)
               VALUES (gen_random_uuid(), $1, $2, $3, $4, false, now(), now())
               RETURNING id, tenant_id, code, name, description, created_at, updated_at"#,
        )
        .bind(tenant.0)
        .bind(code)
        .bind(name)
        .bind(description)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        tx.commit().await.map_err(map_sqlx)?;
        Ok(row.into())
    }

    async fn get_project(&self, tenant: &TenantId, project_id: Uuid) -> Result<Project> {
        let mut tx = self.tenant_tx(tenant).await?;

        let row: ProjectRow = sqlx::query_as(
            r#"SELECT id, tenant_id, code, name, description, created_at, updated_at
               FROM "01_vault"."03_fct_projects"
               WHERE id = $1 AND tenant_id = $2 AND is_deleted = false"#,
        )
        .bind(project_id)
        .bind(tenant.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?
        .ok_or(Error::NotFound)?;

        tx.commit().await.map_err(map_sqlx)?;
        Ok(row.into())
    }

    async fn list_projects(&self, tenant: &TenantId, params: ListParams) -> Result<Page<Project>> {
        let cursor_id: Option<Uuid> = params.cursor.as_deref().map(decode_cursor).transpose()?;
        let mut tx = self.tenant_tx(tenant).await?;

        let rows: Vec<ProjectRow> = sqlx::query_as(
            r#"SELECT id, tenant_id, code, name, description, created_at, updated_at
               FROM "01_vault"."03_fct_projects"
               WHERE tenant_id = $1 AND is_deleted = false
                 AND ($2::uuid IS NULL OR id > $2::uuid)
               ORDER BY id ASC
               LIMIT $3"#,
        )
        .bind(tenant.0)
        .bind(cursor_id)
        .bind(params.limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        tx.commit().await.map_err(map_sqlx)?;

        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let next_cursor = if rows.len() == params.limit as usize {
            rows.last().map(|r| r.id.to_string())
        } else {
            None
        };

        Ok(Page {
            items: rows.into_iter().map(Into::into).collect(),
            next_cursor,
        })
    }

    // ── Environments ──────────────────────────────────────────────────────────

    async fn create_environment(
        &self,
        tenant: &TenantId,
        project_id: Uuid,
        code: &str,
        name: &str,
        parent_env_id: Option<Uuid>,
    ) -> Result<Environment> {
        let mut tx = self.tenant_tx(tenant).await?;

        // Pre-check: ensure the project exists and belongs to this tenant (→ 404 not 500).
        let proj_ok: bool = sqlx::query(
            r#"SELECT 1 FROM "01_vault"."03_fct_projects"
               WHERE id = $1 AND tenant_id = $2 AND is_deleted = false"#,
        )
        .bind(project_id)
        .bind(tenant.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?
        .is_some();

        if !proj_ok {
            return Err(Error::NotFound);
        }

        // Validate parent: must exist in the same project + tenant, and must not create a cycle
        // or exceed depth 5.
        if let Some(parent_id) = parent_env_id {
            let parent_row: Option<(Uuid,)> = sqlx::query_as(
                r#"SELECT project_id FROM "01_vault"."04_fct_environments"
                   WHERE id = $1 AND tenant_id = $2 AND is_deleted = false"#,
            )
            .bind(parent_id)
            .bind(tenant.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_sqlx)?;

            match parent_row {
                None => return Err(Error::NotFound),
                Some((parent_project_id,)) if parent_project_id != project_id => {
                    return Err(Error::Validation(
                        "parent_env_id must belong to the same project".to_owned(),
                    ));
                }
                _ => {}
            }

            // Walk up the chain from parent_id checking for cycles and depth (≤ 4 ancestors → depth 5 total).
            let depth = check_env_chain_depth(&mut tx, tenant.0, parent_id).await?;
            if depth >= 5 {
                return Err(Error::Validation(
                    "environment inheritance chain would exceed maximum depth of 5".to_owned(),
                ));
            }
        }

        let row: EnvironmentRow = sqlx::query_as(
            r#"INSERT INTO "01_vault"."04_fct_environments"
               (id, tenant_id, project_id, code, name, parent_env_id, is_deleted, created_at, updated_at)
               VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, false, now(), now())
               RETURNING id, tenant_id, project_id, code, name, parent_env_id, created_at, updated_at"#,
        )
        .bind(tenant.0)
        .bind(project_id)
        .bind(code)
        .bind(name)
        .bind(parent_env_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        tx.commit().await.map_err(map_sqlx)?;
        Ok(row.into())
    }

    async fn get_environment(&self, tenant: &TenantId, env_id: Uuid) -> Result<Environment> {
        let mut tx = self.tenant_tx(tenant).await?;

        let row: EnvironmentRow = sqlx::query_as(
            r#"SELECT id, tenant_id, project_id, code, name, parent_env_id, created_at, updated_at
               FROM "01_vault"."04_fct_environments"
               WHERE id = $1 AND tenant_id = $2 AND is_deleted = false"#,
        )
        .bind(env_id)
        .bind(tenant.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?
        .ok_or(Error::NotFound)?;

        tx.commit().await.map_err(map_sqlx)?;
        Ok(row.into())
    }

    async fn list_environments(
        &self,
        tenant: &TenantId,
        project_id: Uuid,
    ) -> Result<Vec<Environment>> {
        let mut tx = self.tenant_tx(tenant).await?;

        let rows: Vec<EnvironmentRow> = sqlx::query_as(
            r#"SELECT id, tenant_id, project_id, code, name, parent_env_id, created_at, updated_at
               FROM "01_vault"."04_fct_environments"
               WHERE tenant_id = $1 AND project_id = $2 AND is_deleted = false
               ORDER BY id ASC"#,
        )
        .bind(tenant.0)
        .bind(project_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        tx.commit().await.map_err(map_sqlx)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    // ── Secrets ───────────────────────────────────────────────────────────────

    async fn put_secret(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        path: &str,
        plaintext: &[u8],
        attrs: HashMap<String, String>,
        cas: Option<i32>,
    ) -> Result<SecretVersionMeta> {
        // QW-7: verify the environment belongs to this tenant before writing.
        // This check + the upsert run in one tenant_tx so RLS guards both.
        let mut tx = self.tenant_tx(tenant).await?;

        let env_ok: bool = sqlx::query(
            r#"SELECT 1 FROM "01_vault"."04_fct_environments"
               WHERE id = $1 AND tenant_id = $2 AND is_deleted = false"#,
        )
        .bind(env_id)
        .bind(tenant.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?
        .is_some();

        if !env_ok {
            return Err(Error::NotFound);
        }

        // Upsert the secret header (idempotent on unique(tenant_id,environment_id,path)).
        let secret: SecretRow = sqlx::query_as(
            r#"INSERT INTO "01_vault"."05_fct_secrets"
               (id, tenant_id, environment_id, path, current_version, cas_required, max_versions,
                is_deleted, created_at, updated_at)
               VALUES (gen_random_uuid(), $1, $2, $3, 0, false, 20, false, now(), now())
               ON CONFLICT (tenant_id, environment_id, path)
               DO UPDATE SET updated_at = "05_fct_secrets".updated_at
               RETURNING id, tenant_id, environment_id, path, current_version, cas_required,
                         max_versions, created_at, updated_at"#,
        )
        .bind(tenant.0)
        .bind(env_id)
        .bind(path)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        tx.commit().await.map_err(map_sqlx)?;

        // QW-5: advance_secret_version encrypts inside the locked section so
        // the version bound into AAD always equals the version column stored.
        // QW-8: derive a per-tenant KEK so DEKs are cryptographically isolated by tenant.
        let tenant_kek = self.kek.derive_tenant_kek(tenant.0);
        let new_version = ledger::advance_secret_version(
            &self.pool,
            &tenant_kek,
            &self.kek.fingerprint(),
            tenant.0,
            secret.id,
            cas,
            plaintext,
        )
        .await?;

        // Store EAV attrs (best-effort in this call; errors propagate).
        if !attrs.is_empty() {
            attrs::set_attrs(&self.pool, tenant, EntityRef::Secret(secret.id), attrs).await?;
        }

        // Fetch the created version row for metadata.
        // This is a version-table read — needs tenant context.
        let mut tx2 = self.tenant_tx(tenant).await?;
        let meta_row: (Uuid, i32, String, String, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
            r#"SELECT secret_id, version, seal_provider, seal_key_id, created_at
                   FROM "01_vault"."06_fct_secret_versions"
                   WHERE secret_id = $1 AND version = $2"#,
        )
        .bind(secret.id)
        .bind(new_version)
        .fetch_one(&mut *tx2)
        .await
        .map_err(map_sqlx)?;
        tx2.commit().await.map_err(map_sqlx)?;

        Ok(SecretVersionMeta {
            secret_id: meta_row.0,
            version: meta_row.1,
            seal_provider: meta_row.2,
            seal_key_id: meta_row.3,
            created_at: meta_row.4,
        })
    }

    async fn get_secret(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        path: &str,
        version: Option<i32>,
    ) -> Result<RevealedSecret> {
        let mut tx = self.tenant_tx(tenant).await?;

        // Fetch the header first.
        let secret: SecretRow = sqlx::query_as(
            r#"SELECT id, tenant_id, environment_id, path, current_version, cas_required,
                      max_versions, created_at, updated_at
               FROM "01_vault"."05_fct_secrets"
               WHERE tenant_id = $1 AND environment_id = $2 AND path = $3 AND is_deleted = false"#,
        )
        .bind(tenant.0)
        .bind(env_id)
        .bind(path)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?
        .ok_or(Error::NotFound)?;

        let target_version = version.unwrap_or(secret.current_version);

        let ver_row: SecretVersionRow = sqlx::query_as(
            r#"SELECT secret_id, version, ciphertext, nonce, wrapped_dek, aad,
                      seal_provider, seal_key_id, created_at
               FROM "01_vault"."06_fct_secret_versions"
               WHERE secret_id = $1 AND version = $2"#,
        )
        .bind(secret.id)
        .bind(target_version)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?
        .ok_or(Error::NotFound)?;

        tx.commit().await.map_err(map_sqlx)?;

        let sealed = soma_crypto::Sealed {
            ciphertext: ver_row.ciphertext,
            nonce: ver_row.nonce,
            wrapped_dek: ver_row.wrapped_dek,
            aad: ver_row.aad,
            seal_provider: ver_row.seal_provider.parse().map_err(Error::Crypto)?,
            seal_key_id: ver_row.seal_key_id,
        };

        // QW-8: decrypt under the per-tenant KEK derived from the master KEK.
        let tenant_kek = self.kek.derive_tenant_kek(tenant.0);
        let plaintext =
            soma_crypto::decrypt_checked(&tenant_kek, &sealed, secret.id, i64::from(target_version))?;

        Ok(RevealedSecret {
            meta: secret.into(),
            version: target_version,
            plaintext,
        })
    }

    async fn get_secret_inherited(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        path: &str,
        version: Option<i32>,
    ) -> Result<InheritedSecret> {
        // Try the requested env first.
        match self.get_secret(tenant, env_id, path, version).await {
            Ok(revealed) => return Ok(InheritedSecret { revealed, inherited_from: None }),
            Err(Error::NotFound) => {}
            Err(e) => return Err(e),
        }

        // Walk the parent chain (depth-bounded to avoid a malformed chain looping).
        let mut current = env_id;
        for _ in 0..5_u8 {
            let parent_id = get_parent_env_id(&self.pool, tenant.0, current).await?;
            let Some(pid) = parent_id else { break };
            match self.get_secret(tenant, pid, path, version).await {
                Ok(revealed) => {
                    return Ok(InheritedSecret {
                        revealed,
                        inherited_from: Some(pid),
                    });
                }
                Err(Error::NotFound) => {
                    current = pid;
                }
                Err(e) => return Err(e),
            }
        }

        Err(Error::NotFound)
    }

    async fn list_secrets(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        params: ListParams,
    ) -> Result<Page<Secret>> {
        let cursor_id: Option<Uuid> = params.cursor.as_deref().map(decode_cursor).transpose()?;
        let mut tx = self.tenant_tx(tenant).await?;

        let rows: Vec<SecretRow> = sqlx::query_as(
            r#"SELECT id, tenant_id, environment_id, path, current_version, cas_required,
                      max_versions, created_at, updated_at
               FROM "01_vault"."05_fct_secrets"
               WHERE tenant_id = $1 AND environment_id = $2 AND is_deleted = false
                 AND ($3::uuid IS NULL OR id > $3::uuid)
               ORDER BY id ASC
               LIMIT $4"#,
        )
        .bind(tenant.0)
        .bind(env_id)
        .bind(cursor_id)
        .bind(params.limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        tx.commit().await.map_err(map_sqlx)?;

        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let next_cursor = if rows.len() == params.limit as usize {
            rows.last().map(|r| r.id.to_string())
        } else {
            None
        };

        Ok(Page {
            items: rows.into_iter().map(Into::into).collect(),
            next_cursor,
        })
    }

    async fn list_secret_versions(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        path: &str,
    ) -> Result<Vec<SecretVersionMeta>> {
        let mut tx = self.tenant_tx(tenant).await?;

        let secret: SecretRow = sqlx::query_as(
            r#"SELECT id, tenant_id, environment_id, path, current_version, cas_required,
                      max_versions, created_at, updated_at
               FROM "01_vault"."05_fct_secrets"
               WHERE tenant_id = $1 AND environment_id = $2 AND path = $3 AND is_deleted = false"#,
        )
        .bind(tenant.0)
        .bind(env_id)
        .bind(path)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?
        .ok_or(Error::NotFound)?;

        // QW-6: filter by tenant_id so a leaked secret_id cannot list another tenant's versions.
        let rows: Vec<(Uuid, i32, String, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
            r#"SELECT secret_id, version, seal_provider, seal_key_id, created_at
                   FROM "01_vault"."06_fct_secret_versions"
                   WHERE secret_id = $1 AND tenant_id = $2
                   ORDER BY version ASC"#,
        )
        .bind(secret.id)
        .bind(tenant.0)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        tx.commit().await.map_err(map_sqlx)?;

        Ok(rows
            .into_iter()
            .map(
                |(secret_id, version, seal_provider, seal_key_id, created_at)| SecretVersionMeta {
                    secret_id,
                    version,
                    seal_provider,
                    seal_key_id,
                    created_at,
                },
            )
            .collect())
    }

    async fn rollback_secret(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        path: &str,
        to_version: i32,
    ) -> Result<Secret> {
        // QW-13: wrap in a transaction; lock the header row first, then re-verify
        // the target version still exists before updating — eliminates the TOCTOU
        // window between the SELECT and the UPDATE.
        // tenant_tx sets app.tenant_id so RLS is active for all queries here.
        let mut tx = self.tenant_tx(tenant).await?;

        let secret: SecretRow = sqlx::query_as(
            r#"SELECT id, tenant_id, environment_id, path, current_version, cas_required,
                      max_versions, created_at, updated_at
               FROM "01_vault"."05_fct_secrets"
               WHERE tenant_id = $1 AND environment_id = $2 AND path = $3 AND is_deleted = false
               FOR UPDATE"#,
        )
        .bind(tenant.0)
        .bind(env_id)
        .bind(path)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?
        .ok_or(Error::NotFound)?;

        // Verify the target version exists (inside the lock).
        let exists: bool = sqlx::query(
            r#"SELECT 1 FROM "01_vault"."06_fct_secret_versions"
               WHERE secret_id = $1 AND version = $2"#,
        )
        .bind(secret.id)
        .bind(to_version)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?
        .is_some();

        if !exists {
            return Err(Error::NotFound);
        }

        let updated: SecretRow = sqlx::query_as(
            r#"UPDATE "01_vault"."05_fct_secrets"
               SET current_version = $1, updated_at = now()
               WHERE id = $2
               RETURNING id, tenant_id, environment_id, path, current_version, cas_required,
                         max_versions, created_at, updated_at"#,
        )
        .bind(to_version)
        .bind(secret.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        tx.commit().await.map_err(map_sqlx)?;
        Ok(updated.into())
    }

    async fn delete_secret(&self, tenant: &TenantId, env_id: Uuid, path: &str) -> Result<()> {
        let mut tx = self.tenant_tx(tenant).await?;

        let affected = sqlx::query(
            r#"UPDATE "01_vault"."05_fct_secrets"
               SET is_deleted = true, deleted_at = now(), updated_at = now()
               WHERE tenant_id = $1 AND environment_id = $2 AND path = $3 AND is_deleted = false"#,
        )
        .bind(tenant.0)
        .bind(env_id)
        .bind(path)
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?
        .rows_affected();

        tx.commit().await.map_err(map_sqlx)?;

        if affected == 0 {
            Err(Error::NotFound)
        } else {
            Ok(())
        }
    }

    // ── Config ────────────────────────────────────────────────────────────────

    async fn put_config(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        key: &str,
        value: &str,
        value_type: ValueType,
        attrs: HashMap<String, String>,
    ) -> Result<ConfigVersion> {
        value_type.validate(value)?;

        // QW-7: verify the environment belongs to this tenant before writing.
        let mut tx = self.tenant_tx(tenant).await?;

        let env_ok: bool = sqlx::query(
            r#"SELECT 1 FROM "01_vault"."04_fct_environments"
               WHERE id = $1 AND tenant_id = $2 AND is_deleted = false"#,
        )
        .bind(env_id)
        .bind(tenant.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?
        .is_some();

        if !env_ok {
            return Err(Error::NotFound);
        }

        let vt_str = value_type.as_str();

        // Upsert config key header.
        let ck: ConfigKeyRow = sqlx::query_as(
            r#"INSERT INTO "01_vault"."07_fct_config_keys"
               (id, tenant_id, environment_id, key, value_type, current_version,
                is_deleted, created_at, updated_at)
               VALUES (gen_random_uuid(), $1, $2, $3, $4, 0, false, now(), now())
               ON CONFLICT (tenant_id, environment_id, key)
               DO UPDATE SET updated_at = "07_fct_config_keys".updated_at
               RETURNING id, tenant_id, environment_id, key, value_type,
                         current_version, created_at, updated_at"#,
        )
        .bind(tenant.0)
        .bind(env_id)
        .bind(key)
        .bind(vt_str)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        tx.commit().await.map_err(map_sqlx)?;

        let new_version =
            ledger::advance_config_version(&self.pool, tenant.0, ck.id, value, vt_str)
                .await?;

        if !attrs.is_empty() {
            attrs::set_attrs(&self.pool, tenant, EntityRef::Config(ck.id), attrs).await?;
        }

        // Fetch the version row to get the DB-stored created_at (avoids clock skew).
        let mut tx2 = self.tenant_tx(tenant).await?;
        let ver: ConfigVersionRow = sqlx::query_as(
            r#"SELECT config_key_id, version, value, value_type, created_at
               FROM "01_vault"."08_fct_config_versions"
               WHERE config_key_id = $1 AND version = $2"#,
        )
        .bind(ck.id)
        .bind(new_version)
        .fetch_one(&mut *tx2)
        .await
        .map_err(map_sqlx)?;
        tx2.commit().await.map_err(map_sqlx)?;

        Ok(ver.into())
    }

    async fn get_config(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        key: &str,
        version: Option<i32>,
    ) -> Result<ConfigVersion> {
        let mut tx = self.tenant_tx(tenant).await?;

        let ck: ConfigKeyRow = sqlx::query_as(
            r#"SELECT id, tenant_id, environment_id, key, value_type,
                      current_version, created_at, updated_at
               FROM "01_vault"."07_fct_config_keys"
               WHERE tenant_id = $1 AND environment_id = $2 AND key = $3 AND is_deleted = false"#,
        )
        .bind(tenant.0)
        .bind(env_id)
        .bind(key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?
        .ok_or(Error::NotFound)?;

        let target_version = version.unwrap_or(ck.current_version);

        let row: ConfigVersionRow = sqlx::query_as(
            r#"SELECT config_key_id, version, value, value_type, created_at
               FROM "01_vault"."08_fct_config_versions"
               WHERE config_key_id = $1 AND version = $2"#,
        )
        .bind(ck.id)
        .bind(target_version)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?
        .ok_or(Error::NotFound)?;

        tx.commit().await.map_err(map_sqlx)?;
        Ok(row.into())
    }

    async fn get_config_resolved(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        key: &str,
        version: Option<i32>,
        resolve_refs: bool,
    ) -> Result<ResolvedConfig> {
        // Walk the inheritance chain: try own env first, then parents.
        let (cv, inherited_from) = get_config_with_inheritance(self, tenant, env_id, key, version).await?;

        if !resolve_refs || cv.value_type != ValueType::SecretRef.as_str() {
            return Ok(ResolvedConfig {
                version: cv,
                resolved_from_ref: false,
                inherited_from,
            });
        }

        // Resolve the ref: the stored value is the secret path in the same env
        // (or the inherited env when the config itself was inherited).
        let ref_path = cv.value.as_deref().ok_or_else(|| {
            Error::Validation("secret_ref config has null value (dangling ref)".to_owned())
        })?;

        // The ref resolves within the *effective* env chain: try the env the config came
        // from first (which may be a parent), then walk up further if still not found.
        let source_env = inherited_from.unwrap_or(env_id);

        let InheritedSecret { revealed, .. } = match self
            .get_secret_inherited(tenant, source_env, ref_path, None)
            .await
        {
            Ok(r) => r,
            Err(Error::NotFound) => {
                return Err(Error::Validation(format!(
                    "secret_ref '{ref_path}' does not exist in environment chain (dangling ref)"
                )));
            }
            Err(e) => return Err(e),
        };

        let plaintext = String::from_utf8_lossy(&revealed.plaintext).into_owned();

        // Return a synthetic ConfigVersion with the resolved plaintext substituted.
        // value_type is changed to "string" to signal the caller it's a concrete value.
        Ok(ResolvedConfig {
            version: ConfigVersion {
                value: Some(plaintext),
                value_type: "string".to_owned(),
                ..cv
            },
            resolved_from_ref: true,
            inherited_from,
        })
    }

    async fn list_config(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        params: ListParams,
    ) -> Result<Page<ConfigKey>> {
        let cursor_id: Option<Uuid> = params.cursor.as_deref().map(decode_cursor).transpose()?;
        let mut tx = self.tenant_tx(tenant).await?;

        let rows: Vec<ConfigKeyRow> = sqlx::query_as(
            r#"SELECT id, tenant_id, environment_id, key, value_type,
                      current_version, created_at, updated_at
               FROM "01_vault"."07_fct_config_keys"
               WHERE tenant_id = $1 AND environment_id = $2 AND is_deleted = false
                 AND ($3::uuid IS NULL OR id > $3::uuid)
               ORDER BY id ASC
               LIMIT $4"#,
        )
        .bind(tenant.0)
        .bind(env_id)
        .bind(cursor_id)
        .bind(params.limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        tx.commit().await.map_err(map_sqlx)?;

        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let next_cursor = if rows.len() == params.limit as usize {
            rows.last().map(|r| r.id.to_string())
        } else {
            None
        };

        Ok(Page {
            items: rows.into_iter().map(Into::into).collect(),
            next_cursor,
        })
    }

    async fn list_config_versions(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        key: &str,
    ) -> Result<Vec<ConfigVersion>> {
        let mut tx = self.tenant_tx(tenant).await?;

        let ck: ConfigKeyRow = sqlx::query_as(
            r#"SELECT id, tenant_id, environment_id, key, value_type,
                      current_version, created_at, updated_at
               FROM "01_vault"."07_fct_config_keys"
               WHERE tenant_id = $1 AND environment_id = $2 AND key = $3 AND is_deleted = false"#,
        )
        .bind(tenant.0)
        .bind(env_id)
        .bind(key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?
        .ok_or(Error::NotFound)?;

        // QW-6: filter by tenant_id so a leaked config_key_id cannot list another tenant's versions.
        let rows: Vec<ConfigVersionRow> = sqlx::query_as(
            r#"SELECT config_key_id, version, value, value_type, created_at
               FROM "01_vault"."08_fct_config_versions"
               WHERE config_key_id = $1 AND tenant_id = $2
               ORDER BY version ASC"#,
        )
        .bind(ck.id)
        .bind(tenant.0)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        tx.commit().await.map_err(map_sqlx)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn rollback_config(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        key: &str,
        to_version: i32,
    ) -> Result<ConfigKey> {
        // QW-13: wrap in a transaction; lock the header row first, then re-verify
        // the target version still exists before updating — eliminates the TOCTOU
        // window between the SELECT and the UPDATE.
        // tenant_tx sets app.tenant_id so RLS is active for all queries here.
        let mut tx = self.tenant_tx(tenant).await?;

        let ck: ConfigKeyRow = sqlx::query_as(
            r#"SELECT id, tenant_id, environment_id, key, value_type,
                      current_version, created_at, updated_at
               FROM "01_vault"."07_fct_config_keys"
               WHERE tenant_id = $1 AND environment_id = $2 AND key = $3 AND is_deleted = false
               FOR UPDATE"#,
        )
        .bind(tenant.0)
        .bind(env_id)
        .bind(key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?
        .ok_or(Error::NotFound)?;

        // Verify target version exists (inside the lock).
        let exists: bool = sqlx::query(
            r#"SELECT 1 FROM "01_vault"."08_fct_config_versions"
               WHERE config_key_id = $1 AND version = $2"#,
        )
        .bind(ck.id)
        .bind(to_version)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?
        .is_some();

        if !exists {
            return Err(Error::NotFound);
        }

        let updated: ConfigKeyRow = sqlx::query_as(
            r#"UPDATE "01_vault"."07_fct_config_keys"
               SET current_version = $1, updated_at = now()
               WHERE id = $2
               RETURNING id, tenant_id, environment_id, key, value_type,
                         current_version, created_at, updated_at"#,
        )
        .bind(to_version)
        .bind(ck.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        tx.commit().await.map_err(map_sqlx)?;
        Ok(updated.into())
    }

    async fn delete_config(&self, tenant: &TenantId, env_id: Uuid, key: &str) -> Result<()> {
        let mut tx = self.tenant_tx(tenant).await?;

        let affected = sqlx::query(
            r#"UPDATE "01_vault"."07_fct_config_keys"
               SET is_deleted = true, deleted_at = now(), updated_at = now()
               WHERE tenant_id = $1 AND environment_id = $2 AND key = $3 AND is_deleted = false"#,
        )
        .bind(tenant.0)
        .bind(env_id)
        .bind(key)
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?
        .rows_affected();

        tx.commit().await.map_err(map_sqlx)?;

        if affected == 0 {
            Err(Error::NotFound)
        } else {
            Ok(())
        }
    }

    // ── EAV attrs ─────────────────────────────────────────────────────────────

    async fn set_attrs(
        &self,
        tenant: &TenantId,
        entity: EntityRef,
        attrs: HashMap<String, String>,
    ) -> Result<()> {
        attrs::set_attrs(&self.pool, tenant, entity, attrs).await
    }

    async fn get_attrs(
        &self,
        tenant: &TenantId,
        entity: EntityRef,
    ) -> Result<HashMap<String, String>> {
        attrs::get_attrs(&self.pool, tenant, entity).await
    }

    // ── EAV registry ──────────────────────────────────────────────────────────

    async fn list_entity_types(&self) -> Result<Vec<EntityType>> {
        // Dim table — no RLS, no tenant context needed.
        let rows: Vec<EntityTypeRow> = sqlx::query_as(
            r#"SELECT id, code, name, description
               FROM "01_vault"."01_dim_entity_types"
               ORDER BY code ASC"#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn list_attr_defs(&self, entity_type: &str) -> Result<Vec<AttrDef>> {
        // Dim table — no RLS, no tenant context needed.
        let rows: Vec<AttrDefRow> = sqlx::query_as(
            r#"SELECT id, entity_type, code, name, data_type, is_required, is_pii, sort_order
               FROM "01_vault"."02_dim_attr_defs"
               WHERE entity_type = $1
               ORDER BY sort_order ASC, code ASC"#,
        )
        .bind(entity_type)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_attr_def(
        &self,
        entity_type: &str,
        code: &str,
        name: &str,
        data_type: &str,
        is_required: bool,
        is_pii: bool,
        sort_order: i32,
    ) -> Result<AttrDef> {
        // Dim table — no RLS, no tenant context needed.
        const ALLOWED_DATA_TYPES: &[&str] = &["text", "int", "float", "bool", "json"];
        if !ALLOWED_DATA_TYPES.contains(&data_type) {
            return Err(Error::Validation(format!(
                "invalid data_type: {data_type}. Allowed: text, int, float, bool, json"
            )));
        }

        let row: AttrDefRow = sqlx::query_as(
            r#"INSERT INTO "01_vault"."02_dim_attr_defs"
               (id, entity_type, code, name, data_type, is_required, is_pii, sort_order, created_at, updated_at)
               VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, now(), now())
               RETURNING id, entity_type, code, name, data_type, is_required, is_pii, sort_order"#,
        )
        .bind(entity_type)
        .bind(code)
        .bind(name)
        .bind(data_type)
        .bind(is_required)
        .bind(is_pii)
        .bind(sort_order)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(row.into())
    }

    async fn update_attr_def(
        &self,
        id: Uuid,
        name: Option<&str>,
        is_required: Option<bool>,
        is_pii: Option<bool>,
        sort_order: Option<i32>,
    ) -> Result<AttrDef> {
        // Dim table — no RLS, no tenant context needed.
        let row: AttrDefRow = sqlx::query_as(
            r#"UPDATE "01_vault"."02_dim_attr_defs"
               SET name        = COALESCE($2, name),
                   is_required = COALESCE($3, is_required),
                   is_pii      = COALESCE($4, is_pii),
                   sort_order  = COALESCE($5, sort_order),
                   updated_at  = now()
               WHERE id = $1
               RETURNING id, entity_type, code, name, data_type, is_required, is_pii, sort_order"#,
        )
        .bind(id)
        .bind(name)
        .bind(is_required)
        .bind(is_pii)
        .bind(sort_order)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?
        .ok_or(Error::NotFound)?;

        Ok(row.into())
    }

    async fn delete_attr_def(&self, id: Uuid) -> Result<()> {
        // Dim table — no RLS, no tenant context needed.
        let affected = sqlx::query(r#"DELETE FROM "01_vault"."02_dim_attr_defs" WHERE id = $1"#)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?
            .rows_affected();

        if affected == 0 {
            Err(Error::NotFound)
        } else {
            Ok(())
        }
    }

    // ── Auth tokens ───────────────────────────────────────────────────────────

    async fn create_token(&self, tenant: &TenantId, name: &str) -> Result<(AuthToken, String)> {
        use rand::RngCore;

        let mut raw = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let token_str = hex::encode(&raw);
        let hash = hex::encode(Sha256::digest(token_str.as_bytes()));

        let mut tx = self.tenant_tx(tenant).await?;

        let row: AuthTokenRow = sqlx::query_as(
            r#"INSERT INTO "01_vault"."11_fct_auth_tokens"
               (id, tenant_id, name, token_hash, is_revoked, created_at)
               VALUES (gen_random_uuid(), $1, $2, $3, false, now())
               RETURNING id, tenant_id, name, role, created_at, last_used_at"#,
        )
        .bind(tenant.0)
        .bind(name)
        .bind(&hash)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        tx.commit().await.map_err(map_sqlx)?;
        Ok((row.into(), token_str))
    }

    async fn find_token_by_plaintext(
        &self,
        token: &str,
    ) -> Result<Option<AuthToken>> {
        // This is a cross-tenant bootstrap lookup: we search by token hash to
        // discover which tenant owns the token.  No tenant context is available
        // yet, so app.tenant_id is intentionally left unset.  The RLS
        // `token_lookup` policy on 11_fct_auth_tokens permits SELECT when
        // app.tenant_id is absent.  Possession of the correct 256-bit hash is
        // the authentication factor, so this broad SELECT is safe.
        let hash = hex::encode(Sha256::digest(token.as_bytes()));

        let row: Option<AuthTokenRow> = sqlx::query_as(
            r#"SELECT id, tenant_id, name, role, created_at, last_used_at
               FROM "01_vault"."11_fct_auth_tokens"
               WHERE token_hash = $1 AND is_revoked = false
                 AND (expires_at IS NULL OR expires_at > now())"#,
        )
        .bind(&hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;

        if let Some(ref r) = row {
            // Update last_used_at; ignore errors (best-effort).
            // We know the tenant now, so we use a tenant_tx for this write.
            let tenant = TenantId(r.tenant_id);
            if let Ok(mut tx) = self.tenant_tx(&tenant).await {
                let _ = sqlx::query(
                    r#"UPDATE "01_vault"."11_fct_auth_tokens"
                       SET last_used_at = now()
                       WHERE id = $1"#,
                )
                .bind(r.id)
                .execute(&mut *tx)
                .await;
                let _ = tx.commit().await;
            }
        }

        Ok(row.map(Into::into))
    }

    async fn list_tokens(&self, tenant: &TenantId) -> Result<Vec<AuthToken>> {
        let mut tx = self.tenant_tx(tenant).await?;

        let rows: Vec<AuthTokenRow> = sqlx::query_as(
            r#"SELECT id, tenant_id, name, role, created_at, last_used_at
               FROM "01_vault"."11_fct_auth_tokens"
               WHERE tenant_id = $1 AND is_revoked = false
               ORDER BY created_at ASC"#,
        )
        .bind(tenant.0)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        tx.commit().await.map_err(map_sqlx)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn revoke_token(&self, tenant: &TenantId, token_id: Uuid) -> Result<()> {
        let mut tx = self.tenant_tx(tenant).await?;

        let affected = sqlx::query(
            r#"UPDATE "01_vault"."11_fct_auth_tokens"
               SET is_revoked = true
               WHERE id = $1 AND tenant_id = $2 AND is_revoked = false"#,
        )
        .bind(token_id)
        .bind(tenant.0)
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?
        .rows_affected();

        tx.commit().await.map_err(map_sqlx)?;

        if affected == 0 {
            Err(Error::NotFound)
        } else {
            Ok(())
        }
    }

    async fn count_tokens(&self, tenant: &TenantId) -> Result<i64> {
        let mut tx = self.tenant_tx(tenant).await?;

        let row: (i64,) = sqlx::query_as(
            r#"SELECT COUNT(*) FROM "01_vault"."11_fct_auth_tokens"
               WHERE tenant_id = $1 AND is_revoked = false"#,
        )
        .bind(tenant.0)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        tx.commit().await.map_err(map_sqlx)?;
        Ok(row.0)
    }

    async fn create_token_with_value(
        &self,
        tenant: &TenantId,
        name: &str,
        plaintext: &str,
    ) -> Result<AuthToken> {
        let hash = hex::encode(Sha256::digest(plaintext.as_bytes()));

        let mut tx = self.tenant_tx(tenant).await?;

        // QW-4: idempotent bootstrap — if a token with this (tenant_key, name) already
        // exists (e.g. two pods racing at cold start) the INSERT is a no-op and we
        // return the existing row.  No new migration needed: the uniqueness guard is
        // enforced by the WHERE NOT EXISTS subquery, not a DB constraint.
        let row: Option<AuthTokenRow> = sqlx::query_as(
            r#"INSERT INTO "01_vault"."11_fct_auth_tokens"
               (id, tenant_id, name, token_hash, is_revoked, created_at)
               SELECT gen_random_uuid(), $1, $2, $3, false, now()
               WHERE NOT EXISTS (
                   SELECT 1 FROM "01_vault"."11_fct_auth_tokens"
                   WHERE tenant_id = $1 AND name = $2
               )
               RETURNING id, tenant_id, name, role, created_at, last_used_at"#,
        )
        .bind(tenant.0)
        .bind(name)
        .bind(&hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        // If INSERT was a no-op, fetch the existing row.
        let row = match row {
            Some(r) => r,
            None => sqlx::query_as(
                r#"SELECT id, tenant_id, name, role, created_at, last_used_at
                   FROM "01_vault"."11_fct_auth_tokens"
                   WHERE tenant_id = $1 AND name = $2"#,
            )
            .bind(tenant.0)
            .bind(name)
            .fetch_one(&mut *tx)
            .await
            .map_err(map_sqlx)?,
        };

        tx.commit().await.map_err(map_sqlx)?;
        Ok(row.into())
    }

    // ── Export ────────────────────────────────────────────────────────────────

    async fn export(&self, tenant: &TenantId, env_id: Uuid) -> Result<ExportBundle> {
        let mut tx = self.tenant_tx(tenant).await?;

        // 1. Load all current config versions.
        let config_rows: Vec<(String, Option<String>)> = sqlx::query_as(
            r#"SELECT ck.key, cv.value
               FROM "01_vault"."07_fct_config_keys" ck
               JOIN "01_vault"."08_fct_config_versions" cv
                 ON cv.config_key_id = ck.id AND cv.version = ck.current_version
               WHERE ck.tenant_id = $1 AND ck.environment_id = $2
                 AND ck.is_deleted = false AND ck.current_version > 0"#,
        )
        .bind(tenant.0)
        .bind(env_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        let mut values: HashMap<String, String> = config_rows
            .into_iter()
            .filter_map(|(k, v)| v.map(|vv| (k, vv)))
            .collect();

        // 2. Load all current secret versions (with ciphertext).
        let secret_rows: Vec<(
            Uuid,
            String,
            i32,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            String,
            String,
        )> = sqlx::query_as(
            r#"SELECT s.id, s.path, sv.version, sv.ciphertext, sv.nonce,
                          sv.wrapped_dek, sv.aad, sv.seal_provider, sv.seal_key_id
                   FROM "01_vault"."05_fct_secrets" s
                   JOIN "01_vault"."06_fct_secret_versions" sv
                     ON sv.secret_id = s.id AND sv.version = s.current_version
                   WHERE s.tenant_id = $1 AND s.environment_id = $2
                     AND s.is_deleted = false AND s.current_version > 0"#,
        )
        .bind(tenant.0)
        .bind(env_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        tx.commit().await.map_err(map_sqlx)?;

        let mut decrypt_errors: Vec<(String, String)> = Vec::new();

        // QW-8: derive the tenant KEK once before the loop (same for all rows in this export).
        let tenant_kek = self.kek.derive_tenant_kek(tenant.0);

        for (
            secret_id,
            path,
            version,
            ciphertext,
            nonce,
            wrapped_dek,
            aad,
            seal_provider,
            seal_key_id,
        ) in secret_rows
        {
            let sealed = match seal_provider.parse::<soma_crypto::SealProvider>() {
                Ok(sp) => soma_crypto::Sealed {
                    ciphertext,
                    nonce,
                    wrapped_dek,
                    aad,
                    seal_provider: sp,
                    seal_key_id,
                },
                Err(e) => {
                    decrypt_errors.push((path, e.to_string()));
                    continue;
                }
            };

            match soma_crypto::decrypt_checked(&tenant_kek, &sealed, secret_id, i64::from(version)) {
                Ok(plaintext) => {
                    let value = String::from_utf8_lossy(&plaintext).into_owned();
                    if values.contains_key(&path) {
                        tracing::warn!(
                            path = %path,
                            "export: secret overwrites config value for key"
                        );
                    }
                    values.insert(path, value);
                }
                Err(e) => {
                    decrypt_errors.push((path, e.to_string()));
                }
            }
        }

        Ok(ExportBundle {
            values,
            decrypt_errors,
        })
    }

    async fn export_effective(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        resolve_refs: bool,
    ) -> Result<EffectiveExportBundle> {
        // Build an ordered chain: [env_id, parent, grandparent, ...] (child first).
        let chain = build_env_chain(&self.pool, tenant.0, env_id).await?;

        // Collect the plain ExportBundle for each env in the chain, starting from the
        // oldest ancestor (last) so that newer envs override.
        // We accumulate in a map; earlier (parent) entries are inserted first, then
        // child entries overwrite.
        let mut values: HashMap<String, ExportEntry> = HashMap::new();
        let mut decrypt_errors: Vec<(String, String)> = Vec::new();

        // Process ancestor-to-child order (chain is child-first, so reverse it).
        for &ancestor_env in chain.iter().rev() {
            let bundle = self.export(tenant, ancestor_env).await?;
            for (key, value) in bundle.values {
                let inherited_from = if ancestor_env == env_id { None } else { Some(ancestor_env) };
                values.insert(key, ExportEntry { value, inherited_from });
            }
            decrypt_errors.extend(bundle.decrypt_errors);
        }

        // Resolve secret_ref config entries if requested.
        if resolve_refs {
            let mut resolved_values: HashMap<String, ExportEntry> = HashMap::new();
            for (key, entry) in &values {
                // We need to know the value_type; export only returns the value string.
                // Re-check via get_config_resolved which already handles inheritance.
                match self.get_config_resolved(tenant, env_id, key, None, true).await {
                    Ok(rc) if rc.resolved_from_ref => {
                        if let Some(v) = rc.version.value {
                            resolved_values.insert(key.clone(), ExportEntry {
                                value: v,
                                inherited_from: entry.inherited_from,
                            });
                        }
                    }
                    Ok(_) | Err(Error::NotFound) => {
                        // Not a config key or not a ref — keep the original entry.
                    }
                    Err(Error::Validation(msg)) => {
                        // Dangling ref — report as a decrypt error rather than aborting.
                        decrypt_errors.push((key.clone(), format!("secret_ref resolution failed: {msg}")));
                        resolved_values.insert(key.clone(), entry.clone());
                    }
                    Err(e) => return Err(e),
                }
            }
            // Merge resolved entries back.
            for (key, entry) in resolved_values {
                values.insert(key, entry);
            }
        }

        Ok(EffectiveExportBundle { values, decrypt_errors })
    }

    // ── Audit log ─────────────────────────────────────────────────────────────

    async fn record_audit(&self, event: AuditEvent) -> Result<()> {
        audit::record_audit(&self.pool, &self.audit_hmac_key, event).await
    }

    async fn list_audit(&self, tenant: &TenantId, filters: AuditFilters) -> Result<Page<AuditEvent>> {
        audit::list_audit(&self.pool, tenant, filters).await
    }

    async fn verify_audit_chain(&self, tenant: &TenantId) -> Result<AuditVerifyResult> {
        audit::verify_audit_chain(&self.pool, &self.audit_hmac_key, tenant).await
    }
}

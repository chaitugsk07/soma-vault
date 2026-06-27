use std::collections::HashMap;

use async_trait::async_trait;
use uuid::Uuid;

/// Caller-supplied context for atomic audit recording inside a business transaction.
pub struct AuditCtx {
    /// Identity of the actor that initiated the operation.
    pub actor_id: Uuid,
    /// Role of the actor (e.g. "admin", "developer").
    pub actor_role: String,
    /// Audit event type string (e.g. "project.create").
    pub event_type: &'static str,
    /// Resource category (e.g. "project", "secret").
    pub resource_type: &'static str,
    /// Identifier for the specific resource (e.g. project code, secret path).
    pub resource_id: String,
}

use crate::types::{
    AttrDef, AuthToken, ConfigKey, ConfigVersion,
    EffectiveExportBundle, EntityRef, EntityType, Environment, ExportBundle, InheritedSecret,
    ListParams, Page, Project, ResolvedConfig, RevealedSecret, Secret, SecretVersionMeta, TenantId,
    ValueType,
};
use crate::Result;

/// Core data-access contract for soma-vault.
///
/// All methods are tenant-scoped: callers supply a [`TenantId`] and the
/// implementation enforces the boundary — no query may cross a tenant.
#[async_trait]
pub trait DataStore: Send + Sync {
    // ── Migrations ────────────────────────────────────────────────────────────

    /// Run pending migrations (idempotent).
    async fn migrate(&self) -> Result<()>;

    /// Liveness check for the backing store — used by readiness probes.
    async fn ping(&self) -> Result<()>;

    // ── Projects ──────────────────────────────────────────────────────────────

    /// Create a new project.
    async fn create_project(
        &self,
        tenant: &TenantId,
        code: &str,
        name: &str,
        description: Option<&str>,
    ) -> Result<Project>;

    /// Fetch a project by ID (must belong to `tenant`).
    async fn get_project(&self, tenant: &TenantId, project_id: Uuid) -> Result<Project>;

    /// List all active projects for a tenant (keyset-paginated).
    async fn list_projects(&self, tenant: &TenantId, params: ListParams) -> Result<Page<Project>>;

    // ── Environments ──────────────────────────────────────────────────────────

    /// Create a new environment inside a project.
    ///
    /// `parent_env_id` — when `Some`, this environment inherits secrets/config from the parent
    /// env when a key is not set locally.  The parent must be in the same project + tenant.
    /// Creating a cycle or exceeding a depth of 5 is rejected with [`crate::Error::Validation`].
    async fn create_environment(
        &self,
        tenant: &TenantId,
        project_id: Uuid,
        code: &str,
        name: &str,
        parent_env_id: Option<Uuid>,
    ) -> Result<Environment>;

    /// Fetch an environment by ID.
    async fn get_environment(&self, tenant: &TenantId, env_id: Uuid) -> Result<Environment>;

    /// List all active environments in a project.
    async fn list_environments(
        &self,
        tenant: &TenantId,
        project_id: Uuid,
    ) -> Result<Vec<Environment>>;

    // ── Secrets ───────────────────────────────────────────────────────────────

    /// Encrypt and store a new secret version (creates or updates the secret at `path`).
    ///
    /// `cas` is the expected `current_version` when `cas_required = true`.
    async fn put_secret(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        path: &str,
        plaintext: &[u8],
        attrs: HashMap<String, String>,
        cas: Option<i32>,
    ) -> Result<SecretVersionMeta>;

    /// Decrypt and return a secret version. `version = None` returns the current pointer.
    ///
    /// When `inherit = true` and the secret is not found in `env_id`, the method walks the
    /// parent chain (depth ≤ 5) and returns the first ancestor that has the secret, marking
    /// `InheritedSecret::inherited_from` with the ancestor env id.
    async fn get_secret(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        path: &str,
        version: Option<i32>,
    ) -> Result<RevealedSecret>;

    /// Like `get_secret` but walks the parent chain on miss.
    async fn get_secret_inherited(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        path: &str,
        version: Option<i32>,
    ) -> Result<InheritedSecret>;

    /// List secrets in an environment (keyset-paginated, excludes deleted).
    async fn list_secrets(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        params: ListParams,
    ) -> Result<Page<Secret>>;

    /// List all version metadata rows for a secret path.
    async fn list_secret_versions(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        path: &str,
    ) -> Result<Vec<SecretVersionMeta>>;

    /// Move the current-version pointer to an existing version number.
    async fn rollback_secret(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        path: &str,
        to_version: i32,
    ) -> Result<Secret>;

    /// Soft-delete a secret.
    async fn delete_secret(&self, tenant: &TenantId, env_id: Uuid, path: &str) -> Result<()>;

    // ── Config ────────────────────────────────────────────────────────────────

    /// Store a new config version.
    async fn put_config(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        key: &str,
        value: &str,
        value_type: ValueType,
        attrs: HashMap<String, String>,
    ) -> Result<ConfigVersion>;

    /// Fetch a config version. `version = None` returns the current pointer.
    ///
    /// When `resolve_refs = true` and the value type is `secret_ref`, the method
    /// decrypts the referenced secret and returns its plaintext as the value.
    /// The response includes `resolved_from_ref = true` in that case.
    ///
    /// When `inherit = true`, walks the parent env chain on miss.
    async fn get_config(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        key: &str,
        version: Option<i32>,
    ) -> Result<ConfigVersion>;

    /// Like `get_config` but supports ref resolution and env inheritance.
    async fn get_config_resolved(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        key: &str,
        version: Option<i32>,
        resolve_refs: bool,
    ) -> Result<ResolvedConfig>;

    /// List config keys in an environment (keyset-paginated, excludes deleted).
    async fn list_config(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        params: ListParams,
    ) -> Result<Page<ConfigKey>>;

    /// List all version rows for a config key.
    async fn list_config_versions(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        key: &str,
    ) -> Result<Vec<ConfigVersion>>;

    /// Move the config key's current-version pointer to an existing version.
    async fn rollback_config(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        key: &str,
        to_version: i32,
    ) -> Result<ConfigKey>;

    /// Soft-delete a config key.
    async fn delete_config(&self, tenant: &TenantId, env_id: Uuid, key: &str) -> Result<()>;

    // ── EAV attrs ─────────────────────────────────────────────────────────────

    /// Upsert a set of EAV attributes onto a secret or config key.
    async fn set_attrs(
        &self,
        tenant: &TenantId,
        entity: EntityRef,
        attrs: HashMap<String, String>,
    ) -> Result<()>;

    /// Read all EAV attributes for a secret or config key.
    async fn get_attrs(
        &self,
        tenant: &TenantId,
        entity: EntityRef,
    ) -> Result<HashMap<String, String>>;

    // ── EAV registry ──────────────────────────────────────────────────────────

    /// List all entity types.
    async fn list_entity_types(&self) -> Result<Vec<EntityType>>;

    /// List attribute definitions for an entity type.
    async fn list_attr_defs(&self, entity_type: &str) -> Result<Vec<AttrDef>>;

    /// Create a new attribute definition.
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
    ) -> Result<AttrDef>;

    /// Update mutable fields on an attribute definition.
    async fn update_attr_def(
        &self,
        id: Uuid,
        name: Option<&str>,
        is_required: Option<bool>,
        is_pii: Option<bool>,
        sort_order: Option<i32>,
    ) -> Result<AttrDef>;

    /// Delete an attribute definition.
    async fn delete_attr_def(&self, id: Uuid) -> Result<()>;

    // ── Auth tokens ───────────────────────────────────────────────────────────

    /// Create a new auth token. Returns `(AuthToken metadata, plaintext token)`.
    ///
    /// The plaintext token is returned exactly once — it is not stored.
    async fn create_token(&self, tenant: &TenantId, name: &str) -> Result<(AuthToken, String)>;

    /// Look up a token by its plaintext value and update `last_used_at`.
    ///
    /// Returns `Ok(None)` when the token is not found or is revoked (not an error).
    /// The token carries its own `tenant_id` — no caller-supplied tenant required.
    async fn find_token_by_plaintext(
        &self,
        token: &str,
    ) -> Result<Option<AuthToken>>;

    /// List all active (non-revoked) tokens for a tenant.
    async fn list_tokens(&self, tenant: &TenantId) -> Result<Vec<AuthToken>>;

    /// Revoke a token by ID.
    async fn revoke_token(&self, tenant: &TenantId, token_id: Uuid) -> Result<()>;

    /// Count active tokens for a tenant.
    async fn count_tokens(&self, tenant: &TenantId) -> Result<i64>;

    /// Create a token with a caller-supplied plaintext value.
    ///
    /// Like [`create_token`] but uses the provided `plaintext` instead of
    /// generating a random one. The plaintext is SHA-256-hashed before storage.
    /// Intended for bootstrap only (D8): persists a known root token at startup.
    async fn create_token_with_value(
        &self,
        tenant: &TenantId,
        name: &str,
        plaintext: &str,
    ) -> Result<AuthToken>;

    // ── Export ────────────────────────────────────────────────────────────────

    /// Export all current config + secrets for an environment as a merged map.
    ///
    /// Secrets win on key collision; failed decryptions are isolated and reported
    /// in [`ExportBundle::decrypt_errors`] rather than aborting the whole export.
    async fn export(&self, tenant: &TenantId, env_id: Uuid) -> Result<ExportBundle>;

    /// Export the *effective* set for an environment: own values overlaid on the
    /// inherited parent chain.  `resolve_refs = true` additionally decrypts
    /// `secret_ref` config entries inline.
    async fn export_effective(
        &self,
        tenant: &TenantId,
        env_id: Uuid,
        resolve_refs: bool,
    ) -> Result<EffectiveExportBundle>;

}

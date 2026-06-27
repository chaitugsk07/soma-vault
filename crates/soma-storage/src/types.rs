use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Opaque tenant identifier. Wraps the stable UUID for the tenant.
///
/// The default value is the deterministic v5 UUID derived from the slug `"default"`
/// in the OID namespace: `02e81b29-f150-54b9-9a08-ce75944f6889`.
/// This matches what `Uuid::new_v5(&Uuid::NAMESPACE_OID, b"default")` returns.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(pub Uuid);

impl Default for TenantId {
    fn default() -> Self {
        // ponytail: deterministic v5 UUID; matches the seeded row in 00_dim_tenants.
        Self(Uuid::new_v5(&Uuid::NAMESPACE_OID, b"default"))
    }
}

impl TenantId {
    /// Derive a `TenantId` from a human slug via v5 UUID (OID namespace).
    ///
    /// Used during bootstrap and for named tenants before a DB lookup is available.
    #[must_use]
    pub fn from_code(code: &str) -> Self {
        Self(Uuid::new_v5(&Uuid::NAMESPACE_OID, code.as_bytes()))
    }

    /// The inner UUID.
    #[must_use]
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl From<Uuid> for TenantId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

/// Access role carried by an auth token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Full administrative access.
    Admin,
    /// Read and write access to secrets and config.
    Developer,
    /// Read-only access.
    Reader,
}

impl std::str::FromStr for Role {
    type Err = crate::Error;

    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "admin" => Ok(Self::Admin),
            "developer" => Ok(Self::Developer),
            "reader" => Ok(Self::Reader),
            other => Err(crate::Error::Validation(format!("unknown role: {other}"))),
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admin => write!(f, "admin"),
            Self::Developer => write!(f, "developer"),
            Self::Reader => write!(f, "reader"),
        }
    }
}

/// Config value type — mirrors the `value_type` CHECK constraint in the DB.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    /// Plain text string.
    String,
    /// 64-bit integer.
    Int,
    /// 64-bit float.
    Float,
    /// Boolean (`true` / `false`).
    Bool,
    /// Arbitrary JSON.
    Json,
    /// A reference to a secret path.
    SecretRef,
}

impl ValueType {
    /// DB-safe lowercase string for this type.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Int => "int",
            Self::Float => "float",
            Self::Bool => "bool",
            Self::Json => "json",
            Self::SecretRef => "secret_ref",
        }
    }

    /// Validate that `raw` is a legal value for this type.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Validation`] when the value does not match the type.
    pub fn validate(&self, raw: &str) -> crate::Result<()> {
        match self {
            Self::String | Self::SecretRef => Ok(()),
            Self::Int => raw
                .trim()
                .parse::<i64>()
                .map(|_| ())
                .map_err(|_| crate::Error::Validation(format!("expected int, got {raw:?}"))),
            Self::Float => raw
                .trim()
                .parse::<f64>()
                .map(|_| ())
                .map_err(|_| crate::Error::Validation(format!("expected float, got {raw:?}"))),
            Self::Bool => match raw.trim() {
                "true" | "false" => Ok(()),
                other => Err(crate::Error::Validation(format!(
                    "expected bool (true/false), got {other:?}"
                ))),
            },
            Self::Json => serde_json::from_str::<serde_json::Value>(raw)
                .map(|_| ())
                .map_err(|e| crate::Error::Validation(format!("invalid JSON: {e}"))),
        }
    }
}

impl std::str::FromStr for ValueType {
    type Err = crate::Error;

    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "string" => Ok(Self::String),
            "int" => Ok(Self::Int),
            "float" => Ok(Self::Float),
            "bool" => Ok(Self::Bool),
            "json" => Ok(Self::Json),
            "secret_ref" => Ok(Self::SecretRef),
            other => Err(crate::Error::Validation(format!(
                "unknown value_type: {other}"
            ))),
        }
    }
}

/// Selects which EAV detail table to operate on.
#[derive(Debug, Clone, Copy)]
pub enum EntityRef {
    /// EAV for a secret row (table `09_dtl_secret_attrs`).
    Secret(Uuid),
    /// EAV for a config key row (table `10_dtl_config_attrs`).
    Config(Uuid),
}

/// Keyset pagination parameters. Cursor is the last row's `id` (UUID string).
#[derive(Debug, Clone)]
pub struct ListParams {
    /// Opaque cursor from a previous page.
    pub cursor: Option<String>,
    /// Maximum items to return per page.
    pub limit: i64,
}

impl Default for ListParams {
    fn default() -> Self {
        Self {
            cursor: None,
            limit: 100,
        }
    }
}

/// A page of results with an optional cursor for the next page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page<T> {
    /// Items in this page.
    pub items: Vec<T>,
    /// Cursor to pass for the next page, or `None` if this is the last page.
    pub next_cursor: Option<String>,
}

/// A project (top-level tenant-scoped resource).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    /// Primary key.
    pub id: Uuid,
    /// Tenant that owns this project.
    pub tenant_id: Uuid,
    /// Short unique code within the tenant.
    pub code: String,
    /// Human-readable name.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Row creation time.
    pub created_at: DateTime<Utc>,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
}

/// An environment within a project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Environment {
    /// Primary key.
    pub id: Uuid,
    /// Tenant that owns this environment.
    pub tenant_id: Uuid,
    /// Parent project.
    pub project_id: Uuid,
    /// Short unique code within the project.
    pub code: String,
    /// Human-readable name.
    pub name: String,
    /// Optional parent environment for inheritance. `None` = root.
    pub parent_env_id: Option<Uuid>,
    /// Row creation time.
    pub created_at: DateTime<Utc>,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
}

/// A secret (header row — no plaintext here).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    /// Primary key.
    pub id: Uuid,
    /// Tenant that owns this secret.
    pub tenant_id: Uuid,
    /// Parent environment.
    pub environment_id: Uuid,
    /// Path within the environment (e.g. `"db/password"`).
    pub path: String,
    /// Version pointer — the currently-active version number.
    pub current_version: i32,
    /// Whether CAS is required for writes.
    pub cas_required: bool,
    /// Maximum number of versions to keep (pruning not yet implemented).
    pub max_versions: i32,
    /// Row creation time.
    pub created_at: DateTime<Utc>,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
}

/// Metadata for one secret version (no ciphertext exposed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersionMeta {
    /// Parent secret.
    pub secret_id: Uuid,
    /// Version number (1-based).
    pub version: i32,
    /// Which KMS backend sealed the DEK.
    pub seal_provider: String,
    /// Key fingerprint.
    pub seal_key_id: String,
    /// When this version was created.
    pub created_at: DateTime<Utc>,
}

/// A decrypted secret. Plaintext is zeroized on drop.
///
/// Intentionally does NOT implement `Clone` (cloning plaintext is a security smell) or
/// derive `Debug` (the compiler-generated form would print raw bytes). Instead a manual
/// redacting `Debug` impl is provided.
pub struct RevealedSecret {
    /// Secret header metadata.
    pub meta: Secret,
    /// Version that was decrypted.
    pub version: i32,
    /// Decrypted plaintext — zeroized when dropped.
    pub plaintext: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for RevealedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevealedSecret")
            .field("path", &self.meta.path)
            .field("version", &self.version)
            .field("plaintext", &"[REDACTED]")
            .finish()
    }
}

/// A config key (header row — no value here).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigKey {
    /// Primary key.
    pub id: Uuid,
    /// Tenant that owns this key.
    pub tenant_id: Uuid,
    /// Parent environment.
    pub environment_id: Uuid,
    /// Key name.
    pub key: String,
    /// Type of the current value.
    pub value_type: String,
    /// Version pointer.
    pub current_version: i32,
    /// Row creation time.
    pub created_at: DateTime<Utc>,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
}

/// One version of a config value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigVersion {
    /// Parent config key.
    pub config_key_id: Uuid,
    /// Version number (1-based).
    pub version: i32,
    /// String-encoded value (may be `None` for future tombstone support).
    pub value: Option<String>,
    /// Type of the value.
    pub value_type: String,
    /// When this version was created.
    pub created_at: DateTime<Utc>,
}

/// A config value with optional secret-ref resolution metadata.
///
/// Serializes flat for backward-compatible API responses: the `ConfigVersion`
/// fields (`config_key_id`, `version`, `value`, `value_type`, `created_at`)
/// appear at the top level alongside `resolved_from_ref` and `inherited_from`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedConfig {
    /// The config version row (raw ref path when not resolved).
    #[serde(flatten)]
    pub version: ConfigVersion,
    /// Whether the value was resolved from a `secret_ref` (decrypted inline).
    pub resolved_from_ref: bool,
    /// If inherited via env chain, the env id it came from.
    pub inherited_from: Option<Uuid>,
}

/// A revealed secret with optional inheritance metadata.
///
/// Does NOT implement `Clone` (moving plaintext is safe; cloning is not).
/// Provides a manual redacting `Debug` impl (delegates to `RevealedSecret`'s).
pub struct InheritedSecret {
    /// The decrypted secret.
    pub revealed: RevealedSecret,
    /// If inherited via env chain, the env id it came from.
    pub inherited_from: Option<Uuid>,
}

impl std::fmt::Debug for InheritedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InheritedSecret")
            .field("revealed", &self.revealed)
            .field("inherited_from", &self.inherited_from)
            .finish()
    }
}

/// Result of [`crate::DataStore::export_effective`].
pub struct EffectiveExportBundle {
    /// Merged effective `name → value` map (child overrides parent).
    pub values: std::collections::HashMap<String, ExportEntry>,
    /// Secrets that failed to decrypt: `(path, error_description)`.
    pub decrypt_errors: Vec<(String, String)>,
}

/// One entry in the effective export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    /// The resolved value string.
    pub value: String,
    /// Whether this entry was inherited from a parent environment.
    pub inherited_from: Option<Uuid>,
}

/// An API auth token (only the metadata — never the plaintext).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    /// Primary key.
    pub id: Uuid,
    /// Owning tenant.
    pub tenant_id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// Role associated with this token.
    pub role: Role,
    /// When the token was created.
    pub created_at: DateTime<Utc>,
    /// When the token was last used (or `None`).
    pub last_used_at: Option<DateTime<Utc>>,
}

/// An entity type in the EAV registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityType {
    /// Primary key.
    pub id: Uuid,
    /// Short code (e.g. `"secret"`, `"config_key"`).
    pub code: String,
    /// Human-readable name.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
}

/// An attribute definition in the EAV registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttrDef {
    /// Primary key.
    pub id: Uuid,
    /// Parent entity type code.
    pub entity_type: String,
    /// Attribute code (`property_key` in detail rows).
    pub code: String,
    /// Human-readable name.
    pub name: String,
    /// Data type (`text`, `int`, `float`, `bool`, `json`).
    pub data_type: String,
    /// Whether all entities of this type must supply this attribute.
    pub is_required: bool,
    /// Whether this attribute is PII and should be treated carefully.
    pub is_pii: bool,
    /// Display sort order.
    pub sort_order: i32,
}

/// Result of [`crate::DataStore::export`].
pub struct ExportBundle {
    /// Merged `name → value` map. Secrets win over config on key collision.
    pub values: std::collections::HashMap<String, String>,
    /// Secrets that failed to decrypt: `(path, error_description)`.
    pub decrypt_errors: Vec<(String, String)>,
}


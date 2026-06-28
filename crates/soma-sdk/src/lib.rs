//! # soma-sdk
//!
//! In-process Rust client for [soma-vault](https://github.com/chaitugsk07/soma-vault).
//! Read secrets and config in your application — no shelling out to the CLI.
//!
//! ## Plug-and-play: zero-config injection
//!
//! Set `SOMA_URL`, `SOMA_TOKEN`, `SOMA_PROJECT`, `SOMA_ENVIRONMENT` in your
//! environment, then at the top of `main`:
//!
//! ```rust,no_run
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Load all secrets+config and inject them into the process environment.
//!     // Vault values overwrite any existing env var with the same name.
//!     soma_sdk::init().await?;
//!
//!     // Your existing code reads from the environment — no .env file needed.
//!     let db_url = std::env::var("DATABASE_URL")?;
//!     Ok(())
//! }
//! ```
//!
//! ## Typed config struct
//!
//! ```rust,no_run
//! use serde::Deserialize;
//!
//! #[derive(Deserialize)]
//! struct Config {
//!     database_password: String,  // vault path "database/password"
//!     server_port: u16,           // vault path "server/port", value "8080" coerced to u16
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let cfg: Config = soma_sdk::from_env().await?;
//!     println!("port={}", cfg.server_port);
//!     Ok(())
//! }
//! ```
//!
//! ## Key mapping
//!
//! Vault path → env var name (same rule as `soma run` / `soma export`):
//! uppercase every letter, replace every non-`[A-Z0-9]` character with `_`.
//!
//! | Vault path          | Env var / struct field       |
//! |---------------------|------------------------------|
//! | `database/password` | `DATABASE_PASSWORD` / `database_password` |
//! | `server/port`       | `SERVER_PORT` / `server_port`             |
//! | `db-host`           | `DB_HOST` / `db_host`                     |
//!
//! ## Manual client
//!
//! ```rust,no_run
//! use soma_sdk::SomaClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), soma_sdk::Error> {
//!     let client = SomaClient::builder()
//!         .url("http://localhost:8080")
//!         .token("sv_...")
//!         .project("your-project-uuid")
//!         .environment("your-env-uuid")
//!         .build()?;
//!
//!     // Read a single secret (decrypted plaintext from the server)
//!     let db_pass: String = client.secret("database/password").await?;
//!
//!     // Read a single config value
//!     let port: String = client.config("server/port").await?;
//!
//!     // Bulk load everything in one HTTP call
//!     let env = client.load_all().await?;
//!     println!("{}", env["database/password"]);
//!
//!     // Cache for sub-microsecond sync reads after the initial load
//!     let cache = client.cache().await?;
//!     let v = cache.get("database/password");
//!
//!     // Inject into process environment (vault wins over existing vars)
//!     client.inject(true).await?;
//!
//!     // Typed deserialization
//!     #[derive(serde::Deserialize)]
//!     struct Cfg { database_password: String }
//!     let cfg: Cfg = client.load().await?;
//!
//!     Ok(())
//! }
//! ```

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::env;

use serde::de::DeserializeOwned;
use serde::Deserialize;

// ── Error ─────────────────────────────────────────────────────────────────────

/// All errors that soma-sdk can return.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Required builder field was missing or empty.
    #[error("configuration error: {0}")]
    Config(String),

    /// The server returned 401 — check your token.
    #[error("unauthorized — check your token")]
    Unauthorized,

    /// The requested secret or config key was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// The server returned an unexpected HTTP error.
    #[error("server error {status}: {body}")]
    Server { status: u16, body: String },

    /// A network or transport error from reqwest.
    #[error("request failed: {0}")]
    Transport(#[from] reqwest::Error),

    /// Deserialization of the vault values into a typed struct failed.
    #[error("deserialize failed: {0}")]
    Deserialize(#[from] serde_json::Error),
}

// ── Builder ───────────────────────────────────────────────────────────────────

/// Builder for [`SomaClient`].
///
/// Each field falls back to an environment variable if not set explicitly:
/// - `url` → `SOMA_URL` (default: `http://127.0.0.1:8080`)
/// - `token` → `SOMA_TOKEN` (required — no default)
/// - `project` → `SOMA_PROJECT`
/// - `environment` → `SOMA_ENVIRONMENT`
#[derive(Default)]
pub struct SomaClientBuilder {
    url: Option<String>,
    token: Option<String>,
    project: Option<String>,
    environment: Option<String>,
}

impl SomaClientBuilder {
    /// Set the soma-vault server URL (e.g. `"http://localhost:8080"`).
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Set the API bearer token.
    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Set the project UUID (or string ID accepted by the API).
    pub fn project(mut self, project: impl Into<String>) -> Self {
        self.project = Some(project.into());
        self
    }

    /// Set the environment UUID (or string ID accepted by the API).
    pub fn environment(mut self, environment: impl Into<String>) -> Self {
        self.environment = Some(environment.into());
        self
    }

    /// Build the client. Returns [`Error::Config`] if any required field is missing.
    pub fn build(self) -> Result<SomaClient, Error> {
        let url = self
            .url
            .or_else(|| env::var("SOMA_URL").ok())
            .unwrap_or_else(|| "http://127.0.0.1:8080".to_owned());
        let url = url.trim_end_matches('/').to_owned();

        let token = self
            .token
            .or_else(|| env::var("SOMA_TOKEN").ok())
            .filter(|t| !t.is_empty())
            .ok_or_else(|| Error::Config("token is required (set via .token() or SOMA_TOKEN)".into()))?;

        let project = self
            .project
            .or_else(|| env::var("SOMA_PROJECT").ok())
            .filter(|p| !p.is_empty())
            .ok_or_else(|| Error::Config("project is required (set via .project() or SOMA_PROJECT)".into()))?;

        let environment = self
            .environment
            .or_else(|| env::var("SOMA_ENVIRONMENT").ok())
            .filter(|e| !e.is_empty())
            .ok_or_else(|| {
                Error::Config("environment is required (set via .environment() or SOMA_ENVIRONMENT)".into())
            })?;

        let http = soma_infra::http::client().map_err(Error::Transport)?;

        Ok(SomaClient {
            http,
            url,
            token,
            project,
            environment,
        })
    }
}

// ── Client ────────────────────────────────────────────────────────────────────

/// An async soma-vault client.
///
/// Construct via [`SomaClient::builder()`]. The underlying `reqwest::Client`
/// already pools connections — do not wrap this in an `Arc` pool.
pub struct SomaClient {
    http: reqwest::Client,
    url: String,
    token: String,
    project: String,
    environment: String,
}

// Internal response shapes — kept private; callers only see the extracted values.
#[derive(Deserialize)]
struct SecretResponse {
    value: String,
}

#[derive(Deserialize)]
struct ConfigResponse {
    value: String,
}

#[derive(Deserialize)]
struct ExportResponse {
    values: HashMap<String, String>,
}

impl SomaClient {
    /// Create a [`SomaClientBuilder`].
    pub fn builder() -> SomaClientBuilder {
        SomaClientBuilder::default()
    }

    /// Base URL for secrets/config within the configured project + environment.
    fn env_base(&self) -> String {
        format!(
            "{}/v1/projects/{}/environments/{}",
            self.url, self.project, self.environment
        )
    }

    /// Percent-encode a path segment so `/` in secret paths is transmitted as `%2F`.
    ///
    /// Matches the same encoding used by the CLI (`pct_encode`).
    fn pct_encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char);
                }
                other => {
                    out.push('%');
                    out.push_str(&format!("{other:02X}"));
                }
            }
        }
        out
    }

    /// Execute a GET request and check the response status.
    async fn get(&self, url: &str) -> Result<reqwest::Response, Error> {
        let resp = self
            .http
            .get(url)
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await?;

        match resp.status().as_u16() {
            200..=299 => Ok(resp),
            401 => Err(Error::Unauthorized),
            _ => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                Err(Error::Server { status, body })
            }
        }
    }

    /// Read a secret value (decrypted plaintext) by path.
    ///
    /// The server decrypts the DEK and returns the plaintext over the
    /// authenticated TLS channel. No crypto happens in this crate.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] when the path does not exist.
    /// - [`Error::Unauthorized`] on a 401.
    /// - [`Error::Transport`] on network failure.
    pub async fn secret(&self, path: &str) -> Result<String, Error> {
        let url = format!("{}/secrets/{}", self.env_base(), Self::pct_encode(path));
        let resp = self.get(&url).await.map_err(|e| match e {
            Error::Server { status: 404, .. } => Error::NotFound(path.to_owned()),
            other => other,
        })?;
        let body: SecretResponse = resp.json().await?;
        Ok(body.value)
    }

    /// Read a config value by key.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] when the key does not exist.
    /// - [`Error::Unauthorized`] on a 401.
    /// - [`Error::Transport`] on network failure.
    pub async fn config(&self, key: &str) -> Result<String, Error> {
        let url = format!("{}/config/{}", self.env_base(), Self::pct_encode(key));
        let resp = self.get(&url).await.map_err(|e| match e {
            Error::Server { status: 404, .. } => Error::NotFound(key.to_owned()),
            other => other,
        })?;
        let body: ConfigResponse = resp.json().await?;
        Ok(body.value)
    }

    /// Bulk-load all secrets and config in a single HTTP call.
    ///
    /// Returns a flat `HashMap<String, String>` where the keys are the raw vault
    /// paths (e.g. `"database/password"`, `"server/port"`). This is the efficient
    /// "load everything once at startup" call.
    ///
    /// # Errors
    ///
    /// - [`Error::Unauthorized`] on a 401.
    /// - [`Error::Transport`] on network failure.
    pub async fn load_all(&self) -> Result<HashMap<String, String>, Error> {
        let url = format!("{}/export", self.env_base());
        let resp = self.get(&url).await?;
        let body: ExportResponse = resp.json().await?;
        Ok(body.values)
    }

    /// Load all secrets and config once and return a [`Cache`] for sync reads.
    ///
    /// Prefer this over repeated [`secret`](SomaClient::secret) /
    /// [`config`](SomaClient::config) calls when you read many keys at startup.
    ///
    /// # Errors
    ///
    /// Same as [`load_all`](SomaClient::load_all).
    ///
    /// # Note on freshness
    ///
    /// ponytail: load-once, no background refresh. Values are as fresh as the
    /// moment `cache()` was called. Upgrade path = SSE-based live refresh (P2-2
    /// on the roadmap) when near-real-time propagation is required.
    pub async fn cache(&self) -> Result<Cache, Error> {
        let values = self.load_all().await?;
        Ok(Cache { values })
    }

    /// Inject all vault secrets+config into the process environment.
    ///
    /// Each vault path is converted to an env var name using the same rule as
    /// `soma run` and `soma export`: uppercase every letter, replace every
    /// non-`[A-Z0-9]` character with `_` (e.g. `database/password` →
    /// `DATABASE_PASSWORD`).
    ///
    /// If `overwrite` is `true` (the default for [`init`]), vault values replace
    /// any existing env var with the same name. Pass `false` to let an existing
    /// env var win (useful when you want explicit env to override the vault).
    ///
    /// # Safety note
    ///
    /// `std::env::set_var` is safe in Rust edition 2021 single-threaded startup
    /// contexts. Call this once, before spawning additional threads.
    pub async fn inject(&self, overwrite: bool) -> Result<(), Error> {
        let values = self.load_all().await?;
        for (path, value) in &values {
            let name = env_var_name(path);
            if overwrite || env::var(&name).is_err() {
                // SAFETY: called once at process startup before threads spawn;
                // edition 2021, safe in this context.
                env::set_var(&name, value);
            }
        }
        Ok(())
    }

    /// Deserialize all vault secrets+config into a typed struct.
    ///
    /// Each vault path maps to a struct field name via the **field-name** form:
    /// lowercase the env var name (`database/password` → `database_password`).
    /// Numeric and boolean values stored as strings are coerced automatically
    /// (e.g. `"8080"` → `u16`, `"true"` → `bool`).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// #[derive(serde::Deserialize)]
    /// struct Config { database_password: String, server_port: u16 }
    ///
    /// # async fn run(client: soma_sdk::SomaClient) -> Result<(), soma_sdk::Error> {
    /// let cfg: Config = client.load().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn load<T: DeserializeOwned>(&self) -> Result<T, Error> {
        let values = self.load_all().await?;
        let obj: serde_json::Map<String, serde_json::Value> = values
            .into_iter()
            .map(|(path, val)| {
                let field = env_var_name(&path).to_ascii_lowercase();
                // Attempt to parse the string as a JSON scalar (number, bool, null)
                // so typed struct fields (u16, bool, etc.) deserialize correctly.
                // Falls back to a JSON string when parsing fails.
                let json_val = serde_json::from_str::<serde_json::Value>(&val)
                    .unwrap_or(serde_json::Value::String(val));
                (field, json_val)
            })
            .collect();
        let cfg = serde_json::from_value::<T>(serde_json::Value::Object(obj))?;
        Ok(cfg)
    }
}

// ── Cache ─────────────────────────────────────────────────────────────────────

/// An in-memory snapshot of all secrets and config, loaded once.
///
/// Get values with [`Cache::get`] — sub-microsecond, no I/O.
/// Construct via [`SomaClient::cache()`].
pub struct Cache {
    values: HashMap<String, String>,
}

impl Cache {
    /// Look up a value by vault path (e.g. `"database/password"`).
    ///
    /// Returns `None` if the key was not present at load time.
    pub fn get(&self, path: &str) -> Option<&str> {
        self.values.get(path).map(String::as_str)
    }

    /// Iterate over all (path, value) pairs in the cache.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.values.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Number of entries in the cache.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns `true` if the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Consume the cache and return the underlying map.
    pub fn into_map(self) -> HashMap<String, String> {
        self.values
    }
}

// ── Free functions ────────────────────────────────────────────────────────────

/// Zero-config startup: load all secrets+config and inject them into the
/// process environment so existing `std::env::var(...)` code works with no
/// `.env` file.
///
/// Builds a [`SomaClient`] entirely from environment variables (`SOMA_URL`,
/// `SOMA_TOKEN`, `SOMA_PROJECT`, `SOMA_ENVIRONMENT`), then calls
/// [`SomaClient::inject`] with `overwrite = true` (vault wins over any
/// pre-existing env var).
///
/// Call once at startup, before spawning additional threads.
///
/// # Errors
///
/// - [`Error::Config`] if any required env var is missing.
/// - [`Error::Unauthorized`] / [`Error::Transport`] on server errors.
pub async fn init() -> Result<(), Error> {
    SomaClient::builder().build()?.inject(true).await
}

/// Zero-config typed load: build a client from env vars and deserialize all
/// vault secrets+config into a typed struct in one call.
///
/// Equivalent to `SomaClient::builder().build()?.load::<T>().await`.
/// See [`SomaClient::load`] for the field-name mapping and type-coercion rules.
///
/// # Errors
///
/// - [`Error::Config`] if any required env var is missing.
/// - [`Error::Deserialize`] if the values don't match the struct's fields/types.
/// - [`Error::Unauthorized`] / [`Error::Transport`] on server errors.
pub async fn from_env<T: DeserializeOwned>() -> Result<T, Error> {
    SomaClient::builder().build()?.load::<T>().await
}

// ── Path → env-var mapping (mirrors soma-cli) ─────────────────────────────────

/// Convert a vault path to an environment variable name.
///
/// Rules (identical to `soma run` / `soma export`): uppercase every letter;
/// replace every character that is not `[A-Z0-9]` with `_`.
///
/// # Examples
///
/// ```
/// assert_eq!(soma_sdk::env_var_name("database/password"), "DATABASE_PASSWORD");
/// assert_eq!(soma_sdk::env_var_name("db-host"), "DB_HOST");
/// assert_eq!(soma_sdk::env_var_name("a.b"), "A_B");
/// ```
pub fn env_var_name(path: &str) -> String {
    path.chars()
        .map(|c| {
            let u = c.to_ascii_uppercase();
            if u.is_ascii_uppercase() || u.is_ascii_digit() { u } else { '_' }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_var_name_mapping() {
        assert_eq!(env_var_name("database/password"), "DATABASE_PASSWORD");
        assert_eq!(env_var_name("db-host"), "DB_HOST");
        assert_eq!(env_var_name("a.b"), "A_B");
        assert_eq!(env_var_name("server/port"), "SERVER_PORT");
    }

    #[test]
    fn field_name_is_lowercase_env_var() {
        // The field name used in load::<T>() is just env_var_name.to_ascii_lowercase()
        assert_eq!(env_var_name("database/password").to_ascii_lowercase(), "database_password");
        assert_eq!(env_var_name("server/port").to_ascii_lowercase(), "server_port");
    }
}

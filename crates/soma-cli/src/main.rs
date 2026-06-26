//! `soma` CLI: run/export/CRUD/migrate/keygen/login/init/import.
//!
//! Exit codes:
//!   0 ok | 1 auth(401) | 2 not-found(404) | 3 forbidden(403)
//!   4 validation(400/422) | 5 server(5xx)

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::io::{IsTerminal as _, Read as _, Write as _};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use serde_json::Value;

// ── CLI definition ─────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "soma", about = "soma-vault CLI")]
struct Cli {
    /// API server URL (env: SOMA_SERVER; fallback: creds file; default: http://127.0.0.1:8080)
    #[arg(long, global = true, env = "SOMA_SERVER")]
    server: Option<String>,

    /// Bearer token (env: SOMA_TOKEN; fallback: creds file)
    #[arg(long, global = true, env = "SOMA_TOKEN")]
    token: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Save server + token to ~/.soma/credentials.toml
    Login {
        #[arg(long)]
        server: String,
        #[arg(long)]
        token: String,
    },
    /// Generate a fresh 64-hex master KEK and print it
    Keygen,
    /// Database migration commands
    Migrate {
        #[command(subcommand)]
        action: MigrateAction,
        /// Path to migrations directory (default: "migrations")
        #[arg(long, default_value = "migrations")]
        migrations: String,
        /// Postgres connection URL (env: DATABASE_URL)
        #[arg(long, env = "DATABASE_URL")]
        database_url: Option<String>,
    },
    /// Project commands
    Projects {
        #[command(subcommand)]
        action: ProjectsAction,
    },
    /// Environment commands
    Envs {
        #[command(subcommand)]
        action: EnvsAction,
    },
    /// Secret commands
    Secrets {
        #[command(subcommand)]
        action: SecretsAction,
    },
    /// Config commands
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Export an environment as dotenv or JSON
    Export {
        /// Project ID (or set via .soma.toml / soma init)
        #[arg(long, short = 'p')]
        project: Option<String>,
        /// Environment ID (or set via .soma.toml / soma init)
        #[arg(long, short = 'e')]
        env: Option<String>,
        /// Output format: dotenv or json
        #[arg(long, default_value = "dotenv")]
        format: String,
        /// Output file (stdout if omitted)
        #[arg(short)]
        o: Option<PathBuf>,
    },
    /// Inject secrets/config into a child process
    Run {
        /// Project ID (or set via .soma.toml / soma init)
        #[arg(long, short = 'p')]
        project: Option<String>,
        /// Environment ID (or set via .soma.toml / soma init)
        #[arg(long, short = 'e')]
        env: Option<String>,
        /// Replace the child's entire environment with only injected vars + minimal safe set
        /// (PATH, HOME, TERM, USER, LANG). Prevents unintended env var leakage.
        #[arg(long)]
        replace_env: bool,
        /// Command and arguments
        #[arg(last = true)]
        cmd: Vec<String>,
    },
    /// Interactively pick a project + environment and write .soma.toml
    Init,
    /// Import a .env file into the vault
    Import {
        /// Path to the .env file to import
        file: PathBuf,
        /// Project ID (or set via .soma.toml / soma init)
        #[arg(long, short = 'p')]
        project: Option<String>,
        /// Environment ID (or set via .soma.toml / soma init)
        #[arg(long, short = 'e')]
        env: Option<String>,
        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum MigrateAction {
    /// Apply pending migrations
    Up,
    /// Show migration status
    Status,
    /// Stub: re-wrap DEKs under a new KEK (not yet implemented)
    Rekey,
}

#[derive(Subcommand)]
enum ProjectsAction {
    /// Create a new project
    Create {
        /// Short code
        code: String,
        /// Human-readable name (defaults to code if omitted)
        #[arg(long)]
        name: Option<String>,
    },
    /// List all projects
    List,
}

#[derive(Subcommand)]
enum EnvsAction {
    /// Create a new environment in a project
    Create {
        /// Short code
        code: String,
        /// Project ID
        #[arg(long)]
        project: String,
        /// Human-readable name (defaults to code if omitted)
        #[arg(long)]
        name: Option<String>,
    },
    /// List environments in a project
    List {
        /// Project ID
        #[arg(long)]
        project: String,
    },
}

#[derive(Subcommand)]
enum SecretsAction {
    /// Set a secret value.
    ///
    /// Secure usage: pipe the value via stdin to keep it out of shell history and ps:
    ///   echo -n 's3cr3t' | soma secrets set db/password
    ///   soma secrets set db/password --value-from-file /run/secrets/db_pass
    ///
    /// Positional <value> is supported for back-compat but is visible in ps aux / shell history.
    Set {
        #[arg(long, short = 'p')]
        project: Option<String>,
        #[arg(long, short = 'e')]
        env: Option<String>,
        path: String,
        /// Secret value (discouraged: visible in ps/history; prefer stdin or --value-from-file)
        value: Option<String>,
        /// Read the secret value from a file instead of positional arg or stdin
        #[arg(long, value_name = "FILE")]
        value_from_file: Option<PathBuf>,
    },
    /// Get a secret value
    Get {
        #[arg(long, short = 'p')]
        project: Option<String>,
        #[arg(long, short = 'e')]
        env: Option<String>,
        path: String,
        /// Print the raw value even when stdout is a TTY (skips masking)
        #[arg(long)]
        reveal: bool,
    },
    /// List secrets
    List {
        #[arg(long, short = 'p')]
        project: Option<String>,
        #[arg(long, short = 'e')]
        env: Option<String>,
    },
    /// Delete a secret
    Rm {
        #[arg(long, short = 'p')]
        project: Option<String>,
        #[arg(long, short = 'e')]
        env: Option<String>,
        path: String,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Set a config value
    Set {
        #[arg(long, short = 'p')]
        project: Option<String>,
        #[arg(long, short = 'e')]
        env: Option<String>,
        key: String,
        value: String,
        #[arg(long, default_value = "string")]
        r#type: String,
    },
    /// Get a config value
    Get {
        #[arg(long, short = 'p')]
        project: Option<String>,
        #[arg(long, short = 'e')]
        env: Option<String>,
        key: String,
    },
    /// List config keys
    List {
        #[arg(long, short = 'p')]
        project: Option<String>,
        #[arg(long, short = 'e')]
        env: Option<String>,
    },
    /// Delete a config key
    Rm {
        #[arg(long, short = 'p')]
        project: Option<String>,
        #[arg(long, short = 'e')]
        env: Option<String>,
        key: String,
    },
}

// ── Credentials file ───────────────────────────────────────────────────────────

#[derive(serde::Serialize, Deserialize, Default)]
struct Credentials {
    server: Option<String>,
    token: Option<String>,
}

fn creds_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".soma").join("credentials.toml"))
}

fn load_creds() -> Credentials {
    let Some(path) = creds_path() else {
        return Credentials::default();
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Credentials::default();
    };
    toml::from_str(&text).unwrap_or_default()
}

fn save_creds(server: &str, token: &str) -> Result<()> {
    let path = creds_path().context("cannot determine home directory")?;
    std::fs::create_dir_all(path.parent().unwrap())?;
    let content = format!("server = \"{server}\"\ntoken = \"{token}\"\n");
    std::fs::write(&path, &content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ── Project context file (.soma.toml in CWD) ──────────────────────────────────

#[derive(serde::Serialize, Deserialize, Default)]
struct ProjectContext {
    server: Option<String>,
    project_id: Option<String>,
    environment_id: Option<String>,
}

fn load_project_context() -> ProjectContext {
    // Walk up from CWD toward root looking for .soma.toml (like git finds .git).
    let Ok(mut dir) = std::env::current_dir() else {
        return ProjectContext::default();
    };
    loop {
        let candidate = dir.join(".soma.toml");
        if let Ok(text) = std::fs::read_to_string(&candidate) {
            return toml::from_str(&text).unwrap_or_default();
        }
        match dir.parent() {
            Some(parent) => dir = parent.to_path_buf(),
            None => return ProjectContext::default(),
        }
    }
}

fn save_project_context(ctx: &ProjectContext) -> Result<()> {
    let content = toml::to_string(ctx).context("failed to serialize .soma.toml")?;
    std::fs::write(".soma.toml", content)?;
    Ok(())
}

/// Resolve project_id and environment_id from CLI flags or .soma.toml.
///
/// Order: flag value > .soma.toml value > error.
fn resolve_project_env(
    flag_project: Option<&str>,
    flag_env: Option<&str>,
    pctx: &ProjectContext,
) -> Result<(String, String)> {
    let project_id = flag_project
        .map(str::to_owned)
        .or_else(|| pctx.project_id.clone())
        .context("no project: pass --project/-p or run `soma init`")?;
    let env_id = flag_env
        .map(str::to_owned)
        .or_else(|| pctx.environment_id.clone())
        .context("no environment: pass --env/-e or run `soma init`")?;
    Ok((project_id, env_id))
}

// ── Context resolution ─────────────────────────────────────────────────────────

struct Ctx {
    server: String,
    token: String,
    client: reqwest::Client,
}

impl Ctx {
    fn new(cli_server: Option<String>, cli_token: Option<String>) -> Result<Self> {
        let creds = load_creds();
        let server = cli_server
            .or(creds.server)
            .unwrap_or_else(|| "http://127.0.0.1:8080".to_owned());
        let token = cli_token
            .or(creds.token)
            .context("no token: pass --token, set SOMA_TOKEN, or run `soma login`")?;
        let client = reqwest::Client::new();
        Ok(Self {
            server,
            token,
            client,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1{}", self.server.trim_end_matches('/'), path)
    }

    async fn get(&self, path: &str) -> Result<Value> {
        let resp = self
            .client
            .get(self.url(path))
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await?;
        handle_response(resp).await
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value> {
        let resp = self
            .client
            .post(self.url(path))
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&body)
            .send()
            .await?;
        handle_response(resp).await
    }

    async fn put(&self, path: &str, body: Value) -> Result<Value> {
        let resp = self
            .client
            .put(self.url(path))
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&body)
            .send()
            .await?;
        handle_response(resp).await
    }

    async fn delete(&self, path: &str) -> Result<Value> {
        let resp = self
            .client
            .delete(self.url(path))
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await?;
        handle_response(resp).await
    }
}

// ── HTTP error handling → exit codes ──────────────────────────────────────────

async fn handle_response(resp: reqwest::Response) -> Result<Value> {
    let status = resp.status();
    if status.is_success() || status == reqwest::StatusCode::NO_CONTENT {
        if status == reqwest::StatusCode::NO_CONTENT {
            return Ok(Value::Null);
        }
        let v: Value = resp.json().await?;
        return Ok(v);
    }
    // Try to extract {"error": "..."} body.
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    let msg = body
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown error")
        .to_owned();

    let code: i32 = match status.as_u16() {
        401 => 1,
        404 => 2,
        403 => 3,
        400 | 422 => 4,
        s if s >= 500 => 5,
        _ => 1,
    };
    // Encode the exit code in the error so main() can propagate it.
    Err(CliError { msg, code }.into())
}

#[derive(Debug)]
struct CliError {
    msg: String,
    code: i32,
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl std::error::Error for CliError {}

fn exit_code_from_err(e: &anyhow::Error) -> i32 {
    if let Some(ce) = e.downcast_ref::<CliError>() {
        return ce.code;
    }
    1
}

// ── env_var_name: path → ENV_VAR ──────────────────────────────────────────────

/// Convert a secret/config path to an environment variable name.
///
/// Rules: uppercase ASCII; every character that is not `[A-Z0-9]` becomes `_`.
///
/// # Examples
///
/// ```
/// assert_eq!(env_var_name("database/password"), "DATABASE_PASSWORD");
/// assert_eq!(env_var_name("db-host"), "DB_HOST");
/// assert_eq!(env_var_name("a.b"), "A_B");
/// ```
pub fn env_var_name(path: &str) -> String {
    path.chars()
        .map(|c| {
            let u = c.to_ascii_uppercase();
            if u.is_ascii_uppercase() || u.is_ascii_digit() {
                u
            } else {
                '_'
            }
        })
        .collect()
}

/// Convert an env var name to a vault path for import.
///
/// Inverse of `env_var_name` for the common case: lowercase the name.
/// `_` is preserved as `_` (not converted to `/`), so `DATABASE_PASSWORD`
/// stores as path `database_password` and `env_var_name("database_password")`
/// → `DATABASE_PASSWORD`. Round-trips perfectly for all-underscore names.
///
/// ponytail: if users prefer `database/password` style paths they can use
/// `soma secrets set` directly; import prioritises lossless round-trip.
fn env_var_to_path(name: &str) -> String {
    name.to_ascii_lowercase()
}

// ── Render helpers ─────────────────────────────────────────────────────────────

/// Render a `{values: {key: val, ...}}` response as dotenv text.
pub fn render_dotenv(values: &HashMap<String, String>) -> String {
    let mut lines: Vec<String> = values
        .iter()
        .map(|(k, v)| {
            // ponytail: minimal quoting — escape double-quotes in value.
            let escaped = v.replace('"', "\\\"");
            format!("{}=\"{}\"", env_var_name(k), escaped)
        })
        .collect();
    lines.sort();
    lines.join("\n")
}

/// Render a `{values: {key: val, ...}}` response as JSON `{"NAME": "value"}`.
pub fn render_json(values: &HashMap<String, String>) -> Result<String> {
    let mapped: HashMap<String, &String> =
        values.iter().map(|(k, v)| (env_var_name(k), v)).collect();
    Ok(serde_json::to_string_pretty(&mapped)?)
}

// ── Export values extraction ───────────────────────────────────────────────────

/// Fetch export bundle and build the name→value map with collision warnings.
async fn fetch_export_map(ctx: &Ctx, pid: &str, eid: &str) -> Result<HashMap<String, String>> {
    let url = format!("/projects/{pid}/environments/{eid}/export");
    let resp = ctx.get(&url).await?;

    let values = resp
        .get("values")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    // Build env-var-name → (original path, value) map, warning on collision.
    let mut result: HashMap<String, (String, String)> = HashMap::new();
    for (path, val) in &values {
        let Some(val_str) = val.as_str() else {
            continue;
        };
        let env_name = env_var_name(path);
        if let Some((prev_path, _)) = result.get(&env_name) {
            tracing::warn!(
                env_name = %env_name,
                first_path = %prev_path,
                second_path = %path,
                "export: name collision — both paths map to the same env var; latter wins"
            );
        }
        result.insert(env_name, (path.clone(), val_str.to_owned()));
    }

    Ok(result.into_iter().map(|(k, (_, v))| (k, v)).collect())
}

// ── dotenv parser (hand-rolled, no extra dep) ─────────────────────────────────

/// Parse a dotenv file into (key, value) pairs.
///
/// Skips blank lines and `#` comments. Splits on the FIRST `=`. Strips
/// surrounding single or double quotes from values. Warns and skips malformed lines.
fn parse_dotenv_file(text: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(eq) = line.find('=') else {
            eprintln!("warning: line {}: no '=' found, skipping: {line:?}", lineno + 1);
            continue;
        };
        let key = line[..eq].trim().to_owned();
        if key.is_empty() {
            eprintln!("warning: line {}: empty key, skipping", lineno + 1);
            continue;
        }
        let raw_val = line[eq + 1..].trim();
        let value = strip_quotes(raw_val).to_owned();
        pairs.push((key, value));
    }
    pairs
}

fn strip_quotes(s: &str) -> &str {
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

// ── stdin prompt helper ────────────────────────────────────────────────────────

fn prompt(msg: &str) -> Result<String> {
    print!("{msg}");
    std::io::stdout().flush()?;
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_owned())
}

fn pick_from_list(prompt_msg: &str, count: usize) -> Result<usize> {
    loop {
        let input = prompt(prompt_msg)?;
        match input.parse::<usize>() {
            Ok(n) if n >= 1 && n <= count => return Ok(n - 1),
            _ => eprintln!("please enter a number between 1 and {count}"),
        }
    }
}

// ── Command handlers ───────────────────────────────────────────────────────────

async fn cmd_login(server: &str, token: &str) -> Result<()> {
    save_creds(server, token)?;
    println!("credentials saved to ~/.soma/credentials.toml");
    Ok(())
}

fn cmd_keygen() -> Result<()> {
    let hex = soma_crypto::MasterKek::generate()?;
    println!("{hex}");
    Ok(())
}

async fn cmd_migrate(
    action: &MigrateAction,
    migrations: &str,
    database_url: Option<String>,
) -> Result<()> {
    use soma_schema::{Migrator, PostgresConfig, PostgresDriver};

    if let MigrateAction::Rekey = action {
        // ponytail: stub — will re-wrap DEKs old→new KEK via soma_crypto::rewrap_dek
        // (cloud-KMS migration); implement when KMS backend is added in Phase 2.
        println!("not implemented — will re-wrap DEKs old→new KEK via soma_crypto::rewrap_dek (cloud-KMS migration)");
        return Ok(());
    }

    let url = database_url
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .context("no database URL: pass --database-url or set DATABASE_URL")?;

    let cfg = soma_infra::db::PoolConfig::new(url);
    let pool = soma_infra::db::connect(&cfg)
        .await
        .context("failed to connect to database")?;

    let pg_cfg = PostgresConfig {
        schema: Some("01_vault".into()),
        advisory_lock_key: 0x050A_1A33_5641_0017_i64,
        ..Default::default()
    };
    let driver = PostgresDriver::new(pool, pg_cfg).context("failed to create migration driver")?;
    let migrator = Migrator::from_root(migrations);

    match action {
        MigrateAction::Up => {
            migrator.up(&driver).await.context("migration failed")?;
            println!("migrations applied");
        }
        MigrateAction::Status => {
            let status = migrator
                .status(&driver)
                .await
                .context("failed to get migration status")?;
            println!("Applied ({}):", status.applied.len());
            for m in &status.applied {
                println!("  [✓] v{} {}", m.version, m.file);
            }
            println!("Pending ({}):", status.pending.len());
            for m in &status.pending {
                println!("  [ ] v{} {}", m.version, m.file);
            }
        }
        MigrateAction::Rekey => unreachable!(),
    }
    Ok(())
}

async fn cmd_projects(action: &ProjectsAction, ctx: &Ctx) -> Result<()> {
    match action {
        ProjectsAction::Create { code, name } => {
            let name = name.as_deref().unwrap_or(code);
            let resp = ctx
                .post("/projects", serde_json::json!({"code": code, "name": name}))
                .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        ProjectsAction::List => {
            let resp = ctx.get("/projects").await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
    }
    Ok(())
}

async fn cmd_envs(action: &EnvsAction, ctx: &Ctx) -> Result<()> {
    match action {
        EnvsAction::Create {
            code,
            project,
            name,
        } => {
            let name = name.as_deref().unwrap_or(code);
            let path = format!("/projects/{project}/environments");
            let resp = ctx
                .post(&path, serde_json::json!({"code": code, "name": name}))
                .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        EnvsAction::List { project } => {
            let path = format!("/projects/{project}/environments");
            let resp = ctx.get(&path).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
    }
    Ok(())
}

/// Percent-encode a path segment (encode `/` and other reserved chars).
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

async fn cmd_secrets(action: &SecretsAction, ctx: &Ctx, pctx: &ProjectContext) -> Result<()> {
    match action {
        SecretsAction::Set {
            project,
            env,
            path,
            value,
            value_from_file,
        } => {
            // Precedence: positional value > --value-from-file > stdin.
            let secret_value = if let Some(v) = value {
                v.clone()
            } else if let Some(file) = value_from_file {
                std::fs::read_to_string(file)
                    .with_context(|| format!("cannot read {}", file.display()))?
                    .trim_end_matches('\n')
                    .to_owned()
            } else {
                let mut buf = String::new();
                std::io::stdin()
                    .read_to_string(&mut buf)
                    .context("failed to read secret value from stdin")?;
                // Strip a single trailing newline (as produced by echo).
                if buf.ends_with('\n') {
                    buf.pop();
                    if buf.ends_with('\r') {
                        buf.pop();
                    }
                }
                buf
            };
            let (pid, eid) = resolve_project_env(project.as_deref(), env.as_deref(), pctx)?;
            let enc = pct_encode(path);
            let url = format!("/projects/{pid}/environments/{eid}/secrets/{enc}");
            let resp = ctx
                .put(&url, serde_json::json!({"value": secret_value}))
                .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        SecretsAction::Get {
            project,
            env,
            path,
            reveal,
        } => {
            let (pid, eid) = resolve_project_env(project.as_deref(), env.as_deref(), pctx)?;
            let enc = pct_encode(path);
            let url = format!("/projects/{pid}/environments/{eid}/secrets/{enc}");
            let resp = ctx.get(&url).await?;
            if let Some(v) = resp.get("value").and_then(|v| v.as_str()) {
                // Mask when writing to an interactive terminal and --reveal not given.
                if !reveal && std::io::stdout().is_terminal() {
                    eprintln!("[hidden — use --reveal to show or pipe to a command]");
                } else {
                    print!("{v}");
                    // Newline only when stdout is a TTY; piped callers get bare value.
                    if std::io::stdout().is_terminal() {
                        println!();
                    }
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
        }
        SecretsAction::List { project, env } => {
            let (pid, eid) = resolve_project_env(project.as_deref(), env.as_deref(), pctx)?;
            let url = format!("/projects/{pid}/environments/{eid}/secrets");
            let resp = ctx.get(&url).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        SecretsAction::Rm {
            project,
            env,
            path,
        } => {
            let (pid, eid) = resolve_project_env(project.as_deref(), env.as_deref(), pctx)?;
            let enc = pct_encode(path);
            let url = format!("/projects/{pid}/environments/{eid}/secrets/{enc}");
            ctx.delete(&url).await?;
            println!("deleted");
        }
    }
    Ok(())
}

async fn cmd_config(action: &ConfigAction, ctx: &Ctx, pctx: &ProjectContext) -> Result<()> {
    match action {
        ConfigAction::Set {
            project,
            env,
            key,
            value,
            r#type,
        } => {
            let (pid, eid) = resolve_project_env(project.as_deref(), env.as_deref(), pctx)?;
            let enc = pct_encode(key);
            let url = format!("/projects/{pid}/environments/{eid}/config/{enc}");
            let resp = ctx
                .put(&url, serde_json::json!({"value": value, "type": r#type}))
                .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        ConfigAction::Get {
            project,
            env,
            key,
        } => {
            let (pid, eid) = resolve_project_env(project.as_deref(), env.as_deref(), pctx)?;
            let enc = pct_encode(key);
            let url = format!("/projects/{pid}/environments/{eid}/config/{enc}");
            let resp = ctx.get(&url).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        ConfigAction::List { project, env } => {
            let (pid, eid) = resolve_project_env(project.as_deref(), env.as_deref(), pctx)?;
            let url = format!("/projects/{pid}/environments/{eid}/config");
            let resp = ctx.get(&url).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        ConfigAction::Rm {
            project,
            env,
            key,
        } => {
            let (pid, eid) = resolve_project_env(project.as_deref(), env.as_deref(), pctx)?;
            let enc = pct_encode(key);
            let url = format!("/projects/{pid}/environments/{eid}/config/{enc}");
            ctx.delete(&url).await?;
            println!("deleted");
        }
    }
    Ok(())
}

async fn cmd_export(
    ctx: &Ctx,
    pctx: &ProjectContext,
    flag_project: Option<&str>,
    flag_env: Option<&str>,
    format: &str,
    output: Option<&PathBuf>,
) -> Result<()> {
    let (pid, eid) = resolve_project_env(flag_project, flag_env, pctx)?;

    let env_map = fetch_export_map(ctx, &pid, &eid).await?;

    let content = match format {
        "json" => render_json(&env_map)?,
        _ => render_dotenv(&env_map),
    };

    match output {
        Some(path) => {
            std::fs::write(path, &content)?;
            println!("wrote {}", path.display());
        }
        None => println!("{content}"),
    }
    Ok(())
}

async fn cmd_run(
    ctx: &Ctx,
    pctx: &ProjectContext,
    flag_project: Option<&str>,
    flag_env: Option<&str>,
    cmd: &[String],
    replace_env: bool,
) -> Result<()> {
    if cmd.is_empty() {
        anyhow::bail!("no command specified after --");
    }
    let (pid, eid) = resolve_project_env(flag_project, flag_env, pctx)?;
    let env_map = fetch_export_map(ctx, &pid, &eid).await?;

    let (exe, args) = cmd.split_first().unwrap();
    let mut command = std::process::Command::new(exe);
    command.args(args);

    if replace_env {
        // Clear parent env; keep only the minimal safe set + injected vars.
        command.env_clear();
        for var in &["PATH", "HOME", "TERM", "USER", "LANG"] {
            if let Ok(val) = std::env::var(var) {
                command.env(var, val);
            }
        }
    }
    command.envs(&env_map);

    exec_or_wait(exe, command)
}

fn exec_or_wait(exe: &str, mut command: std::process::Command) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        // exec() replaces the current process image; only returns on error.
        let err = command.exec();
        Err(err).with_context(|| format!("failed to exec {exe}"))
    }
    #[cfg(not(unix))]
    {
        let status = command
            .status()
            .with_context(|| format!("failed to spawn {exe}"))?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// `soma init` — interactive project+environment picker, writes .soma.toml.
async fn cmd_init(ctx: &Ctx, server: &str) -> Result<()> {
    // List projects.
    let resp = ctx.get("/projects").await?;
    // The paginated list shape has an "items" array (Page<T> serialises as {items, next_cursor}).
    let projects = resp
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_else(|| {
            // Fallback: maybe it's a bare array.
            resp.as_array().cloned().unwrap_or_default()
        });

    if projects.is_empty() {
        println!("No projects found. Run `soma projects create <code>` first.");
        return Ok(());
    }

    println!("Projects:");
    for (i, p) in projects.iter().enumerate() {
        let id = p.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        let name = p
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| p.get("code").and_then(|v| v.as_str()).unwrap_or("?"));
        println!("  {}. {name} ({id})", i + 1);
    }

    let proj_idx = pick_from_list("Pick a project [number]: ", projects.len())?;
    let project = &projects[proj_idx];
    let project_id = project
        .get("id")
        .and_then(|v| v.as_str())
        .context("project has no id")?;

    // List environments for chosen project.
    let env_resp = ctx
        .get(&format!("/projects/{project_id}/environments"))
        .await?;
    let envs = env_resp
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_else(|| {
            env_resp.as_array().cloned().unwrap_or_default()
        });

    if envs.is_empty() {
        println!("No environments found for this project. Run `soma envs create <code> --project {project_id}` first.");
        return Ok(());
    }

    println!("Environments:");
    for (i, e) in envs.iter().enumerate() {
        let id = e.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        let name = e
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| e.get("code").and_then(|v| v.as_str()).unwrap_or("?"));
        println!("  {}. {name} ({id})", i + 1);
    }

    let env_idx = pick_from_list("Pick an environment [number]: ", envs.len())?;
    let env = &envs[env_idx];
    let environment_id = env
        .get("id")
        .and_then(|v| v.as_str())
        .context("environment has no id")?;

    let pctx = ProjectContext {
        server: Some(server.to_owned()),
        project_id: Some(project_id.to_owned()),
        environment_id: Some(environment_id.to_owned()),
    };
    save_project_context(&pctx)?;

    println!("Wrote .soma.toml — `soma run -- <cmd>` now works in this directory.");
    Ok(())
}

/// `soma import <file>` — parse a dotenv file and upload secrets to the vault.
async fn cmd_import(
    ctx: &Ctx,
    pctx: &ProjectContext,
    file: &PathBuf,
    flag_project: Option<&str>,
    flag_env: Option<&str>,
    yes: bool,
) -> Result<()> {
    let (pid, eid) = resolve_project_env(flag_project, flag_env, pctx)?;

    let text = std::fs::read_to_string(file)
        .with_context(|| format!("cannot read {}", file.display()))?;
    let pairs = parse_dotenv_file(&text);

    if pairs.is_empty() {
        println!("No secrets found in {}.", file.display());
        return Ok(());
    }

    println!("Found {} secrets in {}:", pairs.len(), file.display());
    for (key, _) in &pairs {
        println!("  {key}");
    }

    if !yes {
        let answer = prompt(&format!(
            "Import these {} secrets into project {pid} / env {eid}? [y/N] ",
            pairs.len()
        ))?;
        if !matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let mut ok = 0usize;
    let mut fail = 0usize;
    for (key, value) in &pairs {
        // Round-trip: env_var_name(env_var_to_path(KEY)) == KEY for all-uppercase names.
        let path = env_var_to_path(key);
        let enc = pct_encode(&path);
        let url = format!("/projects/{pid}/environments/{eid}/secrets/{enc}");
        match ctx.put(&url, serde_json::json!({"value": value})).await {
            Ok(_) => {
                println!("  ✓ {key}");
                ok += 1;
            }
            Err(e) => {
                eprintln!("  ✗ {key}: {e}");
                fail += 1;
            }
        }
    }

    println!("\nImported {ok}/{} secrets.", pairs.len());

    if fail > 0 {
        anyhow::bail!("{fail} secret(s) failed to import");
    }

    // Delete the .env and add it to .gitignore. The whole point of `import` is to
    // get secrets OUT of the file, so `--yes` does this automatically; otherwise we
    // confirm first.
    let file_name = file.display().to_string();
    let do_cleanup = if yes {
        true
    } else {
        let answer = prompt(&format!(
            "Delete {file_name} and add it to .gitignore? [Y/n] "
        ))?;
        // Default to yes on empty input — removing the file is the intended outcome.
        matches!(answer.to_ascii_lowercase().as_str(), "" | "y" | "yes")
    };

    if do_cleanup {
        std::fs::remove_file(file)
            .with_context(|| format!("failed to delete {file_name}"))?;
        println!("Deleted {file_name}.");

        // Append to .gitignore only if not already present.
        let gitignore_path = std::path::Path::new(".gitignore");
        let existing = std::fs::read_to_string(gitignore_path).unwrap_or_default();
        let entry = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or(file_name.clone());
        if !existing.lines().any(|l| l.trim() == entry.as_str()) {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(gitignore_path)
                .context("failed to open .gitignore")?;
            writeln!(f, "{entry}")?;
            println!("Added {entry} to .gitignore.");
        } else {
            println!("{entry} is already in .gitignore.");
        }
    }

    Ok(())
}

// ── Entry point ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    soma_infra::telemetry::init();

    let cli = Cli::parse();

    let result = dispatch(cli).await;

    if let Err(e) = result {
        eprintln!("error: {e}");
        let code = exit_code_from_err(&e);
        std::process::exit(code);
    }
}

async fn dispatch(cli: Cli) -> Result<()> {
    let pctx = load_project_context();
    let Cli { server: cli_server, token: cli_token, command } = cli;
    match command {
        Command::Login { server, token } => cmd_login(&server, &token).await,
        Command::Keygen => cmd_keygen(),
        Command::Migrate {
            action,
            migrations,
            database_url,
        } => cmd_migrate(&action, &migrations, database_url).await,
        Command::Projects { action } => {
            let ctx = Ctx::new(cli_server, cli_token)?;
            cmd_projects(&action, &ctx).await
        }
        Command::Envs { action } => {
            let ctx = Ctx::new(cli_server, cli_token)?;
            cmd_envs(&action, &ctx).await
        }
        Command::Secrets { action } => {
            let ctx = Ctx::new(cli_server, cli_token)?;
            cmd_secrets(&action, &ctx, &pctx).await
        }
        Command::Config { action } => {
            let ctx = Ctx::new(cli_server, cli_token)?;
            cmd_config(&action, &ctx, &pctx).await
        }
        Command::Export {
            project,
            env,
            format,
            o,
        } => {
            let ctx = Ctx::new(cli_server, cli_token)?;
            cmd_export(&ctx, &pctx, project.as_deref(), env.as_deref(), &format, o.as_ref()).await
        }
        Command::Run {
            project,
            env,
            replace_env,
            cmd,
        } => {
            let ctx = Ctx::new(cli_server, cli_token)?;
            cmd_run(&ctx, &pctx, project.as_deref(), env.as_deref(), &cmd, replace_env).await
        }
        Command::Init => {
            let ctx = Ctx::new(cli_server, cli_token)?;
            let server = ctx.server.clone();
            cmd_init(&ctx, &server).await
        }
        Command::Import {
            file,
            project,
            env,
            yes,
        } => {
            let ctx = Ctx::new(cli_server, cli_token)?;
            cmd_import(&ctx, &pctx, &file, project.as_deref(), env.as_deref(), yes).await
        }
    }
}

// ── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_var_name_basic() {
        assert_eq!(env_var_name("database/password"), "DATABASE_PASSWORD");
        assert_eq!(env_var_name("db-host"), "DB_HOST");
        assert_eq!(env_var_name("a.b"), "A_B");
    }

    #[test]
    fn env_var_name_collision() {
        // a/b and a.b both collapse to A_B
        assert_eq!(env_var_name("a/b"), "A_B");
        assert_eq!(env_var_name("a.b"), "A_B");
    }

    #[test]
    fn render_dotenv_basic() {
        let mut m = HashMap::new();
        m.insert("DATABASE_PASSWORD".to_owned(), "s3cr3t".to_owned());
        m.insert("DB_HOST".to_owned(), "localhost".to_owned());
        let out = render_dotenv(&m);
        assert!(out.contains("DATABASE_PASSWORD=\"s3cr3t\""));
        assert!(out.contains("DB_HOST=\"localhost\""));
    }

    #[test]
    fn render_dotenv_escapes_double_quote() {
        let mut m = HashMap::new();
        m.insert("KEY".to_owned(), r#"val"ue"#.to_owned());
        let out = render_dotenv(&m);
        assert!(out.contains(r#"KEY="val\"ue""#));
    }

    #[test]
    fn render_json_basic() {
        let mut m = HashMap::new();
        m.insert("DATABASE_PASSWORD".to_owned(), "s3cr3t".to_owned());
        let out = render_json(&m).unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["DATABASE_PASSWORD"], "s3cr3t");
    }

    #[test]
    fn pct_encode_slash() {
        assert_eq!(pct_encode("database/password"), "database%2Fpassword");
        assert_eq!(pct_encode("plain"), "plain");
        assert_eq!(pct_encode("a.b"), "a.b");
    }

    #[test]
    fn parse_dotenv_basic() {
        let text = "# comment\nFOO=bar\nBAZ=\"quoted\"\nEMPTY=\nSINGLE='val'";
        let pairs = parse_dotenv_file(text);
        assert_eq!(pairs.len(), 4);
        assert_eq!(pairs[0], ("FOO".to_owned(), "bar".to_owned()));
        assert_eq!(pairs[1], ("BAZ".to_owned(), "quoted".to_owned()));
        assert_eq!(pairs[2], ("EMPTY".to_owned(), "".to_owned()));
        assert_eq!(pairs[3], ("SINGLE".to_owned(), "val".to_owned()));
    }

    #[test]
    fn parse_dotenv_skips_blanks_and_comments() {
        let text = "\n\n# skip me\n  # also skip\nKEY=value\n";
        let pairs = parse_dotenv_file(text);
        assert_eq!(pairs, vec![("KEY".to_owned(), "value".to_owned())]);
    }

    #[test]
    fn env_var_to_path_roundtrip() {
        // env_var_name(env_var_to_path(x)) == x for all-uppercase underscore names.
        for key in &["DATABASE_PASSWORD", "DB_HOST", "FOO", "MY_API_KEY"] {
            let path = env_var_to_path(key);
            assert_eq!(env_var_name(&path), *key, "round-trip failed for {key}");
        }
    }

    #[test]
    fn resolve_project_env_from_flags() {
        let pctx = ProjectContext::default();
        let (p, e) = resolve_project_env(Some("proj-1"), Some("env-1"), &pctx).unwrap();
        assert_eq!(p, "proj-1");
        assert_eq!(e, "env-1");
    }

    #[test]
    fn resolve_project_env_from_context() {
        let pctx = ProjectContext {
            server: None,
            project_id: Some("p-from-ctx".to_owned()),
            environment_id: Some("e-from-ctx".to_owned()),
        };
        let (p, e) = resolve_project_env(None, None, &pctx).unwrap();
        assert_eq!(p, "p-from-ctx");
        assert_eq!(e, "e-from-ctx");
    }

    #[test]
    fn resolve_project_env_flag_overrides_context() {
        let pctx = ProjectContext {
            server: None,
            project_id: Some("p-ctx".to_owned()),
            environment_id: Some("e-ctx".to_owned()),
        };
        let (p, e) = resolve_project_env(Some("p-flag"), None, &pctx).unwrap();
        assert_eq!(p, "p-flag");
        assert_eq!(e, "e-ctx");
    }

    #[test]
    fn resolve_project_env_missing_errors() {
        let pctx = ProjectContext::default();
        assert!(resolve_project_env(None, None, &pctx).is_err());
        assert!(resolve_project_env(Some("p"), None, &pctx).is_err());
    }
}

# soma-vault Phase 1 — CLI, SDK & Secret/Config Injection

soma-vault ships three consumer surfaces in Phase 1: a `soma` CLI binary, a `soma-sdk` Rust crate, and a Kubernetes operator (`soma-vault-operator`). Together they cover every realistic injection pattern — process-env injection for any language via `soma run`, in-process typed access with live config updates via the SDK, and native Kubernetes Secret reconciliation via the CRD operator. TypeScript and Python SDKs are Phase 2; non-Rust services in Phase 1 use `soma run` or the REST API directly. The 10-minute onboarding gate — a solo developer from zero infrastructure to `soma run -- node server.js` on EKS or bare-metal — drives every design decision in this document.

---

## 1. Identity Planes

Two independent planes operate in soma-vault and must never be conflated in code or documentation.

| Plane | Who | Credential | Authorizes |
|---|---|---|---|
| App-principal | Humans, service accounts, CI pipelines | soma-iam JWT → soma-vault session token | Reading/writing secrets and config |
| Pod-workload | soma-vault server pods | K8s projected ServiceAccount token → AWS IRSA → KMS Decrypt | Unwrapping the master KEK on boot |

The CLI and SDK operate exclusively on the app-principal plane. The pod-workload plane is transparent to users and is covered in the architecture and cloud-native specs.

---

## 2. Authentication

### 2.1 Auth Methods

**Method 1 — soma-iam JWT (primary)**

```
Client → POST /v1/auth/login
         { "type": "soma_iam_jwt", "token": "<soma-iam JWT>" }

soma-vault:
  1. Fetch JWKS from soma-iam JWKS endpoint (cached; single-flight refresh on kid miss,
     negative-cache unknown kid for 60 s; circuit-breaker after 5 consecutive fetch failures)
  2. Verify signature (RS256 or ES256), iss, aud == ["soma-vault"], exp, iat
  3. Extract sub (principal UUID), tenant_id (tid claim), workspace_roles[], org_role
  4. Check jti against jti_replay_cache table — reject if already exchanged
  5. Look up tenants row by soma_iam_org_id = tid; reject if absent
  6. Issue soma-vault session token (short-lived JWT, RS256, signed with per-deployment
     key derived from master KEK; see §2.3)
  7. Record jti in jti_replay_cache with TTL = JWT exp

Response: { "token": "eyJ...", "expires_at": "<iso8601>", "tenant_id": "<uuid>" }
```

**JWKS singleflight:** when a `kid` miss occurs, exactly one goroutine-equivalent fetches the JWKS; concurrent waiters block on the same future via `tokio::sync::OnceCell` keyed on `kid`. Other pods are unaffected. Negative cache: after a re-fetch confirms a `kid` is absent, reject tokens with that `kid` for 60 seconds without a network call.

**Method 2 — Universal Auth (local dev and bootstrapping only)**

```
Client → POST /v1/auth/login
         { "type": "universal_auth", "client_id": "<uuid>", "client_secret": "<secret>" }
```

`client_secret` is Argon2id-hashed in Postgres (`universal_auth_credentials` table). Response format is identical to Method 1.

Universal Auth is a bootstrapping and local-dev mechanism. In production, all machine identities — including the Kubernetes operator — should be soma-iam-managed (projected ServiceAccount token → soma-iam OIDC exchange → soma-vault session token). Universal Auth for the operator is acceptable only for Phase 1 before soma-iam supports Kubernetes projected SA token exchange.

### 2.2 CI/CD OIDC

CI pipelines exchange their platform-native OIDC token at soma-iam, not at soma-vault directly. soma-iam is the single OIDC trust anchor; it validates the GitHub Actions / GitLab / CircleCI JWT and issues a soma-iam machine-identity JWT. That JWT is presented to `/v1/auth/login` as Method 1.

This means soma-vault has one auth contract with one IdP regardless of how many CI providers are in use.

**GitHub Actions (Universal Auth — Phase 1 before soma-iam is ready):**

```yaml
- name: Authenticate to soma-vault
  env:
    SOMA_CLIENT_ID: ${{ vars.SOMA_CLIENT_ID }}
    SOMA_CLIENT_SECRET: ${{ secrets.SOMA_CLIENT_SECRET }}
  run: soma auth login --method universal-auth
```

**GitHub Actions (soma-iam OIDC — target model once soma-iam is built):**

```yaml
permissions:
  id-token: write
  contents: read

- name: Authenticate to soma-vault
  uses: soma-platform/secrets-action@v1
  with:
    soma-iam-url: https://iam.soma.example.com
    soma-vault-url: https://vault.soma.example.com
    machine-identity-id: ${{ vars.SOMA_MACHINE_IDENTITY_ID }}
  # sets SOMA_TOKEN env var; no static secrets
```

### 2.3 Session Token Design

soma-vault issues its own session tokens as **short-lived RS256 JWTs** (not opaque strings backed by a Postgres table). The signing key is a per-deployment RSA key pair where the private key is derived from the master KEK via HKDF with salt `b"soma-vault-session-signing-v1"` and stored only in pod RAM.

Benefits over a Postgres-backed opaque token:
- Eliminates one indexed DB read per authenticated hot-path request.
- Eliminates the `sessions` table and its expiry sweeper background task.
- Validation is CPU-only (signature verify + exp check).

Revocation on explicit logout: a small in-memory `jti` blocklist per pod with TTL matching session lifetime (15 min). Data loss on pod restart is acceptable given the 15-minute window — a revoked token becomes invalid by natural expiry within one session period at most.

| Field | Value |
|---|---|
| Format | RS256 JWT, prefix `sv_` when serialized for display |
| TTL | 15 minutes (configurable via `SESSION_TTL_SECONDS`) |
| Renewal | `POST /v1/auth/refresh` — returns a new token |
| Revocation | `DELETE /v1/auth/logout` — adds jti to in-memory blocklist |
| Hot path | No DB call; signature verification only |

**JWT replay prevention:** soma-iam JWTs presented at `/v1/auth/login` have their `jti` recorded in the `jti_replay_cache` Postgres table (columns: `jti TEXT PK`, `expires_at TIMESTAMPTZ`). On each login call, check for existing `jti`; reject if found. A periodic task prunes expired rows. This prevents a stolen soma-iam JWT from creating multiple soma-vault sessions.

### 2.4 Workspace Roles and org_role Mapping

soma-iam JWTs carry `workspace_roles: [{workspace_id, role}]` claims for workspace-scoped access. soma-vault does not maintain a redundant `principal_workspace_roles` table — workspace role bindings are owned by soma-iam and delivered in the JWT. This is a requirement on soma-iam: when a principal is revoked in soma-iam, all subsequent JWT issuances omit that principal's workspace roles, and all soma-vault session tokens expire within 15 minutes.

soma-vault owns only the path-capability policy overlay (`policies` table: `tenant_id`, `workspace_id`, `path_glob`, `capabilities TEXT[]`). Policy evaluation combines the JWT's workspace role with the path-capability overlay to make authZ decisions.

**org_role auto-provisioning rule:** When a principal with `org_role: admin` authenticates and the JWT carries no `workspace_roles` entries, soma-vault treats that principal as `ws_admin` for all workspaces in the tenant. For `org:member` and `org:viewer`, no auto-provisioning — explicit workspace invitation via soma-iam is required.

---

## 3. CLI — `soma` Binary

### 3.1 Overview

Single `soma` binary. Ships as a statically-linked musl binary for Linux and a universal binary for macOS. Driven by `clap`. No daemon, no background process, no persistent state beyond credentials and context files.

| File | Path | Permissions |
|---|---|---|
| Credentials | `~/.soma/credentials.toml` | 0600 |
| Global context | `~/.soma/context.toml` | 0600 |
| Per-project context | `.soma.toml` (walks up to root) | — |

### 3.2 Command Surface

#### Auth

```
soma auth login [--method soma-iam|universal-auth] [--url <vault-url>]
soma auth logout
soma auth status
soma auth service-accounts create --name <name> [--workspace <id>]
soma auth service-accounts list
soma auth service-accounts revoke <client-id>
soma auth service-accounts rotate-secret <client-id>
```

`soma auth login` without flags launches an interactive prompt. `--method soma-iam` opens the OIDC Authorization Code + PKCE URL in the browser. `--method universal-auth` prompts for client-id and client-secret.

`rotate-secret` generates a new `client_secret` (printed once), invalidates the old one, and preserves all role bindings and policies. This is the documented rotation runbook for operator credentials: update the Kubernetes Secret with the new value, then perform a rolling restart.

#### Init and Context

```
soma init
```

Interactive wizard: server URL → login → select/create workspace → select/create project → select/create environment → write `.soma.toml`.

**Context resolution order** (first match wins):
1. CLI flags (`--workspace`, `--project`, `--env`)
2. Environment variables (`SOMA_WORKSPACE_ID`, `SOMA_PROJECT_ID`, `SOMA_ENV`)
3. `.soma.toml` walked up from current directory
4. `~/.soma/context.toml`

`.soma.toml` example:

```toml
[context]
workspace_id = "018e3c5a-1234-7abc-bdef-123456789abc"
project_id   = "018e3c5b-abcd-7def-1234-abcdef012345"
environment  = "development"

[env_map]
"database/password" = "DB_PASS"
"api/stripe_key"    = "STRIPE_SECRET_KEY"
```

#### Secrets

```
soma secrets get <path> [--env <env>] [--version <n>] [--reveal]
soma secrets set <path> <value> [--env <env>] [--cas <expected-version>] [--reason <text>]
soma secrets delete <path> [--env <env>]
soma secrets list [--prefix <path>] [--env <env>]
soma secrets versions <path> [--env <env>]
soma secrets rollback <path> --to-version <n> [--env <env>]
soma secrets export [--format env|json|dotenv] [--output <file>] [--env <env>]
```

`soma secrets get` masks the value by default when stdout is a TTY; pass `--reveal` to print. When stdout is a pipe, the raw value is emitted with no decoration — safe for `$(soma secrets get db/password)`.

`soma secrets export` resolves the full env map for the project and environment (including parent-environment inheritance) and writes in the requested format. Atomic write: temp file then rename. Output file is not created if the API call fails.

#### Config

```
soma config get <path> [--env <env>]
soma config set <path> <value> --type string|int|float|bool|json [--env <env>] [--schema-file <path>]
soma config delete <path> [--env <env>]
soma config list [--prefix <path>] [--env <env>]
```

`--type json` with `--schema-file` validates the value against the provided JSON Schema Draft 2020-12 document client-side before sending to the API, giving faster feedback than waiting for the server.

#### Run / Exec

```
soma run [--env <env>] [--only-secrets] [--only-config] [--replace-env] -- <command> [args...]
```

This is the primary onboarding command.

1. Read session token from `~/.soma/credentials.toml` or `SOMA_TOKEN` env var.
2. `GET /v1/workspaces/{workspace_id}/projects/{project_id}/environments/{env_id}/secrets/export` — one bulk fetch returning resolved secrets and config as a flat key-value map (environment inheritance applied server-side).
3. Build env map: path `database/password` → `DATABASE_PASSWORD` (slashes to underscores, uppercased). Custom mappings from `.soma.toml` `[env_map]` override the default.
4. Conflict rule: if a secret path and a config path produce the same env-var key, the secret takes precedence. A warning is printed to stderr. This is a hard error if `--strict` is passed.
5. `std::process::Command::new(cmd).envs(map).exec()` — replaces the current process.

By default, existing env vars in the parent process are not overridden. Pass `--replace-env` to start with a clean env (only the soma-vault map plus a minimal `PATH`).

**Security note:** Environment variables are readable from `/proc/<pid>/environ` on Linux by any process with the same UID. For secrets requiring stronger isolation (TLS private keys, HSM PINs), use the SDK's `secrets.get()` pull model instead. This tradeoff is documented in `soma run --help`.

**Examples:**

```bash
soma run -- node server.js
soma run --env production -- ./bin/migrate
soma run -- python -m uvicorn app:app
soma run -- cargo run
```

#### Workspace / Project / Environment Management

```
soma workspaces list
soma workspaces create --name <name>
soma projects list [--workspace <id>]
soma projects create --name <name> [--workspace <id>]
soma environments list [--project <id>]
soma environments create --name <name> [--project <id>] [--inherits-from <env-id>]
```

#### Tenant Admin (server operators only)

```
soma vault admin register-tenant --soma-iam-org-id <uuid> --name <name>
```

Calls `POST /v1/admin/tenants` gated on a server-side `ADMIN_TOKEN` (separate env var, distinct from regular session tokens). This is the Phase 1 tenant bootstrap mechanism. In production the preferred path is a soma-iam webhook (`POST /v1/internal/tenants`, internal-network-only) triggered on org creation in soma-iam — but the CLI command is the fallback for self-host operators.

### 3.3 Environment Variables

| Variable | Purpose |
|---|---|
| `SOMA_URL` | soma-vault server URL |
| `SOMA_TOKEN` | Session token (bypasses credentials file) |
| `SOMA_WORKSPACE_ID` | Active workspace |
| `SOMA_PROJECT_ID` | Active project |
| `SOMA_ENV` | Active environment name |

`SOMA_TOKEN` in the environment bypasses all credential file logic. Recommended CI pattern: authenticate once with `soma auth login`, export the token, run multiple `soma` commands.

### 3.4 Output and Error UX

- All user-facing output goes to **stderr**. All machine-readable output (secret values, export data) goes to **stdout**. `$(soma secrets get foo)` works cleanly.
- `--json` on any command returns structured JSON on stdout.
- TTY detection: progress spinners and ANSI color only when stderr is a TTY.
- Exit codes: `0` success, `1` auth error, `2` not found, `3` permission denied, `4` validation error, `5` server error.

### 3.5 CLI Crate Dependencies

| Crate | Purpose |
|---|---|
| `clap` 4.x (`derive`) | Argument parsing |
| `reqwest` 0.12.x (`json`, `rustls-tls`) | HTTP client |
| `tokio` 1.x (`full`) | Async runtime |
| `serde` + `serde_json` 1.x | JSON serialization |
| `toml` 0.8.x | `.soma.toml` and credentials files |
| `dirs` 5.x | `~/.soma/` path resolution |
| `indicatif` 0.17.x | Progress spinners (TTY-gated) |
| `colored` 2.x | Terminal color (TTY-gated) |

Note: `eventsource-client` is NOT included in Phase 1. It will be added in Phase 2 when `--watch` is implemented.

---

## 4. Rust SDK — `soma-sdk` Crate

### 4.1 Design Principles

- **Secrets are pull-only, never cached.** Every `secrets.get()` call makes an authenticated API request. No local secret cache — a compromised process cannot dump all secrets by inspecting memory. The server decrypts in pod RAM; the response body (over TLS) carries the plaintext which the SDK wraps in `Secret<String>`.
- **Config is cached and SSE-updated.** An in-process `DashMap` cache is seeded at startup via one bulk GET and kept live by a background SSE subscription. `config.get::<T>(key)` is always a local read — zero network latency.
- **`Secret<String>` prevents accidental logging.** `secrecy::Secret<T>` suppresses `Debug` and `Display` and is not `Clone`. Callers must explicitly call `.expose_secret()`.

### 4.2 Client Construction

```rust
use soma_sdk::{SomaClient, SomaClientConfig};

let client = SomaClient::new(SomaClientConfig {
    url: std::env::var("SOMA_URL")?.parse()?,
    token: std::env::var("SOMA_TOKEN")?,
    project_id: std::env::var("SOMA_PROJECT_ID")?.parse()?,
    environment: std::env::var("SOMA_ENV").unwrap_or_else(|_| "production".into()),
}).await?;
```

`SomaClient::new` at construction time:
1. Validates the token via `GET /v1/auth/me` (one startup call; fails fast on expired token).
2. Bulk-fetches all config values for `(project_id, environment)` via `GET /v1/config` and populates the in-process cache.
3. Spawns a background `tokio::task` maintaining the SSE connection, updating the cache on `ConfigChangeEvent` messages.

If the SSE connection drops, the background task reconnects with exponential backoff (1 s, 2 s, 4 s … capped at 30 s). During reconnect it polls `GET /v1/config` every 60 seconds to fill any gap, then resumes SSE. When SSE reconnects with `Last-Event-ID`, the server replays events from a 60-second / 500-event ring buffer (whichever limit is reached first); if the client is beyond the replay window, it performs a full re-seed bulk GET before resuming.

### 4.3 Secrets API

```rust
// Returns Secret<String> — not Debug/Display/Clone
let db_password: Secret<String> = client.secrets().get("database/password").await?;

// Must call .expose_secret() to use the value
connect_db(db_password.expose_secret()).await?;
// db_password dropped here; ZeroizeOnDrop fires
```

Each `secrets.get()` call:
- `GET /v1/workspaces/{ws}/projects/{proj}/environments/{env}/secrets/{path}`
- Server derives tenant KEK, unwraps DEK, decrypts via AES-256-GCM, zeroizes DEK, returns plaintext over TLS.
- Server writes an audit event for the read.
- No value is cached locally in the SDK.

```rust
pub enum SecretError {
    NotFound,
    PermissionDenied,
    TokenExpired,
    Transport(reqwest::Error),
}
```

### 4.4 Config API

```rust
// All reads are local — zero network
let enabled: bool     = client.config().get::<bool>("features/new_onboarding")?;
let max_retries: i64  = client.config().get::<i64>("limits/max_retries")?;
let base_url: String  = client.config().get::<String>("api/base_url")?;
let settings: serde_json::Value = client.config().get::<serde_json::Value>("app/settings")?;

// Config key with value_type=secret_ref — fetches the secret on demand
let (host, pass) = client
    .config()
    .get_with_secret("database/connection", client.secrets())
    .await?;
// host: String (from config cache), pass: Option<Secret<String>> (from secrets API)
```

`get::<T>` returns `Err(ConfigError::NotFound)` if the key is absent or `Err(ConfigError::TypeMismatch)` if the stored type does not convert to `T`.

### 4.5 SSE Cache Internals

```rust
// ponytail: DashMap over RwLock<HashMap> — lower per-key lock contention.
// Ceiling: ~50k keys before memory overhead warrants a bounded LRU.
// Upgrade path: add capacity bound with LRU eviction if telemetry shows growth.
let cache: Arc<DashMap<String, ConfigValue>> = Arc::new(DashMap::new());
```

`ConfigChangeEvent` received from the server:

```rust
pub struct ConfigChangeEvent {
    pub path: String,
    pub value_type: ValueType,
    // None for secret_ref — secret UUID is NOT pushed over SSE
    pub value: Option<ConfigScalar>,
    pub version: u64,
}
```

For `secret_ref` events, the cache marks the key dirty. The next `get_with_secret()` call fetches fresh from the secrets API. Secret plaintext never enters the SSE stream.

**SSE authorization:** The server validates the session token on SSE connect and binds the subscription to `(tenant_id, project_id, environment_id)`. The broadcast channel's write path filters by `tenant_id` before dispatching. For `secret_ref` config change events, the `secret_id` field is omitted from SSE events entirely — only the path and version are sent. Callers who need the current secret value must call `secrets.get()` explicitly, which triggers its own authZ check.

### 4.6 Shutdown

```rust
client.close().await;
// Cancels the background SSE task. Outstanding secrets.get() calls complete.
```

`Drop` cancels (but does not await) the SSE task. `close()` awaits graceful completion.

### 4.7 Feature Flags

| Feature | Default | Description |
|---|---|---|
| `tls` | on | TLS via rustls + aws-lc-rs |
| `sse` | on | Background SSE config subscription |
| `zeroize` | on | ZeroizeOnDrop on all key-material types — cannot be disabled |

### 4.8 SDK Crate Dependencies

| Crate | Purpose |
|---|---|
| `reqwest` 0.12.x (`stream`, `rustls-tls`) | REST + SSE stream |
| `tokio` 1.x | Async runtime; `broadcast` channels |
| `tokio-stream` 0.1.x | Bridge `broadcast::Receiver` to `Stream` |
| `dashmap` 6.x | Lock-free concurrent config cache |
| `serde` + `serde_json` 1.x | Config value deserialization |
| `secrecy` 0.10.x | `Secret<T>` — no `Debug`/`Display`/`Clone` |
| `zeroize` + `zeroize_derive` 1.x | `ZeroizeOnDrop` on key-material types |
| `uuid` 1.x | Project/tenant UUID parsing |
| `url` 2.x | Server URL validation |
| `thiserror` 1.x | Typed error variants |

---

## 5. Real-Time Config Delivery — SSE Protocol

### 5.1 Server-Side Architecture

```
Config write committed to Postgres
        |
        v
Handler calls: NOTIFY config_changes, '{"tenant_id":"...","project_id":"...","env_id":"...","path":"...","value_type":"string","version":7}'
        |
        v  (one dedicated LISTEN connection per pod — non-pooled)
Relay task receives NOTIFY payload
        |
        v
broadcast::Sender<ConfigChangeEvent> keyed on (project_id, environment_id)
stored in DashMap — created lazily on first subscriber, dropped on last disconnect
        |      |      |
        v      v      v
   axum Sse  axum Sse  axum Sse   (one per connected SDK client)
```

**NOTIFY payload contains only routing keys — never the config value:**

```json
{"tenant_id":"...","project_id":"...","env_id":"...","path":"server/port","value_type":"int","version":7}
```

The receiving relay task looks up the current value from the `config_versions` table before broadcasting to SSE subscribers. This eliminates the Postgres 8000-byte NOTIFY payload limit risk and ensures that `is_sensitive` config values never appear unredacted in the WAL or on the wire.

**Relay task health:** The dedicated LISTEN connection is monitored with a periodic `SELECT 1` heartbeat (every 30 s). On connection drop, the relay task reconnects with exponential backoff and sends a synthetic `stream_interrupted` SSE event to all subscribers so they fall back to 60-second polling during the reconnect window.

**Policy cache invalidation reuses this infrastructure:** After any INSERT/UPDATE/DELETE on the `policies` table, the handler sends `NOTIFY policy_changes, '{"tenant_id":"...","workspace_id":"..."}'`. The same relay task clears the in-memory radix-trie policy cache for that tenant on receipt. Cross-pod policy revocations propagate within the NOTIFY roundtrip latency (typically < 1 s).

**ponytail note:** One `broadcast::Sender` per `(project_id, env_id)` pair. Ceiling: ~50 pods × subscriber count before in-process fan-out becomes the bottleneck. Upgrade path: Redis pub/sub relay on the NOTIFY side (zero SDK change required).

### 5.2 SSE Endpoint

```
GET /v1/config/stream?project_id=<uuid>&env_id=<uuid>
Authorization: Bearer <token>
Accept: text/event-stream
```

`workspace_id` is omitted — `project_id` is unique within a tenant, and `tenant_id` is resolved from the session token.

Response headers:
```
Content-Type: text/event-stream
Cache-Control: no-cache
X-Accel-Buffering: no
```

**Event format:**

```
id: 018e3c5c-0000-0000-0000-000000000042
event: config_change
data: {"path":"features/new_onboarding","value_type":"bool","value":true,"version":7}

id: 018e3c5c-0000-0000-0000-000000000043
event: config_change
data: {"path":"database/connection","value_type":"secret_ref","version":3}

event: stream_interrupted
data: {"reason":"relay_reconnecting"}

: keepalive
```

For `secret_ref` config changes, the event carries only `path`, `value_type`, and `version` — no `secret_id`, no resolved value. Keepalive comments are sent every 30 seconds.

**Reconnect:** The client sends `Last-Event-ID` on reconnect. The server replays events from a bounded ring buffer: events from the last 60 seconds or the last 500 events, whichever is exhausted first. Beyond this window, the SDK performs a full re-seed bulk GET before resuming SSE.

### 5.3 Fallback Polling

When SSE is down, the SDK polls `GET /v1/config?project_id=<uuid>&env_id=<uuid>` every 60 seconds and merges the response into the cache. Polling stops on successful SSE reconnect.

---

## 6. Injection Mechanisms

### 6.1 Process Env Injection (`soma run`)

Covered in §3.2. The primary injection mechanism for Phase 1, suitable for any language runtime.

Security tradeoff: env vars are readable from `/proc/<pid>/environ` on Linux by processes sharing the same UID. Documented in CLI help. For higher-sensitivity secrets, use the SDK pull model.

### 6.2 File Export

```bash
soma secrets export --format env                              # stdout
soma secrets export --format dotenv --output .env.production  # file
soma secrets export --format json --output secrets.json
```

**`env` format:**
```
DATABASE_PASSWORD='abc123'
STRIPE_KEY='sk_live_...'
FEATURES_NEW_ONBOARDING='true'
```

**`dotenv` format:**
```
DATABASE_PASSWORD=abc123
STRIPE_KEY=sk_live_...
```

**`json` format:**
```json
{
  "DATABASE_PASSWORD": "abc123",
  "STRIPE_KEY": "sk_live_...",
  "FEATURES_NEW_ONBOARDING": "true"
}
```

All formats include both secrets and typed config values in a flat key-value map. Every bulk export is a single audit event that lists the secret paths accessed. Atomic write to disk: temp file then rename. No file is created if the API call fails.

### 6.3 Kubernetes Operator — `SomaSecret` CRD

A separate single-binary operator (`soma-vault-operator`) deployed via Helm. Authenticates to the soma-vault API using Universal Auth in Phase 1. Once soma-iam supports Kubernetes projected SA token exchange, the operator should migrate to that path — a static `client_secret` in a Kubernetes Secret contradicts the static-credential elimination story. The Helm chart and operator docs call this out explicitly.

**Operator credential bootstrap:** operators must:
1. Deploy soma-vault server.
2. Create a service account via CLI: `soma auth service-accounts create --name vault-operator`.
3. Store the returned `client_id` and `client_secret` in a Kubernetes Secret.
4. Reference that Secret in Helm values.

The `client_secret` must never appear in Helm `values.yaml` files committed to source control — inject via `--set-string` from a CI secret, Sealed Secrets, or an External Secrets pre-step.

**CRD definition:**

```yaml
apiVersion: secrets.soma.dev/v1alpha1
kind: SomaSecret
metadata:
  name: my-app-secrets
  namespace: production
spec:
  secretPath: "myapp/*"
  environment: "production"
  projectId: "018e3c5b-abcd-7def-1234-abcdef012345"
  targetSecretName: "my-app-secrets"
  restartDeploymentOnChange: true
  # ponytail: polling because the operator runs outside the SSE subscriber model.
  # Ceiling: 60 s staleness acceptable for K8s native secret sync.
  # Upgrade path: SSE webhook trigger from soma-vault server on secret write.
  pollIntervalSeconds: 60
```

**Reconciliation loop:**
1. Authenticate to soma-vault API (Universal Auth).
2. `GET /v1/workspaces/{ws}/projects/{proj}/environments/{env}/secrets?prefix=myapp/*` — fetch matching secrets.
3. Construct a `v1.Secret` object with `type: Opaque` and `data: { KEY: base64(value) }`.
4. `kubectl apply` (create or update).
5. If `restartDeploymentOnChange: true` and any value changed, patch Deployments annotated with `soma.dev/restart-on-change: "my-app-secrets"` to trigger a rolling restart.

The operator writes to native Kubernetes Secrets (etcd-backed). Mitigations: etcd encryption at rest, RBAC restricting Secret access to the operator's ServiceAccount. Explicit tradeoff: the CSI driver (Phase 2) avoids etcd entirely.

**Helm values:**

```yaml
operator:
  enabled: true
  universalAuth:
    clientId: ""
    secretName: "soma-operator-credentials"   # K8s Secret with client_secret key
  vaultUrl: "https://vault.soma.example.com"
```

### 6.4 SDK Pull Model (Rust services)

```rust
#[tokio::main]
async fn main() {
    let soma = SomaClient::new(SomaClientConfig {
        url: std::env::var("SOMA_URL")?.parse()?,
        token: std::env::var("SOMA_TOKEN")?,
        project_id: std::env::var("SOMA_PROJECT_ID")?.parse()?,
        environment: std::env::var("SOMA_ENV").unwrap_or_else(|_| "production".into()),
    })
    .await
    .expect("soma-vault: failed to connect");

    let db_password = soma
        .secrets()
        .get("database/password")
        .await
        .expect("soma-vault: database/password not found");

    let pool = PgPoolOptions::new()
        .connect_with(
            PgConnectOptions::new().password(db_password.expose_secret()),
        )
        .await?;

    // Config reads are local — no network call
    let max_pool_size: i64 = soma.config().get("database/max_pool_size")?;
    // ... pool reconfiguration, serve requests
}
```

Config values are live — they update in the background via SSE without requiring a restart.

---

## 7. API Endpoints

All endpoints require `Authorization: Bearer <soma-vault-session-token>` unless noted.

| Method | Path | Used by | Description |
|---|---|---|---|
| `POST` | `/v1/auth/login` | CLI, SDK | Exchange soma-iam JWT or Universal Auth for session token |
| `DELETE` | `/v1/auth/logout` | CLI | Invalidate session token (adds jti to in-memory blocklist) |
| `POST` | `/v1/auth/refresh` | SDK | Renew session token |
| `GET` | `/v1/auth/me` | SDK init | Validate token, return principal/tenant info |
| `GET` | `/v1/workspaces/{ws}/projects/{proj}/environments/{env}/secrets/{path}` | CLI, SDK | Get current secret (decrypted) |
| `PUT` | `/v1/workspaces/{ws}/projects/{proj}/environments/{env}/secrets/{path}` | CLI | Create or update secret |
| `DELETE` | `/v1/workspaces/{ws}/projects/{proj}/environments/{env}/secrets/{path}` | CLI | Soft-delete secret |
| `GET` | `/v1/workspaces/{ws}/projects/{proj}/environments/{env}/secrets` | CLI, SDK, Operator | List secrets by prefix |
| `GET` | `/v1/workspaces/{ws}/projects/{proj}/environments/{env}/secrets/{path}/versions` | CLI | List version history |
| `POST` | `/v1/workspaces/{ws}/projects/{proj}/environments/{env}/secrets/{path}/rollback` | CLI | Roll back to a prior version |
| `GET` | `/v1/workspaces/{ws}/projects/{proj}/environments/{env}/secrets/export` | CLI | Bulk resolved env map (`?format=env\|json\|dotenv`) |
| `GET` | `/v1/workspaces/{ws}/projects/{proj}/environments/{env}/config/{path}` | CLI | Get single config value |
| `PUT` | `/v1/workspaces/{ws}/projects/{proj}/environments/{env}/config/{path}` | CLI | Create or update config |
| `DELETE` | `/v1/workspaces/{ws}/projects/{proj}/environments/{env}/config/{path}` | CLI | Delete config |
| `GET` | `/v1/workspaces/{ws}/projects/{proj}/environments/{env}/config` | SDK init | Bulk-fetch all config (cache seed) |
| `GET` | `/v1/config/stream?project_id=&env_id=` | SDK | SSE config change stream |
| `GET` | `/v1/workspaces` | CLI | List workspaces |
| `POST` | `/v1/workspaces` | CLI | Create workspace |
| `GET` | `/v1/workspaces/{ws}/members` | CLI, Dashboard | List workspace members |
| `POST` | `/v1/workspaces/{ws}/members` | CLI, Dashboard | Add member (`{principal_id, role}`) |
| `PATCH` | `/v1/workspaces/{ws}/members/{principal_id}` | CLI, Dashboard | Change member role |
| `DELETE` | `/v1/workspaces/{ws}/members/{principal_id}` | CLI, Dashboard | Remove member |
| `GET` | `/v1/workspaces/{ws}/projects` | CLI | List projects |
| `POST` | `/v1/workspaces/{ws}/projects` | CLI | Create project |
| `GET` | `/v1/workspaces/{ws}/projects/{proj}/environments` | CLI | List environments |
| `POST` | `/v1/workspaces/{ws}/projects/{proj}/environments` | CLI | Create environment |
| `POST` | `/v1/workspaces/{ws}/service-accounts` | CLI | Create service account |
| `GET` | `/v1/workspaces/{ws}/service-accounts` | CLI | List service accounts |
| `DELETE` | `/v1/workspaces/{ws}/service-accounts/{sa_id}` | CLI | Revoke service account |
| `POST` | `/v1/workspaces/{ws}/service-accounts/{sa_id}/rotate-secret` | CLI | Rotate `client_secret` |
| `GET` | `/v1/audit` | Dashboard | Query audit events (filterable) |
| `GET` | `/v1/audit/verify` | Dashboard | Walk hash chain; returns first bad seq_num or "intact" |
| `POST` | `/v1/admin/tenants` | CLI (`soma vault admin`) | Register new tenant (admin token only) |
| `POST` | `/v1/internal/tenants` | soma-iam webhook | Upsert tenant on org creation (internal network only) |
| `GET` | `/health/live` | K8s | Liveness: always 200 if process is alive |
| `GET` | `/health/ready` | K8s | Readiness: 503 if KMS grace period expired; 200 with `degraded:true` during grace period |
| `GET` | `/health/startup` | K8s | Startup probe: 503 during 60 s KMS retry window; 200 after first successful unseal; never reverts |
| `GET` | `/health/status` | Ops | Full seal/KMS state JSON |
| `GET` | `/metrics` | Prometheus | Prometheus text format |

---

## 8. Security Constraints

**Session tokens are short-lived signed JWTs.** All authZ decisions involve signature verification plus the path-capability radix trie. No Postgres lookup per request on the hot path.

**`Secret<String>` is not `Clone`.** Enforced by the `secrecy` crate's type system. The only access path is `.expose_secret()` — a deliberate, auditable call site.

**Bulk export is audited.** Every `soma secrets export` or bulk API call generates one audit event listing all secret paths accessed.

**`soma run` never writes secret values to disk.** Values are injected into the child process env in memory. `soma secrets export` writes to disk only on explicit request, atomically.

**SSE events never carry secret plaintext.** For `secret_ref` config keys, SSE events carry only `path`, `value_type`, and `version` — no `secret_id`, no resolved value. All subscribers see this regardless of their permission set on the referenced secret.

**`resolve_refs` authorization is strict.** When `resolve_refs=true` on a config fetch, the server checks read permission on both the config key and the referenced secret. If the secret permission check fails, the response sets `ref_resolved: false` and `ref_resolve_error: "FORBIDDEN"` — the secret UUID is not returned. `secret_ref` is restricted to secrets in the same environment as the config key; cross-environment references are rejected at write time.

**Dashboard session tokens use httpOnly cookies.** `/v1/auth/login` sets an `httpOnly; Secure; SameSite=Strict` cookie. The Leptos WASM client does not touch the token directly. CSRF protection uses the Double Submit Cookie pattern (a non-httpOnly CSRF token echoed in a request header).

**Operator `client_secret` is never in ConfigMaps.** The Helm chart creates a Kubernetes Secret; RBAC restricts access to the operator's ServiceAccount only. The value is injected at deploy time via `--set-string`, Sealed Secrets, or an External Secrets pre-step.

---

## 9. Onboarding — Under 10 Minutes

### Path A: EKS or Bare-Metal (any language runtime)

```bash
# Step 1 (~2 min): deploy soma-vault
helm repo add soma https://charts.soma.dev
helm install soma-vault soma/soma-vault \
  --set kms.provider=aws \
  --set kms.keyArn=arn:aws:kms:us-east-1:123456789012:key/... \
  --set database.url=postgres://... \
  --set iamJwks.url=https://iam.soma.example.com/.well-known/jwks.json

# Step 2 (~1 min): install CLI
curl -sSL https://soma.dev/install.sh | sh
# or: brew install soma-platform/tap/soma

# Step 3 (~2 min): login and init project
soma auth login --method universal-auth \
  --client-id $CLIENT_ID --client-secret $CLIENT_SECRET \
  --url https://vault.soma.example.com
soma init   # interactive: workspace → project → environment → writes .soma.toml

# Step 4 (~1 min): add secrets
soma secrets set database/password "my-secret-password"
soma secrets set api/stripe_key "sk_live_..."

# Step 5 (~30 s): run your app
soma run -- node server.js
```

### Path B: Kubernetes Workload

```bash
# Steps 1–2: same as Path A; operator.enabled=true in Helm values

# Step 3: create a SomaSecret CRD
kubectl apply -f - <<EOF
apiVersion: secrets.soma.dev/v1alpha1
kind: SomaSecret
metadata:
  name: myapp
  namespace: production
spec:
  secretPath: "myapp/*"
  environment: production
  projectId: "018e3c5b-abcd-7def-1234-abcdef012345"
  targetSecretName: myapp-secrets
  restartDeploymentOnChange: true
EOF

# Step 4: reference the native K8s Secret in your Deployment
# spec.template.spec.containers[].envFrom:
#   - secretRef:
#       name: myapp-secrets
```

---

## 10. Open Questions

**soma-iam availability during Phase 1 development.** Method 1 (soma-iam JWT) is the production auth path but soma-iam does not yet exist. Decision needed: build a minimal stub soma-iam (~200 lines of Rust: OIDC discovery endpoint + RS256 JWT signing with a dev key) to enable end-to-end auth testing, or ship Phase 1 with Universal Auth only and defer Method 1 testing until soma-iam is available. The stub approach validates the full JWT contract earlier but adds a build dependency.

**Operator authentication upgrade.** The Phase 1 operator uses Universal Auth (`client_id` + `client_secret`). This should be upgraded to projected ServiceAccount token → soma-iam → soma-vault session token once soma-iam supports Kubernetes projected SA token exchange. Define a migration milestone in the soma-iam roadmap to unblock this.

**soma-iam contract for workspace roles.** This document requires soma-iam to issue `workspace_roles: [{workspace_id, role}]` claims in JWTs. soma-iam must be aware of soma-vault workspace existence (webhook on workspace create/delete from soma-vault). The exact JWT schema (claim names, role vocabulary, workspace_id format) needs joint agreement between soma-vault and soma-iam design sessions.

**GitHub Actions composite action scope.** `soma-platform/secrets-action@v1` is referenced but does not exist. The action is ~100 lines of YAML. Decision: include in Phase 1 (improves CI onboarding significantly; Doppler and Infisical both ship first-party actions) or defer to Phase 2 and document Universal Auth for CI in the interim.

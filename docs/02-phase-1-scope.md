# soma-vault Phase 1 Scope

soma-vault is a cloud-native secrets and typed configuration platform built on async Rust, PostgreSQL, and Leptos. This document defines exactly what ships in Phase 1, what is explicitly out, and what "done" looks like. The five non-negotiable architecture tenets (multi-tenancy, stateless HPA pods, workload-identity auto-unseal, envelope encryption, and schema-enforced secrets/config separation) are foundational — they are in scope and present from the first commit, not retrofitted later.

---

## The Five Non-Negotiable Tenets

These are in scope for Phase 1. Every feature below either directly implements one of these or depends on one being in place.

| Tenet | What it requires in Phase 1 |
|---|---|
| **1. Multi-tenant, multi-workspace** | Hard per-row tenant isolation; `tenant_id` on every table; two independent enforcement layers (application + RLS) |
| **2. Stateless, HPA-native pods** | Kubernetes Deployment (never StatefulSet); zero PVCs; all mutable state in Postgres; Postgres advisory locks for singleton workers |
| **3. Auto-unseal via workload identity** | AWS IRSA on pod boot; no manual unseal ceremony; readiness probe gates on successful KMS Decrypt; software-KMS fallback for self-host without cloud KMS |
| **4. Envelope encryption end-to-end** | Four-layer key hierarchy; per-secret-version DEK; AES-256-GCM; all key types zeroized after use; Postgres dump useless without KMS access |
| **5. Secrets and config separated at the schema level** | Two structurally distinct table families; no ciphertext columns in config tables; no typed-value columns in secrets tables; `$ref` pointer model for config-to-secret references |

---

## Phase 1 Feature Set

### 1. Multi-tenant Postgres schema

**In scope:**

- Five tables in the core hierarchy: `tenants`, `workspaces`, `projects`, `environments`, plus the secrets and config leaf tables.
- `tenant_id UUID NOT NULL` denormalized as the leading column on every leaf table row. No FK-chain traversal required for RLS policies.
- `TenantId(Uuid)` Rust newtype required as a compile-time parameter on every repository function. A handler that skips tenant context does not compile.
- All repository functions accept `&mut Transaction<'_, Postgres>` (not `&PgPool`) to guarantee every query runs inside an explicit transaction — required for transaction-scoped RLS `set_config`.
- Postgres RLS: `ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY` on every table. Policy: `tenant_id = current_setting('app.tenant_id', true)::uuid`. Transaction-scoped `SET LOCAL app.tenant_id = $1` as the first statement inside every transaction. `soma_vault_app` role is NOT the table owner.
- All views use `SECURITY INVOKER = true` (Postgres 15+).
- Unique constraints are always tenant-scoped: `(tenant_id, project_id, path)` never `(path)` alone.
- `environments.inherits_from` optional FK (parent env in same project, max depth 3 enforced at write time by walking the chain and checking for cycles, plus a belt-and-suspenders Postgres trigger).
- `kms_deployment_keys` table: `(id UUID PK, deployment_id TEXT UNIQUE, kms_provider TEXT, kms_key_id TEXT, wrapped_master_kek BYTEA NOT NULL, kms_key_version INT, created_at TIMESTAMPTZ)`. One row per deployment. Pods SELECT from this table on boot.

**Out of scope:**

- Schema-per-tenant, database-per-tenant.
- Row-quota enforcement tables, noisy-neighbor metering. No scale pressure yet.

**Why:** Cross-tenant leakage in a secrets store is catastrophic. The hierarchy DDL must exist before the first secret is written; every subsequent feature — RBAC, SSE scoping, envelope encryption partitioning, audit partitioning — depends on it.

---

### 2. KMS auto-unseal via AWS IRSA

**In scope:**

- `KmsBackend` trait with `wrap_key(plaintext_kek)` and `unwrap_key(wrapped_kek)` methods.
- AWS implementation: `aws-sdk-kms` + `aws-config` IRSA credential chain (`AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN` injected by EKS admission controller). Zero static credentials.
- Boot sequence: projected ServiceAccount JWT → STS `AssumeRoleWithWebIdentity` → ephemeral credentials → KMS Decrypt to unwrap master KEK into `Zeroizing<[u8;32]>` in pod RAM.
- **First-boot bootstrap:** on boot with no existing `kms_deployment_keys` row, the pod generates 32 random bytes via `OsRng`, calls KMS Encrypt to wrap them, and INSERTs via `INSERT ... ON CONFLICT (deployment_id) DO NOTHING`. It then re-SELECTs the committed row (which may have been written by a concurrent pod in a race) and calls KMS Decrypt on that row. All pods converge on one canonical master KEK.
- `soma vault admin init-kms` CLI command documents this as the mandatory one-time setup step for self-hosters.
- Readiness probe gates on successful KMS Decrypt. A pod that cannot reach KMS or fails OIDC exchange never becomes ready.
- Pod is a Kubernetes Deployment, never StatefulSet, no PVCs.

**Out of scope:**

- GCP Cloud KMS and Azure Key Vault backend implementations. The `KmsBackend` trait is defined; these are Phase 2.
- SPIFFE/SPIRE. Phase 2 for on-prem/multi-cloud enterprise.
- Manual Shamir unseal. soma-vault pods prove their identity to the KMS; no human unseal ceremony is ever needed.
- Any static credential on the pod for KMS access.

**Why:** Tenet 3 is the product's primary positioning claim. Retrofitting stateless workload-identity-based auto-unseal onto a system built with env-var keys or manual ceremony requires a coordinated operator migration that is infeasible post-launch.

---

### 3. Software-KMS fallback for self-host without cloud KMS

**In scope:**

- `SOMA_MASTER_KEK_HEX` environment variable (32 bytes, hex-encoded) injected via a Kubernetes Secret. The pod reads the hex string on boot, decodes it into `Zeroizing<[u8;32]>`, and uses it as the master KEK directly.
- This is explicitly the Infisical `ENCRYPTION_KEY` model. Security posture: master KEK protected by Kubernetes etcd encryption at rest and RBAC. The one acceptable exception to tenet 3 for self-hosters who choose not to operate a cloud KMS.
- Health endpoint exposes `"seal_backend": "software_kms"` with `"severity": "WARNING"`. Docs clearly state the tradeoff.
- No `age` crate dependency. Simpler, fewer moving parts, honest about the security model.

**Out of scope:**

- Routing the env-var key through a cloud KMS (that is Phase 1 AWS KMS with extra steps).
- Any pretense that the software fallback is equivalent security to cloud KMS with workload identity.

**Why:** Without a self-host fallback, indie developers without AWS/GCP/Azure cannot run soma-vault locally. Blocking launch on cloud KMS availability eliminates the indie-first target market. The tradeoff is stated honestly.

---

### 4. Envelope encryption: four-layer key hierarchy

**In scope:**

- Layer 0: External KMS key. Never leaves the HSM.
- Layer 1: Master KEK in pod RAM only. `Zeroizing<[u8;32]>`, loaded from KMS on boot, never on disk or in an env var in cloud-KMS mode.
- Layer 2: Per-tenant KEK derived via `HKDF-SHA256(master_kek, salt=b"soma-vault-tenant-kek-v1", info=tenant_id_bytes)`. One KMS call yields all tenant KEKs via CPU-only HKDF. Cached in `Arc<RwLock<LruCache<TenantId, Box<Zeroizing<[u8;32]>>>>>` with 5-min TTL. `Box` pins the key at a stable heap address to prevent moved-memory zeroing gaps. `ZeroizeOnDrop` on eviction.
- Layer 3: Per-secret-version DEK. 32 bytes from `OsRng`. Encrypts the secret value with AES-256-GCM (`aes-gcm` crate, NCC Group audited). DEK wrapped under the tenant KEK using **AES Key Wrap RFC 3394** (`aes-kw` crate) — nonceless by design, the correct algorithm for key wrapping. Zeroized immediately after use.
- Postgres row stores `(ciphertext BYTEA, wrapped_dek BYTEA, nonce BYTEA)`. The `nonce` column belongs to the secret-value AES-GCM encryption, not to the DEK wrap (AES-KW is nonceless). A column comment on `wrapped_dek` states "RFC 3394 AES-KW output — no nonce".
- AEAD additional data: `secret_id_bytes || version_id_bytes` passed live to every encrypt/decrypt call. Prevents ciphertext transplant attacks.
- `aad_fingerprint BYTEA` column stores `SHA-256(secret_id_bytes || version_id_bytes)` as a diagnostic field only. The AEAD tag is the cryptographic binding. On every decrypt, `aad_fingerprint` is recomputed and compared via `subtle::ConstantTimeEq` before decryption proceeds, as a secondary integrity check. Code comment states: "diagnostic — AEAD tag is the security-critical binding".
- ChaCha20Poly1305 (`chacha20poly1305` crate, NCC audited) is a server config option for non-AES-NI hardware.
- Rollback always generates a fresh DEK and nonce. Code comment at the rollback handler: "Always fresh DEK and nonce — NEVER copy wrapped_dek or nonce from the source version row."
- All key-holding types derive `Zeroize + ZeroizeOnDrop`, wrapped in `secrecy::Secret<T>`.
- TLS via `rustls 0.23.x` with `aws-lc-rs` backend. No `ring` dependency anywhere — `hmac 0.12.x` (RustCrypto) + `sha2 0.10.x` cover all HMAC needs including audit log chaining.

**Out of scope:**

- Workspace-scoped or project-scoped DEKs. Blast radius is too large.
- AES-CBC (no authentication), deterministic/counter nonces, AES-GCM-SIV (unnecessary when per-DEK granularity makes the 2^32 limit unreachable), OpenSSL.

**Why:** Tenet 4. Per-secret-version DEK is the AWS Secrets Manager model and the correct blast-radius boundary. One compromised DEK exposes one secret version, not a workspace. Retrofitting this from a workspace-scoped DEK requires re-encrypting every row.

---

### 5. Separate Postgres tables for secrets and config

**In scope:**

```sql
-- Secrets side: NO typed-value columns
CREATE TABLE secrets (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      UUID NOT NULL,
  environment_id UUID NOT NULL REFERENCES environments(id),
  path           TEXT NOT NULL,
  current_version INT NOT NULL DEFAULT 0,
  max_versions   INT NOT NULL DEFAULT 20,
  cas_required   BOOL NOT NULL DEFAULT FALSE,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, environment_id, path)
);

CREATE TABLE secret_versions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  secret_id       UUID NOT NULL REFERENCES secrets(id),
  tenant_id       UUID NOT NULL,
  version         INT NOT NULL,
  ciphertext      BYTEA NOT NULL,
  wrapped_dek     BYTEA NOT NULL,  -- RFC 3394 AES-KW output, no nonce
  nonce           BYTEA NOT NULL,  -- 96-bit random, for the secret-value AES-GCM
  aad_fingerprint BYTEA NOT NULL,  -- SHA-256(secret_id||version_id), diagnostic only
  kms_key_version INT NOT NULL DEFAULT 1,
  is_deleted      BOOL NOT NULL DEFAULT FALSE,
  deleted_at      TIMESTAMPTZ,
  is_destroyed    BOOL NOT NULL DEFAULT FALSE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by_id   UUID NOT NULL,
  UNIQUE (secret_id, version)
);

-- Config side: NO ciphertext columns
CREATE TABLE config_keys (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL,
  environment_id  UUID NOT NULL REFERENCES environments(id),
  path            TEXT NOT NULL,
  value_type      TEXT NOT NULL CHECK (value_type IN
                    ('string','int','float','bool','json','secret_ref')),
  schema_json     JSONB,
  is_sensitive    BOOL NOT NULL DEFAULT FALSE,
  current_version INT NOT NULL DEFAULT 0,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, environment_id, path)
);

CREATE TABLE config_versions (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  config_key_id UUID NOT NULL REFERENCES config_keys(id),
  tenant_id     UUID NOT NULL,
  version       INT NOT NULL,
  string_value  TEXT,
  int_value     BIGINT,
  float_value   DOUBLE PRECISION,
  bool_value    BOOL,
  json_value    JSONB,
  secret_ref    UUID,  -- references secrets(id), same tenant, same environment
  is_deleted    BOOL NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (config_key_id, version)
);
```

- `secret_ref` is restricted to secrets in the **same environment**. Cross-environment secret refs are not permitted in Phase 1 — eliminates the cross-environment authorization gap identified in review.
- The column layout makes conflation structurally impossible: no handler can accidentally put ciphertext in a config row or typed values in a secrets row.

**Out of scope:**

- A unified KV table with a sensitivity flag. This makes safe audit logging and SSE push architecturally impossible.
- Envelope-encrypting non-sensitive config values in Phase 1.
- Cross-environment `secret_ref` (same-environment only in Phase 1).

**Why:** Tenet 5. The `$ref` pointer model is load-bearing: it makes audit logs safe to retain in full, SSE push safe (config events contain no sensitive values), and typed schema validation tractable.

---

### 6. Typed config with write-time JSON Schema validation

**In scope:**

- Per-config-key `value_type` enum. For `value_type=json`, optional `schema_json JSONB` holds a JSON Schema Draft 2020-12 document validated at write time via the `jsonschema` crate (compile schema once, reuse on all writes to the same key).
- API rejects invalid payloads with structured error: `schema_path`, `instance_path`, error message.
- For `value_type=secret_ref`, API validates the referenced secret UUID exists in the same tenant and same environment.

**Out of scope:**

- Full JSON Schema validation on every read.
- Client-side schema-derived type codegen (`schemars` → Rust/TypeScript structs). Phase 2.

**Why:** Catches misconfiguration at write time, not runtime — the same model Replane, AWS AppConfig, and Azure App Configuration use.

---

### 7. Real-time config delivery via SSE

**In scope:**

- `GET /v1/workspaces/{workspace_id}/projects/{project_id}/environments/{env_id}/config/stream` returns `Content-Type: text/event-stream`.
- One `tokio::sync::broadcast::Sender<ConfigChangeEvent>` per `(project_id, env_id)` in a `DashMap`, created lazily on first subscriber.
- On config write (committed transaction), handler sends to the broadcast channel; all connected SDK subscribers on that pod receive a typed delta event within <1s.
- SSE event payload: `{path, value_type, value}` for non-`secret_ref` types. For `secret_ref`: `{path, value_type: "secret_ref"}` — secret UUID and resolved value are **omitted from all SSE events** regardless of subscriber permissions. SSE subscribers with `config:read` do not learn secret UUIDs from the stream.
- SDK holds a `DashMap` in-process cache seeded at startup via one bulk GET. `config.get(key)` is always a local cache read. Background SSE task updates the cache.
- 60-second polling fallback on disconnect (bounded replay: last 500 events or 60 seconds, whichever is reached first; clients beyond the window re-seed via bulk GET).
- Cross-pod fan-out: Postgres `LISTEN/NOTIFY` relay on a dedicated non-pooled connection per pod. NOTIFY payload: `{project_id, env_id, path, event_id}` — routing keys only, never config values. This avoids the 8000-byte NOTIFY limit and keeps sensitive config out of the WAL.
- The LISTEN relay task actively monitors its connection with periodic `SELECT 1` and reconnects with exponential backoff on failure. On reconnection, it sends a synthetic `stream_interrupted` event so clients fall back to polling during the gap.
- After any `policies` table write, the handler sends `NOTIFY policy_changes, '{tenant_id, workspace_id}'`. Each pod's LISTEN connection receives this and clears the in-memory radix trie policy cache for that tenant. Zero additional infrastructure.
- `ponytail:` comment at channel init notes the ceiling (~50 pods × subscriber density) and names Redis pub/sub as the upgrade path.

**Out of scope:**

- Secret plaintext or secret UUIDs in SSE events.
- WebSocket (SSE is sufficient; axum ships it natively).
- Redis as a required Phase 1 dependency.

**Why:** Sub-second config propagation is the Replane-proven differentiator over all polling-based competitors. The `axum::response::sse` module is zero additional dependency.

---

### 8. Stateless Kubernetes Deployment with Postgres advisory lock singleton workers

**In scope:**

- `soma-vault-server` runs as a Kubernetes Deployment. Zero PVCs. All mutable state in Postgres. Any pod can serve any request.
- `sqlx` connection pool, PgBouncer transaction-pooling mode safe (transaction-scoped `SET LOCAL`).
- Background singleton workers (rotation sweeper stub, lease expiry, audit flush): each acquires a Postgres session-level advisory lock via `pg_try_advisory_lock` on a dedicated, non-pooled connection. This connection has explicit TCP keepalive parameters set: `keepalives=1 keepalives_idle=60 keepalives_interval=10 keepalives_count=3` (via `ConnectOptions`). This ensures Postgres detects a dead pod within ~90 seconds rather than the 7200-second OS default, preventing the zombie-lock scenario on OOM kill. A `statement_timeout` is also set on the dedicated connection.
- Pod crash = TCP close (within the keepalive window) = automatic lock release. Non-holders poll `pg_try_advisory_lock` every 30s.
- `ponytail:` comment at the advisory lock setup names Kubernetes Lease object as the upgrade path when pod count exceeds ~50.

**Out of scope:**

- Kubernetes LeaderElection controller (adds K8s API dependency, breaks bare-metal self-host).
- Redis for leader election.
- Separate operator process for `soma-vault-server` itself.

**Why:** Tenet 2. StatefulSet + Raft is the root cause of Vault's HPA-hostility. This structural choice must be made at launch.

---

### 9. HMAC-SHA256 hash-chained audit log

**In scope:**

```sql
CREATE TABLE audit_events (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL,
  seq_num       BIGINT NOT NULL,  -- per-tenant monotonic, generated via pg_advisory_xact_lock + MAX+1
  event_type    TEXT NOT NULL CHECK (event_type IN (
                  'secret_read','secret_write','secret_delete','secret_destroy',
                  'secret_rollback','config_write','config_delete',
                  'session_create','session_revoke',
                  'service_account_create','service_account_revoke',
                  'workspace_create','workspace_delete',
                  'policy_write','policy_delete',
                  'member_add','member_remove','member_role_change'
                )),
  actor_type    TEXT NOT NULL,
  actor_id      UUID NOT NULL,
  actor_ip      INET,
  resource_type TEXT NOT NULL,
  resource_id   UUID,
  resource_name TEXT,
  outcome       TEXT NOT NULL CHECK (outcome IN ('success','failure')),
  reason        TEXT,  -- break-glass justification field
  jti           TEXT,  -- soma-iam JWT ID for cross-platform correlation
  prev_entry_hash TEXT NOT NULL,
  entry_hash    TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, seq_num)
);
```

- KMS plane events (`kms_unseal_success`, `kms_unseal_fail`, `kms_degraded_entry`, `kms_sealed`) are removed from this table. They are pod-infrastructure events, not tenant-scoped data operations. They belong in structured logs, Prometheus metrics, and `/health/status` — not the per-tenant audit chain.
- HMAC key: `HKDF-SHA256(master_kek, salt=b"soma-vault-audit-hmac-v1", info=tenant_id_bytes)`. Because this is derived from the master KEK, a master KEK compromise simultaneously breaks audit integrity. This is explicitly documented: "master KEK compromise invalidates both secret confidentiality and audit chain integrity guarantees. These are linked by design — a separate audit root key would require a second KMS-wrapped secret, adding operational complexity that is Phase 2 for SOC 2 certification."
- `jti` column (JWT ID from the soma-iam JWT) populated on every `session_create` event, enabling cross-platform audit correlation with soma-iam.
- `soma_vault_app` role: INSERT + SELECT only, no UPDATE/DELETE.
- `seq_num` generated via `pg_advisory_xact_lock(hashtext('audit:' || tenant_id::text))` + `SELECT COALESCE(MAX(seq_num), 0) + 1` inside the transaction.
- Secret read audit writes use a **synchronous write within the request transaction** for correctness. The "best-effort channel" model is incompatible with the hash chain's `seq_num` continuity requirement and the SOC 2 claim that every read is individually logged. Latency cost is accepted.
- Secret values never appear in any audit entry. `resource_name` stores an HMAC-SHA256 hash of the path.
- `GET /v1/audit/verify?from=&to=` (admin-only, rate-limited) walks the chain and returns the first bad `seq_num` or `"chain_intact": true`.

**Out of scope:**

- Per-entry RSA signing, Merkle trees.
- External SIEM streaming. Phase 2 enterprise feature.
- Separate Postgres instance for audit. Phase 2.
- KMS infrastructure events in the tenant audit chain.

**Why:** Every secret read must be individually logged with a tamper-evident chain for SOC 2. The `reason` field is a day-one differentiator. The hash chain must be designed in from launch because retrofitting invalidates all prior log entries.

---

### 10. RBAC + path-capability authorization

**In scope:**

- Two-layer authorization:
  1. Workspace-level roles in `principal_workspace_roles` table: `(tenant_id, workspace_id, principal_id, role TEXT CHECK (role IN ('ws:admin','ws:developer','ws:reader')), UNIQUE (tenant_id, workspace_id, principal_id))`.
  2. Path-capability overlay: `policies` table `(tenant_id, workspace_id, path_glob TEXT, capabilities TEXT[] CHECK ...)` with `deny` always winning. Glob: `*` suffix, `+` single-segment.
- Policy cache: in-memory radix trie per tenant, refreshed on `NOTIFY policy_changes`.
- Org-level roles (`org:admin | org:member | org:viewer`) flow in from soma-iam JWT claims. Explicit mapping rule: a principal with `org_role: 'admin'` who has no `principal_workspace_roles` row is auto-provisioned as `ws:admin` for all workspaces in that tenant on first authenticated request. `org:member` and `org:viewer` require explicit workspace invitation.
- Axum type-state pattern: `Request<Authorized>` vs `Request<Unauthenticated>` — handlers cannot be reached without `authz::check()`. Compile-time enforcement.
- Workspace member management API: `GET`, `POST`, `PATCH`, `DELETE` on `/v1/workspaces/{workspace_id}/members`.

**Out of scope:**

- Cedar policy engine in Phase 1. Designed as the Phase 2 upgrade path — the `policies` table stores policy strings to accommodate Cedar without migration.
- OPA sidecar, ABAC conditions (time-of-day, IP ranges). Phase 2.
- SAML for human users (soma-iam's concern).

**Why:** "Service account reads `staging/*` but not `prod/*`" is a baseline requirement that pure role-only RBAC cannot express without role explosion.

---

### 11. soma-iam JWT integration with session-token exchange

**In scope:**

- soma-vault validates soma-iam RS256/ES256 JWTs via locally cached JWKS (`jsonwebtoken` crate). Cache uses a singleflight pattern (exactly one in-flight re-fetch per kid miss, other waiters block on the same future) to prevent thundering-herd against soma-iam's JWKS endpoint during key rotation.
- Negative caching: unknown `kid` cached as "not found" for 60s; circuit breaker after N consecutive failed fetches.
- Validates `iss`, `aud == ["soma-vault"]`, `exp`, `iat`, and requires `tenant_id` claim. Tokens without `tenant_id` are rejected at the auth boundary.
- Extracts `sub` (principal UUID), `roles[]`, `tenant_id`.
- Issues its own short-lived **signed JWTs** as session tokens (RS256, signed with a keypair whose private key is derived from the master KEK via HKDF with salt `b"soma-vault-session-signing-v1"`). Validation is signature verification — zero DB read per authenticated request. No `sessions` table.
- JWT ID (`jti`) replay protection: `jti_replay_cache` table with expiry matching the soma-iam JWT `exp`. On every `/v1/auth/login`, rejects previously-seen `jti` values. Expired rows pruned by the background cleanup worker. This prevents soma-iam JWT replay for the full validity window.
- Session token TTL: 15 minutes. For forced revocation (logout), maintain a small in-memory `jti` blocklist with TTL matching the session token — acceptable data loss on pod restart given the 15-minute window.
- Universal Auth (client_id + Argon2id-hashed client_secret) for local dev and machine-identity fallback. Production machine identities use soma-iam OIDC.
- `POST /v1/workspaces/{workspace_id}/service-accounts/{sa_id}/rotate-secret` issues a new `client_secret` and invalidates the old one.

**Out of scope:**

- JWT pass-through on every request (couples availability to soma-iam).
- Token introspection on hot paths.
- Calling soma-iam for every authz decision.
- SAML (soma-iam's concern).

**Why:** A soma-iam outage must not prevent secret reads. Session-token exchange decouples soma-vault read availability from soma-iam availability.

---

### 12. Tenant bootstrap

**In scope:**

- `POST /v1/admin/tenants` endpoint, gated on a server-side `SOMA_ADMIN_TOKEN` environment variable (not exposed through the public load balancer). Creates the `tenants` row keyed to `soma_iam_org_id`.
- The soma-iam contract requires: on org provisioning, soma-iam calls `POST /v1/admin/tenants` with an HMAC-signed webhook payload. The webhook is idempotent (upsert on `soma_iam_org_id`).
- `soma vault admin register-tenant --soma-iam-org-id <uuid> --name <name>` CLI command for self-hosters.

**Out of scope:**

- Self-registration via public API without an admin token.

**Why:** The tenant row is the trust root for all multi-tenancy. Without a defined bootstrap path, no customer can onboard.

---

### 13. KMS circuit-breaker / grace-period mode

**In scope:**

- Transient KMS errors during boot or per-tenant KEK derivation: pod enters DEGRADED state, extends tenant KEK cache TTL up to `SOMA_KMS_GRACE_PERIOD_MINUTES` (default 30, max 240), continues serving from cached KEK material.
- `/health/ready` returns HTTP 200 (pod stays in Service Endpoints, continues receiving traffic) with `"degraded": true` and `"active_alerts": ["kms_unreachable"]` in the JSON body.
- If the grace period expires and KMS remains unreachable, pod transitions to SEALED, returns 503 from `/health/ready`, and emits a CRITICAL structured log.
- On pod boot (no cached KEKs): 60-second retry window with exponential backoff before the readiness probe fails.
- `/health/startup` endpoint: returns 503 during the 60-second KMS boot retry window; transitions to 200 once KMS succeeds. Used by the Kubernetes `startupProbe`. Does not revert to 503 after first success (unlike `/health/ready`).
- Prometheus gauge `soma_vault_kms_grace_period_active` for HPA/monitoring integration. Docs note: returning HTTP 200 in DEGRADED state keeps the pod in the Service Endpoints list — it does not directly affect HPA scaling decisions, which are metric-driven.

**Out of scope:**

- Serving requests with a zeroed or placeholder KEK.
- Grace period beyond 4 hours.
- Skipping the CRITICAL alert when grace period expires.

**Why:** A KMS regional incident during HPA scale-out would prevent new pods from becoming ready and silently shrink capacity. The circuit-breaker bounds this blast radius. AWS KMS SLA is 99.999% but incidents do happen.

---

### 14. CLI exec wrapper and secrets export

**In scope:**

- Single `soma` binary (clap-driven).
- `soma run -- <cmd>`: authenticates, fetches resolved env for project+environment (including inherited overrides), injects as environment variables, execs child via `std::process::Command`.
- `soma secrets export --format=env|json|dotenv`.
- `soma login`, `soma init`, `soma secrets get|set|delete`, `soma config get|set|delete`.
- `soma vault admin init-kms`, `soma vault admin register-tenant`.
- `soma vault verify-encryption` (spot-checks a sample of `secret_versions` rows for decryptability).

**Out of scope:**

- A daemon/agent process. Phase 2.
- `--watch` flag, shell completion scripts. Phase 2.
- `eventsource-client` crate in Phase 1 `Cargo.toml` — added when `--watch` is implemented.

**Why:** The `doppler run` pattern is the #1 DX feature for indie developer adoption. Without it, soma-vault requires SDK integration or manual env-var wiring before anyone can use it.

---

### 15. Secret versioning: max_versions, soft-delete, destroy, CAS, rollback

**In scope:**

- Monotonic integer version per secret per environment. `max_versions` (default 20, configurable). Oldest version hard-destroyed (ciphertext and `wrapped_dek` zeroed, `is_destroyed=true`) atomically with each INSERT that exceeds the limit.
- Soft-delete: `is_deleted=true + deleted_at`; ciphertext retained; recoverable.
- Destroy: `is_destroyed=true`, ciphertext and `wrapped_dek` set to zero bytes. Irreversible. `UNIQUE (secret_id, version)` constraint prevents version number reuse after destroy.
- CAS: optional `expected_version INT` on write; mismatch returns 409.
- Rollback: `POST .../rollback?to_version=N` re-encrypts the specified version's plaintext as a new current version with a **fresh DEK and fresh nonce**. Never copies `wrapped_dek` or `nonce` from the source version row.

**Out of scope:**

- Git-like point-in-time snapshots across all secrets in an environment. Phase 2.

**Why:** Without versioning and rollback, a bad secret rotation or accidental overwrite is unrecoverable. CAS prevents silent concurrent overwrites.

---

### 16. Rust SDK

**In scope:**

- Async client. `secrets.get(path) -> Secret<String>` (secrecy crate, not clonable, no Debug impl). Each call triggers a fresh API request + DEK unwrap. Secrets never cached.
- `config.get::<T>(key) -> T` with typed accessors from in-process `DashMap` cache. `config.get_with_secret(key, &secrets_client) -> (T, Option<Secret<String>>)` for `secret_ref` resolution.
- Background SSE subscription task updates the config cache.
- SDK seeded at startup via one bulk GET.

**Out of scope:**

- TypeScript, Python, Go SDKs. Phase 2. Phase 1 non-Rust consumers use `soma run --` or the REST API.

**Why:** The Rust SDK is the primary integration surface for soma-platform itself and validates the API design before other language bindings.

---

### 17. Leptos (CSR) web dashboard — minimal Phase 1 scope

**In scope:**

- Universal Auth login (no OIDC redirect — soma-iam does not exist yet in Phase 1, so OIDC is untestable).
- Secret CRUD: create, list with masked values, explicit-click reveal with auto-hide, delete.
- Config CRUD: value_type selector, inline validation feedback.
- Basic workspace/project/environment tree navigation.
- Service account create/revoke.
- httpOnly `Secure SameSite=Strict` session cookie set by the axum login handler. The WASM client never touches the token directly. Double Submit Cookie CSRF protection.

**Out of scope (deferred to Phase 2 / post-launch):**

- soma-iam OIDC redirect login (untestable without soma-iam).
- Audit log viewer with chain verification UI.
- Health status page, per-environment override tab, config version diff view.
- Approval workflow UI, policy management UI, A/B flag targeting UI.
- Real-time secret live-refresh in the dashboard (30s polling is sufficient).

**Why:** The Phase 1 gate does not require a polished dashboard. OIDC login is untestable until soma-iam exists. `soma run --` is the primary onboarding path for Phase 1. The minimal dashboard unblocks non-CLI users without blocking the Phase 1 gate on soma-iam availability.

---

### 18. Single binary self-host + Helm chart

**In scope:**

- One `soma-vault-server` binary: embeds sqlx migrations (`sqlx::migrate!()`), serves REST API + SSE + Leptos dashboard static assets.
- Configured entirely via environment variables (`KMS_PROVIDER`, `KMS_KEY_ID`, `DATABASE_URL`, `SOMA_IAM_JWKS_URL`, `SOMA_MASTER_KEK_HEX` for software-KMS, `LOG_LEVEL`, `SOMA_ADMIN_TOKEN`, `SOMA_KMS_GRACE_PERIOD_MINUTES`).
- No external runtime dependencies beyond Postgres.
- Helm chart: Deployment, Service, ServiceAccount (with `eks.amazonaws.com/role-arn` annotation for IRSA), ConfigMap, optional HPA, PodDisruptionBudget.
- N-1 rolling deploy compatibility: all Phase 1 migrations are additive (new nullable columns or new tables only). `soma-vault-server` checks the `_sqlx_migrations` table on startup against its compiled-in expected migration count and fails the readiness probe if the database schema is ahead of or behind the binary's expected version by more than one migration.

**Out of scope:**

- Redis as any Phase 1 dependency.
- Consul.
- A separate operator binary for `soma-vault-server` itself.

**Why:** The single-binary self-host model is the primary moat over managed-only competitors.

---

## Explicit Non-Goals and YAGNI Reasoning

| Non-goal | Deferred because |
|---|---|
| **Dynamic secrets** (ephemeral DB credentials, AWS STS with lease-based auto-revocation) | Requires per-backend `CredentialProvider` adapters and outbound connectivity from pods to target systems. The `leases` table shape and `CredentialProvider` trait are reserved in schema comments. Phase 2. |
| **PKI / internal Certificate Authority** | `certificate_authorities` table shape is reserved. Requires `rcgen`, CRL, OCSP. Phase 2. |
| **Transit / Encryption-as-a-Service API** (`/v1/transit/*`) | The internal envelope encryption plumbing exists; the external API surface is additive. Phase 2. |
| **GCP Cloud KMS and Azure Key Vault backends** | `KmsBackend` trait is defined; these are new structs. No customer has requested them yet. Phase 2. |
| **SPIFFE/SPIRE** | Cloud workload identity (IRSA / GKE WI / Azure WI) satisfies tenet 3 for cloud deployments. SPIRE adds a DaemonSet and operational overhead inappropriate for Phase 1. Phase 2 for on-prem/multi-cloud enterprise. |
| **Kubernetes mutating admission webhook / sidecar injector** | Cluster-critical admission webhooks require high availability and add significant operational risk. Phase 2. |
| **Secrets Store CSI Driver provider** | `soma run --` and the Helm chart Deployment cover Phase 1 injection needs without the CSI complexity. Phase 2. |
| **Kubernetes Operator (SomaSecret CRD)** | Indie developers use `soma run --`. The operator adds a second binary, a static `client_secret`, and 60s polling. The manual pattern (`soma secrets export` → K8s Job populating a native Secret) achieves the same result. Phase 2 alongside the CSI driver once the API contract is stable. |
| **Static secret rotation infrastructure** | The four-stage lifecycle, `rotation_jobs` table, SKIP LOCKED workers, and `rotation_schedules` table all ship with zero working rotation adapters. The infrastructure cannot be validated end-to-end against a real consumer, and the Phase 1 gate does not require rotation. Phase 2 includes the first two adapters (Postgres DB password, AWS access key), at which point the lifecycle design is validated against a real consumer. |
| **External SIEM audit log streaming** | The append-only HMAC-chained Postgres table is the Phase 1 foundation. Async streaming fanout is additive. Phase 2 enterprise feature. |
| **Approval / change-request workflow** | The audit log with the `reason` field is the Phase 1 governance surface. The proposal/approval state machine is Phase 2. |
| **TypeScript and Python SDKs** | Rust SDK validates the API design first. Phase 1 non-Rust consumers use `soma run --` or the REST API. Phase 2. |
| **Go SDK, .NET IConfigurationProvider** | Phase 2. |
| **Multi-region active-active replication** | Postgres streaming replication covers Phase 1 and Phase 2 HA. Active-active requires distributed consensus that contradicts the stateless-pod model. Phase 3. |
| **Per-project customer-managed KMS keys (BYOK/CMEK)** | `KmsBackend` trait supports it. One master KMS key per deployment is sufficient for Phase 1. Phase 2 enterprise. |
| **Redis as any dependency** | Enforced as a non-goal through all phases until Postgres LISTEN/NOTIFY ceiling is actually measured to be insufficient. Single-binary self-host requires Postgres to be the only stateful dependency. |
| **Secret scanning / leak detection in source control** | Separate tool category (GitGuardian, Trufflehog). Out of scope for this product. |
| **Honey tokens / canary secrets** | Trivial to add as a flag on the `secrets` table. Not needed for Phase 1 credibility. Phase 2. |
| **JSON Schema codegen** (`schemars`-derived structs) | Phase 1 validates at write time. Client-side type generation is a CLI tool on top. Phase 2. |
| **Gradual config rollout / canary strategies** | Phase 1 config changes are atomic. Deployment-strategy objects are Phase 2. |
| **Consul** | Out of scope. soma-vault is designed around a single Postgres dependency; adding Consul as a storage or coordination backend would re-introduce the multi-component operational surface that single-binary self-host is designed to avoid. |
| **Per-operation-class distributed rate limiting** | A correct distributed rate limiter requires Redis (forbidden) or a write-hot Postgres counter (one extra write per request). Phase 1 applies per-IP rate limiting on `/v1/auth/*` only (in-memory token bucket — acceptable inaccuracy across pods for auth endpoints). Phase 2 when Redis is chosen for another reason. |
| **Cursor-based pagination on list endpoints** | Phase 1 uses offset pagination (`limit` + `offset` + `has_more` boolean). No `total` count field (expensive, inconsistent with cursor semantics). Cursor-based pagination is Phase 2 when scale profile is known. |
| **`kms_state` Postgres table** | Per-pod seal status is ephemeral runtime state. Storing it in Postgres adds concurrent upserts from N pods with no tenant context. Served from in-memory `KmsState` struct. Monitoring uses Prometheus metrics + structured logs. |

---

## The soma-iam Contract

soma-vault defines the requirements; soma-iam is built to satisfy them.

**soma-iam MUST provide:**

- OIDC discovery endpoint and JWKS endpoint.
- JWTs with claims: `sub` (UUID), `tid` (tenant UUID, mapped from soma-iam org_id), `roles: string[]`, `aud: ["soma-vault"]`, `exp`, `iat`, `jti`.
- Workspace-scoped role claims: `workspace_roles: [{workspace_id: UUID, role: string}]` for machine identities, so that soma-vault-local `principal_workspace_roles` rows can eventually be replaced by JWT claims.
- `org.created` webhook: soma-iam calls `POST /v1/admin/tenants` on soma-vault's internal endpoint when a new org is provisioned. Signed with a pre-shared HMAC key. Idempotent.
- `principal.deactivated` webhook: soma-iam calls a soma-vault endpoint to purge `principal_workspace_roles` rows and revoke active session tokens for the deactivated principal.
- Kubernetes projected ServiceAccount token exchange for cluster workloads (not just GitHub Actions / GitLab CI).
- Short-lived token TTLs for machine identities (≤15 minutes) to bound replay window.

**Two distinct identity planes — never conflated:**

| Plane | Principal | Credential | Purpose |
|---|---|---|---|
| Infrastructure | soma-vault pod | Kubernetes projected SA token → AWS IRSA → KMS | Auto-unseal; pod proves its identity to the KMS |
| Application | Human or service account | soma-iam JWT → soma-vault session JWT | Reads and writes secrets/config |

The Kubernetes operator (Phase 2) will authenticate via its projected SA token → soma-iam OIDC exchange → soma-vault session token. It will NOT use a static `client_secret`.

---

## Crypto Stack Summary

| Purpose | Crate | Notes |
|---|---|---|
| Secret-value AEAD | `aes-gcm 0.10.x` | AES-256-GCM, NCC Group audited, pure Rust. Primary cipher. |
| Secret-value AEAD (fallback) | `chacha20poly1305 0.10.x` | NCC audited; server config option for non-AES-NI hardware |
| DEK wrapping under tenant KEK | `aes-kw 0.3.x` | RFC 3394 AES Key Wrap — nonceless, correct for key wrapping |
| Per-tenant KEK derivation + audit HMAC key | `hkdf 0.12.x` + `sha2 0.10.x` | HKDF-SHA256; different salt values ensure domain separation |
| Audit HMAC chain | `hmac 0.12.x` + `sha2 0.10.x` | Replaces `ring` entirely — same RustCrypto suite as HKDF |
| Key material zeroing | `zeroize 1.x` + `zeroize_derive` | ZeroizeOnDrop on all key structs; `Box<Zeroizing<[u8;32]>>` in caches |
| Sensitive type wrapper | `secrecy 0.10.x` | `Secret<T>` suppresses Debug/Display |
| Constant-time comparison | `subtle 2.x` | Token and HMAC verification |
| CSPRNG | `rand 0.9.x` (OsRng) | DEK and nonce generation; never `thread_rng()` for key material |
| TLS | `rustls 0.23.x` + `aws-lc-rs` | Zero OpenSSL; FIPS 140-3 upgrade path via `aws-lc-fips-sys` |
| AWS KMS | `aws-sdk-kms` + `aws-config` | IRSA credential chain; no static credentials |
| Software-KMS (self-host) | env var (`SOMA_MASTER_KEK_HEX`) | Hex-encoded 32 bytes in a K8s Secret; WARNING on health endpoint |
| Universal Auth hashing | `argon2 0.5.x` | Argon2id for `client_secret` |
| JWT validation | `jsonwebtoken 9.x` | RS256/ES256/EdDSA; singleflight JWKS refresh |
| JWT replay protection | `jti_replay_cache` table | Indexed on `(jti, exp)`; pruned by background worker |

No `ring` dependency anywhere. No OpenSSL dependency anywhere.

---

## Phase 1 Is Done When

A solo developer can:

1. **Deploy soma-vault-server on EKS** (AWS IRSA configured, `DATABASE_URL` pointing to an RDS Postgres instance) and reach a healthy readiness probe within 90 seconds, with zero manual key ceremony.
2. **Run `soma run -- node server.js`** from a laptop (software-KMS mode with `SOMA_MASTER_KEK_HEX`) and have the child process receive the correct environment variables from soma-vault, end to end, in under 10 minutes from first `cargo install soma`.
3. **Demonstrate that a Postgres dump is cryptographically useless** without KMS access: take a `pg_dump` of the database, point a fresh Postgres instance at it, and confirm that no `secret_versions` row yields plaintext without the master KEK.
4. **Scale the Deployment from 1 to 3 replicas and back to 1** with no human intervention, no coordination between pods, and no stale data. Each new pod comes up ready by independently authenticating to KMS.
5. **Show the HMAC chain is intact** via `GET /v1/audit/verify` returning `"chain_intact": true` after 100 secret reads and writes across multiple tenants.
6. **Demonstrate hard tenant isolation**: a session token issued to tenant A returns zero results for any query scoped to tenant B's data, even when the `WHERE tenant_id` clause is removed from the application query (RLS backstop fires).
7. **Create a config key with `value_type=json` and a JSON Schema**, write an invalid value (expect 400 with structured error), write a valid value, observe the config update arrive in the SDK's in-memory cache within 1 second via SSE.

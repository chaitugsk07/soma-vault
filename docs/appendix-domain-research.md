# Appendix: Domain Research — soma-vault Core Domains and Crypto Stack

This appendix documents the research behind soma-vault's key design decisions. Each section covers one domain: how production systems handle it today, the design options considered, the recommended approach, and the Rust crates required. Phase tags indicate whether a domain ships in Phase 1 or later.

---

## 1. KV Secret and Configuration Storage

**Phase: 1**

### What It Is

The core data-layer problem: storing encrypted blobs (secrets) and typed structured values (config) with full version history, per-principal access control, multi-tenant isolation, and low-latency delivery — while keeping the DB dump worthless without KMS access.

### How the Leaders Do It

**Vault KV v2 / OpenBao** — two storage keys per secret path: a metadata entry (current_version pointer, max_versions, cas_required, delete_version_after, custom_metadata, timestamps) and N numbered version entries (encrypted blob + lifecycle flags). Default 10-version retention; configurable per-secret. CAS prevents silent overwrites. Soft-delete sets deletion_time but keeps ciphertext; destroy zeroes it irreversibly. Single barrier key per mount — no per-secret DEK.

**Infisical** — two table pairs in PostgreSQL: `SecretV2` (live row) and `SecretVersionsV2` (append-only history). Workspace-scoped DEK (not per-secret). Git-like commit snapshots for point-in-time recovery scoped to environment+folder.

**AWS Secrets Manager** — per-secret-version DEK: KMS generates a fresh 256-bit data key per version; ciphertext + wrapped DEK stored together. Staging labels (`AWSCURRENT`, `AWSPREVIOUS`, `AWSPENDING`) rather than integer version numbers. Soft-delete with 7–30 day recovery window.

**GCP Secret Manager** — immutable auto-numbered versions, per-secret DEK wrapped by Cloud KMS KEK. Soft-disable and destroy operations.

**GCP Parameter Manager (2025)** — typed JSON/YAML config up to 1 MiB per version, AES-256 encrypted. Embeds `__REF__(//secretmanager.googleapis.com/projects/.../secrets/.../versions/...)` syntax resolved server-side at render time — the cleanest implementation of the config-references-secret pattern in production.

**Replane** — SSE-first real-time typed config delivery. JSON Schema validation. Immutable version snapshots. Local SDK cache + background SSE sync.

### Design Options

| Option | Pros | Cons |
|--------|------|------|
| A: Unified entry table (single table for both, discriminated by enum) | Fewer tables, simpler queries | Violates tenet 5 (secrets != config at data-model level). Cannot enforce that config never carries ciphertext. AWS/GCP both moved away from this — industry consensus is separate storage. |
| **B: Separate secrets and config tables, per-secret-version DEK (recommended)** | Enforces tenet 5 at schema level. Smallest blast radius (one DEK = one secret version). Config values are unencrypted: typed, loggable, indexable. `secret_ref` FK in config makes the pointer pattern explicit. | More tables (4 core tables vs 2). KMS call per secret-version write (~5–50ms, acceptable for writes). |
| C: Separate tables, workspace-scoped DEK (Infisical model) | Fewer KMS calls | Blast radius is the entire workspace if DEK is compromised. Contradicts tenet 4 (per-secret envelope encryption). |
| D: Path-namespace model (Vault-style KV over Postgres) | Matches Vault's proven model | Loses relational integrity. Multi-tenant isolation becomes path-prefix convention. No typed config without a separate schema registry. |
| E: SSE push for both secrets and config | Uniform SDK interface | Secret values in SSE stream is a high-severity security risk. Industry consensus: pull-only for secrets. |

### Recommended Approach

**Option B.** Four core tables:

```sql
-- Secrets: encrypted blobs only
secrets (
  id UUID PK, tenant_id UUID NOT NULL, workspace_id UUID, project_id UUID,
  environment_id UUID, path TEXT, current_version INT,
  cas_required BOOL DEFAULT false, max_versions SMALLINT DEFAULT 20,
  delete_version_after INTERVAL, custom_metadata JSONB, created_at, updated_at
)

secret_versions (
  id UUID PK, secret_id UUID FK, version INT,
  encrypted_value BYTEA,  -- AEAD ciphertext
  wrapped_dek BYTEA,      -- KMS-wrapped DEK
  nonce BYTEA,
  is_deleted BOOL, deleted_at TIMESTAMPTZ,
  is_destroyed BOOL,      -- ciphertext and DEK zeroed
  created_at, created_by_type ENUM('user','service_account','system'), created_by_id UUID
)

-- Config: typed, unencrypted, loggable, schema-validated
config_entries (
  id UUID PK, tenant_id UUID NOT NULL, workspace_id UUID, project_id UUID,
  environment_id UUID, path TEXT,
  value_type ENUM('string','int','float','bool','json','secret_ref'),
  schema_json JSONB,  -- JSON Schema for 'json' type; NULL otherwise
  is_sensitive BOOL,  -- governs logging/redaction
  current_version INT, created_at, updated_at
)

config_versions (
  id UUID PK, config_entry_id UUID FK, version INT,
  string_value TEXT, int_value BIGINT, float_value DOUBLE PRECISION,
  bool_value BOOL, json_value JSONB,
  secret_ref TEXT,  -- secret path; NULL unless value_type = 'secret_ref'
  is_deleted BOOL, created_at
)
```

Key decisions:
- **Per-secret-version DEK**: generate a 32-byte random DEK via `OsRng`, encrypt plaintext with `XChaCha20Poly1305` (192-bit nonce eliminates nonce-reuse risk), call KMS `Encrypt(DEK)` to get `wrapped_dek`, store `(ciphertext, wrapped_dek, nonce)`. On read: KMS `Decrypt(wrapped_dek)` → DEK → decrypt → zeroize DEK immediately.
- **Config entries are never envelope-encrypted** — they are typed values, loggable by design.
- **`secret_ref` is first-class**: a config_version row with `value_type = 'secret_ref'` resolves at read time. The secret value never inlines into config responses.
- **CAS**: write API accepts optional `expected_version`; mismatch returns 409.
- **SSE push for config only**: on `config_version` insert/update, broadcast to all SSE connections subscribed to that project+environment. Secrets are pull-only.
- **Audit log**: separate append-only `audit_events` table (see §8).

**Not built in Phase 1:** JSON Schema validation on config_entries (Phase 2), gradual rollout / canary deployment, dynamic secrets, full commit snapshots (Infisical PiTR model), secret rotation automation, multiple KMS backends (AWS KMS + software fallback for self-host in Phase 1; GCP/Azure in Phase 2).

### Pitfalls

- Zeroize the DEK using `zeroize` (ZeroizeOnDrop) — a plain `Vec<u8>` is not zeroed by the compiler on drop.
- CAS requires `SELECT FOR UPDATE` or a serializable transaction — a check-then-write without a lock has a TOCTOU race.
- SSE connections must be authenticated and scoped to a single tenant+project+environment. A broadcast handler that iterates all connections without tenant filtering is a cross-tenant data leak.
- `max_versions` enforcement must be atomic with the insert — run both in one transaction.
- The `secret_ref` resolver must check authZ for both the config entry AND the referenced secret.
- Soft-delete (`is_deleted`) is not access control. Destroyed versions must never return data.
- Batch imports fire N KMS calls — parallelize with bounded concurrency to avoid KMS throttling.

### Rust Crates

| Crate | Role |
|-------|------|
| `chacha20poly1305` | XChaCha20Poly1305 AEAD for per-secret-version encryption |
| `aes-gcm` | AES-256-GCM alternative for HW-accelerated paths |
| `zeroize` | ZeroizeOnDrop on DEK buffers |
| `rand` (OsRng) | CSPRNG for DEK and nonce generation |
| `aws-sdk-kms` | AWS KMS Encrypt/Decrypt for DEK wrapping |
| `sqlx` | Async PostgreSQL with compile-time query checking |
| `axum` + `tokio-stream` | SSE delivery for real-time config push |
| `uuid` | UUID v4 PKs |
| `serde` + `serde_json` | JSONB serialization |

---

## 2. Application Configuration Management

**Phase: 1**

### What It Is

Storing, validating, distributing, and updating non-code configuration values (feature flags, tuning knobs, typed structured settings, per-environment overrides) separately from secrets. Config values are typed, indexable, loggable, and safe to display in dashboards.

### How the Leaders Do It

**AWS AppConfig** — typed Feature Flags and Free-Form Configurations. JSON Schema or Lambda validators run before every deployment and auto-rollback on failure. AppConfig Agent runs as a sidecar, caches config locally, app calls local HTTP endpoint.

**Azure App Configuration** — key-value store with labels (label = environment dimension). Key Vault references for `$ref` pointers (config stores the KV URI, SDK resolves at fetch time). Polling with configurable refresh interval (default 30s, minimum 1s).

**Replane** — SSE-first: sub-second config propagation, ~4,500 msg/s on M2 Pro, 5,000 concurrent clients at ~1.5 cores. JSON Schema per config key. In-memory SDK cache seeded at startup; background SSE connection updates cache on change. ~4 LOC SDK integration.

**Doppler** — treats everything as env vars, no typed schema layer. No SSE push.

**Infisical** — no native typed config at the data model level; everything is a string KV pair. Config vs secret distinction is UI/access-control only.

**Configu** — schema-first (`.cfgu.json` files in source control). Config data model is `(key, value, set)` triplets; type enforcement is schema-side. Delegates secret storage to external managers.

### Design Options

| Option | Verdict |
|--------|---------|
| Pure polling (AWS AppConfig / Azure model) | Simplest, but latency = poll interval (minimum ~10–30s in practice). Not the DX target. |
| **SSE push with in-process SDK cache (Replane model) — recommended** | Sub-second propagation. Zero-latency local reads. axum SSE is built-in. Proven at scale. |
| Webhook / event bus delivery | Adds an operational dependency (broker or webhook endpoint per service). Overkill for Phase 1. |
| **Separate config and secrets tables with $ref pointers — recommended** | Config table safe to log/audit/index. Secret values never inline into config responses. Satisfies tenet 5. |
| Unified KV store with sensitivity flag (Doppler / Infisical model) | Violates tenet 5. Sensitive values can leak into logs. |

### Recommended Approach

1. **Two first-class entity types in Postgres** (per §1 schema): `config_values` (typed, schema-validated, logged, indexable) and `secrets` (encrypted, DEK-wrapped, never logged, never inlined). A config value with `value_type = 'secret_ref'` stores only the secret path — never the plaintext. The delivery layer resolves it at fetch time.

2. **Typed config with JSON Schema validation**: each config key has an optional `schema_json` (JSONB). Validate at write time using the `jsonschema` crate; reject invalid payloads. Phase 1 validates only the `value_type` enum; full schema validation ships in Phase 2.

3. **Environment hierarchy**: `tenant → workspace → project → environment → config_value`. Environments have an optional `inherits_from` FK. At fetch time, walk the inheritance chain and merge (child values win). Cap depth at 3 levels.

4. **SSE push with local cache**: `GET /v1/config/stream?project=X&env=Y` returns `text/event-stream`. On any `config_value` write, broadcast a `ConfigChangeEvent` to all connected SDK subscribers. SDK seeds its cache at startup (one bulk fetch), then maintains a background SSE connection. Config reads from the SDK are always local (zero network latency). Polling fallback every 60s handles reconnects. **Never push secret plaintext over SSE** — if a config key is a `secret_ref`, the SSE event sends the path, not the value.

5. **Feature flags**: no separate entity. A feature flag is a `config_value` with `value_type = 'bool'` or `value_type = 'int'` for percentage rollout. Add `is_feature_flag: bool` for UI filtering. No specialized evaluation SDK in Phase 1.

6. **Personal dev configs**: handled by environment inheritance. A personal environment inherits from dev with per-user overrides. `environments` has an optional `owner_user_id` for scoping.

**Not built in Phase 1:** approval/change-request workflows, A/B experimentation, gradual rollout SDK evaluation, external config source integrations (S3, SSM), Lambda/webhook validators.

### Pitfalls

- Building a change-request/approval system before the core delivery path is stable — defer to Phase 2.
- SSE fan-out via a shared in-process broadcast channel works per-pod; multi-pod cross-pod fan-out requires Redis pub/sub (add in Phase 2). Document the ceiling with a `// ponytail:` comment in code.
- Storing resolved secret values in config audit logs — log the `$ref` pointer, never the plaintext.
- Infinite inheritance depth — cap at 3–4 levels and detect cycles at write time.
- JSON Schema validation on every read (hot path) — validate at write time, trust stored values at read time.

### Rust Crates

| Crate | Role |
|-------|------|
| `jsonschema` v0.46.5 | JSON Schema validation (Drafts 4–2020-12); build once, validate many |
| `schemars` | Derive `#[derive(JsonSchema)]` on Rust config structs for SDK type generation |
| `axum::response::sse` | Built-in SSE handler; no extra crate needed |
| `tokio::sync::broadcast` | Fan-out to connected SDK subscribers per pod |
| `serde` + `serde_json` | JSONB config value serialization |
| `sqlx` | Async Postgres; `tenant_id` on every query |
| `zeroize` | Zeroing plaintext DEK after use |

---

## 3. Multi-Tenant, Multi-Workspace Data Isolation

**Phase: 1**

### What It Is

How to store secrets and config for many tenants (orgs), each with many workspaces, projects, and environments, in one Postgres database — with hard tenant isolation, encrypted-at-rest data, stateless pods, and a plain portable schema.

### How the Leaders Do It

**Infisical** — migrated from MongoDB to Postgres (early 2024). Stateless server, scales horizontally. Shared schema with `org_id`/`workspace_id` columns on every row. Application-layer tenant enforcement (no published RLS). Single workspace-scoped DEK wrapped by operator-provided `INFISICAL_ENCRYPTION_KEY` env var — NOT a per-pod KMS unseal.

**OpenBao v2.3 (May 2025)** — namespaces (multi-tenancy) shipped in OSS under MPL-2.0 after being Enterprise-only in HashiCorp Vault. Raft-based StatefulSet — still not truly stateless.

**Postgres isolation patterns (2025–2026 consensus)**: four patterns: (A) shared schema + `tenant_id` column, (B) schema-per-tenant, (C) database-per-tenant, (D) hybrid tiering. For secrets platforms: Option A + RLS as defense-in-depth + application-layer enforcement. RLS pitfalls: table-owner bypasses RLS by default (use `FORCE ROW LEVEL SECURITY`); pgBouncer transaction-pooling leaks session variables (use `set_config(..., true)` inside a transaction); `SECURITY DEFINER` views bypass RLS (use `security_invoker=true` on Postgres 15+); unique constraints leak cross-tenant existence; materialized views copy data outside RLS.

### Design Options

| Option | Verdict |
|--------|---------|
| A: Shared schema + application-layer `tenant_id` only | Infisical uses this successfully. Defense-in-depth is weaker — one missing WHERE clause leaks data. |
| **B: Shared schema + application-layer + RLS as backstop — recommended** | Two independent enforcement layers. 2–4% overhead on indexed `tenant_id`. Compatible with sqlx via `set_config('app.tenant_id', $1, true)` inside every transaction. |
| C: Schema-per-tenant | O(N tenants) migration complexity. pg_catalog bloat. Not recommended for new SaaS in 2026. |
| D: Database-per-tenant | Maximum isolation but operationally incompatible with single-binary self-host. Reserved for enterprise tier. |

**Key hierarchy options:**

| Option | Verdict |
|--------|---------|
| E: Single global KEK wraps all DEKs | Catastrophic blast radius — one KEK compromise exposes every tenant's secrets. |
| **F: Per-tenant KEK derived via HKDF from master key, per-secret DEK wrapped by tenant KEK — recommended** | Blast radius is per-tenant. Master key rotation only re-derives KEKs (cheap). Per-secret DEKs give individual secret isolation. |

### Recommended Approach

**Tenancy model**: Option B — shared schema + `tenant_id` on every table + application-layer enforcement as the primary gate + RLS as defense-in-depth. Use `FORCE ROW LEVEL SECURITY` on every table, `set_config('app.tenant_id', $1, true)` in every Axum request via a database middleware, composite indexes on `(tenant_id, id)` and `(tenant_id, created_at)`, `SECURITY INVOKER` on all views (Postgres 15+).

**Schema hierarchy**: `tenant` (= soma-iam `org_id`, UUID, the root scope) → `workspace` → `project` → `environment` → `secret | config_key`. Every table carries `tenant_id` directly (denormalized) for RLS policy evaluation without joins.

**Key hierarchy** (Option F — four layers):

```
Layer 0: External KMS key (AWS/GCP/Azure CMK) — never leaves HSM
Layer 1: Tenant Root Key (TRK): 256-bit random, KMS-wrapped, stored in tenant_kms_keys table
         Derived in pod RAM via KMS Decrypt; held in LRU cache (TTL 5 min), zeroized on eviction
Layer 2: Per-secret DEK: 256-bit random, wrapped by TRK in-process (no additional KMS call)
         Stored as dek_wrapped BYTEA alongside ciphertext
Layer 3: Secret ciphertext: AES-256-GCM (96-bit random nonce) or XChaCha20Poly1305
```

**Auto-unseal (Tenet 3)**: pod presents K8s projected ServiceAccount token → cloud OIDC exchange → ephemeral cloud credentials → KMS Decrypt → TRK in memory. Zero static credentials. Zero human ceremony. Self-host fallback: `age`-based software KMS (document as reduced-security tier).

**Config values** are not envelope-encrypted (typed, logged, indexable). Config values with `value_type = 'secret_ref'` store only the secret ID, never the plaintext.

### Pitfalls

- RLS table-owner bypass: the application role must NOT be the table owner; use `FORCE ROW LEVEL SECURITY`.
- pgBouncer transaction-pooling: always use `set_config('app.tenant_id', $1, true)` inside `BEGIN/COMMIT`; add an `after_release` hook to `RESET app.tenant_id`.
- `SECURITY DEFINER` views bypass RLS — use `security_invoker=true` (Postgres 15+).
- Tenant-scoped unique indexes `(tenant_id, key_name)` — not global ones — to prevent cross-tenant existence leaks via duplicate-key errors.
- Enforce RLS policy on every new table; add a migration linter or CI check.
- Materialized views and background jobs escape RLS — always filter by `tenant_id` explicitly.
- Per-tenant KEK caching: cache only for the duration of a single request; zeroize on drop.
- AEAD nonce reuse: generate fresh random nonce per encryption via `OsRng`.
- SSE fan-out ceiling: one `tokio::broadcast` channel per environment works up to ~thousands of subscribers per pod. Document the ceiling and the upgrade path (Postgres `LISTEN/NOTIFY` or Redis pub/sub) with a `// ponytail:` comment.

### Rust Crates

`sqlx`, `axum`, `tokio`, `aes-gcm`, `chacha20poly1305`, `hkdf`, `sha2`, `zeroize`, `rand`, `aws-sdk-kms`, `google-cloud-kms`, `age`, `uuid` (v7 for time-ordered inserts), `serde` + `serde_json`, `tokio-stream`.

---

## 4. Master-Key Envelope Encryption and Auto-Unseal

**Phase: 1**

### What It Is

A three-to-four layer key hierarchy where each layer wraps the one below it, so no plaintext key ever touches persistent storage. Auto-unseal means a pod proves its cloud workload identity and the KMS unwraps the root key — no human ceremony, no mounted secret.

### How the Leaders Do It

**Vault / OpenBao auto-unseal**: root key wrapped by external KMS (AWS KMS, GCP Cloud KMS, Azure Key Vault). Pod's workload identity (IRSA, GKE Workload Identity) gives it the IAM permission to call KMS. No manual Shamir shares on restart. **However**: Vault still uses Raft with StatefulSet + PVC — it is not truly stateless.

**Infisical**: four-layer hierarchy — operator-provided 256-bit AES `ROOT_ENCRYPTION_KEY` (env var or HSM) → Internal KMS Root Key (encrypted in DB) → per-org data key → per-project data key → secret ciphertext. AES-256-GCM with 96-bit nonces throughout. The root key is still an env var in self-hosted mode — not true KMS auto-unseal for the application tier.

**AWS Secrets Manager / GCP Secret Manager / Azure Key Vault**: per-secret DEKs wrapped by provider-managed KEK that lives exclusively in cloud HSM. Access control is entirely IAM-based (IRSA, GKE Workload Identity, Azure MI). Zero static credentials. This is the gold standard.

**Bitwarden Secrets Manager**: per-item Cipher Key (64 random bytes) wrapped by Organization Symmetric Key, distributed via RSA public key per member. AES-CBC-256 + HMAC (not GCM). Human-password-anchored — not optimized for machine-to-machine at scale.

**SPIFFE/SPIRE**: cloud-agnostic workload identity standard. SPIRE Agent issues X.509-SVIDs (default 1h TTL, auto-rotated) usable as identity for KMS calls. The correct abstraction for multi-cloud or on-prem.

### Design Options

| Option | Verdict |
|--------|---------|
| A: Single root key, single DEK per workspace (Infisical model) | Simpler, one KMS call per workspace. Blast radius = entire workspace if DEK is compromised. |
| B: Single root key, per-secret DEK | Maximum isolation. AWS/GCP/Azure model. One KMS call per unique DEK (mitigated by TRK cache). |
| **C: Two-tier tenant root key (KMS-wrapped) + per-secret DEK — recommended** | One KMS call unwraps the TRK; TRK unwraps per-secret DEKs in memory (no repeated KMS calls on reads). Blast radius = per-tenant for TRK compromise, per-secret-version for DEK compromise. |
| D: Single encryption key per pod (classic Vault without per-secret DEKs) | Violates tenet 4. No per-secret blast-radius isolation. |

### Recommended Approach

**Option C** — two-tier with KMS-wrapped TRK + per-secret DEK:

```
Layer 0: External KMS key (AWS/GCP/Azure CMK) — never leaves HSM. Pod's workload identity
         (IRSA / GKE WI / Azure MI) is the only access credential. No static credentials.
Layer 1: Tenant Root Key (TRK): 256-bit random. KMS Decrypt on first request per tenant.
         Cached in pod memory (Arc<RwLock<HashMap<tenant_id, Zeroizing<[u8;32]>>>>, TTL 5 min).
         Zeroized on eviction.
Layer 2: Per-secret DEK: 256-bit random. Wrapped by TRK in-process (AES-KW / AES-256-GCM wrap).
         Stored as dek_wrapped BYTEA per secret_versions row.
Layer 3: Secret ciphertext: AES-256-GCM (96-bit random nonce) or XChaCha20Poly1305.
         AEAD associated data = secret_id || version_id to prevent ciphertext replay.
```

**Key rotation**: re-wrap all DEKs for the tenant under the new TRK (bulk `UPDATE`). Secret ciphertext is never re-encrypted — only the DEK wrapping changes.

**Zeroization**: every plaintext key must be `Zeroizing<[u8; 32]>`. Use `secrecy::Secret<Zeroizing<Vec<u8>>>` for variable-length material. The `zeroize` drop guarantee ensures keys are wiped from memory.

**Self-host fallback** (no cloud KMS): `age`-based or Shamir-split (`vsss-rs`) software KMS as the KEK-0 substitute. Document explicitly: this removes the no-human-ceremony-on-restart guarantee. Operators must provide the passphrase or shares on first boot.

### Pitfalls

- Never store plaintext DEK or TRK in Postgres — only `kms_wrapped_key` and `dek_wrapped`.
- Never log or serialize a type holding plaintext key material — use `secrecy::Secret` to prevent `Debug`/`Display` leakage.
- Nonce reuse with AES-GCM is catastrophic — generate a fresh `OsRng` nonce per encryption; or switch to AES-GCM-SIV for the DEK-wrapping layer.
- The in-memory TRK cache is the main attack surface — short TTL (5 min), zeroize on eviction, tenant-scoped (never shared across tenants).
- Using KMS `Encrypt` directly on secret values bypasses the DEK layer — always use `GenerateDataKey` + local AEAD.
- KMS key deletion is irreversible data loss — implement KMS key deletion protection at the infrastructure level.

### Rust Crates

| Crate | Role |
|-------|------|
| `aes-gcm` (NCC Group audited) | AES-256-GCM primary cipher |
| `chacha20poly1305` (NCC Group audited) | XChaCha20Poly1305 alternative |
| `aes-gcm-siv` | Nonce-misuse-resistant variant for DEK wrapping layer |
| `hkdf` | HMAC-based KDF for sub-key derivation from TRK |
| `zeroize` | Secure memory zeroing on all key material |
| `secrecy` | `Secret<T>` wrapper (no Debug/Display/log leakage) |
| `subtle` | Constant-time comparisons for MAC verification |
| `aws-sdk-kms` | AWS KMS Encrypt/Decrypt/GenerateDataKey |
| `google-cloud-kms-v1` | GCP KMS (Phase 2) |
| `azure_security_keyvault_keys` | Azure Key Vault wrap/unwrap |
| `rand` (OsRng) | CSPRNG for nonce and DEK generation |
| `argon2` | Argon2id for self-host software-KMS passphrase path |
| `age` | Age encryption for self-host master key file |

---

## 5. Cloud-Native Kubernetes Operation

**Phase: 1**

### What It Is

Running soma-vault as stateless, horizontally-autoscalable pods that boot autonomously via workload identity, hold key material in memory only, store all persistent state in Postgres, and coordinate singleton background work through Postgres advisory locks.

### How the Leaders Do It

**Vault / OpenBao**: Raft-based StatefulSet with persistent volumes. Auto-unseal delegates master-key decryption to AWS/GCP/Azure KMS via workload identity, but Vault still requires StatefulSet + PVC + Raft membership. Not truly stateless. HPA requires special handling of Raft `auto_join`.

**Infisical**: explicitly stateless server — "Infisical is stateless and scales horizontally; all data lives in Postgres." Standard Deployment, not StatefulSet. Weakness: encryption key is a static env var, not a KMS-wrapped root key proven fresh on each boot.

**Akeyless**: Distributed Fragments Cryptography — the gateway is stateless because it never holds a complete key. No unseal ceremony. The inspiration for soma-vault's tenet 2.

**EKS envelope encryption (March 2025)**: Amazon EKS enables envelope encryption of all Kubernetes API data by default on clusters running K8s 1.28+. Uses KMS v2 provider with unique DEK per Kubernetes resource. Strong precedent for per-resource DEKs.

### Recommended Approach

**1. Auto-Unseal via Workload Identity** — annotate the soma-vault pod's `ServiceAccount` with the cloud-provider annotation (`eks.amazonaws.com/role-arn`, `iam.gke.io/gcp-service-account`, `azure.workload.identity/client-id`). On pod boot: Kubernetes TokenRequest API injects a projected JWT; soma-vault exchanges it with the cloud provider's STS; resulting ephemeral credentials authorize one KMS `Decrypt` call to load the root TRK. Zero static credentials. Zero human ceremony. Pod readiness probe gates on successful unseal.

**2. Envelope Encryption per Secret** — per §4 design. Generate fresh DEK via `ring::rand::SystemRandom` or `OsRng`, AEAD-encrypt, KMS-wrap the DEK, store `(ciphertext, wrapped_dek, nonce)`. Zeroize DEK immediately after use.

**3. Stateless Pods / HPA** — `Deployment` (NOT `StatefulSet`). No persistent volumes. All mutable state in Postgres. Connection pooling via PgBouncer or `deadpool`/`bb8` in-process.

**4. Postgres Leader Election for Background Jobs** — session-level advisory lock (`pg_try_advisory_lock(constant_id)`) on a dedicated long-lived connection outside the pool. Each pod races to acquire the lock; winner runs the scheduler loop; losers poll every 30s. Pod crash releases the lock automatically.

```
// ponytail: per-pod broadcast channels work for ~thousands of SSE subscribers.
// Ceiling: when pods * subscribers outgrows single-pod broadcast, add Redis pub/sub fan-out.
```

**5. Single Binary, Helm Chart** — one binary `soma-vault-server`. Embed migrations with `sqlx migrate embed`. Helm chart creates: `Deployment`, `Service`, `ServiceAccount` with workload-identity annotation, `ConfigMap` for non-secret config, optional `HorizontalPodAutoscaler`. No operator in Phase 1.

### Design Options (summary)

| Option | Verdict |
|--------|---------|
| KMS auto-unseal via cloud workload identity | **Recommended** — zero static secrets, proven, HPA-safe |
| Shamir secret sharing (Vault default) | Not used — soma-vault pods prove their identity to a KMS; no unseal ceremony needed (tenet 2) |
| Shared symmetric key as env var (Infisical model) | Weaker security posture; acceptable only for self-host fallback |
| DFC (Akeyless model) | Patented, extreme complexity; KMS wrapping achieves equivalent operational properties |
| SPIFFE/SPIRE as workload identity | Phase 2 — correct for on-prem enterprise but adds operational overhead |
| Postgres advisory lock leader election | **Recommended** for Phase 1 — zero extra infra, same DB dependency |
| Kubernetes Lease leader election (kube-rs) | Adds K8s API dependency and RBAC; redundant given Postgres is already required |

### Pitfalls

- Vault's auto-unseal does not make Vault stateless — the Raft StatefulSet still requires quorum and coordinated membership changes. Model soma-vault's K8s deployment on the stateless Deployment pattern (as Infisical does) combined with KMS-backed key material.
- PgAdvisoryLock zombie-lock: hold advisory locks on a DEDICATED non-pooled connection. If the lock connection is returned to the pool, the lock survives but is no longer associated with the intended holder.
- EKS IRSA token audience: the projected token at the well-known path has audience `sts.amazonaws.com`. Do not use the default kube-apiserver token. The `aws-sdk-kms` default credential chain handles this automatically if `AWS_WEB_IDENTITY_TOKEN_FILE` is set by the EKS admission controller.
- HPA thundering-herd scale-out: 0→10 pods simultaneously each calling KMS on boot may hit KMS rate limits. Use exponential backoff on KMS errors; cache the TRK (no re-fetch needed per request, only on pod boot and scheduled rotation).

### Rust Crates

`aws-sdk-kms`, `aws-config` (WebIdentityTokenCredentialsProvider), `google-cloud-kms`, `azure_security_keyvault_keys`, `kms-aead` (v0.25.0 — envelope encryption combining KMS wrapping with ChaCha20Poly1305), `ring`, `zeroize`, `sqlx`, `spiffe` (Phase 2), `axum`, `tokio`, `serde` + `serde_json`.

---

## 6. Encryption-as-a-Service (Transit) / Envelope Encryption

**Phase: 1 (internal only); Phase 2 (external transit API)**

### What It Is

An internal crypto service layer that performs encrypt, decrypt, sign, verify, HMAC, and data-key generation on behalf of callers. In soma-vault, two distinct uses: (1) internal envelope encryption for stored secrets (Phase 1); (2) external transit API for tenants who want soma-vault as a crypto oracle (Phase 2).

### How the Leaders Do It

**Vault / OpenBao Transit Engine** — named, versioned key rings. Ciphertext carries a version prefix (`vault:v3:...`). Key types: AES-256-GCM-96 (default), ChaCha20-Poly1305, Ed25519, P-256/P-384/P-521 ECDSA, RSA. `rewrap` re-encrypts with the newest key version without exposing plaintext to the caller — the designed key-rotation migration path. Min/max decryption version gates which versions are active.

**AWS KMS** — `GenerateDataKey` returns `(plaintext DEK, wrapped DEK)`. Direct `Encrypt`/`Decrypt` capped at 4 KB. `ReEncrypt` = Vault's rewrap. All key material stays in FIPS 140-3 Level 3 HSMs.

**Infisical** — AES-256-GCM with 96-bit nonces. Four-layer hierarchy (§4). No external transit API for tenants.

**hyperion_vault (open-source PostgreSQL extension)** — per-secret-version DEK wrapped with AWS KMS `GenerateDataKey`. XChaCha20-Poly1305 with version-bound AEAD associated data. DEKs cached in-memory for configurable TTL for KMS resilience. The closest open reference to soma-vault's internal design.

### Design Options

| Option | Verdict |
|--------|---------|
| Full Transit EaaS Layer (Vault-parity) in Phase 1 | Violates YAGNI. Risk of building a feature few indie users need on day one. |
| Internal-only Envelope Encryption (Phase 1) | Satisfies all five non-negotiable tenets. |
| **Hybrid: internal envelope encryption Phase 1, transit EaaS Phase 2 (recommended)** | Builds key management infrastructure once. Phase 2 is additive: expose `/v1/transit/*` routes over the same plumbing. |
| Convergent Encryption for searchable secrets | Leaks frequency information. Postgres indexes on plaintext metadata are sufficient for Phase 1. |

### Recommended Approach

**Phase 1 — Internal Envelope Encryption:**

Key hierarchy:

- **Tier 1 (KMS Root KEK)**: lives inside AWS/GCP/Azure KMS or `age`-based software fallback. Pods acquire via workload identity at boot.
- **Tier 2 (Tenant Workspace Key, TWK)**: one AES-256 key per workspace, generated at creation, stored encrypted in Postgres using AES-256-GCM with the KMS root KEK. Pod decrypts on first use and caches in memory.
- **Tier 3 (Per-Secret DEK)**: fresh 32-byte random per secret-version write. Encrypted with AES-256-GCM (96-bit nonce, AEAD AAD = `secret_id || version_id`). DEK wrapped using TWK via AES-KW (RFC 3394). Plaintext DEK zeroized after use.

Schema per `secret_versions` row:

```sql
ciphertext         BYTEA NOT NULL,
wrapped_dek        BYTEA NOT NULL,
nonce              BYTEA NOT NULL,
aad_fingerprint    BYTEA NOT NULL,  -- HMAC of secret_id||version_id
key_version        INT NOT NULL     -- which TWK generation encrypted wrapped_dek
```

Key rotation: fetch `wrapped_dek`, unwrap with old TWK, re-wrap with new TWK, write back. Secret ciphertext is never touched — only the DEK wrapping changes.

KMS abstraction trait:

```rust
trait KmsBackend {
    async fn encrypt_key(&self, plaintext_dek: &[u8]) -> Result<Vec<u8>>;
    async fn decrypt_key(&self, wrapped_dek: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}
// Implementations: AwsKms, GcpKms, AzureKeyVault, AgeSoftwareKms
```

**Phase 2 (Later) — External Transit EaaS API**: expose `/v1/transit/{workspace_id}/keys` CRUD + `/encrypt`, `/decrypt`, `/sign`, `/verify`, `/hmac`, `/rewrap`, `/datakey` endpoints. Transit keys are a new `key_type` in the same key table. Zero Phase 1 schema changes required if the key table has a `key_type` discriminator from day one.

### Pitfalls

- Never store the plaintext DEK anywhere. Use `secrecy::Secret<[u8;32]>` as the type; zeroize in the same scope it was generated.
- Nonce reuse with AES-256-GCM is catastrophic — `OsRng` fresh random 96-bit nonce per encryption.
- AEAD associated data must bind ciphertext to `(secret_id, version_id)` — without AAD, ciphertexts can be swapped between rows.
- KMS latency on read hot path — cache decrypted TWKs in pod memory (`Arc<RwLock<HashMap<workspace_id, Zeroizing<[u8;32]>>>>`). TWKs are stable (rotated quarterly).
- Key rotation must be atomic: write new `wrapped_dek` and increment `key_version` in a single `UPDATE`.
- Vault's `export` for key material is dangerous — if transit EaaS is added, `export_allowed: false` must be the default.

### Rust Crates

`aes-gcm`, `chacha20poly1305`, `aes-gcm-siv`, `aes-kw` v0.3.0 (AES Key Wrap RFC 3394), `zeroize`, `secrecy`, `hkdf`, `aws-sdk-kms`, `google-cloud-kms`, `aws-lc-rs`, `p256`, `ed25519-dalek`, `hmac` + `sha2`, `age`, `rand` + `getrandom`, `sqlx`.

---

## 7. Dynamic Secrets

**Phase: Later**

### What It Is

On-demand ephemeral credentials with a bounded TTL (minutes to hours), auto-revoked at expiry. The credential does not exist until requested, is unique per request, and expires. Canonical use cases: database credentials, cloud IAM credentials, TLS certificates, SSH certificates.

### How the Leaders Do It

**Vault / OpenBao** — database secrets engine executes parameterized SQL (`CREATE ROLE "{{name}}" ... VALID UNTIL '{{expiration}}' ...`), returns credentials with a `lease_id`. The Expiration Manager loads ALL lease records into memory at startup — a known O(n) pathology that causes OOM at Kubernetes scale. Revocation fires SQL after the TTL fires. Vault retries revocation 6 times; after 6 failures marks the lease irrevocable. 20+ dynamic secret backends via a gRPC plugin interface.

**Infisical** — Enterprise-only. PostgreSQL, MySQL, AWS IAM, and more. Uses a Gateway component for private network access. Architecture mirrors Vault but with simpler role model.

**AWS Secrets Manager** — rotation, not dynamic secrets. Lambda-based rotation on a schedule. `AWSPENDING` staging label prevents double-rotation.

### Recommended Approach

**Phase 1 scope: PostgreSQL dynamic creds only.** Estimated: ~600 lines of Rust, one migration, no new dependencies.

**Architecture** (Options B + C):

1. **Lease table in Postgres**: `leases (tenant_id, workspace_id, lease_id UUID PK, credential_type, target_config_id, principal_id, issued_at, expires_at, revoked_at, revocation_attempts, last_attempt_at, payload BYTEA)`. Indexed on `(tenant_id, expires_at)`.

2. **Credential providers as enum/trait** (no plugin framework): `enum CredentialProvider { Postgres, ... }`. Each implements `generate()` and `revoke()`. Add providers as plain Rust match arms.

3. **Revocation sweeper**: `SELECT ... FROM leases WHERE expires_at <= now() AND revoked_at IS NULL AND revocation_attempts < 7 ... FOR UPDATE SKIP LOCKED LIMIT 100` every 10 seconds. `SKIP LOCKED` lets multiple pod replicas sweep in parallel. On failure, exponential backoff; after 7 attempts mark irrevocable and emit structured audit event.

4. **No startup lease reload** — the deliberate inversion of Vault's model. Sweeper queries Postgres continuously.

5. **Short default TTL**: 1 hour default, 24 hour max. Even if all pods die simultaneously, leases expire within 1 hour with no action required.

6. **Version-bound AEAD**: new credential version gets its own DEK with AAD binding; rotation idempotency key = the `rotation_version` UUID.

**Not built in Phase 1:** plugin framework, AWS IAM / cloud IAM dynamic creds, alternating-user rotation, Kubernetes Lease leader election.

### Pitfalls

- Vault's O(n) startup lease load: soma-vault avoids this entirely by querying Postgres in the sweep — never reconstruct in-memory state from leases.
- Cross-tenant lease revocation: validate `tenant_id` on every lease lookup — never trust `lease_id` alone.
- Irrevocable leases: mark with a dedicated status, emit alert, retain for operator cleanup — never silently drop.
- TTL thundering herd: add ±10% jitter to issued TTLs; cap concurrent revocation workers.
- `SKIP LOCKED` is required — without it, double-revocation SQL under concurrent pods.

### Rust Crates

`sqlx`, `tokio`, `uuid`, `secrecy`, `zeroize`, `deadpool-postgres` or `bb8`, `aws-sdk-sts`, `thiserror`, `tracing`.

---

## 8. PKI / Certificate Issuance

**Phase: Later**

### What It Is

Operating private Certificate Authorities (CAs) to issue X.509 certificates to services, workloads, and devices. Distinct from soma-vault's own auto-unseal (which uses cloud workload identity, not a custom CA).

### How the Leaders Do It

**Vault / OpenBao PKI engine** — root CA mount (HSM/KMS-backed via Managed Keys since v1.10) signs intermediate CA mounts. Single mount can hold multiple issuers since v1.11. EC P-256 issues ~65k certs/sec; RSA-4096 drops to ~160/sec. Supports ACME, EST, CMPv2, SCEP. CRL and OCSP supported as of v1.12.

**Infisical** — full private CA product: root CA + intermediate CA hierarchy, mTLS, SSH certs, ACME. Multi-tenant isolation is per-organization.

**Let's Encrypt** ended its OCSP service on August 6, 2025 — clearest industry signal that short-lived certs have won. CA/B Forum is reducing max public TLS cert TTL to 47 days.

**SPIFFE/SPIRE** — workload identity standard. SPIRE Agent issues X.509-SVIDs (1h default TTL, auto-rotated). Kubernetes PKI for pod-to-pod mTLS (KEP-4317) reached beta in Kubernetes v1.35.

### Design Options

| Option | Verdict |
|--------|---------|
| A: Delegated PKI (AWS PCA / GCP CAS as root) | ~$400/month/CA makes per-tenant intermediate CAs financially unviable for indie tier. |
| **C: Embedded intermediate CA, offline/cloud root (recommended for Phase 2)** | Root CA never touches soma-vault. Intermediate CA key KMS-wrapped. Per-tenant intermediate CAs are a DB row, not a cloud resource. |
| D: No native PKI in Phase 1, use SPIFFE/SPIRE for internal identity | YAGNI-correct. Internal auto-unseal does NOT need a custom CA — cloud workload identity suffices. |

### Recommended Approach

**Two PKI planes, handled completely differently:**

- **Plane A (internal pod identity for KMS auto-unseal)**: cloud workload identity natively — IRSA on AWS, Workload Identity on GCP, Azure Workload Identity. No custom CA needed. Fully satisfies tenet 3.
- **Plane B (PKI-as-a-product for tenants)**: Phase 2. Design the data model now (per-tenant CA rows, CA key wrapped as a DEK under the tenant KEK — same pattern as secret DEKs).

**Data model to design into Phase 1 schema (zero-cost reservation):**

```sql
certificate_authorities (
  id UUID PK, tenant_id UUID NOT NULL, workspace_id UUID,
  ca_type ENUM('root','intermediate','leaf_issuer'), parent_ca_id UUID,
  subject_dn TEXT, key_algorithm TEXT,
  wrapped_private_key_dek BYTEA,  -- same KMS-wrapped DEK pattern as secrets
  cert_der BYTEA, status TEXT,
  valid_from TIMESTAMPTZ, valid_until TIMESTAMPTZ,
  created_at, updated_at
)
```

**Revocation strategy**: short-lived certs + passive revocation. Workload certs: 1-hour TTL (SPIFFE/SPIRE standard), renewed at 50% of TTL. Service certs: 24-hour to 7-day TTL. Generate CRLs for compliance. **No OCSP responder** — industry consensus confirms short-lived certs have won.

**Per-tenant intermediate CAs**: each workspace gets its own intermediate CA. Cost = one DB row. EC P-256 or ED25519 as default. RSA only for legacy compatibility.

### Pitfalls

- Conflating the two PKI planes: soma-vault's own pod auto-unseal uses cloud workload identity, NOT a custom CA.
- RSA key algorithms in high-throughput CA: EC P-256 is ~1,800x faster than RSA-4096.
- Shared CA for all tenants — retrofitting per-tenant isolation is infeasible. Per-workspace intermediate CAs from day one.
- OCSP responder — operational overhead with diminishing returns for internal PKI. Use CRLs only.
- Using the `openssl` crate — it is a C FFI dependency that contradicts the memory-safety north star. Use `rcgen` + `aws-lc-rs` + `x509-cert`.

### Rust Crates

`rcgen` 0.14.x (cert generation, CA signing, CRL, ED25519/P-256), `x509-cert` (RFC 5280 parsing for CSR intake), `aws-lc-rs` (FIPS-compliant crypto provider for rcgen and rustls), `rustls` 0.23.x, `tokio-rustls`, `instant-acme` (Phase 3 ACME endpoint).

---

## 9. Leasing / TTL and Secret Rotation

**Phase: 1**

### What It Is

Leasing: a time-bounded promise that a secret is valid for exactly TTL seconds, after which it is automatically revoked. Rotation: periodically replacing the credential material itself on both the target system and in the secrets store.

### How the Leaders Do It

**Vault / OpenBao** — Expiration Manager: in-process goroutine-per-lease scheduler that loads ALL leases into memory at startup (O(n) pathology). HA: only the ACTIVE node runs the expiration manager. Static secret rotation uses cron schedules per role, run on the active node only.

**AWS Secrets Manager** — 4-step Lambda lifecycle with `AWSPENDING` staging label as the in-flight protection: `createSecret` → `setSecret` → `testSecret` → `finishSecret`. `ClientRequestToken` is the idempotency key. Double-rotation prevented by the `AWSPENDING` gate — any new rotation invocation returns an error if `AWSPENDING` exists.

**Infisical** — Redis (BullMQ) as the job queue. Rotation v2: dual-phase where new credentials go `ACTIVE` while old go `INACTIVE` (30-day overlap grace period). Workers are stateless; BullMQ provides job deduplication.

### Recommended Approach

**Postgres-native job queue with advisory locks — no external coordinator, no Redis, no Kubernetes Lease dependency.**

**Lease model:**

```sql
leases (
  lease_id UUID PK, secret_id UUID FK, tenant_id UUID, workspace_id UUID,
  created_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, max_expires_at TIMESTAMPTZ,
  renewable BOOL, revoked_at TIMESTAMPTZ, last_renewed_at TIMESTAMPTZ
)
```

Background worker polls `SELECT ... FROM leases WHERE expires_at <= now() AND revoked_at IS NULL FOR UPDATE SKIP LOCKED LIMIT 100` on a 1s tick and calls the revoke hook.

**Rotation state machine:**

```sql
rotation_jobs (
  id UUID PK, secret_id UUID FK, tenant_id UUID,
  status ENUM('pending','in_progress','succeeded','failed'),
  stage ENUM('create','set','test','finish'),
  rotation_version UUID NOT NULL,  -- idempotency key
  created_at, started_at, completed_at, error TEXT, next_attempt_at TIMESTAMPTZ
)
```

Worker claims via `FOR UPDATE SKIP LOCKED`. Each stage is idempotent. Double-rotation guard: before inserting a new `rotation_job`, check no row for this `secret_id` has `status IN (pending, in_progress)`.

**Secret versioning model** (mirrors AWS):

```sql
secret_versions (
  version_id UUID PK, secret_id UUID FK, tenant_id UUID,
  stage ENUM('current','previous','pending','archived'),
  ...
)
-- Partial unique index enforces at most one 'current' and one 'pending' per secret:
CREATE UNIQUE INDEX ON secret_versions (secret_id) WHERE stage = 'current';
CREATE UNIQUE INDEX ON secret_versions (secret_id) WHERE stage = 'pending';
```

The `finish` stage atomically sets old `current→previous`, `pending→current` in one transaction — the in-flight guard equivalent to AWS's `AWSPENDING` check.

**Scheduler**: `rotation_schedules (secret_id FK, cron_expr TEXT, next_run_at TIMESTAMPTZ)`. Scheduler loop runs every 30s; `FOR UPDATE SKIP LOCKED` on eligible rows.

```
// ponytail: all pods compete at the DB level on every tick (1s). Ceiling: ~50 pods
// before DB polling load warrants switching to a single-leader pattern via
// pg_try_advisory_xact_lock('rotation-scheduler') or a k8s Lease object.
```

**Not built in Phase 1:** dynamic secrets (§7), ACME rotation, cloud IAM credential rotation, alternating-user rotation.

### Pitfalls

- Double-rotation: partial unique index on `(secret_id) WHERE stage='pending'`; INSERT conflict guard on `rotation_jobs` before claiming.
- TTL thundering herd: ±10% jitter on issued TTLs; cap concurrent revocation workers.
- Visibility timeout too short: heartbeat `UPDATE` to extend `visible_at` from the worker during long-running stages; or make each stage idempotent.
- DEK leak during rotation: generate DEK only INSIDE the transaction that writes ciphertext + wrapped DEK atomically; never hold DEK across an `await` point outside that transaction.
- Max TTL bypass: enforce `max_expires_at = created_at + max_ttl` with a Postgres `CHECK` constraint.
- Dual-phase grace period: maintain `current` and `previous` with a 24h grace period before archiving — never delete `previous` before the grace period.

### Rust Crates

`sqlx`, `tokio`, `tokio-cron-scheduler` (cron expression parsing only; actual dispatch goes through the DB queue), `graphile_worker_rs` (evaluate as rotation job queue backbone — wraps sqlx, SKIP LOCKED, job_key deduplication, LISTEN/NOTIFY wakeup), `cron` (pure-Rust cron expression parser for `next_run_at` computation), `zeroize`, `ring` or `aws-lc-rs`, `aws-sdk-kms`, `uuid` (v7), `time`, `tracing`.

---

## 10. Audit Logging

**Phase: 1**

### What It Is

A tamper-evident, append-only ledger of every read, write, rotate, policy change, and auth event. Serves security forensics, compliance (SOC 2 CC6.1/CC7.2/CC7.3/CC8.1, PCI DSS, ISO 27001), and operational debugging. Must never become a DoS vector and must never leak secret values in plaintext.

### How the Leaders Do It

**Vault / OpenBao** — HMAC-SHA256 field-level hashing on every sensitive string (tokens, secret values). Salt is per-audit-device. NO per-entry hash chaining between sequential entries. Blocking behavior: if ALL audit devices fail, the API call is refused (hardest correctness guarantee; biggest operational risk — disk full = Vault down). Backends: file, syslog, socket, HTTP (OpenBao).

**Infisical** — no hash chaining, no HMAC field hashing. Append-only enforced at the Postgres role level (INSERT+SELECT, no UPDATE/DELETE). Separate `AUDIT_LOGS_DB_CONNECTION_URI` Postgres instance for enterprise. 80+ event types. Streaming to Datadog, Splunk, Azure Monitor (Enterprise).

**Doppler** — two-tier: Activity Logs (team actions) and Access Logs (secret read events). Tracks `first_read` and `most_recent_read` timestamps only — not every individual read. Weaker than Vault/Infisical.

**AWS CloudTrail** — SHA-256 per-file hash + RSA-signed hourly digest files, each embedding the previous digest hash. File-level chain, not per-entry. `aws cloudtrail validate-logs` recomputes and re-verifies. Secret values never appear in CloudTrail logs.

**Hash chaining in Postgres (Tracehold pattern):**

```
entry_hash = HMAC-SHA256(key, join("|", [version, seq_num, org_id, actor_type,
             actor_id, event_type, event_summary, timestamp,
             SHA256(canonical_json(parameters)), prev_entry_hash]))
```

`pg_advisory_xact_lock(hashtext('audit:' || org_id))` serializes appends per-org without blocking other orgs. HMAC key must NOT live in Postgres — must be in KMS.

### Design Options

| Option | Verdict |
|--------|---------|
| A: HMAC-SHA256 hash chain per entry | Strongest tamper-evidence. Works entirely in Postgres. Satisfies SOC 2 auditors definitively. |
| B: Append-only + seq_num + periodic signed digest (CloudTrail model) | Less per-write serialization. Digest-level tamper-evidence with hourly lag window. |
| C: Plain append-only with role-level write restriction only (Infisical model) | Fails SOC 2 auditor scrutiny for enterprise. A DBA with ALTER TABLE access can modify rows silently. |
| D: Stream-first to immutable external sink (S3 Object Lock / SIEM) | Hard external dependency; breaks single-binary self-host tenet. |

### Recommended Approach

**Hybrid of A + B, phased.** Phase 1 ships Option A (per-entry HMAC chain); Phase 2 adds Option B (signed digest exports for compliance export workflows).

**Schema:**

```sql
audit_events (
  id UUID PK,
  tenant_id UUID NOT NULL,
  workspace_id UUID, project_id UUID, environment_id UUID,
  seq_num BIGINT NOT NULL,              -- per-tenant monotonic
  event_type TEXT NOT NULL,             -- 'secret_read', 'secret_create', etc.
  actor_type TEXT NOT NULL,             -- 'human' | 'service_account' | 'system'
  actor_id UUID NOT NULL,
  actor_ip INET, actor_user_agent TEXT,
  resource_type TEXT NOT NULL,
  resource_id UUID NOT NULL,
  resource_name TEXT,                   -- HMAC-SHA256 hashed (never plaintext)
  action TEXT NOT NULL,
  outcome TEXT NOT NULL,                -- 'success' | 'denied' | 'error'
  reason TEXT,                          -- nullable break-glass justification field
  request_hash TEXT,                    -- SHA-256 of canonical request metadata
  prev_entry_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL,
  hmac_schema_version SMALLINT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
```

**HMAC key**: derived from the same KMS master key: `audit_hmac_key = HKDF(master_key, salt="audit", info=tenant_id)`. Lives in pod memory only.

**Write path**: `pg_advisory_xact_lock` per tenant → `SELECT entry_hash ... FOR UPDATE` (last row) → compute `entry_hash` → `INSERT`. Per-tenant lock, so concurrent cross-tenant writes are fully parallel.

**Append-only enforcement**: `REVOKE ALL ON audit_events FROM soma_vault_app; GRANT INSERT, SELECT ON audit_events TO soma_vault_app;`

**Sensitive field handling**: secret values NEVER appear, not even hashed. `resource_name` is HMAC-hashed. Request parameters are SHA-256 hashed (non-sensitive metadata only).

**`reason` field**: nullable `TEXT` on the `audit_events` table from day one. CLI/SDK expose `--reason` / `reason=` on every write operation. None of the major competitors have this in their base schema — it is a differentiator.

**What soma-vault logs vs what goes to soma-iam**: soma-vault logs all secret/config CRUD, reads, policy changes, workspace/project/environment changes, rotation events, KMS auto-unseal events, service account token issuance/revocation. soma-vault EMITS (async, fire-and-forget) lightweight event notifications to soma-iam's event bus for `token_issue`, `token_revoke`, `policy_change` (tenant-level) for cross-product audit correlation. Human authentication events (login, MFA) are owned by soma-iam entirely.

**Verification endpoint**: `GET /tenants/{id}/audit/verify` (admin-only, rate-limited) walks the chain for a time range and returns the first mismatched `seq_num` or `chain intact`.

**Phase 1 deferred**: digest files / signed snapshots, streaming to external SIEM, time-range partitioning, HMAC key rotation with chain versioning, separate audit Postgres instance.

### Pitfalls

- GCP Data Access audit logs are DISABLED BY DEFAULT — soma-vault must add a startup health check verifying audit logging is active on GCP deployments.
- Vault's blocking audit mode: soma-vault should use non-blocking async audit writes with a bounded in-memory queue for reads (prefer availability); blocking is acceptable for writes (secret create/update/delete). Document this policy explicitly.
- HMAC audit key must never live in Postgres — a DBA who can modify the key can forge the chain.
- Every secret read must be logged individually — Doppler's `first_read`/`most_recent_read` model leaves gaps in incident investigations.
- Advisory lock serializes all audit writes per tenant — at very high fanout (CI/CD pulling 1000 secrets simultaneously), use a short-lived in-memory batch buffer (100ms window) to group events into a single chained batch entry.
- SOC 2 auditors ask: "can your DBA modify audit logs?" The answer must be: (a) the `entry_hash` chain breaks detectably if any row is modified; (b) the HMAC key is in KMS not in Postgres; (c) the `/audit/verify` endpoint provides on-demand cryptographic proof.

### Rust Crates

`ring` v0.17 (HMAC-SHA256), `zeroize`, `sqlx`, `uuid`, `time`, `serde` + `serde_json` (canonical JSON for `request_hash`).

---

## 11. Policy / Authorization Model

**Phase: 1**

### What It Is

The engine that answers: "is this authenticated principal allowed to perform this action on this resource, in this tenant?" It sits between authentication (soma-iam) and the secret/config data.

### How the Leaders Do It

**Vault / OpenBao** — path-based HCL ACL. Capabilities: `create`, `read`, `update`, `patch`, `delete`, `list`, `sudo`, `deny`. Glob (`*`) and single-segment (`+`) wildcards. Deny-by-default. Identity templating: `{{identity.entity.id}}` in paths. Enterprise-only: Sentinel EGP for policy-as-code; Namespaces for true multi-tenant isolation (OSS Vault has no namespace isolation; OpenBao namespaces shipped in OSS v2.3).

**Infisical** — two-tier RBAC: org-level roles AND project-level roles per identity. Machine identities authenticate via cloud workload methods (K8s TokenReview, AWS IRSA, GCP, Azure, OIDC). No path-glob policies — isolation is project × environment × role.

**AWS Secrets Manager** — IAM identity-based + resource-based policies. Fine-grained ABAC via tag matching. Principal tags flow in as STS session tags.

**Akeyless** — RBAC + ABAC layered. Path-hierarchy permissions (`/foo/devops-*`, `+` single-segment wildcard). Six permissions: list, read, create, update, delete, deny (deny always wins). ABAC policies restrict by time-of-day, source IP, environment. Deny-by-default confirmed.

**Cedar** (`cedar-policy` crate, Apache-2.0) — purpose-built for authorization. Supports RBAC + ABAC in one model. Deny-by-default (explicit `permit` required). Formally analyzable. AWS uses it in production for Amazon Verified Permissions.

### Design Options

| Option | Verdict |
|--------|---------|
| A: Pure path-based ACL (Vault-style) | Proven. Path hierarchy maps directly to soma-vault's hierarchy. No ABAC out of the box. ~300 LOC in Rust. |
| B: RBAC only (Doppler/Infisical-style) | Simplest. Cannot express path-wildcard scoping. Hits a wall at scale. |
| **C: RBAC base + path-capability overlay (Akeyless-style hybrid) — recommended** | RBAC for coarse-grained role hierarchy. Path capabilities for fine-grained secret-level access. Deny-by-default at both layers. ABAC can be layered in Phase 2. |
| D: Embed Cedar as the policy engine | Right long-term engine; adds complexity for Phase 1. Phase 2 upgrade target. |
| E: Delegate all policy to soma-iam | soma-iam doesn't exist yet. Adds synchronous network dependency on every secret read. Hard no. |

### Recommended Approach

**Option C** — RBAC base + path-capability overlay, hand-rolled in Rust for Phase 1. Cedar as the Phase 2 upgrade path.

**Data model:**

```sql
-- Coarse-grained workspace roles (soma-vault owns this)
principal_workspace_roles (
  tenant_id UUID NOT NULL, workspace_id UUID NOT NULL,
  principal_id UUID NOT NULL, role TEXT NOT NULL  -- 'ws:admin', 'ws:developer', 'ws:reader'
)

-- Fine-grained path capabilities
policies (
  tenant_id UUID NOT NULL, workspace_id UUID NOT NULL,
  path_glob TEXT NOT NULL,     -- Vault-style: 'project/prod/*', 'project/+/db'
  capabilities TEXT[] NOT NULL -- ['read','list'], ['write','delete'], 'deny' always wins
)
```

**Identity flow:**
1. Principal presents soma-iam JWT.
2. soma-vault validates JWT signature against soma-iam JWKS (cached in-process, refreshed on `kid` miss). No soma-iam network call on hot path.
3. Extracts `tenant_id` claim — enforces tenant isolation at this boundary.
4. Looks up workspace roles from Postgres.
5. Evaluates path capabilities from in-memory policy cache (radix trie scan).
6. Deny-by-default: access granted only if workspace role permits the operation AND at least one path capability grants the required capability with no `deny` override.

**Deny-by-default enforcement** — Rust type-state pattern:

```rust
// Every handler requires Request<Authorized> — impossible to reach without authz::check()
async fn get_secret(
    State(state): State<AppState>,
    Authed(ctx): Authed,  // extractor fails if JWT invalid; injects AuthContext
    Path(path): Path<SecretPath>,
) -> Result<Json<SecretResponse>, ApiError> {
    ctx.require(Action::Read, &path)?;  // returns Err(Forbidden) by default
    // ...
}
```

**The soma-iam contract** soma-vault requires:
- OIDC Discovery endpoint (`/.well-known/openid-configuration`)
- JWKS endpoint with `kid` rotation support
- JWTs carrying: `sub` (principal UUID), `tid` (tenant UUID), `aud` (`["soma-vault"]`), `iat`/`exp` (≤15 min), `org_role` (admin|member|viewer), optional `groups[]`

**Multi-tenant isolation**: `tenant_id` on every Postgres table. Rust newtype `TenantId(Uuid)` prevents accidental cross-tenant queries at compile time. `RLS` policy on every table enforces `tenant_id = current_setting('app.current_tenant')::uuid`.

**Phase 2 Cedar upgrade path**: store Cedar policy strings per tenant in the `policies` table alongside the path-glob model. Cedar entity/action/resource maps to soma-vault's tenant/workspace/project/env/secret hierarchy. Migration is additive — no schema change required if the table has a `policy_type` discriminator from day one.

### Pitfalls

- Vault namespaces are Enterprise-only — do not design multi-tenancy as a namespace overlay. `tenant_id` is in every row.
- Never put the KMS unseal key derivation on the app-principal auth path. Two identity planes, two code paths, no shared state.
- Deny-by-default must be enforced via Rust type-states — impossible to reach a handler without going through `authz::check()`.
- Never call soma-iam on the hot path — validate the JWT signature locally using a cached JWKS. A soma-iam outage must not affect secret reads.
- Path glob precedence gotchas: define and test the precedence rules explicitly. Vault's docs warn about edge cases.
- Cedar policies stored as strings must be versioned and audited per tenant — a Cedar policy change is a security-sensitive event requiring an audit log entry.

### Rust Crates

`axum`, `jsonwebtoken`, `cedar-policy` (Phase 2), `casbin` (alternative), `radix_trie` or `prefix-tree` (in-process path-glob evaluation), `uuid`, `secrecy`, `tower`.

---

## 12. Secret and Config Injection / Developer Experience

**Phase: 1**

### What It Is

The mechanisms by which soma-vault delivers values to consuming workloads: CLI exec wrappers, file export, SDK libraries with live cache, Kubernetes injection, CI/CD OIDC federation, and typed config delivery.

### How the Leaders Do It

**CLI exec (Doppler/Infisical model)**: `doppler run -- <cmd>` / `infisical run -- <cmd>` — authenticate → fetch env → `exec` child with envs. Functionally identical across all major platforms.

**SDK delivery**: Replane is the clearest leader — SSE push with <1s propagation, ~4,500 msg/s on M2 Pro, 5,000 concurrent clients. SDK holds a local in-process cache; background SSE connection updates on change; reads are always local (zero network latency).

**Kubernetes injection — four patterns:**
1. Secrets Store CSI Driver — CSI volume, no etcd exposure, rotation alpha. Supported by Vault, Infisical, Akeyless, AWS, Azure, GCP.
2. External Secrets Operator (ESO) — reconciles to native K8s Secrets; still writes to etcd. Project paused/transferred 2025; Infisical native operator is positioning as replacement.
3. Mutating Admission Webhook / Agent Injector — transparent injection, sidecar mode gives continuous sync. Vault and Infisical implement this.
4. Native Kubernetes Operator with pod redeployment — Infisical's `InfisicalSecret` CRD syncs secrets AND triggers rolling redeploys.

**CI/CD OIDC**: platform-native OIDC JWT → secrets platform validates `iss`/`aud`/`sub` + bound claims → issues short-lived platform token. GitHub Actions, GitLab, CircleCI all use the same JWT pattern. `id-token: write` permission required in GitHub workflow.

**Typed config vs secrets**: the industry gap — nobody provides typed, schema-validated non-sensitive config AND envelope-encrypted secrets in one system with `$ref` pointers. Vault/Infisical/Doppler conflate them at the data-model level; soma-vault enforces the separation at the schema level.

### Recommended Approach

**Phase 1: three delivery mechanisms.**

**1. CLI exec wrapper (`soma run -- <cmd>`):**
Authenticate with soma-iam machine identity (OIDC/JWT), fetch resolved env for project+environment, exec child via `std::process::Command` with env set. Support `soma secrets export --format=env|json|dotenv`. Single `clap`-driven binary. No agent, no daemon in Phase 1.

**2. SSE-based real-time config delivery:**
`GET /v1/config/stream?project=X&env=Y` returns `text/event-stream`. Server holds `tokio::sync::broadcast::Sender<ConfigChangeEvent>` per project+env; on any `config_value` write, broadcast fires, all connected SDK clients receive delta within <1s. SDK maintains in-process `DashMap` or `ArcSwap` cache; falls back to last-known values on disconnect. **Never push secret plaintext over SSE** — if a config key is a `$ref`, the SSE event sends the path + version, not the value. SDK resolves via a separate REST API call.

**3. Kubernetes operator (native CRD — minimal Phase 1):**
`SomaSecret` CRD; operator reconciles by fetching from soma-vault and writing a native K8s `Secret` (acceptable for Phase 1 given etcd encryption at rest is standard). Pod annotation support for rolling restart on secret change. Mutating webhook injector and CSI provider: Phase 2.

**CI/CD OIDC (Phase 1):**
JWT auth method: accept GitHub Actions / GitLab / any OIDC-provider JWT, validate `iss`/`aud`/`sub` against a registered machine identity (stored in soma-iam), issue short-lived soma-vault token (15 min TTL). Provide a GitHub Actions composite action `soma-platform/secrets-action`. No static keys anywhere.

**Typed config enforcement at schema level:**
Table `config_values`: tenant-scoped, typed, schema-validated, plaintext, indexable, full audit log, SSE-pushable. Table `secret_values`: tenant-scoped, opaque ciphertext, never logged as plaintext, never in SSE stream, never in config responses. A config key with `secret_ref: UUID` — SDK fetches the secret separately with an explicit call. The separation is load-bearing.

**Phase 2 deferred:** sidecar/init-container injector, CSI driver, Doppler-style push-sync to AWS SSM / GitHub, dynamic secrets / lease management, SPIFFE/SPIRE integration.

### Pitfalls

- SSE long-lived connections: disable request timeouts at the load balancer; use HTTP/2 or sticky sessions. Bounded broadcast channels must drop lagging receivers gracefully.
- Secrets in env vars readable from `/proc/<pid>/environ` by any process with same UID. For high-sensitivity secrets, prefer file delivery (tmpfs). Document the tradeoff.
- ESO project health uncertain (2025) — implement native K8s operator first; no hard ESO dependency.
- Never inline secret plaintext in config responses, SSE streams, audit logs, or error messages.
- OIDC JWT validation must pin the issuer URL and validate `aud` strictly.
- Do not implement per-CI-provider OIDC directly in soma-vault — soma-iam is the token exchange point.
- KMS calls add ~10ms latency per DEK unwrap — cache the unwrapped DEK in pod memory for the duration of the request; zeroize after.

### Rust Crates

`axum` (SSE via `axum::response::sse::Sse`), `tokio` (broadcast channel for SSE fan-out), `sqlx`, `aes-gcm`, `chacha20poly1305`, `hkdf`, `zeroize`, `secrecy`, `rand` + `getrandom`, `aws-sdk-kms`, `jsonwebtoken`, `clap`, `serde` + `serde_json`, `uuid`, `tower` + `tower-http`, `tracing` + `tracing-subscriber`.

---

## 13. Rust Crypto Stack

**Phase: 1**

### What It Is

The concrete Rust crates and configuration decisions for AEAD cipher selection, envelope encryption, KMS auto-unseal by workload identity, and in-memory key hygiene.

### AEAD Cipher Selection

**Primary cipher: `aes-gcm` (RustCrypto, NCC Group audited)** — AES-256-GCM with a random 96-bit nonce per encryption call. Safety argument: each DEK encrypts exactly one secret value (plus version updates — at most hundreds of writes over a secret's lifetime), so the 2^32-messages-per-key birthday bound is never approached.

**Fallback cipher: `chacha20poly1305` (RustCrypto, NCC Group audited)** — preferred for environments without AES-NI hardware (ARM dev machines, some edge nodes). Expose cipher choice as a server config option; default to AES-256-GCM.

**Do not use AES-GCM-SIV in Phase 1** — slower (two-pass), less universally supported in HSMs, unnecessary when per-secret DEKs make nonce reuse structurally impossible at the DEK level.

### Underlying Crypto Backend

**Use `aws-lc-rs` (not `ring`)** as the low-level backend for TLS (via `rustls`) and any operations requiring a FIPS-capable backend. Reasons:
- FIPS 140-3 validated (via `aws-lc-fips-sys`), maintained by AWS.
- Now `rustls`'s default backend since 2024.
- `ring-API` compatible for easy migration.
- `ring` itself: described by its author as an "experiment", lacks P-521 (real-world breakage with Cloudflare WARP), and has no FIPS path.

For RustCrypto AEAD crates (`aes-gcm`, `chacha20poly1305`): they operate as pure Rust above the crypto provider layer — acceptable for Phase 1 given per-DEK isolation. Do not add wolfcrypt or wolfSSL in Phase 1.

**TLS**: `rustls` with `aws-lc-rs` as backend. TLS 1.3, no OpenSSL dependency, FIPS upgrade path via feature flag.

### Key Derivation

`hkdf` (RustCrypto) for deriving per-tenant KEKs from the master KEK: `tenant_kek = HKDF(master_kek, salt=tenant_id_bytes, info=b"soma-vault-tenant-kek")`. HKDF context binding must include a fixed domain prefix + `tenant_id` to prevent cross-tenant key confusion.

`argon2` (RustCrypto, Argon2id) for password-based key derivation in CLI token hashing and initial self-host master key bootstrap from a passphrase.

### In-Memory Key Hygiene

Wrap every DEK, KEK, and plaintext secret in `secrecy::Secret<T>` where `T: Zeroize`. This prevents accidental logging/debug printing (`Secret<T>` does not implement `Display` or `Debug`), prevents reallocation, and triggers `ZeroizeOnDrop`. Use `#[derive(Zeroize, ZeroizeOnDrop)]` on all structs holding key material.

Known ceiling: CPU registers cannot be zeroized — this is inherent to any software KMS and is acceptable.

### KMS Auto-Unseal Summary

| Cloud | Mechanism |
|-------|-----------|
| AWS EKS | IRSA: K8s projected OIDC token → AWS STS `AssumeRoleWithWebIdentity` → `aws-sdk-kms` `Decrypt` |
| GCP GKE | GKE Workload Identity: OIDC exchange → `google-cloud-kms` `CryptoKey.Decrypt` |
| AKS | Azure Workload Identity: federated credential → `azure_security_keyvault_keys` `UnwrapKey` |
| Self-host | `age`-based software KMS: master KEK in an age-encrypted file, mounted read-only via K8s Secret |

### Key Hierarchy

```
Level 0: External KMS key — never leaves HSM
Level 1: Tenant KEK (derived from master via HKDF, lives in pod RAM only)
Level 2: Per-project/per-environment DEK (random 32 bytes, wrapped by tenant KEK, stored in Postgres)
Level 3: Secret/config ciphertext — AES-256-GCM(DEK, plaintext, AAD=secret_id||version_id)
```

### Pitfalls

- AES-GCM nonce reuse: catastrophic confidentiality and integrity failure. Random 96-bit nonce per call is safe at per-DEK scale; never use a counter without a persistent counter store.
- Forgetting AEAD associated data: without `AAD = secret_id || version_id`, a ciphertext can be replayed to a different secret row.
- DEK plaintext surviving request lifetime: never clone a DEK into a plain `Vec<u8>`; use `secrecy::Secret<[u8; 32]>`.
- `ring`'s P-521 gap: do not use `ring` for TLS in production — use `aws-lc-rs` via `rustls`.
- HKDF context without domain separation: missing domain prefix is a subtle but critical cross-tenant key confusion bug.
- FIPS lock-in: do not enable `aws-lc-fips-sys` in Phase 1 — design the abstraction layer so it can be swapped in later via a feature flag.
- Config tier leaking secret plaintext: the `$ref` resolver must return a typed placeholder or a short-lived token, never the raw secret value.

### Rust Crates

| Crate | Role |
|-------|------|
| `aes-gcm` (NCC Group audited) | AES-256-GCM AEAD, primary cipher |
| `chacha20poly1305` (NCC Group audited) | ChaCha20Poly1305 fallback |
| `aws-lc-rs` | Ring-compatible backend, FIPS 140-3 path, `rustls` default |
| `rustls` (aws-lc-rs feature) | TLS 1.3, no OpenSSL |
| `hkdf` | HKDF for per-tenant KEK derivation |
| `argon2` | Argon2id for password-based key derivation in self-host bootstrap |
| `zeroize` + `zeroize_derive` | Volatile-write zeroing for all key material on drop |
| `secrecy` | `Secret<T>` wrapper: no Debug/Display, prevents reallocation |
| `aws-sdk-kms` | AWS KMS Encrypt/Decrypt/GenerateDataKey (Tokio-native, IRSA) |
| `google-cloud-kms` | GCP Cloud KMS + Application Default Credentials + Workload Identity |
| `azure_security_keyvault_keys` | Azure Key Vault key wrap/unwrap |
| `age` | Self-host software KMS fallback |
| `subtle` (Quarkslab audited) | Constant-time comparisons for token/HMAC verification |

---

## 14. Delegated Identity / External IdP Integration

**Phase: 1**

### What It Is

How app principals (humans and service accounts) authenticate to soma-vault without soma-vault re-implementing identity. Critically: two identity planes that must never be conflated:

- **App-principal plane**: humans and service accounts authenticate via soma-iam (OIDC/JWT) to get secrets/config.
- **Pod-workload-identity plane**: soma-vault's own pods authenticate to the KMS via cloud workload identity (IRSA/GKE WI/Azure WI) to unwrap the master key on boot.

### How the Leaders Do It

**Vault / OpenBao** — JWT/OIDC auth method: client presents JWT → Vault fetches IdP's JWKS (cached) → verifies signature, checks `iss`/`aud`/`sub`/`bound_claims` → if role matches, mints Vault's own short-lived token with policies. Kubernetes auth: pod sends projected SA token → Vault calls K8s TokenReview API → issues Vault token. AuthZ is entirely Vault-internal.

**Infisical** — eight auth methods: Token, Universal Auth, Kubernetes, AWS, GCP, Azure, OIDC, SPIFFE. OIDC flow: workload fetches JWT from IdP → POST to Infisical → JWKS retrieval + validation → short-lived `accessToken`. Project-level identity + org-level identity.

**Doppler** — OIDC without static tokens. CI tool generates platform-native OIDC token → POST to Doppler → validates claim rules → short-lived API token scoped to project+config.

**AWS Secrets Manager** — no external IdP concept. The cloud IS the IdP. App presents STS credentials from IRSA → IAM evaluates resource-based + identity-based policies.

### Design Options

| Option | Verdict |
|--------|---------|
| A: JWT pass-through (validate soma-iam JWTs directly on every request) | JWKS fetch overhead; JWT is long-lived if soma-iam issues long TTLs; couples request path to soma-iam availability. |
| **B: JWT exchange (validate once at /v1/auth/login, issue soma-vault's own short-lived session token) — recommended** | Decouples soma-vault request path from soma-iam availability. soma-vault controls TTL and revocation. Standard pattern used by Infisical and Doppler. |
| C: Token introspection on every request | Synchronous soma-iam dependency on every hot-path request. Does not meet HPA-native stateless requirement. Hard no. |
| D: Direct cloud IAM integration (trust AWS/GCP/Azure tokens directly) | Breaks multi-tenant model. Requires N cloud-specific implementations. Conflicts with soma-iam as the single identity source. |

### Recommended Approach

**Option B — JWT exchange pattern:**

1. Client (human CLI/UI or service account) presents soma-iam JWT to `POST /v1/auth/login`.
2. soma-vault fetches JWKS from soma-iam (cached in-process, refreshed on `kid` miss or TTL), verifies signature, validates `iss`/`aud`/`exp`.
3. Extracts `tenant_id` claim — enforces tenant isolation at this boundary. Reject tokens without `tenant_id`.
4. Looks up internal RBAC: maps soma-iam `roles[]` + `project_id` onto soma-vault's permission model.
5. Issues a short-lived soma-vault Bearer access token (opaque, stored in Postgres with TTL, scoped to tenant+permissions).
6. All subsequent requests carry the soma-vault token — no further soma-iam validation until re-auth.

**Machine identity for CI** — CI job generates platform-native OIDC token → exchanges at soma-iam (RFC 8693 token exchange) for a soma-iam service-account JWT → presented to soma-vault `/v1/auth/login`. soma-vault never knows GitHub's OIDC issuer directly; soma-iam is the single trust anchor.

**The soma-iam contract** soma-vault requires:
- OIDC Discovery endpoint (`/.well-known/openid-configuration`)
- JWKS endpoint with `kid` rotation support
- JWTs: `sub`, `tid` (tenant UUID), `aud` (`["soma-vault"]`), `exp`/`iat`, `org_role` (admin|member|viewer), optional `groups[]`
- Token revocation: `jti` blacklist via introspection endpoint (optional for normal reads; used for high-privilege mutations)

**Auto-unseal is completely separate** — pod workload identity → KMS → root key. This plane never touches soma-iam.

### Pitfalls

- Conflating the two identity planes. Two planes, two tokens, two trust roots, two code paths.
- Option A/C create availability coupling — soma-iam down = no secret reads. The session-token exchange breaks this.
- Missing `tenant_id` claim validation: every JWT from soma-iam must carry `tenant_id`; reject tokens without it.
- Long-lived machine tokens for CI: machine identities must get short-lived tokens (<1 hour).
- JWKS caching without rotation support: on signature verification failure due to unknown `kid`, re-fetch JWKS before rejecting.
- Skipping the `aud` claim check: soma-vault MUST enforce `aud == ["soma-vault"]` to prevent token reuse from other soma-platform services.
- Implementing per-CI-provider OIDC directly in soma-vault — violates YAGNI; soma-iam is the token exchange point.
- Reusing the pod workload identity (KMS auto-unseal SA token) as an app credential — forbidden.

### Rust Crates

| Crate | Role |
|-------|------|
| `jsonwebtoken` | JWT decode/verify with RS256/ES256/EdDSA; `aud`/`iss`/`exp` validation |
| `openidconnect` | Full OIDC client including Discovery fetch and JWKS parsing |
| `jwt-authorizer` | axum middleware for JWT validation with JWKS endpoint caching and `kid` rotation |
| `reqwest` | HTTP client for JWKS endpoint fetches |
| `tower` | Middleware primitives for auth layer composition |
| `uuid` | `jti` and session token generation |
| `zeroize` | Wipe plaintext key material after use |
| `secrecy` | `Secret<T>` for token/key handling |

---

## Crate Reference Summary

The table below aggregates all Phase 1 Rust crates across domains.

| Crate | Domain(s) | Purpose |
|-------|-----------|---------|
| `aes-gcm` | Crypto, KV, Transit, DX | AES-256-GCM AEAD (primary cipher) |
| `chacha20poly1305` | Crypto, KV, Transit | XChaCha20Poly1305 AEAD (fallback) |
| `aws-lc-rs` | Crypto, K8s | FIPS-capable crypto backend for rustls |
| `rustls` | Crypto, DX | TLS 1.3, no OpenSSL |
| `hkdf` | Crypto, Tenant Isolation | HMAC-based KDF for tenant KEK derivation |
| `argon2` | Crypto | Argon2id for self-host passphrase bootstrap |
| `zeroize` | All crypto domains | Secure memory zeroing on all key material |
| `secrecy` | All crypto domains | `Secret<T>` — no Debug/Display/log leakage |
| `subtle` | Crypto, Audit | Constant-time comparisons |
| `aws-sdk-kms` | Crypto, K8s | AWS KMS Encrypt/Decrypt/GenerateDataKey |
| `google-cloud-kms` | Crypto, K8s | GCP Cloud KMS (Phase 2) |
| `azure_security_keyvault_keys` | Crypto, K8s | Azure Key Vault key wrap/unwrap |
| `age` | Crypto, K8s | Self-host software KMS fallback |
| `rand` (OsRng) | Crypto, KV | CSPRNG for DEK and nonce generation |
| `aes-kw` v0.3.0 | Transit | AES Key Wrap (RFC 3394) for DEK wrapping |
| `sqlx` | All data domains | Async PostgreSQL, compile-time query checking |
| `axum` | API, DX, Audit | HTTP server, SSE, middleware |
| `tokio` | All async domains | Async runtime |
| `tokio::sync::broadcast` | Config, DX | SSE fan-out per project+environment |
| `jsonschema` v0.46.5 | Config | JSON Schema validation at write time |
| `schemars` | Config | Derive JSON Schema from Rust structs |
| `jsonwebtoken` | Policy, Identity | JWT decode/verify with OIDC claims |
| `openidconnect` | Identity | OIDC Discovery and JWKS parsing |
| `jwt-authorizer` | Identity | axum JWT middleware with JWKS caching |
| `ring` v0.17 | Audit | HMAC-SHA256 for hash chaining |
| `uuid` | All | UUID v7 PKs (time-ordered, sortable) |
| `time` | All | TIMESTAMPTZ serialization |
| `serde` + `serde_json` | All | Serialization for API payloads and JSONB |
| `clap` | DX | CLI argument parsing |
| `thiserror` | Dynamic Secrets | Typed error variants |
| `tracing` + `tracing-subscriber` | All | Structured async-aware logging |
| `tower` + `tower-http` | API | Middleware: auth, rate limiting, tracing |
| `rcgen` 0.14.x | PKI (Phase 2) | X.509 cert generation, CA signing, CRL |
| `x509-cert` | PKI (Phase 2) | RFC 5280 parsing for CSR intake |
| `graphile_worker_rs` | Rotation | PostgreSQL-backed job queue with SKIP LOCKED |
| `cron` | Rotation | Pure-Rust cron expression parser |
| `kms-aead` v0.25.0 | K8s | Envelope encryption combining KMS + AEAD |
| `spiffe` | K8s (Phase 2) | SPIFFE Workload API for SPIRE-based identity |

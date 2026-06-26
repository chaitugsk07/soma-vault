# soma-vault: Vision and Positioning

soma-vault is a cloud-native secrets and typed configuration platform built in Rust: one binary, one Postgres database, and nothing else required to run. It targets indie developers and startup teams first — delivering Doppler-grade developer experience (one-command CLI, env injection, real-time config delivery) on top of an architecture that is genuinely enterprise-credible from day one: hard multi-tenant isolation, envelope encryption per secret version, stateless pods that auto-unseal via cloud workload identity, and a schema-level split between encrypted secrets and typed config that no incumbent offers. The managed SaaS and the self-host binary are the same artifact.

---

## The Problem

Secrets management is solved. Configuration management is solved. The two remain separate products, and that separation creates real friction:

- Teams run Vault or Infisical for secrets and AWS AppConfig, Replane, or Configu for typed config — two auth flows, two SDKs, two billing lines, two operational surfaces.
- Secrets-only tools (Vault, Infisical, Bitwarden SM) treat all values as opaque encrypted blobs. You cannot safely audit-log a secret read, SSE-push a secret value to a running process, or schema-validate a secret. The tools that do all three things — audit, push, validate — are config-only (Replane, Configu, AppConfig) and refuse to touch secrets.
- The result is a `$ref` problem nobody has solved in the data model: when a config value needs to reference a secret (a database URL, an API key), every tool either stores the secret inline in the config (wrong) or forces developers to write custom wiring code (friction).

On the operational side, Vault and OpenBao have excellent crypto foundations but were designed around a stateful Raft topology. That StatefulSet + Raft model means pods are not freely autoscalable, and the default unseal model requires a human operator or a separately managed unseal script each time a pod restarts — an operational pattern that cloud-native teams are looking to move away from.

---

## The Wedge: Indie and Startup DX First

The fastest path to adoption is making the first five minutes better than Doppler:

```sh
soma login
soma run -- node server.js
```

That is the entire onboarding story. No SDK integration. No env-var wiring. No YAML operator configuration. Zero code changes to an existing app.

From there, teams get:

- Real-time config delivery — no restarts to pick up a changed value.
- A single dashboard for secrets and typed config, with version history, audit log, and diff views.
- A Kubernetes operator that syncs secrets into native `Secret` objects.
- A Rust SDK that validates types at compile time and suppresses secret values from logs.

Enterprise credibility comes from the architecture — multi-tenancy, envelope encryption, workload-identity auto-unseal — not from a feature checklist. Those properties are present from day one, not retrofitted when the first enterprise deal requires them.

---

## The Memory-Safe, Low-Footprint Thesis

HashiCorp Vault's Go runtime carries a non-trivial memory footprint: a single standby node consumes 200–400 MB at idle, and a recommended Kubernetes deployment requests 8 GiB. The Go garbage collector can copy key material through heap memory, making mlock guarantees less deterministic than they appear on paper. The binary is not statically analyzable for memory safety in the way a Rust binary is.

soma-vault's design answers this directly:

| Property | Vault / OpenBao | soma-vault |
|---|---|---|
| Language | Go (GC, not memory-safe) | Rust (ownership, no GC) |
| Idle pod RSS target | 200–400 MB | < 20 MB |
| Key material handling | GC may copy | `Zeroize` + `ZeroizeOnDrop`, pinned |
| TLS backend | OpenSSL (C) | `rustls` + `aws-lc-rs` (Rust, FIPS path) |
| AEAD cipher | Varies | `aes-gcm` / `chacha20poly1305` (NCC Group audited) |
| Storage topology | Raft StatefulSet | Stateless Deployment, all state in Postgres |

The target is a pod that idles below the memory footprint of a basic Node.js process, serves thousands of RPS, and zeroizes key material correctly — not as a best-effort, but as a Rust ownership invariant enforced at compile time.

---

## The Headline Differentiator: Auto-Unseal Without Ceremony

Vault's manual unseal is the single most disruptive operational reality in secrets management. When a pod restarts — planned or unplanned — an operator must supply threshold Shamir key shares before the pod can serve traffic. Auto-unseal via cloud KMS removes the human ceremony, but the pod still transitions through a "sealed" state and must complete a KMS round-trip before becoming ready. More importantly, the StatefulSet + Raft architecture means HPA cannot freely add pods. Scaling from 3 to 5 Vault replicas requires a coordinated Raft membership change.

soma-vault's model is structurally different:

**On pod boot:**
1. Kubernetes injects a projected ServiceAccount OIDC JWT (no static credential, no secret in the pod spec).
2. The pod presents this JWT to AWS STS via IRSA (`AssumeRoleWithWebIdentity`).
3. STS returns ephemeral credentials; the pod calls `KMS Decrypt` once to unwrap the master KEK into `Zeroizing<[u8; 32]>` in pod RAM.
4. The readiness probe gates on KMS success. A pod that cannot reach KMS never becomes ready and never receives traffic.
5. Per-tenant KEKs are derived via `HKDF-SHA256(master_kek, info=tenant_id_bytes)` — CPU-only, zero additional KMS calls.

**Under HPA:**
- Each new pod performs steps 1–4 independently. There is no quorum. There is no coordination with existing pods. Scale from 1 to 20 is 20 parallel KMS calls, each using the pod's own projected token.
- Pods carry no local state. No PersistentVolumeClaims. The Helm chart deploys a `Deployment`, never a `StatefulSet`.

**KMS circuit-breaker:**
When KMS is transiently unreachable (AWS KMS SLA is 99.999% but regional incidents do occur), pods extend their in-memory tenant KEK cache TTL up to a configurable grace period (default 30 minutes) and continue serving from cached material. The `/health/ready` endpoint returns HTTP 200 with `degraded: true` and `active_alerts: ["kms_unreachable"]` — HPA counts the pod as ready, preserving capacity. After the grace period expires, the pod stops serving and emits a `CRITICAL` structured log. On initial boot (no cached KEKs), a 60-second retry window with exponential backoff runs before the readiness probe fails.

For self-hosted deployments without a cloud KMS, an `AgeSoftwareKms` backend decrypts an age-encrypted master KEK file mounted as a read-only Kubernetes Secret. The health endpoint exposes `seal_backend: software_kms` with `WARNING` severity. The tradeoff is documented explicitly: this degrades to "master KEK protected by Kubernetes etcd encryption at rest and RBAC," equivalent to Infisical's `ENCRYPTION_KEY` env-var model. Operators who need the full tenet-3 guarantee must use a cloud KMS.

---

## The Unified Secrets + Config Story

Every existing tool forces a choice:

- **Secrets-only** (Vault, Infisical, Bitwarden SM, AWS Secrets Manager): opaque encrypted blobs, no type system, no schema validation, no real-time push. Audit logs must redact all values. SSE-pushing a secret value over the wire is unsafe.
- **Config-only** (Replane, Configu, AppConfig, Azure App Configuration): typed, validated, pushable, loggable — but explicitly refuse to store secrets. Replane's documentation tells users to put secrets in Vault.

soma-vault enforces the split at the schema level, then bridges it with a `$ref` pointer:

### Schema-level separation

```
secrets table:         id, tenant_id, environment_id, path, ...
secret_versions table: id, ciphertext bytea, wrapped_dek bytea, nonce bytea, ...

config_keys table:     id, tenant_id, environment_id, path, value_type, schema_json, ...
config_versions table: id, string_value, int_value, bool_value, json_value, secret_ref uuid, ...
```

The `secrets` table has no typed-value columns. The `config_keys` table has no `ciphertext` or `wrapped_dek` columns. The column layout makes conflation structurally impossible — not policy-forbidden, structurally impossible.

### What this unlocks

**Safe audit logging.** Config reads and writes are fully logged, value included, when `is_sensitive = false`. When `is_sensitive = true`, the value is redacted but the access event is logged. Secret values never appear in any audit entry — only the resource UUID and HMAC-hashed path.

**Safe SSE push.** The real-time config stream (`GET /v1/config/stream`) pushes typed scalar values to connected SDK clients with sub-1-second propagation. For a `config_key` with `value_type = secret_ref`, the event payload contains the secret UUID only — never the resolved plaintext. Secret plaintext never enters the SSE stream under any circumstance.

**The `$ref` pointer model.** A config key with `value_type = secret_ref` stores the secret's UUID. The SDK exposes:

```rust
config.get_with_secret(key, &secrets_client) -> (T, Option<Secret<String>>)
```

The API with `resolve_refs = true` performs a fresh decrypt of the referenced secret — with its own auth check, audit log entry, and DEK unwrap — and returns the resolved plaintext only if the caller has `read` permission on both the config key and the referenced secret. The `Secret<String>` type (from the `secrecy` crate) suppresses `Debug` and `Display` and is not clonable. Secret plaintext cannot accidentally appear in a log line.

### Real-time config delivery

The SDK holds a `DashMap<String, ConfigValue>` in-process cache, seeded at startup via one bulk GET. A background SSE task updates the cache on any `config_versions` INSERT or UPDATE. Every `config.get(key)` call is a local cache read — zero network latency.

Cross-pod fan-out uses Postgres `LISTEN/NOTIFY`. One dedicated non-pooled connection per pod subscribes to `config_changes`; the write handler calls `NOTIFY` after commit. No Redis. No message broker. Postgres is already the only required dependency, and `LISTEN/NOTIFY` handles the fan-out ceiling for Phase 1.

---

## soma-vault and soma-iam: Two Distinct Identity Planes

soma-vault is part of the soma-platform suite alongside soma-iam (the suite's identity and access management service). These are distinct products with distinct responsibilities.

**soma-iam** handles human users, organizations, RBAC roles, and identity-level SSO. soma-vault never reimplements any of this.

**soma-vault** handles secrets and config storage, envelope encryption, and — critically — its own pod identity for KMS auto-unseal.

This creates two identity planes that must never be conflated:

| Plane | Who | How | Purpose |
|---|---|---|---|
| App principals | Humans, service accounts | soma-iam RS256/ES256 JWT → soma-vault session token | Read/write secrets and config |
| soma-vault pods | The server process itself | K8s projected SA token → IRSA → KMS Decrypt | Unwrap master KEK for envelope encryption |

soma-vault validates soma-iam JWTs at `POST /v1/auth/login` via a locally cached JWKS. It issues its own short-lived opaque Bearer session token (15-minute TTL, materialized permissions). All subsequent hot-path requests carry the soma-vault session token — no soma-iam network call per secret read. A soma-iam outage does not prevent secret reads.

soma-iam is not yet built. soma-vault defines the contract it requires: an OIDC discovery endpoint, a JWKS endpoint, and JWTs with `sub`, `tid` (tenant UUID), `roles[]`, and `aud = ["soma-vault"]` claims. Any token without `tid` is rejected at the auth boundary — hard multi-tenancy enforcement at the entry point.

---

## Envelope Encryption: Four-Layer Key Hierarchy

```
Layer 0: External KMS key (never leaves cloud HSM)
         |
         | KMS Decrypt (once per pod boot, via IRSA)
         v
Layer 1: Master KEK — Zeroizing<[u8; 32]> in pod RAM, never on disk
         |
         | HKDF-SHA256(master_kek, salt="soma-vault-tenant-kek-v1", info=tenant_id_bytes)
         v
Layer 2: Per-tenant KEK — LruCache<TenantId, Zeroizing<[u8; 32]>>, 5-min TTL, ZeroizeOnDrop eviction
         |
         | AES-256-GCM wrap in pod RAM (zero KMS call)
         v
Layer 3: Per-secret-version DEK — OsRng 32 bytes, exists in RAM only during encrypt/decrypt
         |
         | AES-256-GCM encrypt(plaintext, nonce=OsRng 96-bit, aad=secret_id||version_id)
         v
Postgres: (ciphertext bytea, wrapped_dek bytea, nonce bytea)
```

The AEAD additional data (`secret_id || version_id`) prevents ciphertext transplant attacks — a stolen ciphertext cannot be decrypted as a different secret. A Postgres dump is cryptographically useless without KMS access, regardless of disk encryption status.

Per-secret-version DEK is the AWS Secrets Manager model. One compromised DEK exposes one secret version, not a workspace — a tighter blast-radius boundary. Tools like Infisical use a per-workspace key, which is simpler to implement but means a compromised workspace key exposes all secrets in that workspace. Once data is written, moving from a workspace-scoped DEK to a per-secret-version DEK requires re-encrypting every row, so this boundary must be set at schema design time.

---

## Competitive Positioning

### Where soma-vault wins

| Dimension | soma-vault | Vault/OpenBao | Doppler | Infisical | Cloud managers | Akeyless | Replane/Configu |
|---|---|---|---|---|---|---|---|
| Stateless HPA pods | Yes, from day one | No (Raft StatefulSet) | N/A (SaaS) | Yes | N/A (SaaS) | Yes (gateway) | Yes |
| Auto-unseal: workload identity | IRSA primary, age fallback | KMS supported but pod still "seals" | N/A | ENCRYPTION\_KEY env var (static secret) | Workload identity | Workload identity | N/A (no secrets) |
| Per-secret-version DEK | Yes | No (barrier key) | No (per-workspace) | No (per-workspace) | Yes (AWS SM) | No documented | N/A |
| Schema-level secrets/config split | Yes, column-level | No (KV blobs) | No (string KV) | No (string KV) | Two separate products | No (secrets only) | Config only |
| Real-time config push (SSE) | Yes, < 1s | No (poll/template) | No | No | No | No | Yes (Replane) |
| Typed config + JSON Schema validation | Yes | No | No | No | Partial (AppConfig) | No | Yes (Replane) |
| Self-host single binary | Yes, MIT | Yes (MPL-2.0) | No (June 2026 enterprise beta) | Yes | No | No | Yes |
| Multi-tenancy in OSS core | Yes, full hierarchy | No (Vault: enterprise only; OpenBao: GA but shared schema) | No (single-tenant instances) | App-layer only | No (path-based RBAC) | No (path-based folders) | Workspace-level only |
| Memory footprint | < 20 MB target | 200–400 MB idle | N/A | 100s MB (Node.js + Redis) | N/A | Undisclosed | ~50–100 MB (Node.js) |
| Memory safety | Yes (Rust) | No (Go GC) | No (Go) | No (Node.js) | Undisclosed | Undisclosed | No (Node.js) |
| Indie-first pricing | Open-core, generous free | CE free but complex | No self-host | MIT, per-identity billing bites at scale | Per-secret billing bites | Sales-gated | MIT self-host |

### HashiCorp Vault / OpenBao

Vault has excellent crypto choices — KMS auto-unseal, AES-GCM, and a comprehensive audit log — and the deepest secrets feature set in the category. Its architecture optimizes for a different set of goals: strong consistency via Raft and a mature, battle-tested StatefulSet deployment. OpenBao takes this foundation, moves it to an open license (MPL-2.0), and adds free namespaces.

soma-vault does not compete on Vault's strengths (dynamic secrets engine breadth, Transit EaaS maturity, PKI depth). Those are Phase 2 items. soma-vault's design is optimized for HPA elasticity and stateless pods: no Raft coordination, sub-20 MB footprint, Rust's ownership-enforced key zeroization, and per-secret-version DEK isolation. These are structural choices that would require a ground-up rebuild of Vault's storage model to replicate.

### Doppler / Infisical

Both have excellent developer experience and are the primary DX reference for soma-vault's CLI and onboarding. The `soma run -- <cmd>` injection pattern is directly inspired by Doppler's workflow.

- **Doppler** treats secrets and config as the same untyped string values, uses one workspace-level encryption key rather than per-secret DEKs, and does not offer real-time SDK push for config. Its Kubernetes Operator bootstraps via a service token — a shared static credential — rather than via workload identity. soma-vault's tenet 3 takes a different path: pods prove their identity to a KMS and no shared bootstrap secret is needed.
- **Infisical** loads its root encryption key from an `ENCRYPTION_KEY` environment variable — a static secret injected at pod startup. That approach is explicitly simpler to operate than a cloud KMS, but it means the pod holds a persistent credential. soma-vault's design eliminates the static credential entirely in favor of cloud workload identity. Infisical also has no typed config plane, and its Pro tier charges per machine identity, which becomes expensive for teams with many Kubernetes service accounts and CI pipelines.

soma-vault aims to match their CLI developer experience while making different architecture choices around unseal and config typing.

### Cloud managers (AWS Secrets Manager, GCP Secret Manager, Azure App Configuration)

AWS Secrets Manager has the correct envelope encryption model (per-secret DEK, IRSA-based pod auth) and soma-vault borrows it. Its gaps are: no typed config, no real-time push, no self-host, AWS-only, per-secret pricing that incentivizes credential stuffing.

GCP and Azure are cloud-locked by definition. They cannot be self-hosted and offer no unified secrets+config story.

soma-vault does not compete with these on AWS-native integration depth. It competes on self-host, multi-cloud, typed config delivery, and developer experience.

### Akeyless

Akeyless is a fully managed, closed-source SaaS with no self-host option and sales-gated pricing; its free tier (5 clients, 3-day audit retention) is sized for evaluation rather than production workloads. Its DFC (Distributed Fragments Cryptography) zero-knowledge story is genuinely interesting; soma-vault's envelope encryption with customer-owned KMS keys achieves equivalent security properties with a simpler operational model.

### Bitwarden Secrets Manager

Open-source core, Rust SDK, clean machine-account model — closer to soma-vault than any other competitor on values. Its gaps: client-side-only encryption (cannot do server-side DEK re-wrapping or KMS-backed auto-unseal), no environment model (roadmap-only as of 2026), no typed config, no SSE push, and self-host locked behind the Enterprise paywall.

### Replane / Configu / AppConfig / Azure App Config

These are config tools, not secrets tools. Replane is the closest to soma-vault's config delivery model (SSE push, JSON Schema validation, in-process SDK cache) and is the primary DX reference for soma-vault's config plane. The gap is that Replane stores values in plaintext and explicitly tells users to put secrets elsewhere.

soma-vault is what you get if you take Replane's config delivery model, add Vault's envelope encryption, and make secrets and config live in the same platform with a schema-enforced `$ref` boundary between them.

---

## Where soma-vault Deliberately Does Not Compete Yet

| Capability | Status | Rationale |
|---|---|---|
| Dynamic secrets (ephemeral DB credentials, STS) | Phase 2 | Requires per-backend adapters and outbound connectivity. Schema designed for it from day one. |
| PKI / internal CA (rcgen, ACME, CRL) | Phase 2 | High value but high complexity. CA private key stored as a wrapped secret row — same code path. |
| Transit EaaS external API | Phase 2 | Internal envelope encryption infrastructure exists. External API surface is additive. |
| GCP Cloud KMS and Azure Key Vault backends | Phase 2 | `KmsBackend` trait defined abstractly. New structs, no migration. |
| SPIFFE/SPIRE workload identity | Phase 2 | Cloud workload identity (IRSA / GKE WI / Azure WI) satisfies tenet 3 for cloud deployments. |
| TypeScript and Python SDKs | Phase 2 | Rust SDK validates the API design first. `soma run -- <cmd>` covers non-Rust consumers at zero integration cost. |
| Multi-region active-active | Phase 3 | Postgres streaming replication covers HA. Active-active write distribution requires distributed consensus that contradicts the stateless-pod model. |
| Redis as any dependency | Never (until measured) | Single-binary self-host requires Postgres to be the only stateful dependency. Postgres `LISTEN/NOTIFY` is the fan-out mechanism until its ceiling is measured to be insufficient. |
| Consul as any dependency | Out of scope | soma-vault is designed around a single Postgres dependency. Adding Consul as a storage backend introduces the same operational surface that single-binary self-host is designed to avoid. |

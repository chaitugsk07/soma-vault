# soma-vault Phase 1 — Architecture, Multi-tenancy, Cryptography & Auto-unseal

soma-vault is a cloud-native secrets and typed configuration platform built on async Rust (axum + tokio) with PostgreSQL as the sole stateful dependency. This document covers the system topology, stateless pod model, KMS-based auto-unseal, four-layer envelope encryption, multi-tenant isolation strategy, secrets-vs-config schema separation, and the Rust crate decisions behind each choice. Every design decision here traces to one or more of the five non-negotiable architecture tenets: hard multi-tenancy, stateless HPA-native pods, KMS auto-unseal via workload identity, end-to-end envelope encryption, and schema-enforced secrets/config separation.

---

## 1. System Topology

### 1.1 Self-host (single binary)

```
┌──────────────────────────────────────────────────────────┐
│  Kubernetes Deployment — soma-vault-server               │
│  (N stateless pods, HPA on CPU + RPS)                   │
│                                                          │
│  ┌───────────────────────────────────────────────────┐   │
│  │  Pod (same binary, replicated N times)             │   │
│  │  • axum HTTP server (REST + SSE + static UI)       │   │
│  │  • sqlx PgPool (PgBouncer tx-pooling safe)         │   │
│  │  • KMS client (boot-time unseal only)              │   │
│  │  • In-memory tenant KEK LRU cache (5-min TTL)      │   │
│  │  • broadcast::Sender per (project, env) — SSE      │   │
│  └───────────────────────────────────────────────────┘   │
│                         │                               │
│         ┌───────────────┼───────────────┐              │
│         ▼               ▼               ▼              │
│   PostgreSQL        Cloud KMS       soma-iam            │
│   (only state)    (unseal only)   (JWKS endpoint)       │
└──────────────────────────────────────────────────────────┘
```

One binary. One stateful dependency (Postgres). One external service for unseal (KMS). No Redis, no Consul, no Raft, no PVCs.

**Helm chart objects:**

| Object | Notes |
|---|---|
| `Deployment` | Never `StatefulSet`. Rollout strategy: `RollingUpdate`. |
| `ServiceAccount` | Annotated with `eks.amazonaws.com/role-arn` (IRSA) or GKE/Azure WI equivalent. |
| `HorizontalPodAutoscaler` | CPU 60% + custom RPS metric. |
| `PodDisruptionBudget` | `minAvailable: 1`. |
| `ConfigMap` | Non-secret config: `KMS_PROVIDER`, `KMS_KEY_ARN`, `DATABASE_URL`, `SOMA_IAM_JWKS_URL`, `LOG_LEVEL`. No secrets in ConfigMap. |
| `Service` | ClusterIP + optional LoadBalancer / Ingress. |

### 1.2 Managed cloud (soma-vault.com)

Same binary, same Helm chart. AWS EKS is the Phase 1 cloud. IRSA is the unseal path. The shared-schema tenant-isolation model is identical; managed cloud adds monitoring, backup automation, and metered billing — not a different architecture.

### 1.3 What is explicitly not in Phase 1

- Redis (any role)
- Consul (any role)
- Raft or etcd
- StatefulSets or PVCs
- Sidecar processes
- Separate operator for soma-vault-server itself
- Multi-region active-active

---

## 2. Stateless Pods & HPA Safety

Every pod is fully equivalent. Any pod can serve any request. HPA scale-out adds pods that each independently unseal themselves; scale-in removes pods without any handshake.

**State inventory:**

| Data | Location | Lifetime |
|---|---|---|
| Secrets ciphertext, wrapped DEKs | Postgres | Persistent |
| Audit log | Postgres | Persistent |
| Session tokens | Postgres `sessions` table | TTL-scoped |
| Rotation jobs | Postgres `rotation_jobs` table | Persistent |
| Master KEK | Pod RAM only (`Zeroizing<[u8;32]>`) | Process lifetime |
| Tenant KEK | Pod RAM LRU cache | 5-min TTL, ZeroizeOnDrop |
| SSE broadcast channels | Pod RAM `DashMap` | Ephemeral, rebuilt on reconnect |
| JWKS cache | Pod RAM | Refreshed on `kid` miss |

No state is written to pod-local disk. Pod crash means all in-RAM keys are gone. The next pod re-unseals from KMS autonomously.

**Singleton background workers** (rotation sweeper, lease expiry, audit flush) each acquire a Postgres session-level advisory lock on a **dedicated non-pooled connection** outside the sqlx pool. That dedicated connection must configure TCP keepalives so an OOM-killed pod is detected within seconds rather than the OS default of 7200 seconds:

```
keepalives=1 keepalives_idle=60 keepalives_interval=10 keepalives_count=3
```

Set these in the `DATABASE_URL` for the advisory-lock connection or via `sqlx::ConnectOptions`. When the TCP session drops, Postgres releases the lock automatically. Remaining pods acquire it on the next 30-second poll.

```rust
// ponytail: advisory lock on dedicated conn prevents zombie-lock bug from
// pool recycling. TCP keepalives above prevent 2-hour zombie on OOM kill.
// Ceiling: 50+ pods polling adds measurable DB load.
// Upgrade path: Kubernetes Lease object for sub-pod-count scale.
const ROTATION_LOCK_ID: i64 = 0x736f6d61_726f7461i64; // "somarota"

async fn acquire_singleton_lock(conn: &mut PgConnection) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(ROTATION_LOCK_ID)
        .fetch_one(conn)
        .await?)
}
```

---

## 3. KMS Deployment Key Bootstrap

Before the first pod can unseal, the master KEK must be generated, wrapped, and stored. This is a one-time step during deployment setup.

**DDL:**

```sql
CREATE TABLE kms_deployment_keys (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    deployment_id       TEXT        NOT NULL UNIQUE,
    kms_provider        TEXT        NOT NULL,          -- 'aws_kms' | 'software'
    kms_key_id          TEXT        NOT NULL,          -- KMS CMK ARN or 'software'
    wrapped_master_kek  BYTEA       NOT NULL,          -- KMS-encrypted 32-byte KEK
    kms_key_version     INT         NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

**Bootstrap sequence (executed by `soma vault init-kms` CLI or Helm post-install Job):**

1. Generate 32 random bytes via `OsRng` as the master KEK.
2. Call `KMS Encrypt` (or `KMS GenerateDataKey`) to produce `wrapped_master_kek`.
3. `INSERT INTO kms_deployment_keys ... ON CONFLICT (deployment_id) DO NOTHING` — handles simultaneous first-boot races; all pods converge on the single committed row.
4. Verify a test `KMS Decrypt` round-trip before exiting. The init command fails loudly if this round-trip fails.

**Normal boot sequence (every subsequent pod start):**

```
SELECT wrapped_master_kek FROM kms_deployment_keys WHERE deployment_id = $1
  → KMS Decrypt → master KEK in Zeroizing<[u8;32]>
  → /health/ready returns 200
```

---

## 4. Auto-unseal: Cloud Workload Identity Flow

This is soma-vault's primary positioning claim. No human touches a pod's key material at any point.

### 4.1 AWS EKS / IRSA (Phase 1 primary)

```
Pod boots
  │
  ▼
K8s injects projected ServiceAccount OIDC JWT
  at /var/run/secrets/eks.amazonaws.com/serviceaccount/token
  (audience: sts.amazonaws.com)
  │
  ▼
aws-config WebIdentityTokenCredentialsProvider reads
  AWS_WEB_IDENTITY_TOKEN_FILE + AWS_ROLE_ARN env vars
  (injected by EKS admission controller, NOT by this binary)
  │
  ▼
STS AssumeRoleWithWebIdentity → ephemeral IAM credentials
  (valid 1h, auto-refreshed by SDK credential chain)
  │
  ▼
SELECT wrapped_master_kek FROM kms_deployment_keys
  KMS Decrypt → master KEK in Zeroizing<[u8;32]>
  Stored in Arc<KmsState>, never on disk, never logged
  │
  ▼
/health/ready returns 200
  Readiness probe gates here — unsealed pod only
  │
  ▼
Pod serves traffic
```

**If KMS is unreachable at boot:** 60-second retry window with exponential backoff (initial 1s, factor 2, cap 30s). After that, the readiness probe fails permanently — the pod never receives traffic and HPA does not count it as ready.

**If KMS becomes unreachable while running (circuit-breaker):**

```
KMS call fails
  │
  ▼
Pod enters DEGRADED state:
  • Extends tenant KEK cache TTL up to grace_period_minutes (default 30)
  • Continues serving from cached KEK material
  • /health/ready → HTTP 200 with {"degraded": true, "active_alerts": ["kms_unreachable"]}
  • Pod stays in Service Endpoints list → capacity preserved
  │
  ▼
If grace period expires and KMS still unreachable:
  • Pod stops serving (transitions to SEALED)
  • /health/ready → HTTP 503
  • CRITICAL structured log emitted
```

Note: returning 200 from `/health/ready` keeps the pod in the Kubernetes Service `Endpoints` list so it continues receiving traffic. This is distinct from HPA scaling, which is driven by metrics. To suppress HPA scale-down during a degraded period, expose `soma_vault_kms_grace_period_active` as a Prometheus gauge and configure an HPA behavior rule against it.

### 4.2 GCP / GKE Workload Identity and Azure Workload Identity

The `KmsBackend` trait (see §7) is defined for both. Implementations are Phase 2.

### 4.3 SPIFFE/SPIRE

Phase 2, for on-prem/bare-metal/multi-cloud enterprise. The `KmsBackend` trait accommodates it without changes to the calling code.

### 4.4 Software fallback for self-host without cloud KMS

For indie developers running soma-vault locally or on bare metal without AWS/GCP/Azure, the `SoftwareKmsBackend` reads the master KEK from an environment variable:

- `SOMA_MASTER_KEK_HEX`: 32 bytes, hex-encoded, injected as a Kubernetes Secret environment variable.

**Documented tradeoff:** This is the one acceptable exception to tenet 3. Security posture degrades to "master KEK protected by Kubernetes etcd encryption at rest and RBAC on the Secret." This is equivalent to Infisical's `ENCRYPTION_KEY` env-var model and is documented as such, not hidden. The health endpoint exposes `"seal_backend": "software"` with `"seal_backend_severity": "WARNING"`. Operators who need the full workload-identity guarantee must use cloud KMS.

The `age` crate is not used for this path. The env-var model is simpler, one dependency fewer, and makes rotation straightforward: update the Kubernetes Secret, trigger a rolling restart.

---

## 5. Key Hierarchy (4 Layers)

```
Layer 0: External KMS key (AWS CMK / GCP key / Azure Key Vault key)
         Lives in cloud HSM. Never exported. Never touches pod.
         ┌─────────────────────────────────────────────────────────────┐
         │  wraps ↓                                                    │
Layer 1: Master KEK [32 bytes, Zeroizing<[u8;32]>]                   │
         Pod RAM only. Derived from KMS Decrypt on boot.              │
         Never on disk, env vars, or logs.                            │
         ┌───────────────────────────────────────────┐               │
         │  HKDF-SHA256 derives ↓                    │               │
Layer 2: Per-tenant KEK [32 bytes, Zeroizing<[u8;32]>]              │
         tenant_kek = HKDF(                          │               │
             ikm    = master_kek,                    │               │
             salt   = b"soma-vault-tenant-kek-v1",   │               │
             info   = tenant_id_bytes)               │               │
         Cached 5-min TTL; ZeroizeOnDrop on eviction.                │
         One KMS call on boot → all tenant KEKs in pod RAM.          │
         ┌──────────────────────────────────────────┐│               │
         │  wraps ↓ (AES Key Wrap RFC 3394, in RAM) ││               │
Layer 3: Per-secret-version DEK [32 bytes, OsRng]  ││               │
         Fresh per secret_version INSERT.           ││               │
         Zeroized immediately after encrypt/decrypt.││               │
         Stored as wrapped_dek (RFC 3394 output).   ││               │
         └──────────────────────────────────────────┘│               │
                         ↓                           │               │
         secret_versions row in Postgres:            │               │
           ciphertext bytea                          │               │
           wrapped_dek bytea  (RFC 3394 AES-KW)     │               │
           nonce bytea        (12-byte random, AEAD) │               │
           aad_fingerprint bytea (SHA-256 diagnostic)│               │
           kms_key_version int                       │               │
         └───────────────────────────────────────────┘               │
└─────────────────────────────────────────────────────────────────────┘
```

**Blast radius by layer:**

| Compromise | Exposed |
|---|---|
| One DEK | One secret version |
| One tenant KEK | All wrapped DEKs for that tenant (unwrappable in memory) |
| Master KEK | All tenant KEKs derivable in pod RAM. Master KEK never leaves pod RAM. |
| KMS key | Master KEK could be unwrapped — mitigated by workload-identity RBAC on the KMS policy |
| Postgres dump alone | Nothing. Useless without KMS access. |

**Audit HMAC key:** The audit chain uses a separate HKDF derivation from its own distinct root. The audit HMAC key must NOT share the master KEK as IKM — a single master KEK compromise must not simultaneously break secret confidentiality AND audit chain integrity:

```rust
// Separate KMS-wrapped audit signing key, loaded alongside master KEK on boot.
// audit_hmac_key = HKDF(ikm=audit_signing_key, salt=b"soma-vault-audit-hmac-v1",
//                       info=tenant_id_bytes)
// The kms_deployment_keys table stores both wrapped_master_kek and
// wrapped_audit_signing_key as separate columns.
```

This means `kms_deployment_keys` stores two independent wrapped keys. The init command generates and wraps both.

---

## 6. Envelope Encryption: Per-secret Write and Read Paths

### 6.1 DEK wrapping algorithm

The DEK is wrapped using **AES Key Wrap (RFC 3394)** via the `aes-kw` crate — not AES-256-GCM. AES-KW is nonceless by design and is the correct algorithm for wrapping fixed-size key material under another key. The `wrapped_dek` column stores RFC 3394 output. There is no wrap nonce; the schema's `nonce` column belongs to the secret-value AEAD call only.

### 6.2 Encrypt (secret write)

```rust
// All key types use Zeroizing wrapper; secrecy::Secret suppresses Debug.
async fn encrypt_secret_version(
    tenant_kek: &Zeroizing<[u8; 32]>,
    plaintext: &[u8],
    secret_id: Uuid,
    version_id: Uuid,
) -> Result<EncryptedSecretVersion> {
    // Layer 3: fresh random DEK, never reused
    let mut dek = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut dek);

    // Nonce: 96-bit random per AEAD call (encrypts the secret value, not the DEK)
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // AAD: binds ciphertext to this exact (secret, version) pair.
    // Prevents ciphertext transplant between secrets or versions.
    let aad = build_aad(secret_id, version_id);

    let cipher = Aes256Gcm::new_from_slice(&*dek)?;
    let ciphertext = cipher.encrypt(nonce, Payload { msg: plaintext, aad: &aad })?;

    // Wrap DEK under tenant KEK using RFC 3394 AES Key Wrap (no nonce, no KMS call)
    let kek = KeyWrap::new(GenericArray::from_slice(&**tenant_kek));
    let wrapped_dek = kek.wrap_with_padding(&*dek)?;

    // SHA-256 fingerprint for diagnostic use only — the AEAD tag is the security binding.
    // On decrypt, recompute and compare with subtle::ConstantTimeEq before decrypting.
    let aad_fingerprint = sha256(&aad);

    // dek is zeroized here on drop (ZeroizeOnDrop)
    Ok(EncryptedSecretVersion {
        ciphertext,
        nonce: nonce_bytes.to_vec(),
        wrapped_dek,
        aad_fingerprint,
        kms_key_version: state.active_key_version,
    })
}
```

### 6.3 Decrypt (secret read)

```rust
async fn decrypt_secret_version(
    tenant_kek: &Zeroizing<[u8; 32]>,
    row: &SecretVersionRow,
) -> Result<Zeroizing<Vec<u8>>> {
    // Diagnostic: recompute fingerprint and verify before decrypting
    let expected_aad = build_aad(row.secret_id, row.version_id);
    let expected_fp = sha256(&expected_aad);
    if !bool::from(expected_fp.ct_eq(&row.aad_fingerprint)) {
        return Err(CryptoError::AadFingerprintMismatch);
    }

    // Unwrap DEK via RFC 3394 AES-KW — no KMS call, no nonce
    let kek = KeyUnwrap::new(GenericArray::from_slice(&**tenant_kek));
    let dek = Zeroizing::new(kek.unwrap_with_padding(&row.wrapped_dek)?);

    let cipher = Aes256Gcm::new_from_slice(&*dek)?;
    let nonce = Nonce::from_slice(&row.nonce);

    let plaintext = cipher.decrypt(nonce, Payload { msg: &row.ciphertext, aad: &expected_aad })?;
    // dek zeroized on drop

    Ok(Zeroizing::new(plaintext))
}
```

### 6.4 Rollback always generates a fresh DEK

The rollback operation (`POST /v1/secrets/{id}/rollback?to_version=N`) decrypts the source version's plaintext using the current tenant KEK, then re-encrypts with a **fresh DEK and fresh nonce**. It never copies `wrapped_dek` or `nonce` from the source row. The rollback result is a new version row with its own independent DEK.

### 6.5 Nonce strategy

96-bit (12-byte) random nonce per AES-256-GCM call. Safe because each DEK encrypts exactly one secret value per version — the birthday-bound 2^32 limit is unreachable at per-DEK granularity. ChaCha20Poly1305 (192-bit nonce) is the server-config option for non-AES-NI hardware; it eliminates nonce-reuse risk entirely.

### 6.6 AEAD associated data (AAD)

```rust
fn build_aad(secret_id: Uuid, version_id: Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32);
    aad.extend_from_slice(secret_id.as_bytes());
    aad.extend_from_slice(version_id.as_bytes());
    aad
}
```

The AAD binding guarantees that a ciphertext row extracted from one secret and inserted into another fails AEAD verification on decrypt. This closes the ciphertext-transplant attack without additional application logic.

---

## 7. KmsBackend Trait

```rust
#[async_trait]
pub trait KmsBackend: Send + Sync {
    /// Wrap plaintext_kek under the KMS key. Returns wrapped bytes.
    async fn wrap_key(&self, plaintext_kek: &[u8]) -> Result<Vec<u8>>;

    /// Unwrap wrapped_kek. Returns plaintext KEK in a Zeroizing buffer.
    async fn unwrap_key(&self, wrapped_kek: &[u8]) -> Result<Zeroizing<Vec<u8>>>;

    /// Backend identifier for health endpoint.
    fn backend_name(&self) -> &'static str;
}
```

Phase 1 implementations:

| Struct | Backend | Credential source |
|---|---|---|
| `AwsKmsBackend` | AWS KMS | IRSA via `aws-config` credential chain |
| `SoftwareKmsBackend` | AES-256-GCM over env var | `SOMA_MASTER_KEK_HEX` Kubernetes Secret |

Phase 2: `GcpKmsBackend`, `AzureKmsBackend`.

---

## 8. In-memory Key Hygiene

### 8.1 Type discipline

| Type | Crate | Guarantees |
|---|---|---|
| `Zeroizing<T>` | `zeroize` | Volatile write + memory fence on drop |
| `Secret<T>` | `secrecy` | No `Debug`/`Display`, no `Clone`, zeroize on drop |
| `#[derive(Zeroize, ZeroizeOnDrop)]` | `zeroize_derive` | Applied to every struct holding key bytes |

No key material appears as a plain `Vec<u8>` or `[u8; N]` at any call boundary. Tenant KEK entries in the LRU cache are stored as `Box<Zeroizing<[u8;32]>>` so the key bytes are pinned to a stable heap address across LRU internal rebalancing.

```rust
struct TenantKekCache {
    // ponytail: Box pins the key bytes at a stable address across LRU moves.
    // Ceiling: ~100 active tenants in RAM at once before LRU evicts.
    // Upgrade path: shard by tenant_id prefix if needed.
    inner: Arc<RwLock<LruCache<TenantId, Box<Zeroizing<[u8; 32]>>>>>,
}
```

### 8.2 What is never logged

- DEK plaintext
- Tenant KEK
- Master KEK
- Secret plaintext
- Session tokens
- Any `Secret<T>` value (suppressed by `secrecy`)

`tracing` spans carry only `secret_id`, `tenant_id`, `version`, `outcome`.

### 8.3 Master KEK lifetime

```
Pod start → KMS Decrypt → master_kek in Zeroizing<[u8;32]> in Arc<KmsState>
         ↓
KmsState held for process lifetime (Arc clone to each request handler)
         ↓
Pod exit → Arc drop → ZeroizeOnDrop fires → memory zeroed
```

CPU registers cannot be zeroed by software — this is inherent to all software-based key management and is documented.

---

## 9. Multi-tenant Isolation

### 9.1 TenantId newtype (compile-time enforcement)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantId(pub Uuid);
```

Every repository function signature requires `TenantId` as an explicit parameter. It is impossible to call a data-access function without providing a tenant context — the compiler rejects it. Every `sqlx` query includes `WHERE tenant_id = $1` supplied from this value.

All repository functions must accept `sqlx::Transaction<'_, Postgres>` (not `PgPool` or `PoolConnection`) so that `SET LOCAL app.tenant_id = $1` is guaranteed to be inside an explicit transaction. A `TenantTransaction<'_>` newtype wraps a transaction and enforces this at the type level:

```rust
pub struct TenantTransaction<'c> {
    inner: Transaction<'c, Postgres>,
    tenant_id: TenantId,
}
```

This prevents autocommit-mode queries where `SET LOCAL` would be a no-op and RLS would silently see a NULL tenant.

### 9.2 Schema: denormalized tenant_id on every table

`tenant_id` is a leading column on every table holding tenant data, making RLS policy evaluation join-free.

Unique constraints are always tenant-scoped to prevent cross-tenant existence leaks:

```sql
-- Correct: tenant-scoped unique
CREATE UNIQUE INDEX idx_secrets_tenant_path
    ON secrets (tenant_id, environment_id, path);

-- Wrong: globally unique — reveals cross-tenant path existence via duplicate-key errors
-- CREATE UNIQUE INDEX ON secrets (path);
```

### 9.3 Two enforcement layers (defense-in-depth)

**Layer 1 (primary) — Application layer:**
The axum middleware extracts `tenant_id` from the validated soma-iam JWT `tid` claim and injects it into request state. The type-state pattern ensures handlers only execute after `authz::check()` has run. All repository calls receive `TenantId` explicitly.

**Layer 2 (defense-in-depth) — Postgres RLS:**

```sql
-- Table owner is soma_vault_admin (DDL role).
-- Application role soma_vault_app is NOT the owner → RLS is not bypassed.
-- Postgres superusers DO bypass RLS — envelope encryption is the boundary
-- against superuser-level Postgres access. RLS catches application bugs only.
GRANT INSERT, SELECT, UPDATE ON ALL TABLES
    IN SCHEMA public TO soma_vault_app;
-- Note: DELETE is NOT granted on tenants to soma_vault_app.

ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE secrets FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON secrets
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
```

`set_config('app.tenant_id', $1, true)` (transaction-local, third argument `true`) is executed as the first statement inside every explicit transaction via the `TenantTransaction` constructor. This is safe under PgBouncer transaction-pooling — the setting resets at transaction end and never bleeds to another session.

All views use `SECURITY INVOKER = true` (Postgres 15+) to prevent `SECURITY DEFINER` bypass.

**Important:** FORCE ROW LEVEL SECURITY does not prevent Postgres superuser access. The cryptographic boundary against a database-level attacker (including a cloud-managed Postgres admin) is the envelope encryption — a superuser sees only ciphertext.

### 9.4 Environment inheritance

```sql
ALTER TABLE environments ADD COLUMN inherits_from UUID
    REFERENCES environments(id);

ALTER TABLE environments ADD CONSTRAINT chk_no_self_inherit
    CHECK (inherits_from IS DISTINCT FROM id);
```

Max inheritance depth is 3, enforced at write time. The application-layer resolution function detects cycles by tracking visited IDs in a small `HashSet` during the walk:

```rust
fn resolve_config_chain(env_id: EnvId, visited: &mut HashSet<EnvId>) -> Result<Vec<EnvId>> {
    if !visited.insert(env_id) {
        return Err(Error::InheritanceCycleDetected(env_id));
    }
    // ... walk inherits_from
}
```

Cycles cannot be created by normal API calls, but a cycle guard in the resolution code ensures a direct DB write or future migration bug does not produce an infinite loop.

Child values override parent values. Secrets have no inheritance — they are always environment-specific.

### 9.5 Tenant bootstrap

When soma-iam provisions a new org, it calls `POST /v1/internal/tenants` on soma-vault. This is an internal-network-only endpoint, not exposed through the public load balancer. It is authenticated via a pre-shared HMAC webhook secret (separate from any user-facing auth). The webhook is idempotent (upsert on `soma_iam_org_id`).

```sql
CREATE TABLE tenants (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    soma_iam_org_id UUID        NOT NULL UNIQUE,
    name            TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

JWT validation at `/v1/auth/login` rejects tokens where the `tid` claim does not match any `soma_iam_org_id` in this table.

---

## 10. Secrets vs Config: Schema-level Separation

The column layout itself makes conflation structurally impossible. This is the most important schema decision.

```sql
-- secrets: NO typed-value columns
CREATE TABLE secrets (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    environment_id  UUID        NOT NULL REFERENCES environments(id),
    path            TEXT        NOT NULL,
    current_version INT         NOT NULL DEFAULT 0,
    max_versions    SMALLINT    NOT NULL DEFAULT 20,
    cas_required    BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, environment_id, path)
    -- NO: string_value, int_value, schema_json, etc.
);

-- secret_versions: NO plaintext column, ever
CREATE TABLE secret_versions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id       UUID        NOT NULL REFERENCES secrets(id),
    tenant_id       UUID        NOT NULL,
    version         INT         NOT NULL,
    ciphertext      BYTEA       NOT NULL,   -- AES-256-GCM output
    wrapped_dek     BYTEA       NOT NULL,   -- RFC 3394 AES-KW output; NO nonce needed
    nonce           BYTEA       NOT NULL,   -- 12-byte random nonce for AEAD on ciphertext
    aad_fingerprint BYTEA       NOT NULL,   -- SHA-256(secret_id_bytes || version_id_bytes); diagnostic only
    kms_key_version INT         NOT NULL DEFAULT 1,
    is_deleted      BOOLEAN     NOT NULL DEFAULT FALSE,
    deleted_at      TIMESTAMPTZ,
    is_destroyed    BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by_id   UUID        NOT NULL,
    UNIQUE (tenant_id, secret_id, version)
);

-- config_keys: NO ciphertext/wrapped_dek columns
CREATE TABLE config_keys (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    environment_id  UUID        NOT NULL REFERENCES environments(id),
    path            TEXT        NOT NULL,
    value_type      TEXT        NOT NULL CHECK (value_type IN
                    ('string','int','float','bool','json','secret_ref')),
    schema_json     JSONB,      -- JSON Schema Draft 2020-12 for value_type=json
    is_sensitive    BOOLEAN     NOT NULL DEFAULT FALSE,
    current_version INT         NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, environment_id, path)
    -- NO: ciphertext, wrapped_dek, nonce
);

-- config_versions: typed plaintext values; secret_ref stores UUID only
CREATE TABLE config_versions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    config_key_id   UUID        NOT NULL REFERENCES config_keys(id),
    tenant_id       UUID        NOT NULL,
    version         INT         NOT NULL,
    string_value    TEXT,
    int_value       BIGINT,
    float_value     DOUBLE PRECISION,
    bool_value      BOOLEAN,
    json_value      JSONB,
    secret_ref      UUID,       -- FK to secrets.id; NULL unless value_type=secret_ref
    is_deleted      BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, config_key_id, version)
);
```

A secret's plaintext cannot appear in a `config_versions` row because that table has no column to hold it. A config value cannot accidentally become encrypted because `config_keys` has no DEK columns.

**secret_ref restrictions:** A `config_key` with `value_type=secret_ref` may only reference a secret in the **same environment** (same `environment_id`). Cross-environment secret refs are rejected at write time. This eliminates a privilege-escalation path where a service account with staging config read resolves a production secret via a cross-environment ref.

**SSE events for secret_ref:** The SSE stream delivers only the config path and `value_type` for `secret_ref` changes — the `secret_id` is omitted from the event payload. Callers who need the referenced secret call the secrets API directly with their own credentials.

---

## 11. Full Postgres Schema

```sql
-- Tenants (root; 1:1 with soma-iam org)
CREATE TABLE tenants (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    soma_iam_org_id UUID        NOT NULL UNIQUE,
    name            TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- KMS deployment key (one row per soma-vault deployment)
CREATE TABLE kms_deployment_keys (
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    deployment_id           TEXT        NOT NULL UNIQUE,
    kms_provider            TEXT        NOT NULL,
    kms_key_id              TEXT        NOT NULL,
    wrapped_master_kek      BYTEA       NOT NULL,
    wrapped_audit_signing_key BYTEA     NOT NULL,  -- separate root for audit HMAC
    kms_key_version         INT         NOT NULL DEFAULT 1,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Workspaces
CREATE TABLE workspaces (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL REFERENCES tenants(id),
    name        TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

-- Workspace member role bindings
CREATE TABLE principal_workspace_roles (
    tenant_id    UUID    NOT NULL,
    workspace_id UUID    NOT NULL REFERENCES workspaces(id),
    principal_id UUID    NOT NULL,
    role         TEXT    NOT NULL CHECK (role IN ('ws:admin','ws:developer','ws:reader')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workspace_id, principal_id)
);

-- Projects
CREATE TABLE projects (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID        NOT NULL,
    workspace_id UUID        NOT NULL REFERENCES workspaces(id),
    name         TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, workspace_id, name)
);

-- Environments (with optional inheritance, depth ≤ 3)
CREATE TABLE environments (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL,
    project_id    UUID        NOT NULL REFERENCES projects(id),
    name          TEXT        NOT NULL,
    inherits_from UUID        REFERENCES environments(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, project_id, name),
    CONSTRAINT chk_no_self_inherit CHECK (inherits_from IS DISTINCT FROM id)
);

-- secrets and secret_versions (see §10)
-- config_keys and config_versions (see §10)

-- Path-capability policies
CREATE TABLE policies (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID        NOT NULL,
    workspace_id UUID        NOT NULL REFERENCES workspaces(id),
    path_glob    TEXT        NOT NULL,
    capabilities TEXT[]      NOT NULL,  -- {read, write, list, delete, deny}
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- ponytail: Cedar policy engine is Phase 2. The path_glob TEXT column stores
-- plain glob strings now; Cedar policy strings are additive to this column later.

-- Service accounts (Universal Auth machine identities)
CREATE TABLE service_accounts (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL,
    workspace_id  UUID        NOT NULL REFERENCES workspaces(id),
    name          TEXT        NOT NULL,
    client_id     UUID        NOT NULL UNIQUE,
    client_secret_hash TEXT   NOT NULL,  -- Argon2id
    last_used_at  TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, workspace_id, name)
);

-- Append-only audit log
CREATE TABLE audit_events (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL,
    seq_num       BIGINT      NOT NULL,   -- from Postgres SEQUENCE per tenant
    event_type    TEXT        NOT NULL,
    actor_type    TEXT        NOT NULL,
    actor_id      UUID        NOT NULL,
    actor_ip      INET,
    resource_type TEXT        NOT NULL,
    resource_id   UUID,
    resource_name TEXT,                   -- HMAC-hashed path
    outcome       TEXT        NOT NULL,
    reason        TEXT,                   -- break-glass justification
    jti           TEXT,                   -- soma-iam JWT ID for cross-platform correlation
    prev_entry_hash TEXT      NOT NULL,
    entry_hash    TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, seq_num)
);
-- soma_vault_app has INSERT + SELECT only on audit_events. No UPDATE or DELETE.

-- Rotation jobs
CREATE TABLE rotation_jobs (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id        UUID        NOT NULL REFERENCES secrets(id),
    tenant_id        UUID        NOT NULL,
    status           TEXT        NOT NULL CHECK (status IN
                     ('pending','in_progress','succeeded','failed','irrevocable')),
    stage            TEXT        CHECK (stage IN ('create','set','test','finish')),
    rotation_version UUID        NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at       TIMESTAMPTZ,
    completed_at     TIMESTAMPTZ,
    error            TEXT,
    next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Double-rotation guard: at most one active job per secret
CREATE UNIQUE INDEX uq_rotation_active ON rotation_jobs (secret_id)
    WHERE status IN ('pending', 'in_progress');
```

**seq_num generation for audit:** A Postgres sequence per tenant (`CREATE SEQUENCE audit_seq_<tenant_id>`) is created when the tenant row is inserted. The audit append acquires `pg_advisory_xact_lock(hashtext('audit:' || tenant_id))` to serialize chain appends and calls `nextval` within the lock.

---

## 12. RBAC & Path-Capability Authorization

Authorization uses two layers evaluated in order:

1. **Workspace role** (`principal_workspace_roles`): coarse-grained — `ws:admin`, `ws:developer`, `ws:reader`. Roles flow in from soma-iam JWT `roles[]` claims for existing bindings; workspace-role management is available via the API (`GET/POST/PATCH/DELETE /v1/workspaces/{workspace_id}/members`).

2. **Path-capability overlay** (`policies` table): fine-grained — `{read, write, list, delete, deny}` evaluated against path globs via an in-process radix trie per tenant. `deny` always wins over `allow`.

The type-state pattern enforces authorization at compile time:

```rust
// Handlers parameterized on Authorized cannot compile without authz::check().
async fn get_secret(
    State(app): State<AppState>,
    auth: Authorized,  // type-state: only reachable after authz::check()
    Path(secret_id): Path<Uuid>,
) -> Result<Json<SecretResponse>> { ... }
```

**Policy cache invalidation:** After any `INSERT`/`UPDATE`/`DELETE` on `policies`, the handler sends `NOTIFY policy_changes, '{"tenant_id":"...","workspace_id":"..."}'` over the existing Postgres LISTEN/NOTIFY infrastructure. Each pod's LISTEN connection receives this and clears the in-memory radix trie for that tenant. This reuses the SSE fan-out pattern with zero additional infrastructure.

**First-login auto-provisioning:** A principal with `org_role: 'admin'` in the soma-iam JWT who has no existing workspace role binding is auto-provisioned as `ws:admin` for all workspaces in that tenant on first login. `org:member` and `org:viewer` require explicit workspace invitation.

---

## 13. soma-iam JWT Contract

soma-vault defines what it requires from soma-iam. soma-iam must satisfy this contract.

**Required JWT claims:**

```json
{
  "iss": "https://iam.soma-platform.com",
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "aud": ["soma-vault"],
  "exp": 1750000000,
  "iat": 1749999100,
  "jti": "unique-token-id",
  "tid": "org-uuid-here",
  "org_role": "member",
  "roles": ["ws:developer"]
}
```

| Claim | Required | Description |
|---|---|---|
| `iss` | Yes | soma-iam issuer URL |
| `sub` | Yes | Principal UUID (opaque) |
| `aud` | Yes | Must include `"soma-vault"` — rejected otherwise |
| `exp` | Yes | Short-lived (≤ 15 min for machine identities) |
| `jti` | Yes | Token ID — stored in `audit_events.jti` for cross-platform audit correlation; checked against replay cache |
| `tid` | Yes | Tenant/org UUID — rejected if absent or unknown |
| `org_role` | Yes | `admin` / `member` / `viewer` |
| `roles` | No | Workspace-level roles array |

**Required soma-iam endpoints:**

| Endpoint | Purpose |
|---|---|
| `/.well-known/openid-configuration` | OIDC Discovery |
| `/jwks` | JWKS with `kid` rotation support |

**JWKS cache behavior:** soma-vault caches JWKS in-process. On `kid` miss, exactly one re-fetch is issued via a singleflight/`OnceCell` pattern — concurrent requests with the same unknown `kid` share a single outbound fetch rather than fanning out to soma-iam. Unknown `kid` values are negatively cached for 60 seconds after the re-fetch returns no matching key, preventing a thundering-herd attack that forces continuous JWKS re-fetches.

**JWT replay prevention:** After soma-vault validates a soma-iam JWT at `/v1/auth/login`, the `jti` is written to a `jti_replay_cache` table with expiry matching `exp`. Subsequent logins with the same `jti` are rejected with 401. Expired entries are pruned by the background sweeper.

---

## 14. Session Token Exchange

```
POST /v1/auth/login
Body: {"token": "<soma-iam JWT>"}

soma-vault:
  1. Validates JWT signature (local JWKS cache, singleflight on kid miss)
  2. Checks iss, aud=["soma-vault"], exp, iat, tid claim exists and is known
  3. Checks jti against replay cache; records jti on success
  4. Issues short-lived signed Bearer session token (RS256, private key in pod RAM
     derived from master KEK via HKDF with salt=b"soma-vault-session-signing-v1")
  5. Session TTL: 15 minutes (configurable)
  6. Returns: {"token": "<session-token>", "expires_at": "..."}

All subsequent requests:
  Authorization: Bearer <session-token>
  → Signature verification (CPU only, no DB lookup, no soma-iam call)
```

Session tokens are short-lived RS256 JWTs signed by soma-vault itself. The signing key is derived in pod RAM from the master KEK — it is never stored in Postgres. Forced revocation (explicit logout) writes the `jti` of the soma-vault session token to a small in-memory revocation set that expires with the token TTL. Acceptable data loss on pod restart given the 15-minute window.

The sessions table is not required with this model. No per-request DB lookup occurs on the hot path.

**Universal Auth (local dev / machine identities):**

```
POST /v1/auth/universal
Body: {"client_id": "...", "client_secret": "..."}

soma-vault:
  1. Looks up client_id in service_accounts table
  2. Argon2id-verifies client_secret against stored hash
  3. Issues session token as above
```

Universal Auth is a bootstrapping and local-dev mechanism. In production, machine identities should authenticate through soma-iam OIDC.

**Dashboard session security:** The Leptos dashboard stores the session token in an `httpOnly`, `Secure`, `SameSite=Strict` cookie set by the server at login time. The WASM client never reads the token directly — the browser attaches the cookie to all requests. A non-httpOnly CSRF token cookie (Double Submit Cookie pattern) provides CSRF protection.

---

## 15. Real-time Config Delivery via SSE

```
GET /v1/config/stream?project_id=X&env_id=Y
→ Content-Type: text/event-stream
```

`workspace_id` is redundant on this endpoint (project IDs are unique within a tenant) and is omitted.

**Pod-local flow:**

1. On first subscriber for a `(project_id, env_id)` pair, a `tokio::sync::broadcast::Sender<ConfigChangeEvent>` is created lazily in a `DashMap`.
2. On any committed `config_versions` INSERT/UPDATE, the handler sends to the broadcast channel.
3. All connected SDK subscribers on that pod receive a typed delta event within <1 second.

**Event payload:** contains only `{path, value_type, version}` — never the config value, not even for non-sensitive config. For `secret_ref` type, the `secret_id` is also omitted. Receiving pods look up the current value from Postgres after processing the notification. This avoids the 8000-byte Postgres NOTIFY payload limit and ensures `is_sensitive` config values never appear in the WAL.

**Cross-pod fan-out:**

```sql
-- After config_versions INSERT/UPDATE (committed):
NOTIFY config_changes, '{"tenant_id":"...","project_id":"...","env_id":"...","path":"...","version":42}';
```

Each pod maintains a dedicated non-pooled LISTEN connection. On notification, it updates its DashMap cache and broadcasts to local SSE subscribers.

The LISTEN connection is actively health-checked with a periodic `SELECT 1`. On silent drop, the task reconnects with exponential backoff and sends a synthetic `stream_interrupted` SSE event to local subscribers so they fall back to the 60-second polling path until the stream resumes.

```
// ponytail: Postgres LISTEN/NOTIFY fan-out. Ceiling: ~50 pods × subscriber density.
// Upgrade path: Redis pub/sub when this ceiling is measured to be insufficient.
```

**SDK cache:** seeded at startup via one bulk GET; updated live via SSE. `config.get(key)` is always a local cache read (zero network). Secrets are never cached — each `secrets.get()` triggers a fresh API call, DEK unwrap, decrypt, and audit log entry.

---

## 16. Audit Log Hash Chain

The audit HMAC key is derived from a separate root (the `wrapped_audit_signing_key` in `kms_deployment_keys`, distinct from the master KEK) so that a master KEK compromise does not simultaneously compromise audit chain integrity.

```rust
// Per-tenant audit HMAC key:
// audit_hmac_key = HKDF(ikm=audit_signing_key,
//                       salt=b"soma-vault-audit-hmac-v1",
//                       info=tenant_id_bytes)
```

Each audit entry's `entry_hash` covers:
`HMAC-SHA256(audit_hmac_key, schema_version || seq_num || tenant_id || actor_id || event_type || resource_id || outcome || timestamp || prev_entry_hash)`

`prev_entry_hash` is `"0" * 64` for the genesis entry.

**Serialization:** Each tenant-scoped append acquires `pg_advisory_xact_lock(hashtext('audit:' || tenant_id))` to guarantee monotonic `seq_num` ordering. `seq_num` is generated via a per-tenant Postgres SEQUENCE, not `MAX(seq_num)+1`.

**Write guarantees by event type:**

| Event class | Write mode |
|---|---|
| Secret CREATE / UPDATE / DELETE / DESTROY | Synchronous within request transaction |
| Config CREATE / UPDATE / DELETE | Synchronous within request transaction |
| Secret READ | Synchronous within request transaction. Every individual read is logged. |
| Rotation events | Synchronous within rotation job transaction |

All audit writes are synchronous. The "best-effort channel" model is not used — it is incompatible with the seq_num hash chain and the SOC 2 claim that every secret read is individually logged. The `reason` field (break-glass justification) is required for high-privilege operations and stored in the audit entry.

**Access control:** `soma_vault_app` has `INSERT` and `SELECT` only on `audit_events` — no `UPDATE` or `DELETE`. The hash chain provides tamper-evidence against `soma_vault_app`-level access. Postgres superuser (`soma_vault_admin`) access bypasses this protection; that role must be restricted to break-glass procedures with separate infrastructure-level audit logging.

**Verification endpoint:** `GET /v1/audit/verify?from=&to=` (admin-only, rate-limited) walks the chain and returns the first bad `seq_num` or `"chain intact"`. Secret values never appear in any audit entry.

**KMS infrastructure events** (`kms_unseal_success`, `kms_unseal_fail`, `kms_degraded_entry`, `kms_sealed`) are pod-level, not tenant-scoped. They belong in structured logs and Prometheus metrics, not in `audit_events`. The `audit_event_type` vocabulary covers only data-plane operations on secrets, config, policies, sessions, and service accounts.

---

## 17. Rust Crate Stack

### 17.1 Crypto

| Crate | Version | Role | Audit |
|---|---|---|---|
| `aes-gcm` | 0.10.x | AES-256-GCM AEAD for secret-value encryption | NCC Group |
| `chacha20poly1305` | 0.10.x | AEAD fallback for non-AES-NI hardware | NCC Group |
| `aes-kw` | 0.3.x | RFC 3394 AES Key Wrap for DEK wrapping under tenant KEK | RustCrypto |
| `hkdf` | 0.12.x | HKDF-SHA256 for per-tenant KEK and audit HMAC key derivation | RustCrypto |
| `sha2` | 0.10.x | SHA-256 backing for HKDF and AAD fingerprints | RustCrypto |
| `hmac` | 0.12.x | HMAC-SHA256 for audit log hash chaining | RustCrypto (NCC Group) |
| `zeroize` + `zeroize_derive` | 1.x | Secure memory zeroing on all key-material types | — |
| `secrecy` | 0.10.x | `Secret<T>` wrapper suppressing Debug/Display/Clone | — |
| `subtle` | 2.x | Constant-time equality for token and HMAC verification | Quarkslab |
| `rand` (OsRng) | 0.9.x | DEK and nonce generation — never `thread_rng()` for key material | — |

`ring` is not used. The audit HMAC uses `hmac` + `sha2` (both RustCrypto, NCC Group audited, already dependencies) rather than adding `ring` as a contradictory crate.

### 17.2 TLS

| Crate | Version | Role |
|---|---|---|
| `rustls` | 0.23.x | TLS 1.3 termination — no OpenSSL dependency |
| `aws-lc-rs` | latest | rustls crypto backend; FIPS 140-3 path via `aws-lc-fips-sys` feature flag |

`ring` is explicitly excluded from TLS. ring lacks P-521, has no FIPS path, and is described by its author as an experiment.

### 17.3 KMS clients

| Crate | Version | Role |
|---|---|---|
| `aws-sdk-kms` | latest | AWS KMS Encrypt/Decrypt |
| `aws-config` | latest | `WebIdentityTokenCredentialsProvider` for IRSA |

### 17.4 Auth & JWT

| Crate | Version | Role |
|---|---|---|
| `jsonwebtoken` | 9.x | soma-iam JWT decode/verify (RS256/ES256/EdDSA) |
| `argon2` | 0.5.x | Universal Auth `client_secret` hashing |

### 17.5 Server & DB

| Crate | Version | Role |
|---|---|---|
| `axum` | 0.8.x | HTTP server; native `axum::response::Sse` |
| `tokio` | 1.x | Async runtime |
| `sqlx` | 0.8.x | Async Postgres, compile-time query checking |
| `dashmap` | 6.x | Lock-free concurrent map for SSE broadcast channels |
| `jsonschema` | 0.46.x | Write-time JSON Schema Draft 2020-12 validation |

### 17.6 Full `Cargo.toml` excerpt

```toml
[dependencies]
# Crypto
aes-gcm           = "0.10"
chacha20poly1305  = "0.10"
aes-kw            = "0.3"
hkdf              = "0.12"
sha2              = "0.10"
hmac              = "0.12"
zeroize           = { version = "1", features = ["derive"] }
secrecy           = "0.10"
subtle            = "2"
rand              = { version = "0.9", features = ["os_rng"] }

# TLS
rustls            = { version = "0.23", features = ["aws-lc-rs"] }
aws-lc-rs         = "1"

# KMS
aws-sdk-kms       = "1"
aws-config        = "1"

# Auth
jsonwebtoken      = "9"
argon2            = "0.5"

# Server
axum              = { version = "0.8", features = ["macros"] }
tokio             = { version = "1", features = ["full"] }
sqlx              = { version = "0.8", features = ["postgres", "uuid", "time", "runtime-tokio-rustls"] }
dashmap           = "6"
jsonschema        = "0.46"

# Shared
uuid              = { version = "1", features = ["v4", "serde"] }
serde             = { version = "1", features = ["derive"] }
serde_json        = "1"
thiserror         = "2"
tracing           = "0.1"
```

---

## 18. Health Endpoints

```
GET /health/live     → 200 always (liveness; pod is running)
GET /health/startup  → 503 during KMS 60-second retry window; 200 after first success
GET /health/ready    → 200 if unsealed and DB reachable; 503 otherwise
GET /health/status   → JSON detail
```

Normal:
```json
{
  "sealed": false,
  "degraded": false,
  "seal_backend": "aws_kms",
  "active_alerts": [],
  "db_pool_size": 10,
  "db_idle": 8
}
```

Degraded (KMS unreachable, grace period active — pod stays in Endpoints list):
```json
{
  "sealed": false,
  "degraded": true,
  "seal_backend": "aws_kms",
  "active_alerts": ["kms_unreachable"],
  "grace_period_remaining_seconds": 1247
}
```

Software-KMS fallback:
```json
{
  "sealed": false,
  "degraded": false,
  "seal_backend": "software",
  "seal_backend_severity": "WARNING",
  "active_alerts": []
}
```

`/health/startup` is distinct from `/health/ready`: it returns 503 only during the initial 60-second KMS retry window on boot, then permanently returns 200 (even if the pod subsequently enters degraded mode). Use this as the Kubernetes `startupProbe`.

---

## 19. KMS Key Rotation Runbook

KMS key rotation is an O(N secrets) re-encryption operation that must complete **before** the old KMS key version is decommissioned.

1. Generate a new KMS key version (or new CMK).
2. Call `KMS Decrypt` on the old `wrapped_master_kek`, then `KMS Encrypt` under the new key to produce new `wrapped_master_kek`. Update `kms_deployment_keys` (same for `wrapped_audit_signing_key`).
3. Background re-encryption job: for each `secret_versions` row with `kms_key_version = old_version`, derive old and new tenant KEKs → unwrap DEK with old tenant KEK → re-wrap DEK with new tenant KEK → update `wrapped_dek` and `kms_key_version`. This is idempotent and resumable — a pod crash during re-encryption leaves rows with the old `kms_key_version` that the next sweep picks up.
4. Only when all `secret_versions` rows have `kms_key_version = new_version`: decommission the old KMS key version.
5. Rollback across key version boundaries requires old and new tenant KEKs derivable from respective master KEK generations. The `kms_deployment_keys` table retains all versions; pods load the version matching each row's `kms_key_version` on decrypt.

Config values are plaintext and require no re-encryption during KMS key rotation.

**Security verification (`soma vault verify-encryption`):** A CLI command that spot-checks a random sample of `secret_versions` rows by attempting decrypt and comparing plaintext length/fingerprint. Returns the number of rows checked and any failures.

---

## 20. Operational Notes

**Scale out (HPA adds pods):** Each new pod independently presents its ServiceAccount token to IRSA → KMS Decrypt → unseal. No coordination with existing pods. Ready in under 2 seconds in the common case (KMS round-trip ~100–300ms).

**Pod crash:** Advisory locks release automatically on TCP close (within keepalive timeout — 60s idle + 30s detection with the configured keepalive parameters). Job and rotation state in Postgres is fully retained. The next pod that acquires the lock sweeps up pending work.

**Rolling deploy schema compatibility:** Every migration must be forward-compatible with the previous pod version for the duration of a rolling deploy. Rules: new columns must be nullable or have a constant default; no column renames in a single migration (use expand-contract over two deploys); new enum values added before code that uses them. On pod startup, the binary asserts that the applied migration count in `_sqlx_migrations` matches the compiled-in expected count — mismatches fail the readiness probe.

**Postgres dump recovery test:** A raw Postgres dump without KMS access contains only `ciphertext`, `wrapped_dek`, and `nonce`. Without the KMS key to unwrap the master KEK, no tenant KEK is derivable and no DEK unwrappable. The dump is cryptographically useless. This is the explicit design goal of tenet 4.

**Backup and restore:** Restore procedure: (1) verify KMS access before attempting restore; (2) restore Postgres backup; (3) for software-KMS deployments, the `SOMA_MASTER_KEK_HEX` env var must be backed up and protected separately — loss of this value with no backup means permanent loss of all encrypted secrets (no recovery path); (4) after KMS key rotation, any backup predating the rotation can only be decrypted with the old KMS key version — retain old KMS key versions until all backups older than the rotation date are expired.

---

## 21. What is Not in Phase 1

| Deferred | Notes |
|---|---|
| GCP Cloud KMS backend | `KmsBackend` trait wired; Phase 2 |
| Azure Key Vault backend | Same |
| SPIFFE/SPIRE | Phase 2 for on-prem/multi-cloud enterprise |
| Dynamic secrets (ephemeral DB creds) | Lease table shape reserved; providers Phase 2 |
| PKI / CA engine | `certificate_authorities` table shape reserved; Phase 2 |
| Transit / Encryption-as-a-Service API | Phase 2 (same key management plumbing, additive routes) |
| Per-project BYOK/CMEK | Phase 2 enterprise |
| External SIEM streaming | Phase 2 |
| Cedar policy-as-code engine | Phase 2; `policies.path_glob` column stores plain glob strings now, Cedar strings later |
| Redis (any role) | Never a Phase 1 dependency; Postgres LISTEN/NOTIFY serves the fan-out use case |
| Kubernetes mutating admission webhook / sidecar injector | Phase 2; cluster-critical, high operational risk |
| Secrets Store CSI Driver provider | Phase 2 |
| TypeScript and Python SDKs | Phase 2; Rust SDK validates the API contract first |
| Multi-region active-active | Phase 3 |

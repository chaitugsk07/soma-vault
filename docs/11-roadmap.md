# soma-vault: Phased Roadmap

soma-vault ships all five non-negotiable architectural tenets (multi-tenancy, stateless HPA pods, KMS auto-unseal, envelope encryption, secrets-vs-config schema split) in Phase 1. Every subsequent phase is additive. Nothing in Phase 2 or Phase 3 requires a data-model migration or a breaking API change if the Phase 1 schema decisions are made correctly.

---

## Phase 1 — Foundation

**Theme:** A working, cloud-native, multi-tenant secrets and typed config platform that proves all five tenets on day one.

**Gate:** Shipped when a solo developer can (1) deploy soma-vault-server on EKS or bare-metal with `soma run -- node server.js` working in under 10 minutes, (2) demonstrate that a Postgres dump is cryptographically useless without KMS access, and (3) add a pod to the Deployment and have it come up ready with zero human ceremony.

### Features

**Multi-tenancy and schema**

- Five-level hierarchy: `tenant → workspace → project → environment → secret | config_key`. `tenant_id UUID NOT NULL` denormalized onto every leaf table row.
- `TenantId(Uuid)` Rust newtype required on every repository function — compile-time enforcement.
- Postgres RLS (`FORCE ROW LEVEL SECURITY`, transaction-scoped `set_config`) as defense-in-depth backstop. `soma_vault_app` role is not the table owner. All views use `SECURITY INVOKER` (Postgres 15+).
- Environment rows carry an optional `inherits_from` FK (parent env in same project, max depth 3 enforced at write time). Child values override parent values. No inheritance on secrets.

**Seal and unseal**

- AWS KMS auto-unseal via IRSA: projected ServiceAccount OIDC JWT → STS `AssumeRoleWithWebIdentity` → ephemeral credentials → KMS Decrypt into `Zeroizing<[u8;32]>` pod RAM. No static credentials anywhere. Readiness probe gates on successful unseal.
- KMS circuit-breaker: on transient KMS failure, pods extend the in-memory tenant KEK cache TTL up to `grace_period_minutes` (default 30) and serve from cached material. Health endpoint returns `degraded: true` with `active_alerts: [kms_unreachable]`. After grace period, pod transitions to SEALED and emits a CRITICAL alert.
- Software-KMS fallback for self-host without cloud KMS: `AgeSoftwareKms` backend (age crate, X25519 identity), master KEK file mounted read-only. Documented tradeoff: security posture degrades to K8s etcd encryption at rest + RBAC. Health endpoint exposes `seal_backend: software_kms` with WARNING severity.
- GCP Cloud KMS and Azure Key Vault: `KmsBackend` trait is defined with `wrap_key` and `unwrap_key` methods; concrete implementations deferred to Phase 2.

**Envelope encryption**

Four-layer key hierarchy:

| Layer | What | Where |
|---|---|---|
| 0 | External KMS CMK | Cloud HSM, never exported |
| 1 | Master KEK | Pod RAM (`Zeroizing<[u8;32]>`), loaded once at boot |
| 2 | Per-tenant KEK | Pod RAM, HKDF-SHA256(master_kek, tenant_id_bytes), LRU-cached 5 min, ZeroizeOnDrop eviction |
| 3 | Per-secret-version DEK | Pod RAM only, scoped to a single encrypt/decrypt call |

- Per-secret-version DEK: 32-byte `OsRng`, AES-256-GCM ciphertext with 96-bit random nonce. AEAD additional data = `secret_id_bytes || version_id_bytes` to prevent ciphertext transplant. DEK wrapped in pod RAM by tenant KEK; zeroized immediately. Postgres stores `(ciphertext bytea, wrapped_dek bytea, nonce bytea)`.
- ChaCha20Poly1305 available as a server config option for non-AES-NI hardware.
- All key-holding types: `Zeroize + ZeroizeOnDrop`, wrapped in `secrecy::Secret<T>`.
- Ciphers: `aes-gcm` and `chacha20poly1305` (both NCC Group audited, RustCrypto). No OpenSSL.

**Secrets vs. config separation**

- `secrets` table: id, tenant_id, environment_id, path, current_version, max_versions, cas_required, created_at, updated_at. No typed-value columns.
- `secret_versions` table: id, secret_id, tenant_id, version, ciphertext bytea, wrapped_dek bytea, nonce bytea, aad_fingerprint bytea, key_version int, is_deleted bool, deleted_at, is_destroyed bool, created_at, created_by_id.
- `config_keys` table: id, tenant_id, environment_id, path, value_type enum(`string|int|float|bool|json|secret_ref`), schema_json jsonb nullable, is_sensitive bool, current_version, created_at, updated_at. No ciphertext or wrapped_dek columns.
- `config_versions` table: id, config_key_id, tenant_id, version, string_value, int_value, float_value, bool_value, json_value, secret_ref uuid nullable.
- The column layout makes conflation structurally impossible, not just policy-forbidden.

**Typed config and real-time delivery**

- Write-time JSON Schema Draft 2020-12 validation via the `jsonschema` crate (build-once-validate-many per key). Structured error response on schema violation.
- `value_type=secret_ref` validated that the referenced secret UUID exists in the same tenant.
- SSE push: `GET /v1/config/stream?project_id=X&env_id=Y` returns `text/event-stream`. One `tokio::sync::broadcast::Sender<ConfigChangeEvent>` per `(project_id, environment_id)` in a `DashMap`, created lazily. On committed `config_versions` INSERT/UPDATE, the handler sends a typed delta event (path + value_type + scalar value). Secret plaintext never appears in the stream; `secret_ref` events carry only the UUID.
- Cross-pod fan-out via Postgres `LISTEN/NOTIFY` (one dedicated non-pooled connection per pod). Zero additional infrastructure.
- SDK holds a `DashMap` in-process cache seeded at startup via one bulk GET; SSE background task updates it. `config.get(key)` is always a local cache read.
- 60-second polling fallback on SSE disconnect.

**Authorization and authentication**

- RBAC: `principal_workspace_roles` table (tenant_id, workspace_id, principal_id, role enum `[ws:admin, ws:developer, ws:reader]`). Org-level roles flow in from soma-iam JWT claims.
- Path-capability overlay: `policies` table (tenant_id, workspace_id, path_glob, capabilities `text[]` with `{read, write, list, delete, deny}`). `deny` always wins. Evaluated via an in-process radix trie per tenant; cache invalidated per tenant on write.
- Axum type-state: `Request<Authorized>` vs `Request<Unauthenticated>`. Handlers are unreachable without going through `authz::check()` — compile-time enforcement.
- soma-iam JWT integration: validates RS256/ES256 JWTs at `POST /v1/auth/login` via locally cached JWKS (`jsonwebtoken` crate, re-fetched on `kid` miss). Validates `iss`, `aud==['soma-vault']`, `exp`, and requires `tenant_id` claim. Issues short-lived opaque Bearer session tokens (stored in Postgres `sessions` table with TTL). No soma-iam network call on the hot path.
- Universal Auth: `client_id` + `client_secret` (Argon2id-hashed) for local dev and machine identities.

**Audit log**

- `audit_events` table: id, tenant_id, seq_num BIGINT (per-tenant monotonic), event_type, actor_type, actor_id, actor_ip INET, resource_type, resource_id, resource_name (HMAC-hashed), outcome, reason TEXT nullable, prev_entry_hash, entry_hash, created_at TIMESTAMPTZ.
- HMAC key: HKDF(master_kek, `b"soma-vault-audit-hmac-v1"`, tenant_id_bytes). Never stored in Postgres.
- `soma_vault_app` role: INSERT + SELECT only, no UPDATE or DELETE.
- `GET /v1/audit/verify?from=&to=` walks the chain and returns the first bad `seq_num` or "chain intact".
- Every individual secret read is logged. For reads, audit writes use a best-effort bounded tokio channel (filled channel emits CRITICAL alert but does not block the read path).
- Secret values never appear in any audit entry. The `reason` field accepts a break-glass justification string on any write — absent from Vault, Infisical, and Doppler.

**Operations**

- Stateless Kubernetes Deployment. Zero PersistentVolumeClaims, no Raft.
- Singleton background workers (rotation sweeper, lease expiry, audit flush): Postgres session-level advisory lock on a dedicated non-pooled connection. Pod crash releases the lock automatically. Non-holders poll `pg_try_advisory_lock` every 30 seconds.
- Secret versioning: max_versions (default 20, configurable per secret), soft-delete (`is_deleted=true`), destroy (ciphertext and wrapped_dek zeroed, irreversible), CAS (expected_version on write, 409 on mismatch), single-version rollback (re-encrypts the specified version plaintext as a new current version).
- Static rotation infrastructure: `rotation_jobs` table with a four-stage lifecycle (create → set → test → finish, mirroring AWS Secrets Manager). Workers use `SELECT ... FOR UPDATE SKIP LOCKED`. Exponential backoff with `irrevocable` status and CRITICAL audit event after 7 failed attempts. Actual rotation adapters (e.g., Postgres DB password) deferred to Phase 2.

**Developer surface**

- CLI: `soma run -- <cmd>` (fetches resolved env, injects as env vars, execs child process). `soma secrets export --format=env|json|dotenv`. `soma login`, `soma init`, `soma secrets get|set|delete`, `soma config get|set|delete`.
- Kubernetes Operator: `SomaSecret` CRD (spec: secretPath, environment, targetSecretName, restartDeploymentOnChange). Authenticates via Universal Auth, writes native K8s Secret objects, reconciles on 60-second poll of soma-vault version endpoint.
- Rust SDK (`soma-sdk`): `secrets.get(path) -> Secret<String>` (never cached, fresh decrypt per call). `config.get::<T>(key)` (local cache read). Background SSE subscription task. `Secret<String>` suppresses Debug/Display, is not clonable.
- Leptos CSR dashboard: soma-iam OIDC login, workspace/project/environment tree, secret CRUD with version history (masked by default), config CRUD with inline validation, audit log viewer, service account management, dark/light theme via soma-ui.
- Single binary: embeds sqlx migrations, serves REST API + SSE + dashboard static assets. Configured via environment variables only (`KMS_PROVIDER`, `KMS_KEY_ARN`, `DATABASE_URL`, `SOMA_IAM_JWKS_URL`, `LOG_LEVEL`). Helm chart: Deployment, ServiceAccount (with workload-identity annotation), ConfigMap, optional HPA, PodDisruptionBudget.

---

## Phase 2 — Scale and Ecosystem

**Theme:** Dynamic secrets, PKI, Transit EaaS, additional KMS backends, SDK breadth, and enterprise governance. Everything in Phase 2 is additive over the Phase 1 schema.

**Gate:** Start when Phase 1 has at least 50 active tenants on the managed cloud tier and at least 3 enterprise prospects have specifically requested dynamic secrets or PKI.

### Feature candidates

**Dynamic secrets**

- `CredentialProvider` trait with `create`, `revoke`, and `test` methods.
- PostgreSQL adapter: on-demand ephemeral DB user creation with a scoped password and a short TTL. SKIP LOCKED lease sweeper revokes expired credentials.
- MySQL and Redis adapters follow the same trait.
- `leases` table (schema stub reserved in Phase 1 data model, not implemented).

**PKI / internal CA**

- `rcgen`-based intermediate CA per workspace. CA private key stored as a DEK-wrapped secret row — same KMS wrapping path as any other secret.
- Leaf certificate issuance, CRL generation, ACME endpoint.
- `certificate_authorities` table shape reserved in Phase 1 schema without implementation.

**Transit Encryption-as-a-Service**

- `/v1/transit/*` routes: encrypt, decrypt, sign, verify, rewrap.
- No new key management code — the Phase 1 `KmsBackend` abstraction and envelope encryption plumbing are the entire backend. The external API surface is additive.

**Additional KMS backends**

- GCP Cloud KMS: `KmsBackend` trait implementation using `google-cloud-kms`.
- Azure Key Vault: `KmsBackend` trait implementation using `azure_security_keyvault`.
- SPIFFE/SPIRE workload identity: for on-prem, bare-metal, and multi-cloud enterprise scenarios where cloud-native workload identity (IRSA / GKE WI / Azure WI) is unavailable.

**SDK and tooling**

- TypeScript SDK and Python SDK. (Phase 1 non-Rust consumers use `soma run --` or the REST API directly; adding language bindings before the API contract is stable wastes effort.)
- Go SDK and .NET `IConfigurationProvider` adapter.
- JSON Schema codegen: `schemars`-derived Rust/TypeScript struct generation from stored `schema_json` (CLI tool, additive over Phase 1 typed config).

**Enterprise governance**

- Approval / change-request workflow: `proposals` table (pending → approved → rejected → merged), reviewer assignment, merge-triggers-audit. Phase 1 `reason` field is the governance surface; the state machine is Phase 2.
- External SIEM audit log streaming: Datadog, Splunk, S3, custom webhook. Async batch delivery layered over the Phase 1 append-only audit table.
- Cedar policy-as-code engine replacing Phase 1 path-glob RBAC. Phase 1 `policies` table stores policy strings to accommodate Cedar without a migration.
- Per-project customer-managed KMS keys (BYOK/CMEK). `KmsBackend` trait supports it from Phase 1; Phase 2 adds the workspace-scoped key registry and rotation.
- SCIM provisioning integration with soma-iam.
- Gradual config rollout: deployment-strategy objects (linear, exponential) with alarm-triggered rollback hooks. Phase 1 config changes are atomic; strategy objects are additive.
- Kubernetes mutating admission webhook / sidecar injector (opt-in, requires HA webhook server — lower operational risk to defer than to ship at Phase 1 when the CRD operator covers the same use case).
- Secrets Store CSI Driver provider.

---

## Phase 3 — Enterprise and Multi-region

**Theme:** Active-active multi-region, compliance certifications, SSH certificate management, and advanced observability. Phase 3 is driven by enterprise customer requirements, not speculative roadmap.

**Gate:** Start when the first enterprise customer requires FedRAMP or multi-region active-active replication, or when Phase 2 dynamic secrets have been in production for 6 or more months without major incidents.

### Feature candidates

- Multi-region active-active replication. Postgres streaming replication covers Phase 1 and Phase 2 HA. Active-active write distribution requires distributed consensus; the exact topology (CockroachDB-compatible schema? Postgres with a consensus extension? custom conflict resolution?) is deferred until a concrete customer drives the requirement.
- SSH certificate management: short-lived SSH certs replacing shared keys, centrally audited against the existing audit log chain.
- SOC 2 Type II certification: audit trail + evidence package tooling built on the Phase 1 HMAC-chained log.
- FIPS 140-3 compliant build: `aws-lc-fips-sys` feature flag. The Phase 1 TLS stack (`rustls` + `aws-lc-rs`) is already on the FIPS upgrade path; the build pipeline change is additive.
- FedRAMP and HIPAA compliance posture documentation.
- Honey tokens / canary secrets: a boolean flag on the `secrets` table plus a Slack/webhook alerting trigger on access. Deferred because it is trivially additive once the Phase 1 audit log is stable.
- GraphQL API as an alternative to the REST API for complex multi-resource queries.
- Quota enforcement and noisy-neighbor metering at the Postgres advisory-lock layer. Deferred until concrete scale pressure from multi-tenant managed cloud justifies it.
- White-label / MSP multi-account management layer.

---

## Explicit Non-Goals (all phases)

These are not deferred — they are out of scope:

| Item | Reason |
|---|---|
| Redis as any dependency | Single stateful dependency (Postgres) is a hard constraint through all phases. Postgres LISTEN/NOTIFY covers Phase 1 and Phase 2 fan-out. Redis is the documented upgrade path only if measured to be insufficient. |
| Consul as any dependency | soma-vault is designed around a single Postgres dependency. Adding Consul as a storage or coordination backend would re-introduce the multi-component operational surface that single-binary self-host is designed to avoid. |
| Secret scanning / leak detection in source control | A separate tool category (GitGuardian, Trufflehog). Not a secrets store function. |
| AES-CBC | No authentication. |
| Shamir unseal / manual ceremony | soma-vault pods prove their identity to a KMS; no unseal ceremony is ever needed. This is a foundational design constraint. |
| Schema-per-tenant or database-per-tenant | O(N) migration complexity and contradiction of the single-binary self-host tenet. |
| Per-workspace or per-project DEKs | Blast radius is too large. Per-secret-version DEK (the AWS Secrets Manager model) is the Phase 1 commitment; retrofitting is not possible without re-encrypting all rows. |
| OpenSSL anywhere | Contradicts the memory-safety north star and the `aws-lc-rs` TLS strategy. |

---

## Phase Summary

| Phase | Theme | Key unlock | Gate |
|---|---|---|---|
| **1** | Foundation | All five tenets on day one; `soma run --` in under 10 minutes; stateless HPA pods; envelope encryption; SSE config push | Solo developer onboarding demo passes end-to-end |
| **2** | Scale and Ecosystem | Dynamic secrets, PKI, Transit EaaS, GCP/Azure KMS, TypeScript/Python/Go SDKs, Cedar policies, SIEM streaming | 50 managed-cloud tenants; 3 enterprise prospects requesting dynamic secrets or PKI |
| **3** | Enterprise and Multi-region | Active-active replication, FedRAMP/SOC 2, SSH certs, FIPS 140-3 build | First enterprise customer requiring FedRAMP or multi-region; Phase 2 dynamic secrets stable for 6+ months |

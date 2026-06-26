# soma-vault: Competitive Roadmap

## 1. EXECUTIVE SUMMARY

**Honest current state:** soma-vault is a well-structured Phase-1 MVP with correct cryptographic primitives (per-secret DEK, AES-256-GCM + AES-KW, AAD binding, Zeroizing), a clean EAV schema, and a working CLI. The bones are right. The marketing is not.

**The five biggest gaps:**

1. **The headline differentiator is a lie in code.** "Auto-unseal by workload identity, no shared unseal secret" is the product's sharpest wedge — and it does not exist. `SealProvider::AwsKms/GcpKms/AzureKms` are empty match arms. The only trust anchor is `SOMA_MASTER_KEK_HEX`, a static shared secret. Any operator who reads the code or Helm chart knows this immediately.

2. **Multi-tenancy is structural fiction.** `TenantId::default()` is hardcoded at boot. The storage layer correctly threads `TenantId` everywhere — the hard work is done — but the API never extracts tenant from a request. No tenants table exists. Every row says `tenant_key = 'default'`. A managed-cloud SaaS requires this to be real.

3. **No audit log.** Zero `audit_events` table, zero INSERT calls. Every serious security evaluation starts with "show me the audit log." This is an instant disqualifier for any compliance-conscious buyer (SOC 2, ISO 27001, enterprise procurement). Infisical ships this on day one.

4. **No RBAC.** Any valid token is a root token. Teams cannot use the product because there is no way to give a developer read-only access to staging without also giving them the ability to delete production. This blocks every team evaluation.

5. **The config `$ref` model is inert.** `ValueType::SecretRef` can be stored but is never resolved. The "typed config + `$ref` to secrets" wedge — which is genuinely differentiated — does not work.

**The sharpest winning wedge that is real today:** Per-secret DEK with per-request decrypt and Zeroizing is real and is better than Infisical's workspace-key model. The single binary, low memory footprint, and unified secrets+config are real. The CLI `soma run -- <cmd>` works. These are defensible claims. Everything else is roadmap.

---

## 2. P0 — FIX NOW

These must be correct before building anything else, because building on them wrong means paying twice.

---

### P0-1: Add `tenants` table and migrate `tenant_key` to `tenant_id UUID FK`
**What:** Add a `tenants` migration (UUID PK, `code TEXT UNIQUE`, `soma_iam_org_id UUID UNIQUE`). Expand-contract: add nullable `tenant_id UUID` column to all `fct`/`dtl` tables, backfill `WHERE tenant_key = 'default'`, add NOT NULL constraint, add FK, drop `tenant_key`.

**Why now:** Every fct/dtl table today has `tenant_key VARCHAR(100) DEFAULT 'default'`. Adding a second tenant later requires a migration proportional to row count. The storage layer already accepts `TenantId` — the DB schema just does not match the design. The longer you wait, the more data is in production and the more expensive the migration.

**Effort:** M (three migrations: add table, backfill, drop column)

**Files:** `migrations/01_migrated/1/20260625_01_init-vault-schema.sql` (all 9 tenant-scoped tables), `crates/soma-storage/src/types.rs:10-13`

---

### P0-2: Extract `TenantId` from auth token per-request; remove from `AppState`
**What:** After P0-1 lands, add `tenant_id UUID` to the `auth_tokens` table. In `auth_middleware`, after `find_token_by_plaintext`, insert `TenantId` into `Request::extensions()`. Remove `AppState.tenant`. Every handler extracts from extensions.

**Why now:** `AppState.tenant` is a singleton that every new route added today bakes in as an assumption. The fix is trivial now (one field remove, one extractor) and expensive after 60 routes exist.

**Effort:** S (after P0-1; the storage layer is already correct)

**Files:** `crates/soma-api/src/lib.rs:76`, `crates/soma-server/src/main.rs:191-195`, `crates/soma-api/src/lib.rs:235-247`

---

### P0-3: Add Row-Level Security
**What:** After P0-1/P0-2, add one migration per tenant-scoped table: `ALTER TABLE ... ENABLE ROW LEVEL SECURITY; ALTER TABLE ... FORCE ROW LEVEL SECURITY; CREATE POLICY tenant_isolation ON ... USING (tenant_id = current_setting('app.tenant_id')::uuid);`. Add `TenantTransaction` wrapper that calls `SET LOCAL app.tenant_id = $1` on every write connection.

**Why now:** Currently, one missing `.bind()` in a query is a cross-tenant data leak. With a single tenant this is academic — with two tenants it is a production incident. RLS is the second enforcement layer the architecture doc specifies and must be in place before onboarding any real customer.

**Effort:** M

**Files:** `crates/soma-storage/src/pg/mod.rs` (all query methods), new `TenantTransaction` type

---

### P0-4: Per-tenant KEK derivation via HKDF
**What:** Add `TenantKek` struct. `MasterKek::derive_tenant_kek(tenant_id: Uuid) -> TenantKek` using HKDF-SHA256 (key = master KEK, info = tenant UUID bytes). Update `encrypt`/`decrypt` signatures to accept `TenantKek` not `MasterKek`. For the current single `'default'` tenant, the derived key is deterministic — no re-wrap needed.

**Why now:** Today all DEKs are wrapped under the same master KEK. Adding per-tenant KEKs after production data exists requires re-wrapping every `wrapped_dek` row. Doing it now (when there is one tenant and zero production data) is a one-hour change. Doing it after onboarding ten tenants is a multi-hour background migration with rollback risk.

**Effort:** S

**Files:** `crates/soma-crypto/src/lib.rs:121-140`, `Cargo.toml` (add `hkdf`)

---

### P0-5: Fix the root token security holes
**What (three sub-items, all tiny):**
- **B2:** Remove the verbatim root token from stderr. Print only first 8 chars in the banner. Gate the full token on `KUBERNETES_SERVICE_HOST` absence or `SOMA_PRINT_TOKEN=true` opt-in. The file path is the canonical retrieval method.
- **B1:** Replace `SHA-256(token)` with `HMAC-SHA256(token, SOMA_TOKEN_HMAC_KEY)` to prevent offline preimage checks against a stolen `token_hash` column.
- **H5/H6:** `std::env::remove_var("SOMA_MASTER_KEK_HEX")` immediately after `from_hex_env()`. Wrap the intermediate hex `String` in `Zeroizing<String>`.

**Why now:** These are one-line fixes that close real attack surface. The root token in container logs is the most embarrassing possible incident for a secrets platform.

**Effort:** S (combined)

**Files:** `crates/soma-server/src/main.rs:139-149`, `crates/soma-storage/src/pg/mod.rs:1103`, `crates/soma-server/src/main.rs:174`, `crates/soma-crypto/src/lib.rs:139-141`

---

### P0-6: Fix the B1/B2 storage correctness bugs (upsert + AAD race)
**What:**
- **B1 (upsert on soft-deleted path):** Add `is_deleted = false` to the `DO UPDATE` clause so a PUT to a deleted path correctly revives the row.
- **B2 (stale version in AAD):** Move encryption inside `advance_secret_version` after the `SELECT FOR UPDATE` so `new_version_number` and the AAD version are always the same value.
- **B4 (non-atomic rollback):** Wrap `rollback_secret`/`rollback_config` in a transaction with `SELECT FOR UPDATE` on the header.
- **B3 (cross-tenant env_id):** Add `WHERE tenant_key = $1 AND id = $2` environment existence check before INSERT in `put_secret`/`put_config`.

**Why now:** B2 can produce ciphertext that can never be decrypted — the data is silently destroyed. B3 enables cross-tenant writes. These are correctness/security bugs, not feature gaps.

**Effort:** S

**Files:** `crates/soma-storage/src/pg/mod.rs:449-472, 628-704, 744-760`

---

### P0-7: Correct the misleading auto-unseal claim in deploy artifacts
**What:** Change `deploy/helm/templates/deployment.yaml` comment (line 26-27) from "stateless pods; auto-unseals via KMS workload identity" to "Phase 1: software KEK from SOMA_MASTER_KEK_HEX. KMS auto-unseal is Phase 2." Update README and any marketing copy. This is not a code change — it is an honesty change that must happen before any public launch.

**Why now:** A prospect who reads the Helm chart and discovers this discrepancy loses all trust. Correcting it costs nothing.

**Effort:** XS

---

## 3. P1 — TABLE-STAKES

Ranked by how quickly they end an evaluation.

---

### P1-1: Audit Log (dealbreaker #1)
**What:** Add `audit_events` table (INSERT-only: `id UUID, tenant_id UUID, actor_token_id UUID, action TEXT, resource_type TEXT, resource_id TEXT, environment_id UUID, ip_addr INET, seq_num BIGINT, hmac_chain BYTEA, created_at TIMESTAMPTZ`). Call `INSERT INTO audit_events` from every mutating handler (secret set/delete/rollback, config set/delete/rollback, token create/revoke, project/env create/delete). Add `GET /v1/audit` endpoint with keyset pagination and filters (actor, resource, date range). Add Audit page to dashboard.

**Why:** Every SOC 2 evaluation, every security-conscious buyer, every enterprise procurement starts here. Infisical and Doppler both ship this. Its absence is an instant disqualifier.

**Depends on:** P0-1 (tenant_id in all rows), P0-2 (actor principal in extensions)

**Effort:** M

---

### P1-2: RBAC — Workspace Roles
**What:** Minimal two-level model to unblock team use. Add `role` column to `auth_tokens` (`admin | developer | reader`). Add role-check extractor in `auth_middleware`. Gate: mutating secret/config routes require `developer+`, management routes (token create, project/env create/delete, attr-def mutations) require `admin`. Add role display + assignment to Access page in dashboard.

**Why:** Any token is a root token today. A team cannot use the product. This is the single most common reason a team evaluation stops.

**Depends on:** P0-1/P0-2

**Effort:** M

---

### P1-3: AWS KMS Auto-Unseal (one real backend)
**What:** Implement `SealProvider::AwsKms` dispatch in `soma-crypto`. Use `aws-sdk-kms` (GenerateDataKey / Decrypt). Wire IRSA path: on startup, call `STS::AssumeRoleWithWebIdentity` using the K8s projected service account token at `AWS_WEB_IDENTITY_TOKEN_FILE`. Add `serviceAccount.create: true` as Helm default with `annotations: {}` for IRSA annotations. Document GCP/Azure as following the same pattern.

**Why:** This is the headline differentiator. Without one real KMS backend, the "no shared unseal secret" claim is false and the auto-unseal SA story in the Helm chart is fiction. Shipping one backend makes the architecture story true.

**Depends on:** P0-4 (per-tenant KEK derivation, so the KMS-wrapped key is the master KEK input to HKDF)

**Effort:** L

---

### P1-4: Resolve `SecretRef` in config GET
**What:** Add `resolve_refs=true` query param to `GET /v1/projects/{p}/environments/{e}/config/{key}` and the export endpoint. When set, follow `SecretRef` values: look up the referenced secret, decrypt via the envelope, return the plaintext value in the config response (never stored, only in-flight).

**Why:** The "typed config + `$ref` to secrets" wedge is the product's second strongest differentiator. It is fully built in the schema and type system but the resolution is a no-op. One missing JOIN+decrypt call is the gap.

**Effort:** S

---

### P1-5: soma-iam JWT Auth (replace SHA-256 token lookup)
**What:** Add JWT verification path: verify RS256/ES256 against soma-iam JWKS endpoint (`SOMA_IAM_JWKS_URL`). Extract `sub` (principal_id), `tenant_id`, `role` from claims. Cache JWKS with a 5-minute TTL. Keep the existing token-hash path for service accounts and machine tokens. This eliminates the DB lookup per request (F9) for human sessions.

**Why:** This is the bridge to soma-iam for human users and is necessary before any "sign in with your org" story. Without it, every user must manually manage a raw token.

**Depends on:** P0-2 (principal in extensions), soma-iam must expose a JWKS endpoint (define the contract now even if soma-iam is not built — implement against a mock)

**Effort:** M

---

### P1-6: path validation, token expiry default, CSRF hardening
**What (bundled small items):**
- **P4:** Validate `path` param: reject empty string, null bytes, `..` sequences, enforce max 255 chars, at API layer (not DB).
- **H2:** Set `expires_at = now() + interval '24 hours'` on `create_token` by default (override via param). Add expiry to `AuthToken` type (F8).
- **B5 (CSRF):** Add Double Submit Cookie pattern (`soma_csrf_token`) checked on all state-changing routes when cookie auth is active.
- **B7 (version tenant guard):** Add `AND tenant_id = $N` to `list_secret_versions` and `list_config_versions`.
- **H4 (attr-def gate):** Add admin role check to `create/update/delete_attr_def` routes (requires P1-2).

**Effort:** S (combined)

---

### P1-7: Kubernetes Operator + Helm hardening
**What:**
- **BP-3:** Implement `/health/startup` endpoint; add `startupProbe` with 90s window to Helm chart.
- **BP-2:** Add `ON CONFLICT (tenant_id, name) DO NOTHING` to `create_token_with_value` (fixes dual-pod race on cold start).
- **BP-4:** Embed migrations at compile time via `sqlx::migrate!()` macro; remove the fragile `CARGO_MANIFEST_DIR/../..` path.
- **BP-1:** Build and copy `soma-cli` binary in Dockerfile; document `soma keygen` via `docker run --entrypoint soma-cli`.
- **BP-5/H-5:** Default `serviceAccount.create: true` in Helm values; wire annotations for IRSA/GKE/Azure.
- **OA-2:** Add `helm package` + `helm push` to release workflow; bump `appVersion` from git tag.
- **OA-3:** Add `linux/arm64` to Docker build platforms.
- **H-5 (Helm secret):** Promote `existingSecret` as the default production path in NOTES.txt; document External Secrets Operator.

**Effort:** M

---

### P1-8: Structured error shape + request tracing
**What:** Standardize all error responses to `{"error": {"code": "...", "message": "...", "request_id": "...", "details": {}}}`. Set `X-Request-ID` on every response (generate if absent). Add `tower_http::trace::TraceLayer`. Add `Retry-After` header to 429 responses.

**Why:** Every SDK, every integration, every support ticket depends on parseable errors with traceable IDs. The current `{"error": "string"}` shape makes programmatic error handling impossible.

**Effort:** S

---

## 4. P2 — DIFFERENTIATION

Build these after the foundation is solid. These are the "why switch" wedges.

---

### P2-1: AWS KMS auto-unseal → full workload identity story
Extend the AWS KMS backend from P1-3 to the full story: GCP Workload Identity + GKE, Azure Workload Identity. Add `kms_key_version` column to `06_fct_secret_versions` for rotation tracking. Implement `rewrap_dek` sweep (background task). Document SPIFFE-SPIRE for self-host-without-cloud. This makes the "no shared unseal secret, ever" claim unconditionally true.

**Effort:** L per cloud provider

---

### P2-2: SSE live config push + in-process cache (the SDK moat)
**What:** Build `soma-sdk` Rust crate. `SomaClient::new(url, token)` subscribes to `GET /v1/projects/{p}/environments/{e}/config/stream` (SSE). Stores values in a `DashMap` (in-process cache). All reads are sub-microsecond local cache hits; SSE push invalidates on mutation. Add SSE endpoint to soma-api. TypeScript and Python SDKs follow the same pattern.

**Why:** This is the capability that makes "zero-latency config reads without polling" real. No competitor does per-process in-memory cache with server-push invalidation as a first-class SDK primitive. This is the moat.

**Effort:** L (server SSE endpoint: S; Rust SDK: M; TS/Python: M each)

---

### P2-3: `soma run --replace-env` and stdin-safe secret set
**What:**
- Fix F1 (signal propagation): use `CommandExt::exec()` on Unix.
- Add F2 (`--replace-env`): clear parent env before injection (keep PATH/HOME/TERM).
- Fix F12 (secret in shell history): accept value from stdin if positional arg absent; add `--value-from-file`.
- Add F4 (`--reveal` flag on `secrets get`): mask on TTY, raw when piped.

**Why:** The "kill the .env file" story is soma-vault's most visceral DX hook. These gaps directly undercut it. `soma run -- python train.py` not propagating SIGTERM is a data corruption risk in ML workloads.

**Effort:** S

---

### P2-4: Anti-AI-agent-leak positioning
**What:** Add `SOMA_REDACT_IN_LOGS=true` env var that installs a tracing `Layer` rewriting known secret patterns to `[REDACTED]` in structured logs. Add a `POST /v1/scan` endpoint that accepts a text blob and returns positions of any string that matches a stored secret value (for CI secret scanning). Document both in the "AI-agent safety" framing.

**Why:** The AI-agent angle is nascent but real — no competitor has explicitly built for "don't let your LLM coding assistant see your secrets." This is a wedge that costs little to build and has high PR value.

**Effort:** M

---

### P2-5: Secret rotation primitives
**What:** Add `rotation_jobs` table. Add `POST /v1/projects/{p}/environments/{e}/secrets/{path}/rotate` endpoint that: calls a registered webhook with the old value, accepts a new value back, calls `put_secret`, logs to audit. Initial targets: database passwords (Postgres, MySQL), API keys (static). Do not try to implement dynamic secrets (Vault-style database plugin) in Phase 2 — that is P3.

**Effort:** L

---

### P2-6: Environment inheritance
**What:** Add `parent_env_id UUID REFERENCES 04_fct_environments(id)` column. Add recursive CTE query in `get_secret`/`get_config`: look up the requested environment, then walk up the parent chain until a value is found. This enables `production → staging → development` inheritance without duplicating values.

**Effort:** M

---

## 5. DASHBOARD OVERHAUL

Prioritized from the design audit findings. The UI is functional but reads as a developer debug screen, not a product.

### Broken/confusing now (fix before any demo)

**D1 — Navigation is a tree drill-down, not context selection (B1)**
Add project + environment `<Select>` dropdowns to the sidebar. All content pages operate within the selected context signal. Every context switch should be one click in the sidebar, not three back-navigations.

**D2 — DataTable sort + action button list are detached (B10)**
The attributes page renders `DataTable` with sortable columns, then a separate `<For>` loop below it for edit/delete buttons. Sort order in the table does not match action button order — clicking delete on row N deletes the wrong attribute. Fix: embed action buttons inside `DataTable` rows.

**D3 — `project_detail.rs` fetches page 1 of all projects to get one name (B8)**
Any user with more than one page of projects sees a blank project header on the detail page. Add `GET /v1/projects/:id` endpoint (one line in the router) and use it.

**D4 — Reveal writes plaintext `<span>`, no copy button, no countdown, eye icon static (B3/B5)**
Replace `<span>` with a `readonly` `<Input>`. Add clipboard copy button. Add 30-second countdown timer that re-masks. Toggle eye-off icon on reveal. Remove the "Value" column from the secrets list table entirely — reveal belongs on the detail page only.

**D5 — Secrets `set` value is a positional CLI arg visible in `ps aux` / shell history (F12)**
This is a CLI fix but surfaces in every dashboard "how do I set a secret" doc: fix the CLI first so documentation does not teach an insecure pattern.

### Missing screens (dealbreakers for any evaluation)

**D6 — No Access Management page (M3)**
Add `/access` route. Show service accounts (tokens) with scope/expiry, and (future) member list. Allow token creation with role selection. This is the first screen a team lead opens.

**D7 — No Audit Log page (M2)**
Add `/audit` route. Filterable `DataTable` over `GET /v1/audit` (from P1-1). Columns: timestamp, actor, action, resource, environment, IP. This depends on P1-1 existing server-side.

**D8 — No home/overview screen**
After login, land on a dashboard home with: active projects count, recent activity feed (from audit log), health status widget. Currently lands on the projects list which has zero context for a new user.

### Polish (do before any public launch)

**D9 — Breadcrumbs everywhere, kill hardcoded "soma-vault" header (B2)**
Replace the hardcoded header label with a `<Breadcrumb>` component fed by route params.

**D10 — Relative timestamps (P3)**
Format all ISO-8601 timestamps to "3 days ago" with the raw string in a `title` tooltip. Implement once in `api.rs`.

**D11 — Pagination "Load more" (B6)**
Wire `page.next_cursor` into a "Load more" button on projects, secrets, and config list pages.

**D12 — Login page needs a wordmark (B7)**
Add product logo/wordmark above the login card. The current UI reads as a debug endpoint, not a product sign-in.

**D13 — Config detail page needs an edit form (M7)**
Add an "Edit" panel to `ConfigDetailPage` that pre-populates from the latest version value.

**D14 — Secret detail page needs current-value reveal + update form (M8)**
Add a header section with readonly `Input` + copy button for the current value, and an update-value form.

---

## 6. RECOMMENDED BUILD ORDER

The sequencing law: **foundation → correctness → credentials to sell → differentiation**. Violating this means rebuilding.

### Milestone 0: Secure the foundation (do now, before any user touches it)
1. P0-5 (root token leaks + HMAC pepper + KEK zeroize) — XS, immediate
2. P0-7 (remove false auto-unseal claim from Helm) — XS, immediate
3. P0-6 (upsert + AAD race + rollback TOCTOU + cross-tenant env) — S, immediate
4. P0-4 (per-tenant HKDF KEK derivation) — S, this week
5. P0-1 + P0-2 (tenants table + per-request TenantId) — M, this sprint

*Gate: `cargo test --workspace` green. No token in stderr. No false claims in Helm.*

### Milestone 1: Multi-tenant foundation + security skeleton
1. P0-3 (RLS migrations) — depends on P0-1
2. P1-6 (path validation + token expiry + CSRF + version tenant guard) — S, bundle
3. P1-2 (RBAC workspace roles) — M, depends on P0-2
4. P1-8 (structured errors + request IDs) — S

*Gate: Two isolated tenants can coexist. Role-restricted tokens work. Errors are parseable.*

### Milestone 2: Table-stakes for evaluation
1. P1-1 (audit log — table + API + dashboard page D7) — depends on M1
2. P1-7 (Kubernetes hardening bundle) — parallel to M1
3. D6 (Access Management dashboard page) — depends on P1-2
4. D1-D5 (dashboard broken-now fixes) — parallel
5. P1-4 (resolve SecretRef in config GET) — S, any time after M1
6. CLI fixes: P2-3 (exec, --replace-env, reveal, stdin) — S, any time

*Gate: An evaluator can: create scoped tokens, read the audit log, deploy to Kubernetes with a startup probe, use `soma run` safely.*

### Milestone 3: Authentication + real KMS (required for production claim)
1. P1-5 (soma-iam JWT auth) — define JWKS contract with soma-iam now; implement against mock
2. P1-3 (AWS KMS auto-unseal, one backend) — depends on P0-4
3. BP-5 (Helm serviceAccount default true + IRSA annotations)

*Gate: A pod can start with zero shared secrets. Human users can log in via soma-iam. The headline differentiator is true.*

### Milestone 4: SDK + SSE (the moat)
1. P2-2 (SSE endpoint + soma-sdk Rust crate)
2. TypeScript SDK
3. Python SDK

*Do NOT start this until Milestone 2 is solid. An SDK that ships to an insecure server is a liability.*

### Milestone 5: Differentiation
1. P2-1 (GCP/Azure KMS backends + rewrap sweep)
2. P2-4 (anti-AI-agent-leak: log redaction + scan endpoint)
3. P2-5 (secret rotation primitives)
4. P2-6 (environment inheritance)

### Dependency graph summary
```
P0-1 (tenants table)
  └─ P0-2 (per-request TenantId)
       ├─ P0-3 (RLS)
       ├─ P1-1 (audit log)  ← D7 (audit dashboard)
       └─ P1-2 (RBAC)       ← D6 (access dashboard)
P0-4 (HKDF per-tenant KEK)
  └─ P1-3 (AWS KMS)
P1-8 (structured errors)
  └─ P1-5 (JWT auth)
P1-1 (audit log)
  └─ P2-2 (SSE/SDK) [need stable API contract first]
```

**Do this before that or pay double:**
- Add per-tenant HKDF (P0-4) before any second tenant — re-wrapping all DEKs costs O(secrets)
- RLS (P0-3) before any customer data — retrofitting is a downtime migration
- Audit log (P1-1) before RBAC (P1-2) — RBAC audit events need the table to exist
- Structured errors (P1-8) before SDKs — SDKs are impossible to build against `{"error": "string"}`
- JWT auth (P1-5) before public launch — shipping with raw SHA-256 token auth as the only path is a sales objection

---

## 7. QUICK WINS

Do these this week. Each is under a half-day and has outsized impact.

| # | What | Why | File | Effort |
|---|---|---|---|---|
| QW-1 | Remove full root token from stderr; print 8-char fingerprint only; remove from K8s pod logs | Most embarrassing possible incident for a secrets manager | `soma-server/src/main.rs:139-149` | 30 min |
| QW-2 | `std::env::remove_var("SOMA_MASTER_KEK_HEX")` after loading | KEK in process env is readable via `/proc/self/environ` on Linux | `soma-server/src/main.rs:174` | 5 min |
| QW-3 | Fix the Helm comment: "auto-unseals via KMS" → "Phase 1: software KEK; KMS auto-unseal is Phase 2" | One line; prevents trust loss from any technical reader | `deploy/helm/templates/deployment.yaml:26-27` | 5 min |
| QW-4 | Add `ON CONFLICT (tenant_id, name) DO NOTHING` to `create_token_with_value` | Dual-pod cold start creates two root tokens today | `soma-storage/src/pg/mod.rs:1212` | 15 min |
| QW-5 | Move encryption inside `advance_secret_version` after `SELECT FOR UPDATE` | AAD race can permanently corrupt a secret — data loss bug | `soma-storage/src/pg/mod.rs:467-472`, `pg/ledger.rs:52-76` | 1 hour |
| QW-6 | Add `AND tenant_id = $N` to `list_secret_versions` and `list_config_versions` | Defense-in-depth gap; trivial to add | `soma-storage/src/pg/mod.rs:628-638, 882-891` | 20 min |
| QW-7 | Add `B3 (cross-tenant env_id check)`: `WHERE tenant_key = $1 AND id = $2` before INSERT | Cross-tenant write is possible today | `soma-storage/src/pg/mod.rs:449-464, 744-760` | 30 min |
| QW-8 | Per-tenant HKDF KEK derivation | Free to add now with one tenant; O(all secrets) cost later | `soma-crypto/src/lib.rs:121-140` | 2 hours |
| QW-9 | Fix `.soma.toml` directory walk (F3) | Every monorepo user hits this immediately; breaks the primary DX flow | `soma-cli/src/main.rs:286` | 1 hour |
| QW-10 | `soma secrets get` — mask on TTY, `--reveal` flag (F4) | Printing plaintext secrets to a terminal is a compliance violation | `soma-cli/src/main.rs:743-744` | 1 hour |
| QW-11 | Fix `secrets set` positional value — accept from stdin if absent (F12) | Secret visible in `ps aux` and shell history; kills the "safe secrets" story | `soma-cli/src/main.rs:170-177` | 1 hour |
| QW-12 | `startupProbe` in Helm + `/health/startup` endpoint | Pods killed during migration on cold DB; breaks every first deploy | `soma-api/src/lib.rs` (add route), `deploy/helm/templates/deployment.yaml` | 1 hour |
| QW-13 | Wrap rollback in a transaction with `SELECT FOR UPDATE` (B4) | TOCTOU: concurrent delete between SELECT and UPDATE leaves a dangling pointer | `soma-storage/src/pg/mod.rs:660-704` | 30 min |
| QW-14 | `soma-cli` binary built and copied in Dockerfile | `soma keygen` is broken for anyone using the Docker image | `deploy/Dockerfile:118,131` | 15 min |
| QW-15 | Remove `#[allow(dead_code)]` on `project_id`, validate it against the env's project | Route hierarchy allows cross-project access via mismatched IDs | `soma-api/src/lib.rs:513-517` | 30 min |
# Phase 1 MVP — Build Specification & Decision Log

**Status:** locked, pre-code. This is the source of truth for the Phase 1 build. It captures every decision made so far (see the Decision Log in §9). The HTML blueprint (`docs/mvp-spec.html`) is a rendering of this document.

**What we're building:** the smallest version of soma-vault that lets you stop juggling `.env` files and env vars across your own apps — encrypted secrets + typed config, managed centrally, consumed by any app with zero code changes. Built to the in-house db-standards (star schema + three-layer EAV). Open-core, AGPLv3 later.

---

## 1. Scope (lean MVP)

**IN (Phase 1):**
- One Postgres database, one schema (`01_vault`).
- Hierarchy: `project → environment → { secret | config }`.
- **Single default tenant** (`tenant_key = 'default'`) — column present on every table so multi-tenant is a later config flip, not a rewrite.
- **One bootstrapped bearer token** for auth (printed once on first boot).
- **Encrypted secrets** with a version ledger (envelope encryption).
- **Typed config** with a version ledger.
- **Three-layer EAV** on secrets + config, driven by a **shared, UI-manageable attribute registry** (add a field with a seed row, no migration).
- **Reusable migration + seed runner** (forward/backward raw SQL; easy setup — §4).
- **CLI consumption:** `soma run -- <cmd>` (env injection) and `soma export` (`.env`/json).

**DEFERRED (later phases, all additive — no rewrite):**
- Audit log (`aud_` table + optional HMAC chain).
- EAV on projects/environments.
- Multi-tenant auth, soma-iam JWT, sessions/JTI, RBAC policies.
- Cloud KMS (AWS/GCP/Azure) + secret rotation — the `seal_provider` column makes this a non-breaking re-wrap.
- Config `$ref` → secret; environment config inheritance.
- Leptos dashboard (Phase 2; uses the `soma-ui` component library).
- SurrealDB / MongoDB / SQLite `DataStore` implementations.
- Distribution / release pipeline (multi-platform binaries, CI).

---

## 2. Architecture

**One Rust binary.** Not a separate backend + frontend.

```
                         ┌──────────────────────────────┐
   CLI  ── HTTP ───────► │        soma-server (axum)     │
   SDK  ── HTTP ───────► │  REST API  +  static dashboard│ ──► PostgreSQL
   Dashboard (WASM) ───► │  master KEK held in RAM only  │     (schema "01_vault")
   (Phase 2)             └──────────────────────────────┘
```

- **Dashboard = Leptos CSR (WASM)** served as static assets by axum — **not SSR**. The server process holds the master KEK in memory; SSR server-functions would execute in that same memory, turning a UI bug into a key-leak path. CSR WASM holds zero key material, talks to the same-origin REST API, session in an `httpOnly` / `Secure` / `SameSite=Strict` cookie.
- **Storage behind a datastore-agnostic `DataStore` trait** — domain operations (not SQL), a `TenantId` on every method, `cursor + limit` on every list. PostgreSQL implementation now; SurrealDB / MongoDB are real later targets (the EAV registry and secret ledger map to documents; the trait is also the unit-test seam via a mock). Kept **thin**: Phase 1 wires the concrete `PgDataStore` directly.

**Crates:**
| Crate | Responsibility |
|-------|----------------|
| `soma-crypto` | Envelope encryption: DEK, AES-256-GCM, key wrap, AAD, zeroization. No DB, no HTTP. |
| `soma-migrate` | Reusable forward/backward SQL migration + seed runner (§4). On sqlx primitives. |
| `soma-storage` | `DataStore` trait + `PgDataStore` (sqlx). Owns all SQL. Calls `soma-migrate` for `migrate()`. |
| `soma-api` | axum router, bearer-auth middleware, handlers. |
| `soma-cli` | the `soma` binary (`run`, `export`, CRUD, `migrate`, `keygen`, `login`). |
| `soma-server` | entry binary: wires `PgDataStore`, migrates on boot, bootstraps the root token, serves. |
| `soma-dashboard` | Leptos CSR WASM (Phase 2). |

---

## 3. Data Model

**Single schema `"01_vault"`** (db-standards forbids cross-schema FKs, and the EAV whitelist + hierarchy need real FKs — so one domain schema keeps every FK intra-schema). Star schema + three-layer EAV. No RLS, no ENUM (VARCHAR + CHECK), `pgcrypto` only, UUID PKs (`gen_random_uuid()`), `tenant_key VARCHAR(100)` on every fact table, explicit constraint names, soft-delete triplet + bidirectional CHECK, `COMMENT ON` everything, PII tags.

**11 application tables** (NN_ prefix = dependency order):

```
01_dim_entity_types ──┐ (whitelist of manageable entity types: secret, config_key)
                      ▼
02_dim_attr_defs ─────────────────────────┐  (the UI-manageable attribute registry:
   (entity_type, code) UNIQUE              │   data_type, is_required, is_pii, sort_order)
                                           │  composite-FK whitelist target ▼
03_fct_projects                            │
   └─ 04_fct_environments                  │
        ├─ 05_fct_secrets ── 06_fct_secret_versions   (crypto ledger: ciphertext/nonce/
        │     └─ 09_dtl_secret_attrs ──────┤            wrapped_dek/aad/seal_provider — BYTEA)
        └─ 07_fct_config_keys ── 08_fct_config_versions (typed value ledger: value TEXT)
              └─ 10_dtl_config_attrs ──────┘
11_fct_auth_tokens   (standalone — bearer tokens)
```

| # | Table | Type | Holds |
|---|-------|------|-------|
| 01 | `dim_entity_types` | dim | Which entities have UI-manageable attributes (`secret`, `config_key`). |
| 02 | `dim_attr_defs` | dim | Attribute registry: `(entity_type, code)`, `data_type`, `is_required`, `is_pii`, `sort_order`. **Add a field = a row here, no migration.** |
| 03 | `fct_projects` | fact | Project (top of hierarchy). |
| 04 | `fct_environments` | fact | Environment within a project (`prod`, `dev`, …). |
| 05 | `fct_secrets` | fact | Secret metadata + `current_version` pointer, `cas_required`, `max_versions`. |
| 06 | `fct_secret_versions` | fact | **Crypto ledger.** `ciphertext`/`nonce`/`wrapped_dek`/`aad` (BYTEA), `seal_provider`, `seal_key_id`, `version`. Structural, never EAV. |
| 07 | `fct_config_keys` | fact | Config key metadata: `value_type`, `current_version` pointer. |
| 08 | `fct_config_versions` | fact | Typed config value ledger: `value TEXT` (coerced per `value_type`), `version`. |
| 09 | `dtl_secret_attrs` | dtl (EAV) | Secret attributes (description, tags, owner) — `property_key`/`property_value` TEXT, composite-FK whitelist. |
| 10 | `dtl_config_attrs` | dtl (EAV) | Config-key attributes — same shape. |
| 11 | `fct_auth_tokens` | fact | Bearer tokens (SHA-256 hash, `last_used_at`). |

**Fact-column vs EAV (DB-801):** identity/keys, FKs, state flags, `value_type`, `current_version`, and all crypto BYTEA columns are **structural fact columns**. Descriptive/extensible attributes (description, tags, owner, notes) are **EAV** in the `dtl_` tables, whitelisted by the registry. Secret ciphertext is the payload, never EAV.

Plus one infra table: `00_schema_migration` (migration tracking — §4).

---

## 4. Migrations & Seeding — easy setup (Prisma / Yoyo / Peewee-Migrate style)

**Goal: standing up or updating a vault is one command.** Plain SQL files that move the schema **forward and backward**. The reusable runner is `soma-migrate` (built on sqlx connection/transaction primitives, implementing db-standards DB-9xx/10xx).

**Directory layout (DB-905):**
```
migrations/
  01_migrated/      # deployed, immutable — never edited
    20260624_01_init-vault-schema.sql
    20260624_02_create-views.sql
    20260624_03_seed-attribute-registry.sql
  02_inprogress/    # editable until promoted to 01_migrated/
    20260701_01_add-something.sql
```
File naming `YYYYMMDD_NN_kebab-description.sql`; seed files include `seed`, backfills include `backfill`.

**Forward (`migrate up`) — like Yoyo apply / Prisma deploy:**
- Acquire `pg_advisory_lock(918273645)` for the whole run (released in a Drop guard — survives panics) so two pods never migrate at once.
- Discover files from `01_migrated/` then `02_inprogress/`, ordered by filename.
- For each **unapplied** file: run it inside **one transaction**, record `(name, checksum)` in `00_schema_migration` only on success, **halt on error** (never the autocommit-and-continue antipattern).
- Refuse to run if an already-applied file's checksum changed (immutability — protects existing databases).

**Backward (`migrate down`) — like Yoyo rollback:**
- Each file may carry a `-- DOWN ==` marker; everything after it is the rollback. `migrate up` strips it before applying; `migrate down` runs it (newest applied first) inside a transaction and removes the tracking row.

**Seeding (DB-1001/1002/1004) — idempotent, re-runnable:**
- Seed files use `INSERT … ON CONFLICT DO NOTHING` with deterministic sentinel UUIDs (`00000000-…-0000000000NN`), so re-running never duplicates or breaks.
- Phase-1 seeds: `dim_entity_types` (`secret`, `config_key`); `dim_attr_defs` (secret → description/tags/owner_team; config_key → description); the bootstrap root token (from `SOMA_ROOT_TOKEN` or generated, printed once).
- Dimension rows are seed data, not application writes.

**Views** are created/updated with `CREATE OR REPLACE VIEW` in migrations (idempotent, DB-908).

**Tracking table:**
```sql
CREATE TABLE "01_vault"."00_schema_migration" (
    id         INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name       VARCHAR(255) NOT NULL UNIQUE,
    applied_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    checksum   TEXT         NOT NULL
);
```

**Easy setup in practice:**
- Fresh vault: `docker compose up -d` (Postgres) → run `soma-server` → it migrates + seeds on boot and prints the root token. Done.
- Manual control: `soma migrate up` / `soma migrate down` / `soma migrate status`.
- This runner **is** the Postgres `DataStore::migrate()` and is reusable across the project.

---

## 5. Crypto & Seal

- **Envelope encryption.** Per-secret-version DEK (32 bytes from `OsRng`) → AES-256-GCM encrypts the plaintext. The DEK is wrapped (RFC 3394 / AES-GCM) under the **master KEK**.
- **Master KEK (software-KMS fallback):** read from `SOMA_MASTER_KEK_HEX` (64 hex) at boot into a `Zeroizing<[u8;32]>`; lives in pod RAM only. Plaintext keys exist only for the active request, then zeroized.
- **AAD = `secret_id` (UUID) + `version`** — immutable IDs, never display names, so a future rename can never silently break decryption. Full AAD bytes stored on the version row.
- **`seal_provider`** (`software` | `aws_kms` | `gcp_kms` | `azure_kms`) + `seal_key_id` on each version row → adopting a cloud KMS later is a background re-wrap sweep, not a breaking migration.
- A Postgres dump is useless without the master KEK.

---

## 6. REST API

Base `/v1`, `Authorization: Bearer <token>` on everything except `/health`. JSON. Single-tenant (no tenant in the path). Errors: `{"error":"..."}` with proper status; never leak raw Postgres text.

```
GET    /health                                              → {status, seal_backend}
POST   /v1/auth/tokens            {name}                    → mint (plaintext once)
GET    /v1/auth/tokens                                      → list (no hashes)
DELETE /v1/auth/tokens/{id}

GET    /v1/projects                                         POST /v1/projects {code, attrs?}
GET    /v1/projects/{p}/environments                        POST … {code, attrs?}

GET    /v1/projects/{p}/environments/{e}/secrets            (list, no values)
PUT    …/secrets/{path}           {value, attrs?}           (encrypt → new version)
GET    …/secrets/{path}[?version=N]                         (decrypt)
GET    …/secrets/{path}/versions
POST   …/secrets/{path}/rollback  {version}                 DELETE …/secrets/{path}

GET    …/config                                             PUT …/config/{key} {value, type, attrs?}
GET    …/config/{key}                                       GET …/config/{key}/versions
POST   …/config/{key}/rollback    {version}                 DELETE …/config/{key}

GET    …/export                                             → {"values":{name:value}}  (decrypted secrets + config merged)
GET    /v1/meta/entity-types                                GET /v1/meta/attr-defs?entity_type=secret
POST   /v1/meta/attr-defs         {entity_type, code, name, data_type, is_required, is_pii}
PATCH  /v1/meta/attr-defs/{id}                              DELETE /v1/meta/attr-defs/{id}
```

- `export` **isolates per-secret decrypt errors** (a bad secret names itself, the batch still returns the rest) and **logs a loud warning on a secret-vs-config name collision** (secret wins).
- Version writes (`PUT` secret/config) are **one transaction**: insert the new version + move `current_version`. Rollback moves the pointer only, never deletes versions.

---

## 7. Consumption (CLI)

- `soma run <project> <env> -- <cmd>` — fetches `export`, maps names to env vars (`database/password` → `DATABASE_PASSWORD`), injects them, runs the command. **Apps need zero code changes.**
- `soma export <project> <env> --format dotenv|env|json [-o file]`.
- `soma secrets|config set/get/list/rm`, `soma projects|envs create/list`, `soma login`, `soma keygen`, `soma migrate up|down|status`.

---

## 8. Testing bar (full db-standards coverage)

- `soma-crypto`: round-trip, wrong-AAD fails, tampered-ciphertext fails (unit, no DB).
- Storage (integration): version increment + pointer move; rollback; config type-validation reject; **EAV 4-case** (valid key / invalid key → FK error / upsert idempotent / reverse lookup); cursor+limit pagination; **cross-tenant isolation** (seed two `tenant_key`s, assert one can't see the other); `migrate()` idempotency (run twice).
- Constraints: each CHECK / FK / UNIQUE actually fires (nonce length, `version > 0`, destroy ⇒ deleted, EAV whitelist FK, partial-unique).
- API: 401 without token; happy CRUD; 400 on bad type; `export` merge (secret wins).

---

## 9. Decision Log

| ID | Decision | Rationale |
|----|----------|-----------|
| — | Lean MVP, personal-use first, AGPLv3 later | Stop juggling `.env`/env vars; smallest credible vault. |
| — | PostgreSQL; `project → environment` hierarchy; CLI consumption (SDK later) | Matches usage; SDK is additive. |
| — | Single schema `01_vault` (not 6) | db-standards forbids cross-schema FKs; EAV whitelist + hierarchy need real FKs. |
| — | Star schema + three-layer EAV | The mandated db-standards architecture. |
| — | No `mco-db` framing anywhere | Owner's call: wrong / non-viable. Portability story = plain Postgres + `DataStore` trait. |
| D2 | Trim further: no audit table, EAV only on secrets + config | Smallest surface; audit + project/env EAV are additive later. |
| D3 | Shared attribute registry (`dim_entity_types` + `dim_attr_defs`) | "Manage every dimension of every entity in one UI; add entities without migration." |
| D4 | Versioned config (mirror the secret ledger) | History + rollback; nearly free since the secret ledger already exists; serves the "config changes" worry. |
| D5 | Full db-standards test coverage | "Well-tested is non-negotiable"; DB-1401/1404; cheap with CC. |
| T1 | Add `seal_provider` + `seal_key_id` now | Cloud-KMS adoption becomes a non-breaking re-wrap, not a data migration. |
| T2 | AAD from immutable IDs (`secret_id` + `version`), not names | Removes a silent data-loss class (rename never bricks decryption). |
| — | DataStore trait kept, thin (Phase 1 wires concrete `PgDataStore`) | Multi-engine seam + test seam, without premature lowest-common-denominator. |
| — | One binary, Leptos CSR (not SSR), axum static-serve | Server holds the KEK; CSR keeps key material out of the UI process. |
| D6 | Custom db-standards migration/seed runner (`soma-migrate`) on sqlx primitives | Owner wants the migrated/inprogress + forward/backward workflow (Prisma/Yoyo/Peewee-Migrate style); don't reinvent the dangerous txn/locking bits. |

---

## 10. Build order & tasks

```
Lane A: soma-crypto                       ─┐
Lane B: soma-migrate → migrations/0001    ─┼─►  soma-api ─┐
        → soma-storage (DataStore+PG)      │   soma-cli ──┴─► soma-server
                                          ─┘
```

- [ ] **T1 (P1)** `soma-crypto` — envelope encryption; AAD = `secret_id‖version`; KEK from `SOMA_MASTER_KEK_HEX`. Tests: round-trip, wrong-AAD, tamper.
- [ ] **T2 (P1)** `soma-migrate` — reusable forward/backward runner (advisory lock, per-file txn, halt-on-error, checksum-immutability, DOWN, idempotent seeds, migrated/inprogress dirs).
- [ ] **T3 (P1)** `migrations/01_migrated/0001…` — the 11-table `01_vault` schema + `00_schema_migration` + seeds (registry, root token). Tests: migrate idempotency.
- [ ] **T4 (P1)** `soma-storage` — `DataStore` trait + `PgDataStore`; version-write txns; generic EAV `attrs_get/set`; error mapping. Full integration test suite.
- [ ] **T5 (P1)** `soma-api` — axum router + bearer middleware + handlers; type validation; export isolation + collision warning.
- [ ] **T6 (P1)** `soma-cli` — `run`/`export`/CRUD/`migrate`/`keygen`/`login`; URL-encoded segments; env-var mapping.
- [ ] **T7 (P1)** `soma-server` — wire `PgDataStore`, migrate-on-boot, bootstrap token, serve `/health`.
- [ ] **T8 (P2)** regenerate `docs/mvp-spec.html` from this spec.
- [ ] **T9 (P3)** distribution/release pipeline — deferred.

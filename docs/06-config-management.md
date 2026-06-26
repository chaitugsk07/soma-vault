# soma-vault Phase 1: Configuration Management Design

soma-vault stores two structurally distinct tiers of data: **secrets** (encrypted blobs, pull-only, never logged in plaintext) and **config** (typed, schema-validated, plaintext, indexable, delivered in real time). This document covers the typed config tier exclusively — how config values are modeled, validated, inherited across environments, how they reference secrets without ever inlining secret plaintext, and how changes propagate to SDK consumers in under one second. It also records what config features are explicitly deferred and why.

---

## 1. Why Config and Secrets Are Separate Tiers

The separation is enforced at the Postgres schema level, not just in the UI. The `config_keys` and `config_versions` tables have no `ciphertext` or `wrapped_dek` columns. The `secrets` and `secret_versions` tables have no typed-value columns. A query that tries to join them for sensitive values cannot be written — there is no column to join on.

This structural choice has three load-bearing consequences:

1. **Audit log safety.** Config values (when `is_sensitive = false`) can be fully logged, including the before/after value on each write. Secret values never appear in any log entry. No redaction preprocessing is needed because the schema makes conflation impossible.
2. **SSE push safety.** Config change events are safe to broadcast to all subscribers because they carry only typed scalars and, for `secret_ref` keys, a UUID pointer — never plaintext secret material. If config and secrets lived in one table, every SSE broadcast would require per-row sensitivity checks.
3. **Schema validation.** Typed columns (`bigint`, `double precision`, `boolean`, `jsonb`) and write-time JSON Schema validation require knowing the sensitivity tier at schema design time. An encrypted blob cannot be validated or indexed.

The tradeoff is more tables and more code paths. That tradeoff is intentional and non-negotiable per tenet 5.

---

## 2. The Typed Config Data Model

### 2.1 Value Types

```sql
CREATE TYPE config_value_type AS ENUM (
    'string',
    'int',
    'float',
    'bool',
    'json',
    'secret_ref'
);
```

| `value_type` | Postgres column | Semantics |
|---|---|---|
| `string` | `string_value TEXT` | UTF-8 string, no length cap at DB layer |
| `int` | `int_value BIGINT` | 64-bit signed integer |
| `float` | `float_value DOUBLE PRECISION` | IEEE 754 double |
| `bool` | `bool_value BOOLEAN` | `true` / `false` |
| `json` | `json_value JSONB` | Arbitrary JSON; optional `schema_json` validates at write time |
| `secret_ref` | `secret_ref UUID` | UUID of a `secrets` row in the same tenant; the secret's plaintext is never stored here |

### 2.2 Table Definitions

```sql
-- Per-key schema and metadata
CREATE TABLE config_keys (
    id              UUID                PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID                NOT NULL REFERENCES tenants(id),
    environment_id  UUID                NOT NULL REFERENCES environments(id),
    path            TEXT                NOT NULL,
    value_type      config_value_type   NOT NULL,
    schema_json     JSONB,              -- JSON Schema Draft 2020-12; only for value_type='json'
    is_sensitive    BOOLEAN             NOT NULL DEFAULT false,
    current_version INT                 NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ         NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ         NOT NULL DEFAULT now(),

    CONSTRAINT uq_config_path UNIQUE (tenant_id, environment_id, path),
    CONSTRAINT chk_schema_only_for_json
        CHECK (schema_json IS NULL OR value_type = 'json')
);

-- Immutable version rows; one row per write
CREATE TABLE config_versions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    config_key_id   UUID        NOT NULL REFERENCES config_keys(id),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id),
    version         INT         NOT NULL CHECK (version > 0),
    string_value    TEXT,
    int_value       BIGINT,
    float_value     DOUBLE PRECISION,
    bool_value      BOOLEAN,
    json_value      JSONB,
    secret_ref      UUID        REFERENCES secrets(id),
    is_deleted      BOOLEAN     NOT NULL DEFAULT false,
    deleted_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by_id   UUID        NOT NULL,

    CONSTRAINT uq_config_version UNIQUE (config_key_id, version),
    CONSTRAINT chk_single_value CHECK (
        (string_value IS NOT NULL)::int +
        (int_value    IS NOT NULL)::int +
        (float_value  IS NOT NULL)::int +
        (bool_value   IS NOT NULL)::int +
        (json_value   IS NOT NULL)::int +
        (secret_ref   IS NOT NULL)::int = 1
    )
);
```

The `chk_single_value` constraint enforces at the database level that exactly one value column is populated per row. The application layer also validates this, but the DB constraint is the backstop.

`is_sensitive = true` marks a config key whose value is redacted in audit log entries; the access event is still recorded. It does not trigger encryption — sensitive config is still stored as plaintext in `config_versions`. Secret material that must be encrypted lives in the `secrets` table, not here.

### 2.3 Postgres Roles and RLS

Config tables follow the same isolation pattern as all other soma-vault tables:

```sql
ALTER TABLE config_keys     ENABLE ROW LEVEL SECURITY;
ALTER TABLE config_keys     FORCE ROW LEVEL SECURITY;
ALTER TABLE config_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE config_versions FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON config_keys
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation ON config_versions
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE ON config_keys     TO soma_vault_app;
GRANT SELECT, INSERT, UPDATE ON config_versions TO soma_vault_app;
```

`soma_vault_app` is not the table owner. The application layer always includes `WHERE tenant_id = $1` using the `TenantId(Uuid)` newtype as the primary enforcement gate; RLS is defense-in-depth.

---

## 3. JSON Schema Validation at Write Time

When `value_type = 'json'` and the caller supplies a `schema_json` document, the server validates the incoming value against the schema before committing the row. Validation uses the `jsonschema` crate's build-once-validate-many API:

```rust
// Compiled once per schema definition, reused across requests.
let compiled = jsonschema::validator_for(&schema_document)?;
compiled.validate(&incoming_value)?;
```

Schema documents are stored verbatim in the `schema_json JSONB` column of `config_keys` and compiled on first use, cached in-process.

Invalid payloads are rejected at write time with a `400 VALIDATION_FAILED` response and a structured error body:

```json
{
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "Config value failed schema validation.",
    "request_id": "uuid",
    "details": [
      {
        "schema_path": "/properties/port/minimum",
        "instance_path": "/port",
        "message": "3000 is less than minimum of 1024"
      }
    ]
  }
}
```

For all other `value_type` values, type correctness is enforced by the Postgres column type at write time (the application layer parses and casts before inserting) and by the `chk_single_value` constraint.

Validation runs at write time only. Stored values are trusted at read time — reading does not re-validate.

---

## 4. Environment Inheritance and Overrides

### 4.1 The `inherits_from` Chain

Each environment row carries an optional `inherits_from UUID` FK referencing a parent environment in the same project. The `environments` table definition:

```sql
CREATE TABLE environments (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id),
    project_id      UUID        NOT NULL REFERENCES projects(id),
    name            TEXT        NOT NULL,
    inherits_from   UUID        REFERENCES environments(id),
    ...
    CONSTRAINT chk_no_self_inherit CHECK (inherits_from IS DISTINCT FROM id)
);
```

Inheritance depth is capped at 3 and enforced at write time by the application layer:

```rust
fn check_inheritance_depth(conn: &mut PgConnection, env_id: Uuid, tenant_id: TenantId)
    -> Result<(), AppError>
{
    let mut visited = HashSet::new();
    let mut current = env_id;
    for depth in 0.. {
        if depth > 3 {
            return Err(AppError::ValidationFailed("inheritance depth exceeds 3"));
        }
        if visited.contains(&current) {
            return Err(AppError::ValidationFailed("inheritance cycle detected"));
        }
        visited.insert(current);
        match fetch_parent(conn, current, tenant_id)? {
            Some(parent) => current = parent,
            None => break,
        }
    }
    Ok(())
}
```

The database enforces only direct self-reference (`chk_no_self_inherit`). The application layer enforces depth and cycles. If a direct Postgres write bypasses the application, cycles and over-depth chains are detectable at resolution time because the resolution code tracks visited IDs using the same `HashSet` approach and returns an error rather than looping.

### 4.2 Resolution Semantics

Secrets do not participate in environment inheritance. A secret is always environment-specific. Only config keys are resolved through the inheritance chain.

At config fetch time, the application walks the chain from the requested environment upward:

```
effective_value = first non-null value found when walking:
  requested_env → parent_env → grandparent_env
```

Child values override parent values. The response includes `inherited_from_env_id: uuid | null` to indicate where the effective value was sourced. The bulk export endpoint (`GET .../config?resolved=true&format=flat`) performs this resolution for all keys in one request, used by the SDK to seed its in-process cache.

### 4.3 Inheritance and `secret_ref`

If a config key in a parent environment has `value_type = 'secret_ref'`, and the child environment does not override it, the child inherits the `secret_ref` UUID pointer to a secret in the parent environment. That secret is a row in the `secrets` table scoped to the parent environment. The authZ check on `resolve_refs=true` validates that the caller has `read` capability on both the config key path and the referenced secret. Cross-environment `secret_ref` is valid within a tenant.

---

## 5. The `secret_ref` Pointer: Config Referencing a Secret

### 5.1 What Is Stored

A config key with `value_type = 'secret_ref'` stores only the UUID of a row in the `secrets` table:

```sql
-- config_versions row for a secret_ref key:
{
  config_key_id: "uuid-of-config-key",
  secret_ref:    "uuid-of-referenced-secret",
  -- all other value columns are NULL
}
```

The secret's plaintext is never stored in `config_versions`. There is no column in the config tables capable of holding ciphertext or plaintext secret material.

### 5.2 Resolution at API Call Time

When a caller fetches a `secret_ref` config key with `resolve_refs=true`:

1. The server verifies the caller holds `read` capability on the config key path.
2. The server verifies the caller holds `read` capability on the referenced secret path.
3. If both checks pass, the server performs a fresh decrypt of the referenced secret (DEK unwrap + AEAD decrypt) and returns the resolved plaintext in the response body for this call only.
4. An audit log entry is written for the secret read with the caller's principal ID, IP, and timestamp — identical to a direct `GET .../secrets/{path}` call.

If check 1 passes but check 2 fails, the response returns the secret UUID unresolved with `ref_resolved: false` and `ref_resolve_error: "FORBIDDEN"`. The caller can act on this rather than silently receiving a null.

The `resolved_value` field is emitted only in this specific HTTP response. It is never cached, never emitted in SSE events, and never appears in audit log values.

### 5.3 Validation at Write Time

When a caller writes a `secret_ref` config value, the server validates that the referenced secret UUID exists within the same tenant:

```sql
SELECT id FROM secrets WHERE id = $1 AND tenant_id = $2
```

If the secret does not exist or is inaccessible, the write is rejected with `422 SECRET_REF_NOT_FOUND`.

### 5.4 SSE Events for `secret_ref` Keys

When a `secret_ref` config key changes, the SSE event carries only the config path and version:

```
id: 8473
event: config_change
data: {"path":"database/password","value_type":"secret_ref","version":2,"env_id":"uuid","project_id":"uuid"}
```

The `secret_id` field is intentionally omitted from SSE events. Clients that need the current secret UUID can fetch the config key directly; clients that need the resolved value must call `GET .../secrets/{path}` explicitly with a scoped token. This prevents SSE subscribers from passively collecting secret UUIDs for every `secret_ref` config key in their scope.

---

## 6. Real-Time Delivery via SSE

### 6.1 Architecture

Config delivery uses Server-Sent Events over a persistent HTTP connection. Each pod maintains:

- One `tokio::sync::broadcast::Sender<ConfigChangeEvent>` per `(project_id, environment_id)` pair, created lazily in a `DashMap` on first subscriber.
- One dedicated, non-pooled Postgres connection subscribed to `LISTEN config_changes`.

When a `config_versions` INSERT or UPDATE commits, the handler issues:

```sql
NOTIFY config_changes, '{"project_id":"...","env_id":"...","path":"...","version":3}';
```

The NOTIFY payload contains only the routing key — no config values. The receiving pod's LISTEN task fires, looks up the current value from Postgres (one indexed query), and broadcasts a typed `ConfigChangeEvent` to all locally-connected SSE clients for that `(project_id, env_id)` pair.

```rust
// ponytail: one broadcast channel per (project_id, env_id) pair.
// Ceiling: ~50 pods × N subscribers each before Postgres NOTIFY
// throughput becomes a bottleneck. Upgrade path: Redis pub/sub fan-out
// relay with no SDK wire-protocol changes.
let channels: DashMap<(Uuid, Uuid), broadcast::Sender<ConfigChangeEvent>>;
```

### 6.2 LISTEN Connection Health

The dedicated LISTEN connection is monitored with a periodic `SELECT 1` heartbeat. If the connection drops, the task reconnects with exponential backoff (1s, 2s, 4s, up to 30s) and sends a `stream_interrupted` SSE event to all current subscribers, triggering them to fall back to polling until the stream is restored.

```
event: stream_interrupted
data: {"reason":"listen_connection_dropped","fallback_poll_interval_secs":60}
```

### 6.3 SSE Event Schema

**Config value change (non-`secret_ref`):**

```
id: 8472
event: config_change
data: {
  "path": "server/port",
  "value_type": "int",
  "value": 9090,
  "version": 3,
  "env_id": "uuid",
  "project_id": "uuid",
  "inherited_from_env_id": null
}
```

**Config key deleted:**

```
id: 8474
event: config_delete
data: {"path":"deprecated/flag","version":4,"env_id":"uuid","project_id":"uuid"}
```

**Keepalive (every 30 seconds):**

```
: keepalive
```

**Connected confirmation (on stream open):**

```
event: connected
data: {"server_time":"2026-06-23T12:00:00Z","env_id":"uuid","project_id":"uuid"}
```

### 6.4 Reconnect and Gap Recovery

The SSE connection carries `Last-Event-ID` on reconnect. The server maintains a bounded event replay buffer per `(project_id, env_id)` pair: events from the last 60 seconds or the last 500 events, whichever bound is reached first. Events older than the replay window are not replayed. Clients that reconnect beyond the replay window must perform a full cache re-seed via the bulk config export endpoint before resuming the SSE stream. This bound is enforced and documented, not left to implementer interpretation.

### 6.5 SDK Cache Semantics

The Rust SDK (`soma-sdk`) implements config access as follows:

1. **On startup:** Call `GET .../config?resolved=true&format=flat` to seed a `DashMap` in-process cache. Store the `version_vector` from the response.
2. **Open SSE stream** with `Last-Event-ID` equal to the last known event ID (empty string on first connect). Present `version_vector` to detect gaps.
3. **On `config_change` event:** Update the `DashMap` entry for the changed `path`.
4. **`config.get::<T>(key)`** is always a local `DashMap` read — zero network, zero latency.
5. **On SSE disconnect:** Poll `GET .../config/{path}` every 60 seconds per key until reconnected.
6. **On reconnect:** Present `Last-Event-ID` to resume. If reconnect exceeds replay window, call bulk export to re-seed.

Secrets are never cached after the decrypt call. Each `secrets.get()` call triggers a fresh API call, DEK unwrap, and decrypt.

### 6.6 API Endpoint

```
GET /v1/config/stream?project_id={uuid}&env_id={uuid}
Authorization: Bearer sv_tok_...
Content-Type: text/event-stream
```

`workspace_id` is not required on this endpoint — `project_id` uniquely identifies the stream scope within a tenant, and `tenant_id` is resolved from the session token.

Auth and capability validation happen at connection time. The caller must hold `read` capability on the config path glob for this environment. An unauthenticated or unauthorized connection receives a `401` or `403` response before the stream opens.

---

## 7. Versioning and Config History

### 7.1 Monotonic Version Per Key

Each `config_key` row tracks `current_version INT`. Each write increments this counter and appends a new `config_versions` row. There is no max-versions cap on config keys — config history is retained indefinitely in Phase 1.

Version history is available at:

```
GET .../config/{path}/versions
```

For `is_sensitive = true` keys, the `value` field is replaced with `"<redacted>"` in version history responses.

### 7.2 Soft Delete

`DELETE .../config/{path}` sets `is_deleted = true` on the current `config_versions` row. The config key itself remains. A subsequent `PUT` creates a new version and sets `is_deleted = false` on the key's `current_version`.

### 7.3 No CAS on Config

Config keys do not support compare-and-swap in Phase 1. Last-write-wins. Concurrent writes are serialized at the Postgres transaction level. If optimistic concurrency control is needed, it can be added as `expected_version` in Phase 2 after the API contract is stable.

---

## 8. Bulk Config Export

```
GET .../config?resolved=true&format=flat
```

Returns all effective config values for the requested environment, walking the inheritance chain. Used by the SDK to seed its in-process cache on startup and by `soma secrets export` for CI/CD injection.

```json
{
  "environment_id": "uuid",
  "resolved_at": "2026-06-23T12:00:00Z",
  "version_vector": { "uuid-config-key-id": 3, "...": 1 },
  "items": [
    { "path": "server/port",       "value_type": "int",    "value": 8080,  "inherited_from_env_id": null },
    { "path": "feature/dark_mode", "value_type": "bool",   "value": true,  "inherited_from_env_id": "parent-uuid" },
    { "path": "database/password", "value_type": "secret_ref", "ref_resolved": false }
  ]
}
```

`secret_ref` items are never resolved in bulk export. The SDK resolves them individually using `secrets.get()` with explicit calls. The `version_vector` is an opaque map the SDK presents back to the SSE stream for gap detection.

---

## 9. Audit Logging for Config Operations

Every config write (`config_create`, `config_update`, `config_delete`) generates a synchronous audit entry within the same database transaction. Config reads are logged best-effort via the bounded async channel — consistent with the treatment of secret reads.

When `is_sensitive = false`, the audit entry includes the new value. When `is_sensitive = true`, the value is redacted in the audit entry. Secret values never appear in any audit entry regardless of path.

`secret_ref` resolution (triggered by `resolve_refs=true` on a config fetch) generates an additional audit entry of type `secret_read` for the referenced secret, identical to a direct secret read. The audit trail shows that the resolution happened, who requested it, and when.

---

## 10. Policy Cache Invalidation

The in-memory radix-trie policy cache used for path-capability authorization is invalidated cross-pod using the same Postgres LISTEN/NOTIFY mechanism as config delivery:

```sql
-- Issued after any INSERT/UPDATE/DELETE on the policies table:
NOTIFY policy_changes, '{"tenant_id":"...","workspace_id":"..."}';
```

Each pod's LISTEN relay task receives the notification and clears the cached radix trie for that `(tenant_id, workspace_id)` pair. This ensures that policy revocations propagate to all pods within the Postgres notification latency window (typically under 100ms on the same network).

---

## 11. What Is Explicitly Deferred

The following config capabilities are deferred to Phase 2 or later, with the YAGNI reason for each.

### Approval / Change-Request Workflow

A proposal/approval state machine (pending → approved → rejected → merged) with reviewer assignment, diff snapshots, and merge-triggers-audit is deferred. The Phase 1 governance surface is the audit log with the `reason` field. No customer has asked for approval gates before a single secret has been stored. The `policies` table schema stores policy strings designed to accommodate Cedar (Phase 2 policy-as-code engine) without migration; the audit table is the stable foundation for Phase 2 change governance.

### Gradual Config Rollout / Canary Deployment Strategies

AppConfig-style exponential or linear rollout with alarm-triggered rollback is deferred. Phase 1 config changes are atomic — a write immediately becomes the effective value for all subscribers. Deployment-strategy objects require a separate evaluation layer that decides which percentage of SDK instances sees which version. This is a feature with zero Phase 1 consumers.

### JSON Schema Codegen

Server-side generation of typed Rust or TypeScript structs from stored `schema_json` documents (`schemars`-derived types) is deferred. Phase 1 validates at write time and trusts the stored value at read time. Client-side type generation is a CLI tool that sits on top of the Phase 1 `GET .../config/{path}` API and can be added without schema changes.

### Feature-Flag Targeting Rules

Percentage-based rollout, user-segment targeting, and A/B experimentation (LaunchDarkly / Statsig territory) are not modeled. A feature flag is a `bool` or `int` config key. The `is_feature_flag: bool` UI affordance is Phase 2. Evaluation-SDK targeting rules require a separate evaluation service; Phase 1 has no such service.

### Config-to-Config References

A config key referencing another config key (not a secret) is not modeled. The only inter-resource reference in Phase 1 is `secret_ref` (config → secret). Config-to-config DAGs add cycle-detection complexity with no clear Phase 1 consumer.

### Per-Config-Key Encryption

Sensitive config values (`is_sensitive = true`) are stored as plaintext with access controlled by RBAC and RLS. Envelope-encrypting them at the row level (same DEK pattern as secrets) is deferred. The use case is genuine for config values like internal API hosts that operators prefer not to expose in DB dumps, but the implementation doubles the crypto surface for the config tier. Document the gap; add in Phase 2 when a customer asks.

---

## 12. Consistency with the API Spec

The following API endpoints cover the config tier. These match the endpoint index in the API specification exactly.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `.../config` | List config keys (paginated, filterable by `path_prefix`, `value_type`) |
| `PUT` | `.../config/{path}` | Write or update a config key |
| `GET` | `.../config/{path}` | Read current value (supports `?version=N`, `?resolve_refs=true`) |
| `GET` | `.../config/{path}/versions` | Version history |
| `DELETE` | `.../config/{path}` | Soft-delete current version |
| `GET` | `/v1/config/stream` | SSE stream for real-time delivery |

The base path prefix for all config CRUD endpoints is:

```
/v1/workspaces/{workspace_id}/projects/{project_id}/environments/{env_id}/config
```

`tenant_id` is never in the URL — it is resolved from the session token and enforced at every repository call via the `TenantId(Uuid)` newtype.

---

## 13. Rust Crates

| Crate | Version | Use |
|---|---|---|
| `jsonschema` | 0.46.x | Write-time JSON Schema Draft 2020-12 validation; `validator_for()` compile-once pattern |
| `serde_json` | 1.x | `json_value JSONB` serialization and canonical JSON for audit hashing |
| `dashmap` | 6.x | In-process config cache in the SDK; SSE broadcast channel map per pod |
| `tokio::sync::broadcast` | (tokio 1.x) | SSE fan-out to locally-connected clients |
| `sqlx` | 0.8.x | Postgres driver; all config table reads and writes use `query_as!` with `TenantId` |
| `axum::response::Sse` | (axum 0.7.x) | SSE handler; no additional crate required |

The `jsonschema` crate is the only new addition to the dependency tree that this document introduces. All other crates are already required by the secrets tier or the HTTP server.

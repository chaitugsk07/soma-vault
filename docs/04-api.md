# soma-vault Phase 1 — REST + Real-Time API

soma-vault exposes a versioned JSON/HTTPS REST API for secrets and typed configuration management, a Server-Sent Events stream for real-time config delivery, and unauthenticated health endpoints for Kubernetes probes. This document is the authoritative API reference for Phase 1. It incorporates all approved design decisions and addresses the issues identified in the engineering review.

---

## Transport and Versioning

All endpoints run over TLS 1.3 (rustls + aws-lc-rs, no OpenSSL). Every resource endpoint is prefixed `/v1`. Breaking changes require a new prefix (`/v2`); additive changes (new optional fields, new endpoints) are made in-place. The `API-Version` response header echoes the server's current minor revision (e.g., `1.3`).

---

## Resource Hierarchy

```
tenant (= soma-iam org_id UUID)
  └── workspace
        └── project
              └── environment
                    ├── secret          (envelope-encrypted, pull-only)
                    └── config_key      (typed plaintext, SSE-pushed)
```

`tenant_id` is never a URL parameter. It is resolved from the authenticated session token and enforced at two independent layers: the application layer (every sqlx query carries a `TenantId(Uuid)` Rust newtype) and Postgres RLS (defense-in-depth backstop). Cross-tenant access is structurally impossible.

---

## Authentication

### soma-iam JWT Exchange

```
POST /v1/auth/login
```

Exchanges a soma-iam-issued JWT for a short-lived soma-vault session token. All subsequent hot-path requests use the soma-vault token; no soma-iam call occurs per request.

**Request:**

```json
{
  "credential_type": "soma_iam_jwt",
  "token": "<soma-iam RS256/ES256 JWT>"
}
```

**Validation performed server-side:**

1. Signature verified against soma-iam JWKS (cached; re-fetched on unknown `kid` with singleflight coalescing — only one in-flight JWKS fetch per `kid` miss, not one per concurrent request).
2. `kid` not in a 60-second negative cache (populated after a re-fetch that still does not contain the key — prevents `kid`-exhaustion DoS against soma-iam).
3. `iss` matches configured soma-iam issuer.
4. `aud` contains `"soma-vault"`.
5. `exp` not in the past.
6. `tenant_id` claim present and maps to a known tenant row; absent `tenant_id` is rejected unconditionally.
7. `jti` claim checked against a `jti_replay_cache` table (one row per JWT, TTL = JWT `exp`); duplicate `jti` is rejected with `401 UNAUTHENTICATED`. This prevents replay of stolen soma-iam JWTs for the duration of their validity window.

**Response `200 OK`:**

```json
{
  "token": "sv_tok_...",
  "token_type": "Bearer",
  "expires_at": "2026-06-23T15:30:00Z",
  "tenant_id": "uuid",
  "principal_id": "uuid"
}
```

**Session token implementation note:** soma-vault session tokens are short-lived RS256 JWTs signed with a per-deployment key pair (private key derived from the master KEK via HKDF, `salt = b"soma-vault-session-signing-v1"`). Validation is signature-only (no DB lookup on the hot path). Explicit revocation (`DELETE /v1/auth/session`) writes the token's `jti` to a small in-memory revoked-JTI set; entries expire with the token TTL. This eliminates the per-request Postgres sessions-table read.

All subsequent requests carry:

```
Authorization: Bearer sv_tok_...
```

### Universal Auth — Machine / Local Dev

```
POST /v1/auth/login
```

```json
{
  "credential_type": "universal_auth",
  "client_id": "uuid",
  "client_secret": "..."
}
```

`client_secret` is verified against the Argon2id hash stored in `service_accounts`. Response shape identical to JWT exchange. Universal Auth is a bootstrapping and local-dev mechanism; production workloads should authenticate via soma-iam machine-identity JWTs.

### CI / Workload OIDC

CI pipelines (GitHub Actions, GitLab CI, etc.) and Kubernetes workloads exchange their platform-native OIDC JWT at soma-iam first. soma-iam validates the platform token, maps it to a service account in the correct tenant, and issues a soma-iam machine-identity JWT. That JWT is then presented to `POST /v1/auth/login` with `credential_type: soma_iam_jwt`. soma-vault trusts exactly one IdP: soma-iam.

### Pod KMS Auto-Unseal — Infrastructure Plane

soma-vault pods authenticate to AWS KMS via IRSA (Kubernetes projected ServiceAccount OIDC token → STS AssumeRoleWithWebIdentity → KMS Decrypt) on boot. This is a pod-to-KMS connection, not an API call that principals make. It is completely separate from app-principal authentication.

### Token Refresh

```
POST /v1/auth/refresh
Authorization: Bearer sv_tok_...
```

Returns a new session token with a fresh TTL. The old token's `jti` is added to the in-memory revocation set immediately.

### Token Revocation

```
DELETE /v1/auth/session
Authorization: Bearer sv_tok_...
```

**Response `204 No Content`.**

---

## Error Model

All errors return `application/json`:

```json
{
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "Secret not found in this environment.",
    "request_id": "uuid",
    "details": []
  }
}
```

`details` carries structured sub-errors for validation failures:

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

### Status Code Reference

| Code | `error.code` | Meaning |
|------|-------------|---------|
| 400 | `INVALID_REQUEST` | Malformed JSON or missing required field |
| 400 | `VALIDATION_FAILED` | JSON Schema validation failure on config write |
| 401 | `UNAUTHENTICATED` | Missing, invalid, or replayed credential |
| 401 | `TOKEN_EXPIRED` | Session token past expiry |
| 403 | `FORBIDDEN` | Authenticated but lacks capability on this path |
| 404 | `RESOURCE_NOT_FOUND` | Resource does not exist or is not visible to caller |
| 409 | `CAS_CONFLICT` | Write rejected: `expected_version` mismatch |
| 410 | `SECRET_DESTROYED` | Secret version irreversibly destroyed |
| 422 | `SECRET_REF_NOT_FOUND` | `secret_ref` points to non-existent or inaccessible secret |
| 429 | `RATE_LIMITED` | Per-IP auth rate limit exceeded; see `Retry-After` |
| 500 | `INTERNAL_ERROR` | Server fault; `request_id` for correlation |
| 503 | `SEALED` | Pod sealed — KMS grace period expired |

---

## Rate Limiting

Phase 1 applies rate limiting only to auth endpoints (the one surface where brute-force is a genuine security risk). All other endpoints have no per-token rate limits in Phase 1; this is a documented gap with Postgres-backed or Redis-backed distributed limiting as the Phase 2 upgrade path.

```
POST /v1/auth/*   — 20 req/min per IP (in-memory token bucket, acceptable pod-local approximation)
```

Responses include `Retry-After` on `429`.

---

## Pagination

List endpoints use offset pagination in Phase 1 (simpler to implement correctly than keyset cursors; cursor-based pagination is Phase 2 when scale profiles are known).

Query parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `limit` | `100` | Max items per page (max: `500`) |
| `offset` | `0` | Number of items to skip |

Response envelope:

```json
{
  "items": [...],
  "has_more": true
}
```

`has_more: false` signals the last page.

---

## Health and Seal Status

These endpoints are unauthenticated and must be reachable by Kubernetes probes.

### Readiness

```
GET /health/ready
```

Returns `200` when the pod has successfully unwrapped the master KEK from KMS and can serve requests. Used as the Kubernetes `readinessProbe`.

**Normal:**

```json
{
  "status": "ready",
  "seal_backend": "aws_kms",
  "seal_backend_severity": "ok"
}
```

**KMS degraded — grace period active:**

```json
{
  "status": "ready",
  "degraded": true,
  "active_alerts": ["kms_unreachable"],
  "seal_backend": "aws_kms",
  "seal_backend_severity": "warning",
  "grace_period_expires_at": "2026-06-23T16:00:00Z"
}
```

The pod returns `200` in degraded state so it remains in the Service Endpoints list and continues receiving traffic. Operators who want to influence HPA scale-down behavior should configure an HPA `externalMetric` rule on the `soma_vault_kms_grace_period_active` Prometheus gauge.

**Sealed (grace period expired or boot KMS failure after 60-second retry window):**

```json
{
  "status": "sealed",
  "seal_backend": "aws_kms",
  "seal_backend_severity": "critical"
}
```

HTTP status `503`.

**Software-KMS fallback (self-host without cloud KMS):**

```json
{
  "status": "ready",
  "seal_backend": "software_kms",
  "seal_backend_severity": "warning",
  "seal_backend_warning": "Software-KMS fallback active. Security posture is reduced: master KEK is protected only by Kubernetes etcd encryption and RBAC, not by workload identity. See documentation."
}
```

### Startup

```
GET /health/startup
```

Used as the Kubernetes `startupProbe`. Returns `503` while the 60-second KMS retry window is active on boot, transitions to `200` once KMS succeeds, and does not revert to `503` after the first successful unseal (unlike `/health/ready`, which can return `503` if the grace period later expires). This prevents the readiness probe from timing out during slow KMS cold-starts.

```json
{ "status": "starting" }    // 503
{ "status": "ready" }       // 200
```

### Liveness

```
GET /health/live
```

Returns `200` if the process is alive. Never returns `503`.

```json
{ "status": "alive" }
```

### Metrics

```
GET /metrics
```

Prometheus text format. Authentication optional (configurable). Key gauges and counters: `soma_vault_kms_grace_period_active`, `soma_vault_kms_unseal_total`, `soma_vault_kms_unseal_errors_total`, `soma_vault_active_sse_connections`, `soma_vault_rotation_queue_depth`, `soma_vault_jwks_refetch_total`, request latency histograms.

---

## Workspace Management

### List Workspaces

```
GET /v1/workspaces
```

Returns workspaces visible to the caller within their tenant.

**Response `200`:**

```json
{
  "items": [
    {
      "id": "uuid",
      "name": "production",
      "description": "...",
      "created_at": "2026-06-01T00:00:00Z",
      "updated_at": "2026-06-01T00:00:00Z"
    }
  ],
  "has_more": false
}
```

### Create Workspace

```
POST /v1/workspaces
```

```json
{ "name": "staging", "description": "optional" }
```

**Response `201 Created`:** full workspace object. The creating principal is automatically granted `ws:admin` for the new workspace.

### Get Workspace

```
GET /v1/workspaces/{workspace_id}
```

### Update Workspace

```
PATCH /v1/workspaces/{workspace_id}
```

```json
{ "name": "new-name", "description": "updated" }
```

### Delete Workspace

```
DELETE /v1/workspaces/{workspace_id}
```

Rejected if any projects exist. **Response `204 No Content`.**

### Workspace Member Management

Workspace roles (`ws:admin`, `ws:developer`, `ws:reader`) are stored in soma-vault and managed via these endpoints. Principals with `org_role: admin` in the soma-iam JWT are automatically granted `ws:admin` on first login to any workspace in their tenant that has no explicit role binding for them. For `org:member` and `org:viewer`, explicit invitation is required.

```
GET /v1/workspaces/{workspace_id}/members
```

```json
{
  "items": [
    {
      "principal_id": "uuid",
      "principal_type": "user",
      "role": "ws:developer",
      "granted_at": "2026-06-01T00:00:00Z",
      "granted_by_id": "uuid"
    }
  ],
  "has_more": false
}
```

```
POST /v1/workspaces/{workspace_id}/members
```

```json
{ "principal_id": "uuid", "role": "ws:developer" }
```

**Response `201 Created`.**

```
PATCH /v1/workspaces/{workspace_id}/members/{principal_id}
```

```json
{ "role": "ws:reader" }
```

**Response `200 OK`.**

```
DELETE /v1/workspaces/{workspace_id}/members/{principal_id}
```

**Response `204 No Content`.** Immediately invalidates all active session tokens for this principal in this workspace.

---

## Project Management

### List Projects

```
GET /v1/workspaces/{workspace_id}/projects
```

### Create Project

```
POST /v1/workspaces/{workspace_id}/projects
```

```json
{ "name": "api-service", "description": "optional" }
```

**Response `201 Created`.**

### Get / Update / Delete Project

```
GET    /v1/workspaces/{workspace_id}/projects/{project_id}
PATCH  /v1/workspaces/{workspace_id}/projects/{project_id}
DELETE /v1/workspaces/{workspace_id}/projects/{project_id}
```

Delete is rejected if environments exist within the project.

---

## Environment Management

Environments live within a project. An environment may inherit from a parent environment in the same project (max depth 3, enforced at write time in application code; a cycle-detection walk also runs at write time — if the new environment's own ID appears anywhere in the ancestor chain, the write is rejected with `400 INVALID_REQUEST`).

### List Environments

```
GET /v1/workspaces/{workspace_id}/projects/{project_id}/environments
```

### Create Environment

```
POST /v1/workspaces/{workspace_id}/projects/{project_id}/environments
```

```json
{
  "name": "staging",
  "inherits_from": "uuid-of-parent-env-or-null"
}
```

**Response `201 Created`:**

```json
{
  "id": "uuid",
  "project_id": "uuid",
  "name": "staging",
  "inherits_from": "uuid-or-null",
  "created_at": "2026-06-01T00:00:00Z"
}
```

### Get / Delete Environment

```
GET    /v1/workspaces/{workspace_id}/projects/{project_id}/environments/{env_id}
DELETE /v1/workspaces/{workspace_id}/projects/{project_id}/environments/{env_id}
```

---

## Secrets API

Secrets are envelope-encrypted: each version gets a fresh 32-byte DEK (OsRng), the plaintext is sealed with AES-256-GCM (96-bit random nonce, AAD = `secret_id_bytes || version_id_bytes`), and the DEK is wrapped under the tenant KEK using AES Key Wrap (RFC 3394, `aes-kw` crate — a deterministic, nonceless algorithm designed for key wrapping). The schema stores `(ciphertext, wrapped_dek, nonce)`. The `aad_fingerprint` column stores `SHA-256(secret_id_bytes || version_id_bytes)` as a structural cross-check only; the actual cryptographic binding is the AEAD tag. Both DEK and plaintext are zeroized from pod memory before the response is written.

Secret plaintext is **never** returned in config API responses, SSE events, audit log entries, or list responses.

Every read of secret plaintext — including reads triggered by `resolve_refs=true` on a config endpoint — emits an individual audit log entry.

### Base Path

```
/v1/workspaces/{workspace_id}/projects/{project_id}/environments/{env_id}/secrets
```

Abbreviated `.../secrets` below.

### List Secrets (metadata only)

```
GET .../secrets
GET .../secrets?path_prefix=database/
```

| Parameter | Description |
|-----------|-------------|
| `path_prefix` | Filter by path prefix |
| `limit` / `offset` | Pagination |

**Response `200`:**

```json
{
  "items": [
    {
      "id": "uuid",
      "path": "database/password",
      "current_version": 4,
      "max_versions": 20,
      "cas_required": false,
      "created_at": "2026-06-01T00:00:00Z",
      "updated_at": "2026-06-20T00:00:00Z"
    }
  ],
  "has_more": false
}
```

### Create / Update Secret

```
PUT .../secrets/{path}
```

Path is slash-delimited (`database/password`). Forward slashes are path delimiters, not percent-encoded.

```json
{
  "value": "supersecret",
  "cas_version": 3
}
```

`cas_version` is optional. If provided and the server's current version does not match, the write is rejected `409 CAS_CONFLICT`. If omitted and `cas_required: true`, the write is also rejected.

**Response `201 Created`** (new secret) or **`200 OK`** (updated):

```json
{
  "id": "uuid",
  "path": "database/password",
  "version": 4,
  "created_at": "2026-06-23T12:00:00Z"
}
```

### Export Secrets (CLI / bulk)

```
GET .../secrets/export?format=env|json|dotenv
```

Returns all current-version plaintext values for this environment as a flat map. Every secret read in the export emits an individual audit log entry. Secret values are returned in the response body; the response sets `Cache-Control: no-store, no-cache, private`.

```json
{
  "environment_id": "uuid",
  "exported_at": "2026-06-23T12:00:00Z",
  "secrets": {
    "DATABASE_PASSWORD": "supersecret",
    "API_KEY": "abc123"
  }
}
```

`format=env` and `format=dotenv` return `text/plain` with `KEY=value\n` lines. Used by `soma secrets export` in the CLI.

### Get Secret (read plaintext)

```
GET .../secrets/{path}
GET .../secrets/{path}?version=3
```

Default: current version.

**Response `200 OK`:**

```json
{
  "id": "uuid",
  "path": "database/password",
  "version": 4,
  "value": "supersecret",
  "created_at": "2026-06-23T12:00:00Z",
  "created_by_id": "uuid"
}
```

Response sets `Cache-Control: no-store, no-cache, private`.

**Response `410 Gone`** if the version is destroyed:

```json
{
  "error": { "code": "SECRET_DESTROYED", "message": "Version 2 has been irreversibly destroyed." }
}
```

### Get Secret Metadata

```
GET .../secrets/{path}/metadata
```

```json
{
  "id": "uuid",
  "path": "database/password",
  "current_version": 4,
  "max_versions": 20,
  "cas_required": false,
  "versions": [
    { "version": 4, "created_at": "...", "is_deleted": false, "is_destroyed": false },
    { "version": 3, "created_at": "...", "is_deleted": false, "is_destroyed": false },
    { "version": 2, "created_at": "...", "is_deleted": true, "deleted_at": "...", "is_destroyed": false },
    { "version": 1, "created_at": "...", "is_deleted": false, "is_destroyed": true }
  ]
}
```

### Update Secret Metadata

```
PATCH .../secrets/{path}/metadata
```

```json
{
  "max_versions": 30,
  "cas_required": true
}
```

**Response `200 OK`:** updated metadata object.

### Soft-Delete a Secret Version

```
DELETE .../secrets/{path}?version=3
```

Sets `is_deleted = true`. Ciphertext retained; recoverable. Omitting `version` soft-deletes the current version.

**Response `204 No Content`.**

### Destroy a Secret Version (irreversible)

```
POST .../secrets/{path}/destroy?version=3
```

Sets `is_destroyed = true`, zeroes `ciphertext` and `wrapped_dek` in the row. Irreversible.

**Response `204 No Content`.**

### Rollback a Secret

Creates a new version by decrypting the specified historical version and re-encrypting it with a **fresh DEK and fresh nonce** (never copies `wrapped_dek` or `nonce` from the source row). The source version must not be destroyed.

```
POST .../secrets/{path}/rollback
```

```json
{ "to_version": 2 }
```

**Response `200 OK`:**

```json
{
  "path": "database/password",
  "new_version": 5,
  "rolled_back_from_version": 2
}
```

---

## Typed Config API

Config keys are typed, validated at write time, stored as plaintext, and delivered in real time via SSE. Config tables have **no** ciphertext columns. Secret tables have **no** typed-value columns. The schema makes conflation structurally impossible.

`secret_ref` config keys store only the UUID of a secret — never the plaintext. SSE events for `secret_ref` keys carry only the secret UUID, never the resolved value.

### Value Types

| `value_type` | Storage column | Notes |
|-------------|---------------|-------|
| `string` | `string_value TEXT` | UTF-8 |
| `int` | `int_value BIGINT` | 64-bit signed |
| `float` | `float_value DOUBLE PRECISION` | IEEE 754 double |
| `bool` | `bool_value BOOLEAN` | `true` / `false` |
| `json` | `json_value JSONB` | Optional `schema_json` validates at write |
| `secret_ref` | `secret_ref UUID` | Same-environment secret UUID; never holds plaintext |

`secret_ref` is restricted to secrets in the **same environment** as the config key. Cross-environment references are not permitted; this eliminates the privilege-escalation vector where a staging config key could reference a production secret.

### Base Path

```
/v1/workspaces/{workspace_id}/projects/{project_id}/environments/{env_id}/config
```

Abbreviated `.../config` below.

### List Config Keys

```
GET .../config
GET .../config?path_prefix=server/&value_type=int
```

| Parameter | Description |
|-----------|-------------|
| `path_prefix` | Filter by path prefix |
| `value_type` | Filter by type |
| `limit` / `offset` | Pagination |

**Response `200`:**

```json
{
  "items": [
    {
      "id": "uuid",
      "path": "server/port",
      "value_type": "int",
      "current_version": 2,
      "is_sensitive": false,
      "created_at": "2026-06-01T00:00:00Z",
      "updated_at": "2026-06-20T00:00:00Z"
    }
  ],
  "has_more": false
}
```

### Get Config Key

```
GET .../config/{path}
GET .../config/{path}?resolve_refs=true
GET .../config/{path}?version=5
```

`resolve_refs=true` triggers server-side resolution of `secret_ref` values. The caller must hold `read` capability on both the config key and the referenced secret. If the caller lacks `read` on the referenced secret, the response returns the config key with `ref_resolved: false` and `ref_resolve_error: "FORBIDDEN"` — the HTTP status remains `200` (the config key itself was found) but the partial failure is explicit. The resolved secret plaintext and its audit log entry are both written in the same request scope.

**Non-`secret_ref` response:**

```json
{
  "id": "uuid",
  "path": "server/port",
  "value_type": "int",
  "value": 8080,
  "version": 2,
  "is_sensitive": false,
  "inherited_from_env_id": null,
  "created_at": "2026-06-01T00:00:00Z"
}
```

**`secret_ref`, `resolve_refs=false`:**

```json
{
  "id": "uuid",
  "path": "database/password",
  "value_type": "secret_ref",
  "secret_id": "uuid-of-referenced-secret",
  "ref_resolved": false,
  "version": 1
}
```

Note: `secret_id` is returned here only when the caller has `read` capability on the referenced secret. Callers without that capability see `value_type: "secret_ref"` with the `secret_id` field omitted entirely, preventing UUID enumeration via config keys.

**`secret_ref`, `resolve_refs=true`, authorized:**

```json
{
  "id": "uuid",
  "path": "database/password",
  "value_type": "secret_ref",
  "secret_id": "uuid-of-referenced-secret",
  "ref_resolved": true,
  "resolved_value": "supersecret",
  "version": 1
}
```

`resolved_value` is never cached, never emitted in SSE, and the response sets `Cache-Control: no-store, no-cache, private`.

**`secret_ref`, `resolve_refs=true`, unauthorized:**

```json
{
  "id": "uuid",
  "path": "database/password",
  "value_type": "secret_ref",
  "ref_resolved": false,
  "ref_resolve_error": "FORBIDDEN",
  "version": 1
}
```

### Environment Inheritance

When `inherited_from_env_id` is non-null, the value was inherited from a parent environment. The server walks the `inherits_from` chain (depth capped at 3) and returns the effective value. Child values always override parent values. Cycle detection runs server-side; a detected cycle returns `500 INTERNAL_ERROR` with a descriptive message (this indicates a data integrity issue, as cycle prevention runs at write time).

### Write / Update Config Key

```
PUT .../config/{path}
```

```json
{
  "value_type": "int",
  "value": 9090,
  "is_sensitive": false
}
```

For `value_type: "json"` with a JSON Schema constraint:

```json
{
  "value_type": "json",
  "value": { "host": "db.internal", "port": 5432 },
  "schema_json": {
    "$schema": "https://json-schema.org/draft/2020-12",
    "type": "object",
    "required": ["host", "port"],
    "properties": {
      "host": { "type": "string" },
      "port": { "type": "integer", "minimum": 1024, "maximum": 65535 }
    }
  }
}
```

Schema validation runs at write time via the `jsonschema` crate (compiled once, validated many times). Invalid payloads are rejected `400 VALIDATION_FAILED` with structured details (see Error Model).

For `value_type: "secret_ref"`:

```json
{
  "value_type": "secret_ref",
  "secret_id": "uuid-of-secret-in-same-environment"
}
```

The server validates the referenced secret UUID exists in the same environment and is accessible to the writing principal. If not, the write is rejected `422 SECRET_REF_NOT_FOUND`.

**Response `201 Created`** or **`200 OK`:** config key object (without any resolved secret value).

### Delete Config Key

```
DELETE .../config/{path}
```

Soft-deletes the current version. **Response `204 No Content`.**

### Get Config Key Version History

```
GET .../config/{path}/versions
```

```json
{
  "items": [
    {
      "version": 3,
      "value_type": "int",
      "value": 9090,
      "created_at": "2026-06-20T00:00:00Z",
      "is_deleted": false
    }
  ],
  "has_more": false
}
```

For `is_sensitive: true` keys, `"value": "<redacted>"` is returned in version history.

### Bulk Config Export (SDK Seed / CLI)

```
GET .../config?resolved=true&format=flat
```

Returns all effective config values for this environment (inheritance chain applied). Used by the SDK to seed its in-process cache at startup and by `soma secrets export`. `secret_ref` entries are **never** resolved in bulk export.

```json
{
  "environment_id": "uuid",
  "resolved_at": "2026-06-23T12:00:00Z",
  "version_vector": { "uuid-config-key-id": 3, "other-id": 1 },
  "items": [
    { "path": "server/port", "value_type": "int", "value": 8080, "inherited_from_env_id": null },
    { "path": "feature/dark_mode", "value_type": "bool", "value": true, "inherited_from_env_id": "parent-uuid" },
    { "path": "database/password", "value_type": "secret_ref", "ref_resolved": false, "version": 1 }
  ]
}
```

`version_vector` is an opaque map the SDK presents to the SSE stream on reconnect for gap detection. `secret_ref` items carry no `secret_id` in bulk export (the SDK calls `secrets.get()` separately for each ref it needs).

---

## Real-Time Config Delivery — SSE Stream

### Endpoint

```
GET /v1/config/stream?project_id={uuid}&env_id={uuid}
Authorization: Bearer sv_tok_...
```

`workspace_id` is redundant here — `project_id` is unique within a tenant — and is omitted from this endpoint. Returns `Content-Type: text/event-stream`.

### Connection Lifecycle

1. Client opens the SSE connection with an authenticated token.
2. Server validates auth and capability (`read` on the config path scope for this environment).
3. Server registers the connection in the per-`(project_id, env_id)` broadcast channel (`tokio::sync::broadcast::Sender<ConfigChangeEvent>`), created lazily on first subscriber.
4. Server sends a `connected` event immediately.
5. Server sends `: keepalive` comments every 30 seconds.
6. On any `config_versions` INSERT committed to Postgres, the handler calls `NOTIFY config_changes` with a routing-key-only payload (see Cross-Pod Fan-Out below). Each pod's dedicated LISTEN connection receives the notification and broadcasts to all locally-connected SSE clients for that scope.
7. On disconnect, the client reconnects with `Last-Event-ID`. The server replays events within the replay window (last 500 events or last 60 seconds, whichever is smaller). Beyond the window, the client must perform a full cache re-seed via bulk config export.

### Cross-Pod Fan-Out

Each pod maintains one dedicated, non-pooled Postgres connection subscribed to `LISTEN config_changes`. The `NOTIFY` payload contains **only routing keys — never config values**:

```json
{ "project_id": "uuid", "env_id": "uuid", "path": "server/port", "event_id": 8472 }
```

The receiving pod looks up the current value from Postgres after receiving the notification, then broadcasts a typed event to its local `broadcast::Sender`. This design keeps config values out of the Postgres WAL NOTIFY payload, enforces the 8 KB NOTIFY limit is never approached, and prevents `is_sensitive` config values from appearing in WAL archives.

The LISTEN connection is health-monitored with a periodic `SELECT 1` heartbeat and reconnects with exponential backoff on failure. When a reconnect is in progress, the relay task sends a `stream_interrupted` SSE event to all local subscribers so they fall back to 60-second polling rather than silently receiving stale data.

> **Ceiling note (ponytail):** This design handles approximately 50 pods × N subscribers per pod at moderate notification rates. At higher pod density, Postgres NOTIFY becomes a bottleneck. The documented upgrade path is Redis pub/sub as a fan-out relay with no SDK wire-protocol changes.

### Event Schema

**Config value change (non-`secret_ref`):**

```
id: 8472
event: config_change
data: {"path":"server/port","value_type":"int","value":9090,"version":3,"env_id":"uuid","project_id":"uuid","inherited_from_env_id":null}
```

**Config value change (`secret_ref`) — UUID omitted for subscribers lacking secret read:**

```
id: 8473
event: config_change
data: {"path":"database/password","value_type":"secret_ref","version":2,"env_id":"uuid","project_id":"uuid"}
```

`secret_id` is omitted from SSE events for `secret_ref` keys regardless of the subscriber's permissions. Subscribers who need the referenced secret UUID must call `GET .../config/{path}` explicitly. This prevents UUID enumeration via SSE.

**Config key deleted:**

```
id: 8474
event: config_delete
data: {"path":"deprecated/flag","version":4,"env_id":"uuid","project_id":"uuid"}
```

**Stream interrupted (LISTEN relay reconnecting):**

```
event: stream_interrupted
data: {"reason":"listen_reconnect","retry_after_ms":5000}
```

**Keepalive:**

```
: keepalive
```

**Connected:**

```
event: connected
data: {"server_time":"2026-06-23T12:00:00Z","env_id":"uuid","project_id":"uuid"}
```

### SDK Cache Semantics

The `soma-sdk` crate implements:

1. Startup: call bulk export to seed a `DashMap` in-process cache. Store `version_vector`.
2. Open SSE stream with `Last-Event-ID: <last-known-event-id>` (empty on first connect).
3. On `config_change` event: update the `DashMap` entry for the changed `path`.
4. On `stream_interrupted` event: switch to 60-second polling per key until reconnected.
5. `config.get::<T>(key)` is always a local `DashMap` read — zero network latency.
6. On reconnect: present `Last-Event-ID`. If the server signals the event is beyond the replay window, perform a full bulk re-seed before resuming the stream.

---

## Audit Log

Audit events are written to an append-only, HMAC-SHA256 hash-chained table. The HMAC key is derived from a **dedicated root secret distinct from the master KEK**: `HKDF-SHA256(audit_root_key, salt=b"soma-vault-audit-hmac-v1", info=tenant_id_bytes)`. The `audit_root_key` is a second KMS-wrapped key used exclusively for audit signing, ensuring that a master KEK compromise does not simultaneously break audit chain integrity.

The `seq_num` column uses a Postgres `SEQUENCE` object (not `MAX+1`) for reliable monotonic assignment. Per-tenant advisory lock (`pg_advisory_xact_lock`) serializes appends to maintain chain ordering.

**Audit logging tiers:**

- Secret creates, updates, deletes, destroys, rollbacks: synchronous within the request transaction. These are mutation events; the audit record is guaranteed before the response is sent.
- Secret reads: written via a bounded async channel (backpressure-safe). If the channel is full, a `CRITICAL` structured log is emitted and the read proceeds — the channel-full event itself is inserted synchronously as an `audit_channel_overflow` marker with the next `seq_num`, so the chain remains intact and verifiable. The overflow marker documents the gap rather than silently breaking the chain.
- Config mutations: synchronous.
- Config reads: not individually logged (config values are non-sensitive typed data; SSE event IDs provide an observable change history).

`resource_name` in audit entries is always `HMAC-SHA256(audit_hmac_key, secret_path_bytes)` — the raw secret path never appears in audit responses.

The `jti` column records the soma-iam JWT token ID from the session's originating token, providing a cross-platform correlation key for linking soma-vault session events to soma-iam token issuance records.

KMS infrastructure events (`kms_unseal_success`, `kms_unseal_fail`, etc.) are **not** stored in the tenant `audit_events` table. They are pod-scoped, not tenant-scoped, and belong in structured logs and the `/metrics` endpoint.

### Query Audit Events

```
GET /v1/audit
```

| Parameter | Description |
|-----------|-------------|
| `from` | Start of time range (RFC 3339) |
| `to` | End of time range (RFC 3339) |
| `event_type` | Filter by event type |
| `actor_id` | Filter by principal UUID |
| `resource_type` | `secret`, `config`, `policy`, `workspace`, `service_account`, `session` |
| `limit` / `offset` | Pagination |

**Response `200`:**

```json
{
  "items": [
    {
      "id": "uuid",
      "seq_num": 8471,
      "event_type": "secret_read",
      "actor_type": "service_account",
      "actor_id": "uuid",
      "actor_ip": "10.0.1.5",
      "resource_type": "secret",
      "resource_id": "uuid",
      "resource_name": "<hmac-sha256-hashed>",
      "outcome": "success",
      "reason": null,
      "jti": "soma-iam-jwt-id",
      "created_at": "2026-06-23T12:00:00Z"
    }
  ],
  "has_more": false
}
```

`reason` is a free-text break-glass justification field populated by callers who include `X-Audit-Reason: <text>` in their request header.

### Verify Audit Chain Integrity

```
GET /v1/audit/verify?from=2026-06-01T00:00:00Z&to=2026-06-23T00:00:00Z
```

Admin-only. Rate-limited to 5 req/min. Walks the HMAC-SHA256 hash chain for the range.

**Chain intact:**

```json
{
  "status": "intact",
  "from_seq": 1,
  "to_seq": 8471,
  "entries_checked": 8471
}
```

**Tamper detected:**

```json
{
  "status": "tampered",
  "first_bad_seq_num": 4203,
  "from_seq": 1,
  "to_seq": 8471
}
```

**Gap marker present (audit channel overflow):**

```json
{
  "status": "intact_with_gaps",
  "gap_markers": [{ "seq_num": 5010, "event_type": "audit_channel_overflow", "created_at": "..." }],
  "from_seq": 1,
  "to_seq": 8471
}
```

---

## Service Account Management

### List Service Accounts

```
GET /v1/workspaces/{workspace_id}/service-accounts
```

### Create Service Account

```
POST /v1/workspaces/{workspace_id}/service-accounts
```

```json
{ "name": "ci-deploy", "description": "GitHub Actions deploy pipeline" }
```

**Response `201 Created`:**

```json
{
  "id": "uuid",
  "name": "ci-deploy",
  "client_id": "uuid",
  "client_secret": "sv_sa_...",
  "created_at": "2026-06-23T12:00:00Z"
}
```

`client_secret` is shown exactly once. The server stores only the Argon2id hash.

### Rotate Service Account Secret

```
POST /v1/workspaces/{workspace_id}/service-accounts/{sa_id}/rotate-secret
```

Generates and returns a new `client_secret`, invalidates the old one, and preserves all role bindings and policies.

**Response `200 OK`:**

```json
{
  "client_id": "uuid",
  "client_secret": "sv_sa_...",
  "rotated_at": "2026-06-23T12:00:00Z"
}
```

### Get Service Account

```
GET /v1/workspaces/{workspace_id}/service-accounts/{sa_id}
```

```json
{
  "id": "uuid",
  "name": "ci-deploy",
  "client_id": "uuid",
  "last_used_at": "2026-06-23T11:55:00Z",
  "last_used_ip": "10.0.2.3",
  "created_at": "2026-06-23T12:00:00Z"
}
```

### Revoke Service Account

```
DELETE /v1/workspaces/{workspace_id}/service-accounts/{sa_id}
```

Invalidates all active session tokens for this service account. **Response `204 No Content`.**

---

## RBAC Policy (Path Capabilities)

The path-capability policy overlay is soma-vault-specific logic (workspace role bindings flow from soma-iam JWT claims; path-glob capabilities are stored here).

`capabilities` values: `read`, `write`, `list`, `delete`, `deny`. `deny` always wins over any other matching policy for the same principal and path. Policy changes are broadcast to all pods via Postgres LISTEN/NOTIFY (`NOTIFY policy_changes, '{"tenant_id":"...","workspace_id":"..."}'`); each pod's LISTEN connection clears the in-memory radix-trie cache for the affected tenant on receipt.

### List Policies

```
GET /v1/workspaces/{workspace_id}/policies
```

### Create Policy

```
POST /v1/workspaces/{workspace_id}/policies
```

```json
{
  "principal_id": "uuid",
  "path_glob": "secrets/database/*",
  "capabilities": ["read", "list"]
}
```

**Response `201 Created`.**

### Delete Policy

```
DELETE /v1/workspaces/{workspace_id}/policies/{policy_id}
```

**Response `204 No Content`.**

---

## Tenant Bootstrap (Admin)

Before any user can log in, the tenant row must exist in soma-vault's database. In the managed cloud SaaS, soma-iam calls `POST /v1/internal/tenants` (internal network only, not exposed through the public load balancer) via an HMAC-signed webhook when an org is provisioned. For self-hosted deployments, the same operation is available as a CLI command.

The internal endpoint is not part of the public API surface and is documented here for completeness.

**CLI:** `soma vault admin register-tenant --soma-iam-org-id <uuid> --name <name>`

This requires a server-side admin token (`SOMA_ADMIN_TOKEN` environment variable or a startup-generated one-time token printed to the server log on first boot). The operation is idempotent: if a tenant row for the given `soma_iam_org_id` already exists, it is returned without modification.

---

## Security Headers

All responses include:

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

Any response that may contain secret values additionally sets:

```
Cache-Control: no-store, no-cache, private
```

### Request Tracing

Every response includes `X-Request-ID` (UUID v4, server-generated or echoed from the client-provided `X-Request-ID` request header). This ID appears in structured logs and in `error.request_id`.

---

## Token Format

| Prefix | Type | Notes |
|--------|------|-------|
| `sv_tok_` | Human / service account session token | Short-lived signed JWT, 15-min TTL |
| `sv_sa_` | Service account `client_secret` | Shown once at creation; Argon2id hash stored |

---

## Endpoint Index

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/auth/login` | Exchange credential for session token |
| `POST` | `/v1/auth/refresh` | Refresh session token |
| `DELETE` | `/v1/auth/session` | Revoke current session |

### Health

| Method | Path | Auth |
|--------|------|------|
| `GET` | `/health/ready` | No |
| `GET` | `/health/startup` | No |
| `GET` | `/health/live` | No |
| `GET` | `/metrics` | Optional |

### Workspaces

| Method | Path |
|--------|------|
| `GET` | `/v1/workspaces` |
| `POST` | `/v1/workspaces` |
| `GET` | `/v1/workspaces/{workspace_id}` |
| `PATCH` | `/v1/workspaces/{workspace_id}` |
| `DELETE` | `/v1/workspaces/{workspace_id}` |
| `GET` | `/v1/workspaces/{workspace_id}/members` |
| `POST` | `/v1/workspaces/{workspace_id}/members` |
| `PATCH` | `/v1/workspaces/{workspace_id}/members/{principal_id}` |
| `DELETE` | `/v1/workspaces/{workspace_id}/members/{principal_id}` |

### Projects

| Method | Path |
|--------|------|
| `GET` | `/v1/workspaces/{workspace_id}/projects` |
| `POST` | `/v1/workspaces/{workspace_id}/projects` |
| `GET` | `/v1/workspaces/{workspace_id}/projects/{project_id}` |
| `PATCH` | `/v1/workspaces/{workspace_id}/projects/{project_id}` |
| `DELETE` | `/v1/workspaces/{workspace_id}/projects/{project_id}` |

### Environments

| Method | Path |
|--------|------|
| `GET` | `/v1/workspaces/{workspace_id}/projects/{project_id}/environments` |
| `POST` | `/v1/workspaces/{workspace_id}/projects/{project_id}/environments` |
| `GET` | `/v1/workspaces/{workspace_id}/projects/{project_id}/environments/{env_id}` |
| `DELETE` | `/v1/workspaces/{workspace_id}/projects/{project_id}/environments/{env_id}` |

### Secrets

Prefix: `/v1/workspaces/{workspace_id}/projects/{project_id}/environments/{env_id}/secrets`

| Method | Path |
|--------|------|
| `GET` | `.../secrets` |
| `PUT` | `.../secrets/{path}` |
| `GET` | `.../secrets/{path}` |
| `GET` | `.../secrets/{path}/metadata` |
| `PATCH` | `.../secrets/{path}/metadata` |
| `DELETE` | `.../secrets/{path}` |
| `POST` | `.../secrets/{path}/destroy` |
| `POST` | `.../secrets/{path}/rollback` |
| `GET` | `.../secrets/export` |

### Config

Prefix: `/v1/workspaces/{workspace_id}/projects/{project_id}/environments/{env_id}/config`

| Method | Path |
|--------|------|
| `GET` | `.../config` |
| `PUT` | `.../config/{path}` |
| `GET` | `.../config/{path}` |
| `GET` | `.../config/{path}/versions` |
| `DELETE` | `.../config/{path}` |

### Real-Time Stream

| Method | Path |
|--------|------|
| `GET` | `/v1/config/stream?project_id={uuid}&env_id={uuid}` |

### Audit

| Method | Path |
|--------|------|
| `GET` | `/v1/audit` |
| `GET` | `/v1/audit/verify` |

### Service Accounts

| Method | Path |
|--------|------|
| `GET` | `/v1/workspaces/{workspace_id}/service-accounts` |
| `POST` | `/v1/workspaces/{workspace_id}/service-accounts` |
| `GET` | `/v1/workspaces/{workspace_id}/service-accounts/{sa_id}` |
| `POST` | `/v1/workspaces/{workspace_id}/service-accounts/{sa_id}/rotate-secret` |
| `DELETE` | `/v1/workspaces/{workspace_id}/service-accounts/{sa_id}` |

### RBAC Policies

| Method | Path |
|--------|------|
| `GET` | `/v1/workspaces/{workspace_id}/policies` |
| `POST` | `/v1/workspaces/{workspace_id}/policies` |
| `DELETE` | `/v1/workspaces/{workspace_id}/policies/{policy_id}` |

---

## Explicit Out-of-Scope for Phase 1

The following are not in this API surface and must not be implemented or stubbed:

- Dynamic secrets / lease endpoints (`/v1/dynamic/*`, `/v1/leases/*`)
- Transit Encryption-as-a-Service (`/v1/transit/*`)
- PKI / certificate issuance (`/v1/pki/*`)
- SIEM export / audit streaming configuration
- Approval / change-request workflow
- GCP and Azure KMS backend configuration endpoints
- Secret scanning
- Honey tokens
- JSON Schema codegen endpoints
- Secret rotation scheduling or rotation job endpoints (Phase 2 — the infrastructure ships when at least one working rotation adapter is ready to validate the lifecycle end-to-end)

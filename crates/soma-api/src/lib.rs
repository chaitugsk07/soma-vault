//! axum router + bearer/cookie auth middleware + REST handlers for soma-vault.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use axum_extra::extract::CookieJar;
use http::header::{HeaderName, HeaderValue, AUTHORIZATION};
use serde::Deserialize;
use serde_json::{json, Value};
use soma_audit_core::{AuditEvent, Outcome};
use soma_audit_pg::LocalSink;
use soma_storage::{AuditCtx, DataStore, Error, ListParams, PgDataStore, Role, TenantId, ValueType};
use tower_http::set_header::SetResponseHeaderLayer;
use uuid::Uuid;

// ── Rate limiter ──────────────────────────────────────────────────────────────

// ponytail: per-pod in-memory fixed-window limiter — resets on restart, not
// shared across pods. Acceptable for v0.1; upgrade path = shared store (Redis
// or Postgres advisory counter) if cross-pod coordination is needed.
const AUTH_RATE_MAX: u32 = 10;
const AUTH_RATE_WINDOW: Duration = Duration::from_secs(60);

struct RateLimiter {
    hits: Mutex<HashMap<IpAddr, (Instant, u32)>>,
    max: u32,
    window: Duration,
}

impl RateLimiter {
    fn new(max: u32, window: Duration) -> Self {
        Self {
            hits: Mutex::new(HashMap::new()),
            max,
            window,
        }
    }

    /// Returns `true` if the request is allowed, `false` if rate-limited.
    fn check(&self, ip: IpAddr) -> bool {
        let mut map = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        // ponytail: crude cap so a flood of distinct IPs can't grow this unbounded.
        // Fixed-window means a full clear at worst resets one window for everyone.
        if map.len() > 10_000 { map.clear(); }
        let now = Instant::now();
        let entry = map.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            // Window elapsed — reset.
            *entry = (now, 1);
            true
        } else if entry.1 < self.max {
            entry.1 += 1;
            true
        } else {
            false
        }
    }
}

// ── Principal ─────────────────────────────────────────────────────────────────

/// Per-request authenticated identity, extracted from the auth middleware.
#[derive(Clone)]
pub struct Principal {
    /// Tenant that owns the token.
    pub tenant: TenantId,
    /// The token's primary key.
    pub token_id: Uuid,
    /// Role associated with the token.
    pub role: Role,
}

impl Principal {
    /// Returns `Ok(())` if the caller's role meets or exceeds `min`, else a 403 Response.
    #[allow(clippy::result_large_err)]
    fn require(&self, min: Role) -> Result<(), Response> {
        if role_rank(self.role) >= role_rank(min) {
            Ok(())
        } else {
            Err(forbidden(min))
        }
    }
}

impl<S> FromRequestParts<S> for Principal
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Principal>()
            .cloned()
            .ok_or_else(unauthorized)
    }
}

// ── Public state + constructor ────────────────────────────────────────────────

/// Shared application state threaded through all handlers.
#[derive(Clone)]
pub struct AppState {
    /// Storage backend (trait object — used for all trait-method calls).
    pub store: Arc<dyn DataStore>,
    /// Concrete Postgres store — used for atomic-audit `_audited` calls.
    pub pg_store: Arc<PgDataStore>,
    /// Audit sink — soma-audit LocalSink writing to vault's own Postgres.
    pub audit: Arc<LocalSink>,
    /// Whether the session cookie should carry the `Secure` flag.
    pub cookie_secure: bool,
    /// Per-IP rate limiter for auth endpoints.
    auth_limiter: Arc<RateLimiter>,
}

impl AppState {
    /// Construct application state with the default rate-limiter settings.
    pub fn new(pg_store: Arc<PgDataStore>, audit: Arc<LocalSink>, cookie_secure: bool) -> Self {
        let store: Arc<dyn DataStore> = pg_store.clone();
        Self {
            store,
            pg_store,
            audit,
            cookie_secure,
            auth_limiter: Arc::new(RateLimiter::new(AUTH_RATE_MAX, AUTH_RATE_WINDOW)),
        }
    }
}

/// Build the axum router. Call this once at startup and serve the result.
pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        // tokens
        .route("/auth/tokens", post(create_token).get(list_tokens))
        .route("/auth/tokens/{id}", delete(revoke_token))
        .route("/auth/me", get(auth_me))
        // projects
        .route("/projects", get(list_projects).post(create_project))
        // environments
        .route(
            "/projects/{project_id}/environments",
            get(list_environments).post(create_environment),
        )
        // secrets
        .route(
            "/projects/{project_id}/environments/{env_id}/secrets",
            get(list_secrets),
        )
        .route(
            "/projects/{project_id}/environments/{env_id}/secrets/{path}",
            get(get_secret).put(put_secret).delete(delete_secret),
        )
        .route(
            "/projects/{project_id}/environments/{env_id}/secrets/{path}/versions",
            get(list_secret_versions),
        )
        .route(
            "/projects/{project_id}/environments/{env_id}/secrets/{path}/rollback",
            post(rollback_secret),
        )
        // config
        .route(
            "/projects/{project_id}/environments/{env_id}/config",
            get(list_config),
        )
        .route(
            "/projects/{project_id}/environments/{env_id}/config/{key}",
            get(get_config).put(put_config).delete(delete_config),
        )
        .route(
            "/projects/{project_id}/environments/{env_id}/config/{key}/versions",
            get(list_config_versions),
        )
        .route(
            "/projects/{project_id}/environments/{env_id}/config/{key}/rollback",
            post(rollback_config),
        )
        // export
        .route(
            "/projects/{project_id}/environments/{env_id}/export",
            get(export),
        )
        // meta / EAV registry
        .route("/meta/entity-types", get(list_entity_types))
        .route("/meta/attr-defs", get(list_attr_defs).post(create_attr_def))
        .route(
            "/meta/attr-defs/{id}",
            patch(update_attr_def).delete(delete_attr_def),
        )
        // audit log
        .route("/audit", get(list_audit_handler))
        .route("/audit/verify", get(verify_audit_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Auth routes get a rate-limit layer on top of the base router.
    let auth_routes = Router::new()
        .route("/v1/auth/session", post(login).delete(logout))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ));

    Router::new()
        .route("/health", get(health))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/health/startup", get(health_startup))
        .merge(auth_routes)
        .nest("/v1", protected)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(
            tower::ServiceBuilder::new()
                .layer(SetResponseHeaderLayer::overriding(
                    HeaderName::from_static("x-content-type-options"),
                    HeaderValue::from_static("nosniff"),
                ))
                .layer(SetResponseHeaderLayer::overriding(
                    HeaderName::from_static("x-frame-options"),
                    HeaderValue::from_static("DENY"),
                )),
        )
        .with_state(state)
}

// ── Rate-limit middleware (auth routes only) ──────────────────────────────────

async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    // ConnectInfo is only available when served with into_make_service_with_connect_info.
    // In oneshot/test contexts it is absent — we allow the request through rather than panic.
    let client_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    if let Some(ip) = client_ip {
        if !state.auth_limiter.check(ip) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error":"too many requests"})),
            )
                .into_response();
        }
    }
    next.run(request).await
}

// ── Auth middleware ───────────────────────────────────────────────────────────

async fn auth_middleware(
    State(state): State<AppState>,
    jar: CookieJar,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    // Bearer token takes priority over cookie.
    let raw_token = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned)
        .or_else(|| jar.get("soma_session").map(|c| c.value().to_owned()));

    let Some(token) = raw_token else {
        return unauthorized();
    };

    match state.store.find_token_by_plaintext(&token).await {
        Ok(Some(auth_token)) => {
            let principal = Principal {
                tenant: TenantId(auth_token.tenant_id),
                token_id: auth_token.id,
                role: auth_token.role,
            };
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        Ok(None) => unauthorized(),
        Err(e) => {
            tracing::error!("auth lookup error: {e}");
            internal_error()
        }
    }
}

async fn auth_me(principal: Principal) -> impl IntoResponse {
    Json(json!({
        "ok": true,
        "tenant": principal.tenant,
        "token_id": principal.token_id,
        "role": principal.role,
    }))
}

// ── Small helpers ─────────────────────────────────────────────────────────────

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error":"unauthorized"})),
    )
        .into_response()
}

fn role_rank(r: Role) -> u8 {
    match r {
        Role::Reader => 0,
        Role::Developer => 1,
        Role::Admin => 2,
    }
}

fn forbidden(required: Role) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"error": format!("forbidden: requires {} role", required)})),
    )
        .into_response()
}

fn internal_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error":"internal error"})),
    )
        .into_response()
}

fn storage_err_to_response(e: Error) -> Response {
    match e {
        Error::NotFound => {
            (StatusCode::NOT_FOUND, Json(json!({"error":"not found"}))).into_response()
        }
        Error::Conflict(msg) => (StatusCode::CONFLICT, Json(json!({"error": msg}))).into_response(),
        Error::Validation(msg) => {
            (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response()
        }
        Error::WhitelistViolation => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error":"attribute key not in whitelist"})),
        )
            .into_response(),
        Error::CrossTenant => {
            (StatusCode::NOT_FOUND, Json(json!({"error":"not found"}))).into_response()
        }
        Error::Crypto(e) => {
            tracing::error!("crypto error: {e}");
            internal_error()
        }
        Error::Db(e) => {
            tracing::error!("db error: {e}");
            internal_error()
        }
        Error::Migrate(msg) => {
            tracing::error!("migrate error: {msg}");
            internal_error()
        }
        Error::Audit(msg) => {
            tracing::error!("audit error: {msg}");
            internal_error()
        }
        e => {
            tracing::error!("unknown error: {e}");
            internal_error()
        }
    }
}

// ── Pagination query params ───────────────────────────────────────────────────

const MAX_PAGE_SIZE: i64 = 500;
const DEFAULT_PAGE_SIZE: i64 = 100;

#[derive(Deserialize)]
struct PaginationParams {
    cursor: Option<String>,
    limit: Option<i64>,
}

impl From<PaginationParams> for ListParams {
    fn from(p: PaginationParams) -> Self {
        Self {
            cursor: p.cursor,
            limit: p.limit.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE),
        }
    }
}

// ── Health ────────────────────────────────────────────────────────────────────

// Reports seal backend; consumed by the dashboard's seal-health panel. The
// k8s probes use /health/live and /health/ready instead.
async fn health() -> impl IntoResponse {
    Json(json!({"status":"ok","seal_backend":"software"}))
}

async fn health_live() -> impl IntoResponse {
    Json(json!({"status":"alive"}))
}

async fn health_ready(State(state): State<AppState>) -> Response {
    match state.store.ping().await {
        Ok(()) => Json(json!({"status":"ready"})).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status":"unavailable"})),
        )
            .into_response(),
    }
}

// The router only exists after migrations complete (main.rs runs migrate before
// building the router), so reaching this handler proves startup is done.
async fn health_startup() -> impl IntoResponse {
    Json(json!({"status":"started"}))
}

// ── Session (login / logout) ──────────────────────────────────────────────────

#[derive(Deserialize)]
struct LoginBody {
    token: String,
}

async fn login(State(state): State<AppState>, Json(body): Json<LoginBody>) -> Response {
    match state.store.find_token_by_plaintext(&body.token).await {
        Ok(Some(_)) => {
            let cookie_val = format!(
                "soma_session={}; HttpOnly; SameSite=Strict; Path=/{}",
                body.token,
                if state.cookie_secure { "; Secure" } else { "" }
            );
            let Ok(hv) = HeaderValue::from_str(&cookie_val) else {
                return internal_error();
            };
            let mut resp = Json(json!({"ok":true})).into_response();
            resp.headers_mut().insert(http::header::SET_COOKIE, hv);
            resp
        }
        Ok(None) => unauthorized(),
        Err(e) => {
            tracing::error!("login lookup error: {e}");
            internal_error()
        }
    }
}

async fn logout() -> Response {
    let cookie_val = "soma_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0";
    let mut resp = Json(json!({"ok":true})).into_response();
    resp.headers_mut().insert(
        http::header::SET_COOKIE,
        HeaderValue::from_static(cookie_val),
    );
    resp
}

// ── Auth tokens ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CreateTokenBody {
    name: String,
    role: Option<Role>,
}

async fn create_token(
    State(state): State<AppState>,
    principal: Principal,
    Json(body): Json<CreateTokenBody>,
) -> Response {
    if let Err(r) = principal.require(Role::Admin) {
        let ev = make_denied_event(&principal, "token.create", "token", "");
        if let Err(e) = state.audit.record(&ev).await {
            tracing::error!(err = %e, "audit denied record failed");
        }
        return r;
    }
    // ponytail: role param accepted for future plumbing; storage create_token
    // always inserts 'admin' (column default). Role assignment needs a
    // storage-layer change outside this crate's scope.
    let _ = body.role;
    let ctx = AuditCtx {
        actor_id: principal.token_id,
        actor_role: principal.role.to_string(),
        event_type: "token.create",
        resource_type: "token",
        resource_id: body.name.clone(),
    };
    match state.pg_store.create_token_audited(&principal.tenant, &body.name, &ctx).await {
        Ok((meta, plaintext)) => {
            (
                StatusCode::CREATED,
                Json(json!({
                    "id": meta.id,
                    "name": meta.name,
                    "token": plaintext,
                    "created_at": meta.created_at,
                })),
            )
                .into_response()
        }
        Err(e) => storage_err_to_response(e),
    }
}

async fn list_tokens(State(state): State<AppState>, principal: Principal) -> Response {
    if let Err(r) = principal.require(Role::Admin) {
        return r;
    }
    match state.store.list_tokens(&principal.tenant).await {
        Ok(tokens) => Json(tokens).into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

async fn revoke_token(State(state): State<AppState>, principal: Principal, Path(id): Path<Uuid>) -> Response {
    if let Err(r) = principal.require(Role::Admin) {
        let ev = make_denied_event(&principal, "token.revoke", "token", &id.to_string());
        if let Err(e) = state.audit.record(&ev).await {
            tracing::error!(err = %e, "audit denied record failed");
        }
        return r;
    }
    let ctx = AuditCtx {
        actor_id: principal.token_id,
        actor_role: principal.role.to_string(),
        event_type: "token.revoke",
        resource_type: "token",
        resource_id: id.to_string(),
    };
    match state.pg_store.revoke_token_audited(&principal.tenant, id, &ctx).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

// ── Projects ──────────────────────────────────────────────────────────────────

async fn list_projects(
    State(state): State<AppState>,
    principal: Principal,
    Query(params): Query<PaginationParams>,
) -> Response {
    match state
        .store
        .list_projects(&principal.tenant, params.into())
        .await
    {
        Ok(page) => Json(page).into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct CreateProjectBody {
    code: String,
    name: String,
    description: Option<String>,
}

async fn create_project(
    State(state): State<AppState>,
    principal: Principal,
    Json(body): Json<CreateProjectBody>,
) -> Response {
    if let Err(r) = principal.require(Role::Developer) {
        let ev = make_denied_event(&principal, "project.create", "project", &body.code);
        if let Err(e) = state.audit.record(&ev).await {
            tracing::error!(err = %e, "audit denied record failed");
        }
        return r;
    }
    let ctx = AuditCtx {
        actor_id: principal.token_id,
        actor_role: principal.role.to_string(),
        event_type: "project.create",
        resource_type: "project",
        resource_id: body.code.clone(),
    };
    match state
        .pg_store
        .create_project_audited(
            &principal.tenant,
            &body.code,
            &body.name,
            body.description.as_deref(),
            &ctx,
        )
        .await
    {
        Ok(project) => (StatusCode::CREATED, Json(project)).into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

// ── Environments ──────────────────────────────────────────────────────────────

async fn list_environments(
    State(state): State<AppState>,
    principal: Principal,
    Path(project_id): Path<Uuid>,
) -> Response {
    match state
        .store
        .list_environments(&principal.tenant, project_id)
        .await
    {
        Ok(envs) => Json(envs).into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct CreateEnvBody {
    code: String,
    name: String,
    /// Optional parent environment id for inheritance. Must belong to the same project.
    parent_env_id: Option<Uuid>,
}

async fn create_environment(
    State(state): State<AppState>,
    principal: Principal,
    Path(project_id): Path<Uuid>,
    Json(body): Json<CreateEnvBody>,
) -> Response {
    if let Err(r) = principal.require(Role::Developer) {
        let ev = make_denied_event(&principal, "environment.create", "environment", &body.code);
        if let Err(e) = state.audit.record(&ev).await {
            tracing::error!(err = %e, "audit denied record failed");
        }
        return r;
    }
    let ctx = AuditCtx {
        actor_id: principal.token_id,
        actor_role: principal.role.to_string(),
        event_type: "environment.create",
        resource_type: "environment",
        resource_id: body.code.clone(),
    };
    match state
        .pg_store
        .create_environment_audited(
            &principal.tenant,
            project_id,
            &body.code,
            &body.name,
            body.parent_env_id,
            &ctx,
        )
        .await
    {
        Ok(env) => (StatusCode::CREATED, Json(env)).into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

// ── Cross-project guard ───────────────────────────────────────────────────────

/// Verify that `env_id` belongs to `project_id` within `tenant`.
/// Returns `Ok(())` when ownership matches, or an error `Response` otherwise.
async fn check_env_project(
    store: &dyn DataStore,
    tenant: &TenantId,
    project_id: Uuid,
    env_id: Uuid,
) -> Result<(), Response> {
    match store.get_environment(tenant, env_id).await {
        Ok(env) if env.project_id == project_id => Ok(()),
        Ok(_) => Err((StatusCode::NOT_FOUND, Json(json!({"error":"not found"}))).into_response()),
        Err(e) => Err(storage_err_to_response(e)),
    }
}

// ── Secrets ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct EnvPathParams {
    project_id: Uuid,
    env_id: Uuid,
}

#[derive(Deserialize)]
struct SecretPathParams {
    project_id: Uuid,
    env_id: Uuid,
    path: String,
}

async fn list_secrets(
    State(state): State<AppState>,
    principal: Principal,
    Path(params): Path<EnvPathParams>,
    Query(pagination): Query<PaginationParams>,
) -> Response {
    if let Err(r) = check_env_project(&*state.store, &principal.tenant, params.project_id, params.env_id).await {
        return r;
    }
    match state
        .store
        .list_secrets(&principal.tenant, params.env_id, pagination.into())
        .await
    {
        Ok(page) => Json(page).into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct PutSecretBody {
    value: String,
    #[serde(default)]
    attrs: HashMap<String, String>,
    cas: Option<i32>,
}

async fn put_secret(
    State(state): State<AppState>,
    principal: Principal,
    Path(params): Path<SecretPathParams>,
    Json(body): Json<PutSecretBody>,
) -> Response {
    if let Err(r) = principal.require(Role::Developer) {
        let ev = make_denied_event(&principal, "secret.write", "secret", &params.path);
        if let Err(e) = state.audit.record(&ev).await {
            tracing::error!(err = %e, "audit denied record failed");
        }
        return r;
    }
    if let Err(r) = check_env_project(&*state.store, &principal.tenant, params.project_id, params.env_id).await {
        return r;
    }
    let ctx = AuditCtx {
        actor_id: principal.token_id,
        actor_role: principal.role.to_string(),
        event_type: "secret.write",
        resource_type: "secret",
        resource_id: params.path.clone(),
    };
    match state
        .pg_store
        .put_secret_audited(
            &principal.tenant,
            params.env_id,
            &params.path,
            body.value.as_bytes(),
            body.attrs,
            body.cas,
            &ctx,
        )
        .await
    {
        Ok(meta) => Json(meta).into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct VersionQuery {
    version: Option<i32>,
}

#[derive(Deserialize)]
struct ConfigGetQuery {
    version: Option<i32>,
    /// When `true` and the value_type is `secret_ref`, decrypt the referenced
    /// secret and return its plaintext inline.
    #[serde(default)]
    resolve_refs: bool,
}

async fn get_secret(
    State(state): State<AppState>,
    principal: Principal,
    Path(params): Path<SecretPathParams>,
    Query(q): Query<VersionQuery>,
) -> Response {
    if let Err(r) = check_env_project(&*state.store, &principal.tenant, params.project_id, params.env_id).await {
        return r;
    }
    let ctx = AuditCtx {
        actor_id: principal.token_id,
        actor_role: principal.role.to_string(),
        event_type: "secret.read",
        resource_type: "secret",
        resource_id: params.path.clone(),
    };
    match state
        .pg_store
        .get_secret_audited(&principal.tenant, params.env_id, &params.path, q.version, &ctx)
        .await
    {
        Ok(revealed) => {
            let value = String::from_utf8_lossy(&revealed.plaintext).into_owned();
            let mut resp = Json(json!({
                "path": revealed.meta.path,
                "version": revealed.version,
                "value": value,
            }))
            .into_response();
            resp.headers_mut().insert(
                http::header::CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            );
            resp
        }
        Err(e) => storage_err_to_response(e),
    }
}

async fn list_secret_versions(
    State(state): State<AppState>,
    principal: Principal,
    Path(params): Path<SecretPathParams>,
) -> Response {
    if let Err(r) = check_env_project(&*state.store, &principal.tenant, params.project_id, params.env_id).await {
        return r;
    }
    match state
        .store
        .list_secret_versions(&principal.tenant, params.env_id, &params.path)
        .await
    {
        Ok(versions) => Json(versions).into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct RollbackBody {
    version: i32,
}

async fn rollback_secret(
    State(state): State<AppState>,
    principal: Principal,
    Path(params): Path<SecretPathParams>,
    Json(body): Json<RollbackBody>,
) -> Response {
    if let Err(r) = principal.require(Role::Developer) {
        let ev = make_denied_event(&principal, "secret.rollback", "secret", &params.path);
        if let Err(e) = state.audit.record(&ev).await {
            tracing::error!(err = %e, "audit denied record failed");
        }
        return r;
    }
    if let Err(r) = check_env_project(&*state.store, &principal.tenant, params.project_id, params.env_id).await {
        return r;
    }
    let ctx = AuditCtx {
        actor_id: principal.token_id,
        actor_role: principal.role.to_string(),
        event_type: "secret.rollback",
        resource_type: "secret",
        resource_id: params.path.clone(),
    };
    match state
        .pg_store
        .rollback_secret_audited(&principal.tenant, params.env_id, &params.path, body.version, &ctx)
        .await
    {
        Ok(secret) => Json(secret).into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

async fn delete_secret(
    State(state): State<AppState>,
    principal: Principal,
    Path(params): Path<SecretPathParams>,
) -> Response {
    if let Err(r) = principal.require(Role::Developer) {
        let ev = make_denied_event(&principal, "secret.delete", "secret", &params.path);
        if let Err(e) = state.audit.record(&ev).await {
            tracing::error!(err = %e, "audit denied record failed");
        }
        return r;
    }
    if let Err(r) = check_env_project(&*state.store, &principal.tenant, params.project_id, params.env_id).await {
        return r;
    }
    let ctx = AuditCtx {
        actor_id: principal.token_id,
        actor_role: principal.role.to_string(),
        event_type: "secret.delete",
        resource_type: "secret",
        resource_id: params.path.clone(),
    };
    match state
        .pg_store
        .delete_secret_audited(&principal.tenant, params.env_id, &params.path, &ctx)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ConfigKeyParams {
    project_id: Uuid,
    env_id: Uuid,
    key: String,
}

async fn list_config(
    State(state): State<AppState>,
    principal: Principal,
    Path(params): Path<EnvPathParams>,
    Query(pagination): Query<PaginationParams>,
) -> Response {
    if let Err(r) = check_env_project(&*state.store, &principal.tenant, params.project_id, params.env_id).await {
        return r;
    }
    match state
        .store
        .list_config(&principal.tenant, params.env_id, pagination.into())
        .await
    {
        Ok(page) => Json(page).into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct PutConfigBody {
    value: String,
    #[serde(rename = "type")]
    value_type: String,
    #[serde(default)]
    attrs: HashMap<String, String>,
}

async fn put_config(
    State(state): State<AppState>,
    principal: Principal,
    Path(params): Path<ConfigKeyParams>,
    Json(body): Json<PutConfigBody>,
) -> Response {
    if let Err(r) = principal.require(Role::Developer) {
        let ev = make_denied_event(&principal, "config.write", "config", &params.key);
        if let Err(e) = state.audit.record(&ev).await {
            tracing::error!(err = %e, "audit denied record failed");
        }
        return r;
    }
    if let Err(r) = check_env_project(&*state.store, &principal.tenant, params.project_id, params.env_id).await {
        return r;
    }
    let vt: ValueType = match body.value_type.parse() {
        Ok(vt) => vt,
        Err(e) => return storage_err_to_response(e),
    };
    let ctx = AuditCtx {
        actor_id: principal.token_id,
        actor_role: principal.role.to_string(),
        event_type: "config.write",
        resource_type: "config",
        resource_id: params.key.clone(),
    };
    match state
        .pg_store
        .put_config_audited(
            &principal.tenant,
            params.env_id,
            &params.key,
            &body.value,
            vt,
            body.attrs,
            &ctx,
        )
        .await
    {
        Ok(cv) => Json(cv).into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

async fn get_config(
    State(state): State<AppState>,
    principal: Principal,
    Path(params): Path<ConfigKeyParams>,
    Query(q): Query<ConfigGetQuery>,
) -> Response {
    if let Err(r) = check_env_project(&*state.store, &principal.tenant, params.project_id, params.env_id).await {
        return r;
    }
    match state
        .store
        .get_config_resolved(&principal.tenant, params.env_id, &params.key, q.version, q.resolve_refs)
        .await
    {
        Ok(rc) => Json(rc).into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

async fn list_config_versions(
    State(state): State<AppState>,
    principal: Principal,
    Path(params): Path<ConfigKeyParams>,
) -> Response {
    if let Err(r) = check_env_project(&*state.store, &principal.tenant, params.project_id, params.env_id).await {
        return r;
    }
    match state
        .store
        .list_config_versions(&principal.tenant, params.env_id, &params.key)
        .await
    {
        Ok(versions) => Json(versions).into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

async fn rollback_config(
    State(state): State<AppState>,
    principal: Principal,
    Path(params): Path<ConfigKeyParams>,
    Json(body): Json<RollbackBody>,
) -> Response {
    if let Err(r) = principal.require(Role::Developer) {
        let ev = make_denied_event(&principal, "config.rollback", "config", &params.key);
        if let Err(e) = state.audit.record(&ev).await {
            tracing::error!(err = %e, "audit denied record failed");
        }
        return r;
    }
    if let Err(r) = check_env_project(&*state.store, &principal.tenant, params.project_id, params.env_id).await {
        return r;
    }
    let ctx = AuditCtx {
        actor_id: principal.token_id,
        actor_role: principal.role.to_string(),
        event_type: "config.rollback",
        resource_type: "config",
        resource_id: params.key.clone(),
    };
    match state
        .pg_store
        .rollback_config_audited(&principal.tenant, params.env_id, &params.key, body.version, &ctx)
        .await
    {
        Ok(ck) => Json(ck).into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

async fn delete_config(
    State(state): State<AppState>,
    principal: Principal,
    Path(params): Path<ConfigKeyParams>,
) -> Response {
    if let Err(r) = principal.require(Role::Developer) {
        let ev = make_denied_event(&principal, "config.delete", "config", &params.key);
        if let Err(e) = state.audit.record(&ev).await {
            tracing::error!(err = %e, "audit denied record failed");
        }
        return r;
    }
    if let Err(r) = check_env_project(&*state.store, &principal.tenant, params.project_id, params.env_id).await {
        return r;
    }
    let ctx = AuditCtx {
        actor_id: principal.token_id,
        actor_role: principal.role.to_string(),
        event_type: "config.delete",
        resource_type: "config",
        resource_id: params.key.clone(),
    };
    match state
        .pg_store
        .delete_config_audited(&principal.tenant, params.env_id, &params.key, &ctx)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

// ── Export ────────────────────────────────────────────────────────────────────

async fn export(State(state): State<AppState>, principal: Principal, Path(params): Path<EnvPathParams>) -> Response {
    if let Err(r) = check_env_project(&*state.store, &principal.tenant, params.project_id, params.env_id).await {
        return r;
    }
    match state.store.export(&principal.tenant, params.env_id).await {
        Ok(bundle) => {
            let errors: Vec<Value> = bundle
                .decrypt_errors
                .into_iter()
                .map(|(path, desc)| json!([path, desc]))
                .collect();
            Json(json!({
                "values": bundle.values,
                "errors": errors,
            }))
            .into_response()
        }
        Err(e) => storage_err_to_response(e),
    }
}

// ── Meta / EAV registry ───────────────────────────────────────────────────────

async fn list_entity_types(State(state): State<AppState>) -> Response {
    match state.store.list_entity_types().await {
        Ok(types) => Json(types).into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct ListAttrDefsQuery {
    entity_type: Option<String>,
}

async fn list_attr_defs(
    State(state): State<AppState>,
    Query(q): Query<ListAttrDefsQuery>,
) -> Response {
    let et = q.entity_type.as_deref().unwrap_or("secret");
    match state.store.list_attr_defs(et).await {
        Ok(defs) => Json(defs).into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct CreateAttrDefBody {
    entity_type: String,
    code: String,
    name: String,
    data_type: String,
    #[serde(default)]
    is_required: bool,
    #[serde(default)]
    is_pii: bool,
    #[serde(default)]
    sort_order: i32,
}

async fn create_attr_def(
    State(state): State<AppState>,
    principal: Principal,
    Json(body): Json<CreateAttrDefBody>,
) -> Response {
    if let Err(r) = principal.require(Role::Admin) {
        let ev = make_denied_event(&principal, "attr_def.create", "attr_def", &body.code);
        if let Err(e) = state.audit.record(&ev).await {
            tracing::error!(err = %e, "audit denied record failed");
        }
        return r;
    }
    match state
        .store
        .create_attr_def(
            &body.entity_type,
            &body.code,
            &body.name,
            &body.data_type,
            body.is_required,
            body.is_pii,
            body.sort_order,
        )
        .await
    {
        Ok(def) => (StatusCode::CREATED, Json(def)).into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct UpdateAttrDefBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    is_required: Option<bool>,
    #[serde(default)]
    is_pii: Option<bool>,
    #[serde(default)]
    sort_order: Option<i32>,
}

async fn update_attr_def(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateAttrDefBody>,
) -> Response {
    if let Err(r) = principal.require(Role::Admin) {
        let ev = make_denied_event(&principal, "attr_def.update", "attr_def", &id.to_string());
        if let Err(e) = state.audit.record(&ev).await {
            tracing::error!(err = %e, "audit denied record failed");
        }
        return r;
    }
    match state
        .store
        .update_attr_def(
            id,
            body.name.as_deref(),
            body.is_required,
            body.is_pii,
            body.sort_order,
        )
        .await
    {
        Ok(def) => Json(def).into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

async fn delete_attr_def(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(r) = principal.require(Role::Admin) {
        let ev = make_denied_event(&principal, "attr_def.delete", "attr_def", &id.to_string());
        if let Err(e) = state.audit.record(&ev).await {
            tracing::error!(err = %e, "audit denied record failed");
        }
        return r;
    }
    match state.store.delete_attr_def(id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => storage_err_to_response(e),
    }
}

// ── Audit log ─────────────────────────────────────────────────────────────────

/// Build a denied `soma_audit_core::AuditEvent` when role check fails.
fn make_denied_event(
    principal: &Principal,
    event_type: &str,
    resource_type: &str,
    resource_id: &str,
) -> AuditEvent {
    AuditEvent::builder(principal.tenant.as_uuid(), event_type, Outcome::Denied)
        .source_service("soma-vault")
        .actor_id(principal.token_id)
        .actor_role(principal.role.to_string())
        .resource(resource_type, resource_id)
        .build()
}


#[derive(Deserialize)]
struct AuditQuery {
    event_type: Option<String>,
    limit: Option<i64>,
    cursor: Option<i64>,
}

async fn list_audit_handler(
    State(state): State<AppState>,
    principal: Principal,
    Query(q): Query<AuditQuery>,
) -> Response {
    if let Err(r) = principal.require(Role::Admin) {
        return r;
    }
    let limit = q.limit.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);
    match state.audit.list(
        principal.tenant.as_uuid(),
        soma_audit_pg::ListFilter { event_type: q.event_type.as_deref(), cursor: q.cursor, ..Default::default() },
        limit,
    ).await {
        Ok((records, next_cursor)) => Json(json!({
            "items": records,
            "next_cursor": next_cursor,
        })).into_response(),
        Err(e) => {
            tracing::error!(err = %e, "audit list failed");
            internal_error()
        }
    }
}

async fn verify_audit_handler(
    State(state): State<AppState>,
    principal: Principal,
) -> Response {
    if let Err(r) = principal.require(Role::Admin) {
        return r;
    }
    match state.audit.verify(principal.tenant.as_uuid()).await {
        Ok(result) => Json(result).into_response(),
        Err(e) => {
            tracing::error!(err = %e, "audit verify failed");
            internal_error()
        }
    }
}

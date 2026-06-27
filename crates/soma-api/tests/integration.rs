//! Integration tests for soma-api. Require a live Postgres instance via
//! `TEST_DATABASE_URL`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use soma_api::{router, AppState};
use soma_audit_pg::{AuditKeys, LocalSink};
use soma_infra::TestDb;
use soma_storage::{DataStore, PgDataStore, TenantId};
use tower::ServiceExt;
use soma_storage::Role;

// Fixed test audit keys (32 bytes each, deterministic).
const TEST_AUDIT_MASTER: [u8; 32] = [0xaa; 32];
const TEST_AUDIT_SIGNING: [u8; 32] = [0xbb; 32];

// ── Test DB helpers ───────────────────────────────────────────────────────────

async fn setup() -> (AppState, TestDb) {
    let db = TestDb::create_from_env()
        .await
        .expect("TestDb::create_from_env — set TEST_DATABASE_URL");

    let kek = soma_crypto::MasterKek::from_hex(
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    )
    .unwrap();

    let store = PgDataStore::new(db.pool.clone(), kek);
    store.migrate().await.expect("migrate");

    // Install soma-audit schema and build LocalSink for tests.
    soma_audit_pg::install(&db.pool).await.expect("soma-audit install");
    let audit_keys = Arc::new(AuditKeys::from_secret(TEST_AUDIT_MASTER, TEST_AUDIT_SIGNING));
    let audit = Arc::new(LocalSink::new(db.pool.clone(), audit_keys, "soma-vault-test"));

    // Wire audit into the store for atomic audit recording.
    let store = Arc::new(store.into_with_audit(audit.clone()));
    let state = AppState::new(store, audit, false);

    (state, db)
}

// Helper: build a request with auth bearer token.
fn authed_request(method: &str, uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

// Helper: read response body as JSON.
async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1_048_576)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ── Test 1: 401 without token ─────────────────────────────────────────────────

#[tokio::test]
async fn test_401_without_token() {
    let (state, _guard) = setup().await;
    let app = router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/projects")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── Test 2: Auth via bearer AND cookie ───────────────────────────────────────

#[tokio::test]
async fn test_auth_bearer_and_cookie() {
    let (state, _guard) = setup().await;

    // Mint a token first — we need a token to call the token endpoint, but
    // the protected endpoint requires auth. Bootstrap by calling create_token
    // directly on the store.
    let (_, plaintext) = state
        .store
        .create_token(&TenantId::default(), "bootstrap")
        .await
        .unwrap();

    // (a) Bearer works.
    let resp = router(state.clone())
        .oneshot(authed_request("GET", "/v1/projects", &plaintext))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "bearer should succeed");

    // (b) POST /v1/auth/session sets an HttpOnly SameSite=Strict cookie.
    let resp = router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/session")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({"token": plaintext})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .expect("set-cookie header")
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        set_cookie.contains("HttpOnly"),
        "cookie must be HttpOnly: {set_cookie}"
    );
    assert!(
        set_cookie.contains("SameSite=Strict"),
        "cookie must be SameSite=Strict: {set_cookie}"
    );

    // (c) Cookie auth works.
    let resp = router(state.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/projects")
                .header("cookie", format!("soma_session={plaintext}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "cookie auth should succeed");
}

// ── Test 3: Happy CRUD ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_happy_crud() {
    let (state, _guard) = setup().await;

    let (_, token) = state
        .store
        .create_token(&TenantId::default(), "test-token")
        .await
        .unwrap();

    // Create project.
    let resp = router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/projects")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({"code":"myproj","name":"My Project"}))
                        .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let proj: serde_json::Value = body_json(resp).await;
    let project_id = proj["id"].as_str().unwrap().to_owned();

    // Create environment.
    let resp = router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/projects/{project_id}/environments"))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({"code":"dev","name":"Dev"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let env: serde_json::Value = body_json(resp).await;
    let env_id = env["id"].as_str().unwrap().to_owned();

    let secret_base = format!("/v1/projects/{project_id}/environments/{env_id}/secrets");

    // PUT secret.
    let resp = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("{secret_base}/mykey"))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({"value":"hunter2"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // GET secret.
    let resp = router(state.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("{secret_base}/mykey"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let got: serde_json::Value = body_json(resp).await;
    assert_eq!(got["value"].as_str(), Some("hunter2"));
    assert_eq!(got["path"].as_str(), Some("mykey"));

    // GET secret has Cache-Control: no-store
    let resp = router(state.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("{secret_base}/mykey"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "secret GET must have Cache-Control: no-store"
    );

    // LIST secrets — should show up without a "value" field.
    let resp = router(state.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(secret_base.clone())
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let list: serde_json::Value = body_json(resp).await;
    let items = list["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert!(
        items[0].get("value").is_none(),
        "list secrets must not expose plaintext"
    );
    assert_eq!(items[0]["path"].as_str(), Some("mykey"));
}

// ── Test 4: 400 on bad config type ───────────────────────────────────────────

#[tokio::test]
async fn test_bad_config_type_400() {
    let (state, _guard) = setup().await;

    let (_, token) = state
        .store
        .create_token(&TenantId::default(), "test-token")
        .await
        .unwrap();

    // Bootstrap project + env via store directly for brevity.
    let proj = state
        .store
        .create_project(&TenantId::default(), "p", "P", None)
        .await
        .unwrap();
    let env = state
        .store
        .create_environment(&TenantId::default(), proj.id, "dev", "Dev", None)
        .await
        .unwrap();

    let config_uri = format!(
        "/v1/projects/{}/environments/{}/config/mykey",
        proj.id, env.id
    );

    // "abc" is not a valid int.
    let resp = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(config_uri)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({"value":"abc","type":"int"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "invalid int value must return 400"
    );
}

// ── Test 5: Export — secret wins over config on collision ─────────────────────

#[tokio::test]
async fn test_export_secret_wins() {
    let (state, _guard) = setup().await;

    let (_, token) = state
        .store
        .create_token(&TenantId::default(), "test-token")
        .await
        .unwrap();

    let proj = state
        .store
        .create_project(&TenantId::default(), "exp", "Exp", None)
        .await
        .unwrap();
    let env = state
        .store
        .create_environment(&TenantId::default(), proj.id, "dev", "Dev", None)
        .await
        .unwrap();

    let secret_base = format!("/v1/projects/{}/environments/{}/secrets", proj.id, env.id);
    let config_base = format!("/v1/projects/{}/environments/{}/config", proj.id, env.id);
    let export_uri = format!("/v1/projects/{}/environments/{}/export", proj.id, env.id);

    // PUT secret "SHARED_KEY".
    router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("{secret_base}/SHARED_KEY"))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({"value":"secret-wins"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // PUT config "SHARED_KEY" with different value.
    router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("{config_base}/SHARED_KEY"))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(
                    serde_json::to_vec(
                        &serde_json::json!({"value":"config-loses","type":"string"}),
                    )
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // PUT config "ONLY_CONFIG" which won't collide.
    router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("{config_base}/ONLY_CONFIG"))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({"value":"config-only","type":"string"}))
                        .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // GET export.
    let resp = router(state.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&export_uri)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bundle: serde_json::Value = body_json(resp).await;

    assert_eq!(
        bundle["values"]["SHARED_KEY"].as_str(),
        Some("secret-wins"),
        "secret must win over config on collision"
    );
    assert_eq!(
        bundle["values"]["ONLY_CONFIG"].as_str(),
        Some("config-only"),
        "non-colliding config key must appear"
    );
}

// ── Test 6: Token self-identifies its tenant ──────────────────────────────────

#[tokio::test]
async fn test_token_resolves_own_tenant() {
    let (state, _guard) = setup().await;
    // Create a token via the store (minting it for default tenant).
    let (_, plaintext) = state
        .store
        .create_token(&TenantId::default(), "tenant-id-test")
        .await
        .unwrap();

    // find_token_by_plaintext no longer requires a tenant arg — the token knows its own tenant.
    let found = state
        .store
        .find_token_by_plaintext(&plaintext)
        .await
        .unwrap()
        .expect("token should be found");

    assert_eq!(
        found.tenant_id,
        TenantId::default().0,
        "token must self-identify its tenant"
    );
    assert_eq!(found.role, Role::Admin, "default role is admin");
}

// ── Test 7: RBAC — role gates enforce correctly ───────────────────────────────

#[tokio::test]
async fn test_rbac() {
    let (state, db) = setup().await;

    let tenant_id = TenantId::default().0;

    // Mint an admin token via store (default role = admin).
    let (_, admin_token) = state
        .store
        .create_token(&TenantId::default(), "admin-token")
        .await
        .unwrap();

    // Bootstrap a project + env for read/write tests.
    let proj = state
        .store
        .create_project(&TenantId::default(), "rbac-proj", "RBAC Proj", None)
        .await
        .unwrap();
    let env = state
        .store
        .create_environment(&TenantId::default(), proj.id, "dev", "Dev", None)
        .await
        .unwrap();

    let secret_uri = format!(
        "/v1/projects/{}/environments/{}/secrets/rbac-key",
        proj.id, env.id
    );

    // Seed one secret using the admin token so readers can GET it.
    router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(&secret_uri)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({"value": "super-secret"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Insert reader and developer tokens directly (store always creates admin role).
    use sha2::{Digest, Sha256};
    let reader_plaintext = "test-reader-token-hex32bytes00000";
    let dev_plaintext    = "test-developer-token-hex32bytes00";

    let reader_hash = hex::encode(Sha256::digest(reader_plaintext.as_bytes()));
    let dev_hash    = hex::encode(Sha256::digest(dev_plaintext.as_bytes()));

    sqlx::query(
        r#"INSERT INTO "01_vault"."11_fct_auth_tokens"
           (id, tenant_id, name, token_hash, role, is_revoked, created_at)
           VALUES (gen_random_uuid(), $1, 'reader-tok', $2, 'reader', false, now()),
                  (gen_random_uuid(), $1, 'dev-tok',    $3, 'developer', false, now())"#,
    )
    .bind(tenant_id)
    .bind(&reader_hash)
    .bind(&dev_hash)
    .execute(&db.pool)
    .await
    .unwrap();

    // ── reader: GET secret → 200 ─────────────────────────────────────────────
    let resp = router(state.clone())
        .oneshot(authed_request("GET", &secret_uri, reader_plaintext))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "reader GET secret should be 200");

    // ── reader: PUT secret → 403 ─────────────────────────────────────────────
    let resp = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(&secret_uri)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {reader_plaintext}"))
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({"value": "evil"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "reader PUT secret should be 403");

    // ── reader: POST /v1/auth/tokens → 403 ───────────────────────────────────
    let resp = router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/tokens")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {reader_plaintext}"))
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({"name": "reader-trying-admin"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "reader create_token should be 403");

    // ── developer: PUT secret → 200 ──────────────────────────────────────────
    let resp = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(&secret_uri)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {dev_plaintext}"))
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({"value": "dev-updated"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "developer PUT secret should be 200");

    // ── developer: POST /v1/auth/tokens → 403 ────────────────────────────────
    let resp = router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/tokens")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {dev_plaintext}"))
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({"name": "dev-trying-admin"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "developer create_token should be 403");

    // ── admin: POST /v1/auth/tokens → 201 ────────────────────────────────────
    let resp = router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/tokens")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({"name": "new-token"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "admin create_token should be 201");
}

// ── Test 8: Audit — admin sees entries, reader gets 403 ──────────────────────

#[tokio::test]
async fn test_audit_rbac() {
    let (state, db) = setup().await;

    let (_, admin_token) = state
        .store
        .create_token(&TenantId::default(), "audit-admin")
        .await
        .unwrap();

    // Insert a reader token.
    use sha2::{Digest, Sha256};
    let reader_plaintext = "audit-reader-token-hex32bytes000";
    let reader_hash = hex::encode(Sha256::digest(reader_plaintext.as_bytes()));
    sqlx::query(
        r#"INSERT INTO "01_vault"."11_fct_auth_tokens"
           (id, tenant_id, name, token_hash, role, is_revoked, created_at)
           VALUES (gen_random_uuid(), $1, 'audit-reader', $2, 'reader', false, now())"#,
    )
    .bind(TenantId::default().0)
    .bind(&reader_hash)
    .execute(&db.pool)
    .await
    .unwrap();

    // Do a mutation to generate an audit entry.
    let proj = state
        .store
        .create_project(&TenantId::default(), "audit-p", "Audit P", None)
        .await
        .unwrap();
    let env = state
        .store
        .create_environment(&TenantId::default(), proj.id, "dev", "Dev", None)
        .await
        .unwrap();

    // PUT secret via the HTTP API (this triggers record_audit in the handler).
    let secret_uri = format!(
        "/v1/projects/{}/environments/{}/secrets/audit-key",
        proj.id, env.id
    );
    router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(&secret_uri)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({"value": "audit-test"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Admin can GET /v1/audit → 200.
    let resp = router(state.clone())
        .oneshot(authed_request("GET", "/v1/audit", &admin_token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "admin should see audit entries");
    let body: serde_json::Value = body_json(resp).await;
    assert!(body["items"].is_array(), "should have items array");

    // Admin can GET /v1/audit/verify → 200.
    let resp = router(state.clone())
        .oneshot(authed_request("GET", "/v1/audit/verify", &admin_token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "admin should access audit verify");
    let verify: serde_json::Value = body_json(resp).await;
    assert_eq!(verify["ok"].as_bool(), Some(true), "chain should be intact");

    // Reader gets 403 on /v1/audit.
    let resp = router(state.clone())
        .oneshot(authed_request("GET", "/v1/audit", reader_plaintext))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "reader should get 403 on audit");
}

// ── Test 9: Atomic audit — project.create appears in audit list ──────────────

#[tokio::test]
async fn test_atomic_audit() {
    let (state, _guard) = setup().await;

    let (_, token) = state
        .store
        .create_token(&TenantId::default(), "atomic-audit-admin")
        .await
        .unwrap();

    // Create a project via the HTTP API.
    let resp = router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/projects")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({"code":"atomic-proj","name":"Atomic"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Audit list should have at least one entry with event_type "project.create".
    let resp = router(state.clone())
        .oneshot(authed_request("GET", "/v1/audit", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = body_json(resp).await;
    let items = body["items"].as_array().expect("items array");
    let has_create = items.iter().any(|i| i["event_type"].as_str() == Some("project.create"));
    assert!(has_create, "should have a project.create audit entry");

    // Verify chain is intact.
    let resp = router(state.clone())
        .oneshot(authed_request("GET", "/v1/audit/verify", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let verify: serde_json::Value = body_json(resp).await;
    assert_eq!(verify["ok"].as_bool(), Some(true), "chain should be intact");
    assert!(verify["entries_checked"].as_u64().unwrap_or(0) > 0, "entries_checked must be > 0");
}

// ── Test 10: Denial audit — unauthorized create_token shows outcome=denied ───

#[tokio::test]
async fn test_denial_audit() {
    let (state, db) = setup().await;

    let (_, admin_token) = state
        .store
        .create_token(&TenantId::default(), "denial-admin")
        .await
        .unwrap();

    // Insert a reader token.
    use sha2::{Digest, Sha256};
    let reader_plaintext = "denial-reader-token-hex32bytes00";
    let reader_hash = hex::encode(Sha256::digest(reader_plaintext.as_bytes()));
    sqlx::query(
        r#"INSERT INTO "01_vault"."11_fct_auth_tokens"
           (id, tenant_id, name, token_hash, role, is_revoked, created_at)
           VALUES (gen_random_uuid(), $1, 'denial-reader', $2, 'reader', false, now())"#,
    )
    .bind(TenantId::default().0)
    .bind(&reader_hash)
    .execute(&db.pool)
    .await
    .unwrap();

    // Reader tries POST /v1/auth/tokens → 403 (requires Admin).
    let resp = router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/tokens")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {reader_plaintext}"))
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({"name": "reader-probe"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Admin checks audit list — should contain an entry with outcome "denied".
    let resp = router(state.clone())
        .oneshot(authed_request("GET", "/v1/audit", &admin_token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = body_json(resp).await;
    let items = body["items"].as_array().expect("items array");
    let has_denied = items.iter().any(|i| i["outcome"].as_str() == Some("denied"));
    assert!(has_denied, "should have a denied audit entry after 403");
}

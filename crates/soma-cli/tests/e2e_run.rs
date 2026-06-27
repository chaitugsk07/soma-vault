//! E2E test for `soma run`: spins up a real axum server with a test DB,
//! seeds a secret, then invokes the CLI binary to verify it injects the value.

use std::net::TcpListener;
use std::sync::Arc;

use axum::serve;
use soma_api::{router, AppState};
use soma_audit_pg::{AuditKeys, LocalSink};
use soma_infra::TestDb;
use soma_crypto::MasterKek;
use soma_storage::{DataStore, PgDataStore, TenantId};

/// All-zeros 32-byte KEK expressed as 64 hex chars.
const TEST_KEK: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MIGRATIONS_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations");

#[tokio::test]
async fn soma_run_injects_secret() {
    // ── 1. Isolated database ───────────────────────────────────────────────────
    let db = TestDb::create_from_env()
        .await
        .expect("TestDb::create_from_env — set TEST_DATABASE_URL");

    // ── 2. Run migrations ──────────────────────────────────────────────────────
    {
        use soma_schema::{Migrator, PostgresConfig, PostgresDriver};
        let cfg = PostgresConfig {
            schema: Some("01_vault".into()),
            advisory_lock_key: 0x050A_1A33_5641_0017_i64,
            ..Default::default()
        };
        let driver = PostgresDriver::new(db.pool.clone(), cfg).expect("create driver");
        Migrator::from_root(MIGRATIONS_ROOT)
            .up(&driver)
            .await
            .expect("migrations");
    }

    // ── 3. Seed store ──────────────────────────────────────────────────────────
    let kek = MasterKek::from_hex(TEST_KEK).expect("parse test KEK");
    let store = PgDataStore::new(db.pool.clone(), kek);
    let tenant = TenantId::default();

    let (_token_meta, token) = store
        .create_token(&tenant, "test")
        .await
        .expect("create_token");

    let project = store
        .create_project(&tenant, "demo", "demo", None)
        .await
        .expect("create_project");

    let env = store
        .create_environment(&tenant, project.id, "dev", "dev", None)
        .await
        .expect("create_environment");

    store
        .put_secret(
            &tenant,
            env.id,
            "database/password",
            b"s3cr3t",
            Default::default(),
            None,
        )
        .await
        .expect("put_secret");

    // ── 4. Serve the axum router ───────────────────────────────────────────────
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let base_url = format!("http://{addr}");
    // tokio::net::TcpListener::from_std requires the socket to already be non-blocking.
    listener.set_nonblocking(true).expect("set_nonblocking");

    // Install soma-audit schema and build LocalSink for the test server.
    soma_audit_pg::install(&db.pool).await.expect("soma-audit install");
    let audit_keys = Arc::new(AuditKeys::from_secret([0xaa; 32], [0xbb; 32]));
    let audit = Arc::new(LocalSink::new(db.pool.clone(), audit_keys, "soma-vault-e2e"));

    let state = AppState::new(Arc::new(store), audit, false);

    let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
    tokio::spawn(async move {
        serve(listener, router(state)).await.expect("server error");
    });

    // Brief pause to let the server start accepting.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let pid = project.id.to_string();
    let eid = env.id.to_string();
    let bin = env!("CARGO_BIN_EXE_soma");

    // ── 5. soma run — assert stdout contains "s3cr3t" ─────────────────────────
    // Use tokio::process::Command so we don't block the executor running the
    // axum server while waiting for the CLI child to finish.
    let output = tokio::process::Command::new(bin)
        .args([
            "--server",
            &base_url,
            "--token",
            &token,
            "run",
            "--project",
            &pid,
            "--env",
            &eid,
            "--",
            "sh",
            "-c",
            "echo $DATABASE_PASSWORD",
        ])
        .output()
        .await
        .expect("spawn soma run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("s3cr3t"),
        "expected 's3cr3t' in stdout, got: {stdout:?}\nstderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // ── 6. soma run — child exit code is propagated ───────────────────────────
    let status = tokio::process::Command::new(bin)
        .args([
            "--server", &base_url, "--token", &token, "run",
            "--project", &pid, "--env", &eid,
            "--", "sh", "-c", "exit 3",
        ])
        .status()
        .await
        .expect("spawn soma run exit 3");

    assert_eq!(
        status.code(),
        Some(3),
        "expected exit code 3, got: {:?}",
        status.code()
    );
}

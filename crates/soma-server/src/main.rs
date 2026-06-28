//! soma-vault server binary.
//!
//! Boot order:
//! 1. Init tracing.
//! 2. Connect pool + load KEK.
//! 3. migrate-on-boot (idempotent, advisory-locked).
//! 4. Bootstrap root token if none exist (D8).
//! 5. Serve /v1 API + embedded portal on SOMA_BIND.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    body::Body,
    http::{header, Request, Response, StatusCode},
    routing::get,
};
use rust_embed::RustEmbed;
use soma_api::AppState;
use soma_infra::{connect_from_env, telemetry};
use soma_audit_pg::{AuditKeys, LocalSink};
use soma_crypto::MasterKek;
use soma_storage::{DataStore, PgDataStore, TenantId};
use tower_http::trace::TraceLayer;
use tracing::info;

// ── Embedded portal ───────────────────────────────────────────────────────────

// ponytail: RustEmbed embeds at compile-time from the relative path below.
// An empty dist/ is fine — the fallback stub handles missing index.html.
#[derive(RustEmbed)]
#[folder = "../../dashboard/dist"]
struct Portal;

// ── Portal handler (SPA fallback) ─────────────────────────────────────────────

async fn portal_handler(req: Request<Body>) -> Response<Body> {
    let path = req.uri().path().trim_start_matches('/');

    // Try the exact requested asset, then fall back to index.html.
    let (data, mime) = if let Some(f) = Portal::get(path) {
        let mime = mime_guess::from_path(path)
            .first_or_octet_stream()
            .to_string();
        (f.data, mime)
    } else if let Some(index) = Portal::get("index.html") {
        (index.data, "text/html; charset=utf-8".to_owned())
    } else {
        // Empty dist — return a built-in stub so the server is still usable.
        let stub = r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>soma-vault</title></head>
<body>
<h1>soma-vault</h1>
<p>Portal not bundled. Run <code>trunk build</code> inside <code>dashboard/</code>
and rebuild the server to embed the portal.</p>
</body>
</html>"#;
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Body::from(stub))
            .expect("static response is valid");
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .body(Body::from(data.into_owned()))
        .expect("asset response is valid")
}

// ── Token bootstrap ───────────────────────────────────────────────────────────

/// Write `content` to `path` with mode 0600 on Unix, plain write elsewhere.
async fn write_token_file(path: &str, content: &str) -> Result<()> {
    #[cfg(unix)]
    write_token_file_unix(path, content).await?;
    #[cfg(not(unix))]
    tokio::fs::write(path, content).await?;
    Ok(())
}

#[cfg(unix)]
async fn write_token_file_unix(path: &str, content: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    use tokio::io::AsyncWriteExt as _;

    let std_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    let mut f = tokio::fs::File::from_std(std_file);
    f.write_all(content.as_bytes()).await?;
    Ok(())
}

async fn bootstrap_root_token(
    store: &PgDataStore,
    tenant: &TenantId,
    token_file: &str,
) -> Result<()> {
    let count = store
        .count_tokens(tenant)
        .await
        .context("counting tokens for bootstrap")?;

    if count > 0 {
        info!("bootstrap: tokens already exist, skipping root token creation");
        return Ok(());
    }

    // Resolve plaintext: env var wins, else generate random.
    let from_env = std::env::var("SOMA_ROOT_TOKEN").ok();
    let plaintext = if let Some(ref v) = from_env {
        v.clone()
    } else {
        use rand::RngCore;
        let mut raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        hex::encode(raw)
    };

    store
        .create_token_with_value(tenant, "root", &plaintext)
        .await
        .context("persisting root token")?;

    // Write to file with restricted permissions.
    write_token_file(token_file, &plaintext)
        .await
        .with_context(|| format!("writing root token to {token_file}"))?;

    // Print banner to stderr — only show the token when it was just generated.
    if from_env.is_none() {
        // QW-1: Never print the full token into pod logs.
        // Full token goes to the token file (0600). Banner shows only a fingerprint.
        // Print the full token + soma-login line only in two safe cases:
        //   1. Not running in Kubernetes (KUBERNETES_SERVICE_HOST absent), OR
        //   2. SOMA_PRINT_TOKEN=true is explicitly set (opt-in for secure local setups).
        use sha2::{Digest, Sha256};
        let fingerprint = {
            let digest = Sha256::digest(plaintext.as_bytes());
            hex::encode(&digest[..4]) // 8 hex chars — enough to correlate, not enough to use
        };
        let in_kubernetes = std::env::var("KUBERNETES_SERVICE_HOST").is_ok();
        let opt_in_print = std::env::var("SOMA_PRINT_TOKEN").as_deref() == Ok("true");
        let show_full = !in_kubernetes || opt_in_print;

        eprintln!();
        eprintln!("╔══════════════════════════════════════════════════════════════════╗");
        eprintln!("║              SOMA-VAULT ROOT TOKEN — SAVE THIS NOW               ║");
        eprintln!("╠══════════════════════════════════════════════════════════════════╣");
        eprintln!("║  Token fingerprint: {fingerprint:<45}║");
        eprintln!("║  Written to:        {token_file:<45}║");
        eprintln!("╠══════════════════════════════════════════════════════════════════╣");
        eprintln!("║  cat {token_file:<60}║");
        eprintln!("╚══════════════════════════════════════════════════════════════════╝");
        eprintln!();
        if show_full {
            eprintln!("  Full token:    {plaintext}");
            eprintln!("  Ready to use:  soma login --token {plaintext}");
            eprintln!();
        }
    } else {
        info!("bootstrap: root token seeded from SOMA_ROOT_TOKEN env var");
    }

    Ok(())
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Tracing.
    telemetry::init();

    // 2. Config from env.
    let bind_addr = soma_infra::config::env_or("SOMA_BIND", "0.0.0.0:8080");
    let cookie_secure = std::env::var("SOMA_COOKIE_SECURE")
        .map(|v| !v.eq_ignore_ascii_case("false") && v != "0")
        .unwrap_or(true);
    let token_file = soma_infra::config::env_or("SOMA_TOKEN_FILE", "./soma-root-token");

    // Fail fast on missing/invalid KEK.
    let kek = MasterKek::from_hex_env().context(
        "SOMA_MASTER_KEK_HEX must be set to a valid 64-character hex string \
         (generate one with: soma-cli keygen)",
    )?;
    // QW-2: scrub the raw hex from the process environment immediately after
    // loading so it is not visible in /proc/self/environ for the pod lifetime.
    // Called once at startup, before any threads are spawned.
    // Edition 2021: std::env::remove_var is safe (became unsafe in edition 2024).
    std::env::remove_var("SOMA_MASTER_KEK_HEX");

    // 3. Pool.
    let pool = connect_from_env()
        .await
        .context("connecting to Postgres (DATABASE_URL)")?;

    // 4. Build a plain store for migrations (no audit wired yet).
    let plain_store = PgDataStore::new(pool.clone(), kek);
    plain_store.migrate().await.context("migrate-on-boot")?;
    info!("migrations applied");

    // 5. Install soma-audit schema (idempotent, advisory-locked).
    soma_audit_pg::install(&pool)
        .await
        .context("soma-audit install failed — check SOMA_AUDIT_MASTER_SECRET / SOMA_AUDIT_SIGNING_KEY")?;
    info!("soma-audit schema ready");

    // 6. Build audit sink.
    let audit_keys = std::sync::Arc::new(
        AuditKeys::from_env().context(
            "SOMA_AUDIT_MASTER_SECRET and SOMA_AUDIT_SIGNING_KEY must be set \
             to valid 64-character hex strings",
        )?,
    );
    let audit_sink = std::sync::Arc::new(LocalSink::new(pool.clone(), audit_keys, "soma-vault"));

    // 7. Rebuild store wired to audit sink for atomic audit recording.
    // plain_store transferred its kek; reconstruct with a fresh kek from the pool.
    // (MasterKek does not implement Clone; we rebuild from the already-cleared env
    //  var by reusing the plain_store and swapping to with_audit via the inner field.)
    // Simplest: wrap plain_store in Arc and call with_audit separately.
    // Since MasterKek is not Clone, we move it into with_audit via plain_store.
    let store = Arc::new(plain_store.into_with_audit(audit_sink.clone()));

    // 8. Bootstrap root token.
    let tenant = TenantId::default();
    bootstrap_root_token(&store, &tenant, &token_file).await?;

    // 9. Build app.
    let state = AppState::new(store, audit_sink, cookie_secure);

    let app = soma_api::router(state)
        .fallback(get(portal_handler))
        .layer(TraceLayer::new_for_http());

    // 7. Serve.
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("binding to {bind_addr}"))?;

    info!(
        addr = %bind_addr,
        portal_files = Portal::iter().count(),
        "soma-vault listening"
    );

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            soma_infra::signal::shutdown_signal().await;
            info!("shutdown signal received");
        })
        .await
        .context("server error")?;

    Ok(())
}


//! Integration test against a live soma-vault server.
//!
//! Gate: requires the env var `SOMA_SDK_TEST_URL` to be set. If absent, or if
//! the server is not reachable, the test is skipped gracefully — it will NOT
//! fail a plain `cargo test` without the server running.
//!
//! Run with:
//!   SOMA_SDK_TEST_URL=http://127.0.0.1:18100 \
//!   SOMA_SDK_TEST_TOKEN=<root-token> \
//!   cargo test -p soma-sdk -- --test-threads=1

use std::collections::HashMap;
use std::env;

use serde::Deserialize;
use soma_sdk::SomaClient;

/// Read the token: prefer `SOMA_SDK_TEST_TOKEN` env var, then fall back to
/// the scratchpad file written by the server setup scripts.
fn read_token() -> Option<String> {
    if let Ok(t) = env::var("SOMA_SDK_TEST_TOKEN") {
        if !t.is_empty() {
            return Some(t.trim().to_owned());
        }
    }
    // Fallback: read from the well-known scratchpad path used by the test harness.
    let path = "/private/tmp/claude-501/-Users-sri-Documents-soma-platform-soma-vault/fa00ea94-e395-463f-a1c0-5fef35f99706/scratchpad/root-token.txt";
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// A project code unique per run, so re-running against a persistent DB doesn't
/// 409-conflict (there's no DELETE-project endpoint to clean up between runs).
fn unique_code(prefix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{prefix}-{}-{nanos}", std::process::id())
}

/// Percent-encode a path segment — mirrors the SDK's internal helper so we can
/// construct raw API URLs from the test without importing a private function.
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[tokio::test]
async fn sdk_round_trip() {
    // ── Gate ─────────────────────────────────────────────────────────────────
    let base_url = match env::var("SOMA_SDK_TEST_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            eprintln!("SOMA_SDK_TEST_URL not set — skipping integration test");
            return;
        }
    };

    let token = match read_token() {
        Some(t) => t,
        None => {
            eprintln!("no token available — skipping integration test");
            return;
        }
    };

    // ── Confirm the server is reachable ───────────────────────────────────────
    let http = reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .expect("build reqwest client");

    let health = http
        .get(format!("{base_url}/health/live"))
        .send()
        .await;

    if health.is_err() || !health.unwrap().status().is_success() {
        eprintln!("server at {base_url} not reachable — skipping integration test");
        return;
    }

    // ── Setup: create a throwaway project + environment ───────────────────────

    let auth = format!("Bearer {token}");

    let proj: serde_json::Value = http
        .post(format!("{base_url}/v1/projects"))
        .header("Authorization", &auth)
        .json(&serde_json::json!({
            "code": unique_code("sdk-integ"),
            "name": "SDK Integration Test"
        }))
        .send()
        .await
        .expect("create project")
        .json()
        .await
        .expect("parse project");

    let pid = proj["id"].as_str().expect("project id");

    let env_resp: serde_json::Value = http
        .post(format!("{base_url}/v1/projects/{pid}/environments"))
        .header("Authorization", &auth)
        .json(&serde_json::json!({"code": "test", "name": "Test"}))
        .send()
        .await
        .expect("create environment")
        .json()
        .await
        .expect("parse environment");

    let eid = env_resp["id"].as_str().expect("environment id");

    // ── Seed: write a secret and a config value ───────────────────────────────

    http.put(format!(
        "{base_url}/v1/projects/{pid}/environments/{eid}/secrets/{}",
        pct("database/password")
    ))
    .header("Authorization", &auth)
    .json(&serde_json::json!({"value": "hunter2"}))
    .send()
    .await
    .expect("put secret")
    .error_for_status()
    .expect("put secret status");

    http.put(format!(
        "{base_url}/v1/projects/{pid}/environments/{eid}/config/{}",
        pct("server/port")
    ))
    .header("Authorization", &auth)
    .json(&serde_json::json!({"value": "9000", "type": "string"}))
    .send()
    .await
    .expect("put config")
    .error_for_status()
    .expect("put config status");

    // ── SDK reads ─────────────────────────────────────────────────────────────

    let client = SomaClient::builder()
        .url(&base_url)
        .token(&token)
        .project(pid)
        .environment(eid)
        .build()
        .expect("build SomaClient");

    // Single secret read
    let secret_val = client.secret("database/password").await.expect("client.secret()");
    assert_eq!(secret_val, "hunter2", "secret round-trip failed");

    // Single config read
    let config_val = client.config("server/port").await.expect("client.config()");
    assert_eq!(config_val, "9000", "config round-trip failed");

    // Bulk export
    let all: HashMap<String, String> = client.load_all().await.expect("client.load_all()");
    assert_eq!(all.get("database/password").map(String::as_str), Some("hunter2"));
    assert_eq!(all.get("server/port").map(String::as_str), Some("9000"));

    // Cache
    let cache = client.cache().await.expect("client.cache()");
    assert_eq!(cache.get("database/password"), Some("hunter2"));
    assert_eq!(cache.get("server/port"), Some("9000"));
    assert_eq!(cache.get("nonexistent"), None);
    assert!(!cache.is_empty());
    assert_eq!(cache.len(), 2);

    // Not-found error
    let err = client.secret("does/not/exist").await;
    assert!(
        matches!(err, Err(soma_sdk::Error::NotFound(_))),
        "expected NotFound, got {err:?}"
    );

    // ── Cleanup: nothing to delete (throwaway project is fine to leave) ───────
    // ponytail: no DELETE endpoint for projects in Phase 1; leaving the test
    // project is harmless for a dev/CI server. The project code is unique-ish
    // enough ("sdk-integ-test") that re-runs may conflict — the server will
    // return a Conflict error on project creation, which would panic above.
    // If this becomes a problem, generate a random suffix or clean up via DELETE.

    eprintln!("sdk_round_trip: all assertions passed");
}

/// Test `init()` injects vault values into the process environment, and
/// `client.load::<T>()` / `from_env::<T>()` deserializes into a typed struct.
///
/// Uses a separate project ("sdk-plug-test") to avoid colliding with sdk_round_trip.
#[tokio::test]
async fn sdk_plug_and_play() {
    // ── Gate ─────────────────────────────────────────────────────────────────
    let base_url = match env::var("SOMA_SDK_TEST_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            eprintln!("SOMA_SDK_TEST_URL not set — skipping plug-and-play test");
            return;
        }
    };

    let token = match read_token() {
        Some(t) => t,
        None => {
            eprintln!("no token available — skipping plug-and-play test");
            return;
        }
    };

    // Confirm reachable
    let http = reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .expect("build reqwest client");

    let health = http.get(format!("{base_url}/health/live")).send().await;
    if health.is_err() || !health.unwrap().status().is_success() {
        eprintln!("server at {base_url} not reachable — skipping plug-and-play test");
        return;
    }

    let auth = format!("Bearer {token}");

    // ── Setup: throwaway project + environment ────────────────────────────────
    let proj: serde_json::Value = http
        .post(format!("{base_url}/v1/projects"))
        .header("Authorization", &auth)
        .json(&serde_json::json!({
            "code": unique_code("sdk-plug"),
            "name": "SDK Plug-and-Play Test"
        }))
        .send()
        .await
        .expect("create project")
        .json()
        .await
        .expect("parse project");

    let pid = proj["id"].as_str().expect("project id");

    let env_resp: serde_json::Value = http
        .post(format!("{base_url}/v1/projects/{pid}/environments"))
        .header("Authorization", &auth)
        .json(&serde_json::json!({"code": "test", "name": "Test"}))
        .send()
        .await
        .expect("create environment")
        .json()
        .await
        .expect("parse environment");

    let eid = env_resp["id"].as_str().expect("environment id");

    // ── Seed: one secret + one numeric-string config ──────────────────────────
    http.put(format!(
        "{base_url}/v1/projects/{pid}/environments/{eid}/secrets/{}",
        pct("plug/secret")
    ))
    .header("Authorization", &auth)
    .json(&serde_json::json!({"value": "mysecretvalue"}))
    .send()
    .await
    .expect("put secret")
    .error_for_status()
    .expect("put secret status");

    http.put(format!(
        "{base_url}/v1/projects/{pid}/environments/{eid}/config/{}",
        pct("plug/port")
    ))
    .header("Authorization", &auth)
    .json(&serde_json::json!({"value": "7777", "type": "string"}))
    .send()
    .await
    .expect("put config")
    .error_for_status()
    .expect("put config status");

    // ── Test 1: client.inject(true) → std::env::var works ────────────────────
    let client = SomaClient::builder()
        .url(&base_url)
        .token(&token)
        .project(pid)
        .environment(eid)
        .build()
        .expect("build SomaClient");

    client.inject(true).await.expect("client.inject()");

    assert_eq!(
        env::var("PLUG_SECRET").as_deref(),
        Ok("mysecretvalue"),
        "inject: PLUG_SECRET not set in env"
    );
    assert_eq!(
        env::var("PLUG_PORT").as_deref(),
        Ok("7777"),
        "inject: PLUG_PORT not set in env"
    );

    // ── Test 2: inject(overwrite=false) does NOT clobber an existing var ──────
    // PLUG_SECRET is already "mysecretvalue"; set a sentinel and re-inject.
    env::set_var("PLUG_SECRET", "sentinel");
    client.inject(false).await.expect("client.inject(false)");
    assert_eq!(
        env::var("PLUG_SECRET").as_deref(),
        Ok("sentinel"),
        "inject(false): should NOT overwrite existing env var"
    );
    // Restore for subsequent assertions.
    env::set_var("PLUG_SECRET", "mysecretvalue");

    // ── Test 3: client.load::<T>() → typed struct ────────────────────────────
    #[derive(Deserialize)]
    struct PlugConfig {
        plug_secret: String,
        plug_port: u16,
    }

    let cfg: PlugConfig = client.load().await.expect("client.load::<PlugConfig>()");
    assert_eq!(cfg.plug_secret, "mysecretvalue");
    assert_eq!(cfg.plug_port, 7777u16, "numeric coercion of '7777' → u16 failed");

    // ── Test 4: from_env::<T>() — zero-config typed path ─────────────────────
    // Set the SOMA_* vars the free function reads.
    env::set_var("SOMA_URL", &base_url);
    env::set_var("SOMA_TOKEN", &token);
    env::set_var("SOMA_PROJECT", pid);
    env::set_var("SOMA_ENVIRONMENT", eid);

    let cfg2: PlugConfig = soma_sdk::from_env().await.expect("from_env::<PlugConfig>()");
    assert_eq!(cfg2.plug_secret, "mysecretvalue");
    assert_eq!(cfg2.plug_port, 7777u16);

    eprintln!("sdk_plug_and_play: all assertions passed");
}

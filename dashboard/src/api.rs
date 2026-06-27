//! Async API helpers. All paths are relative (same-origin).
//! Cookies are sent automatically by the browser (httpOnly session cookie).

use serde::{de::DeserializeOwned, Serialize};
use wasm_bindgen::JsValue;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApiError {
    pub status: u16,
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (HTTP {})", self.message, self.status)
    }
}

async fn handle_response<T: DeserializeOwned>(
    resp: gloo_net::http::Response,
) -> Result<T, ApiError> {
    let status = resp.status();
    if status == 401 {
        let window = web_sys::window().unwrap();
        let _ = window.location().set_href("/login");
        return Err(ApiError {
            status,
            message: "unauthorized".into(),
        });
    }
    if !resp.ok() {
        let body = resp.text().await.unwrap_or_default();
        let msg = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(|e| e.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or(body);
        return Err(ApiError {
            status,
            message: msg,
        });
    }
    resp.json::<T>().await.map_err(|e| ApiError {
        status,
        message: e.to_string(),
    })
}

pub async fn get_json<T: DeserializeOwned>(path: &str) -> Result<T, ApiError> {
    let resp = gloo_net::http::Request::get(path)
        .send()
        .await
        .map_err(|e| ApiError {
            status: 0,
            message: e.to_string(),
        })?;
    handle_response(resp).await
}

pub async fn post_json<B: Serialize, T: DeserializeOwned>(
    path: &str,
    body: &B,
) -> Result<T, ApiError> {
    let resp = gloo_net::http::Request::post(path)
        .header("Content-Type", "application/json")
        .body(JsValue::from_str(&serde_json::to_string(body).unwrap()))
        .map_err(|e| ApiError {
            status: 0,
            message: e.to_string(),
        })?
        .send()
        .await
        .map_err(|e| ApiError {
            status: 0,
            message: e.to_string(),
        })?;
    handle_response(resp).await
}

pub async fn put_json<B: Serialize, T: DeserializeOwned>(
    path: &str,
    body: &B,
) -> Result<T, ApiError> {
    let resp = gloo_net::http::Request::put(path)
        .header("Content-Type", "application/json")
        .body(JsValue::from_str(&serde_json::to_string(body).unwrap()))
        .map_err(|e| ApiError {
            status: 0,
            message: e.to_string(),
        })?
        .send()
        .await
        .map_err(|e| ApiError {
            status: 0,
            message: e.to_string(),
        })?;
    handle_response(resp).await
}

pub async fn patch_json<B: Serialize, T: DeserializeOwned>(
    path: &str,
    body: &B,
) -> Result<T, ApiError> {
    let resp = gloo_net::http::Request::patch(path)
        .header("Content-Type", "application/json")
        .body(JsValue::from_str(&serde_json::to_string(body).unwrap()))
        .map_err(|e| ApiError {
            status: 0,
            message: e.to_string(),
        })?
        .send()
        .await
        .map_err(|e| ApiError {
            status: 0,
            message: e.to_string(),
        })?;
    handle_response(resp).await
}

pub async fn del(path: &str) -> Result<(), ApiError> {
    let resp = gloo_net::http::Request::delete(path)
        .send()
        .await
        .map_err(|e| ApiError {
            status: 0,
            message: e.to_string(),
        })?;
    let status = resp.status();
    if status == 401 {
        let window = web_sys::window().unwrap();
        let _ = window.location().set_href("/login");
        return Err(ApiError {
            status,
            message: "unauthorized".into(),
        });
    }
    if !resp.ok() {
        let body = resp.text().await.unwrap_or_default();
        return Err(ApiError {
            status,
            message: body,
        });
    }
    Ok(())
}

// ── Domain types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Project {
    pub id: String,
    pub code: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Environment {
    pub id: String,
    pub code: String,
    pub name: String,
    pub created_at: String,
}

/// Pagination envelope returned by list_projects, list_secrets, list_config.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SecretMeta {
    pub path: String,
    pub current_version: i32,
    pub updated_at: String,
}

/// One version from GET .../secrets/{path}/versions — bare array, no Page envelope.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SecretVersion {
    pub version: i32,
    /// seal_provider from SecretVersionMeta (no created_by on the server).
    pub seal_provider: String,
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SecretPlaintext {
    pub path: String,
    pub value: String,
    pub version: i32,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ConfigEntry {
    pub key: String,
    pub value_type: String,
    pub current_version: i32,
    pub updated_at: String,
}

/// One version from GET .../config/{key}/versions — bare array, no Page envelope.
/// value is Option<String> per the server type.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ConfigVersion {
    pub version: i32,
    pub value: Option<String>,
    pub value_type: String,
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct AttrDef {
    pub id: String,
    pub code: String,
    pub name: String,
    pub data_type: String,
    pub is_required: bool,
    pub is_pii: bool,
    pub sort_order: i32,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Token {
    pub id: String,
    pub name: String,
    pub role: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CreatedToken {
    pub id: String,
    pub name: String,
    pub token: String, // plaintext, shown once
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Me {
    pub ok: bool,
    pub tenant: Option<String>,
    pub token_id: Option<String>,
    pub role: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct AuditEvent {
    pub id: String,
    pub tenant_id: String,
    pub seq_num: i64,
    pub event_type: String,
    /// Actor UUID (previously actor_token_id — renamed to match soma-audit-core AuditRecord).
    pub actor_id: Option<String>,
    pub actor_role: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub outcome: String,
    pub actor_ip: Option<String>,
    pub prev_hash: Option<String>,
    pub entry_hash: String,
    /// Wall-clock time the record was written to storage (from AuditRecord).
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct AuditVerifyResult {
    pub ok: bool,
    pub entries_checked: i64,
    pub first_broken_seq: Option<i64>,
}

pub async fn get_me() -> Result<Me, ApiError> {
    get_json::<Me>("/v1/auth/me").await
}

pub async fn verify_audit() -> Result<AuditVerifyResult, ApiError> {
    get_json::<AuditVerifyResult>("/v1/audit/verify").await
}

pub async fn get_audit(
    event_type: Option<String>,
    cursor: Option<String>,
    limit: u32,
) -> Result<Page<AuditEvent>, ApiError> {
    let mut url = format!("/v1/audit?limit={}", limit);
    if let Some(et) = event_type {
        if !et.is_empty() {
            url.push_str(&format!("&event_type={}", et));
        }
    }
    if let Some(c) = cursor {
        url.push_str(&format!("&cursor={}", c));
    }
    get_json::<Page<AuditEvent>>(&url).await
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub seal_backend: String,
}

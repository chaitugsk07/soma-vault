#![allow(clippy::doc_markdown, clippy::too_many_arguments)]
//! Audit log persistence: `record_audit`, `list_audit`, `verify_audit_chain`.
//!
//! Chain construction:
//! - `canonical_msg = "{seq_num}|{tenant_id}|{event_type}|{actor_token_id}|{resource_type}|{resource_id}|{outcome}|{created_at_rfc3339}|{prev_hash}"`
//!   where each nullable field is replaced by `""` when `None`.
//! - `entry_hash` = HMAC-SHA256(`audit_key`, `canonical_msg`) as lowercase hex.
//!
//! Serialization: `|` delimiter. Fields that can contain `|` (`resource_id`, `event_type`)
//! are controlled values that will not contain `|` by convention (event types are
//! dot-separated codes; resource_ids are paths or UUIDs). This is documented and
//! sufficient for v1.
//!
//! Sequence ordering: we acquire a per-tenant advisory lock via
//! `pg_advisory_xact_lock(hashtext(tenant_id::text) + 1000000000)` inside the
//! insert transaction, then `SELECT max(seq_num)` for the tenant and compute
//! `next = max + 1` (or 1 if none). The `UNIQUE(tenant_id, seq_num)` constraint
//! is the backstop against races.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use soma_crypto::audit_hmac_hex;

use crate::error::map_sqlx;
use crate::types::{AuditEvent, AuditFilters, AuditVerifyResult, Page, TenantId};
use crate::Result;

// ── sqlx row struct ───────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub(super) struct AuditRow {
    id: Uuid,
    tenant_id: Uuid,
    seq_num: i64,
    event_type: String,
    actor_token_id: Option<Uuid>,
    actor_role: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    outcome: String,
    actor_ip: Option<String>,
    prev_hash: Option<String>,
    entry_hash: String,
    created_at: DateTime<Utc>,
}

impl From<AuditRow> for AuditEvent {
    fn from(r: AuditRow) -> Self {
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            seq_num: r.seq_num,
            event_type: r.event_type,
            actor_token_id: r.actor_token_id,
            actor_role: r.actor_role,
            resource_type: r.resource_type,
            resource_id: r.resource_id,
            outcome: r.outcome,
            actor_ip: r.actor_ip,
            prev_hash: r.prev_hash,
            entry_hash: r.entry_hash,
            created_at: r.created_at,
        }
    }
}

// ── Canonical message builder ─────────────────────────────────────────────────

/// Build the canonical string for HMAC computation.
///
/// Format: "seq_num|tenant_id|event_type|actor_token_id|resource_type|resource_id|outcome|created_at_rfc3339|prev_hash"
/// Nullable fields are empty string when None.
fn canonical_msg(
    seq_num: i64,
    tenant_id: Uuid,
    event_type: &str,
    actor_token_id: Option<Uuid>,
    resource_type: Option<&str>,
    resource_id: Option<&str>,
    outcome: &str,
    created_at: DateTime<Utc>,
    prev_hash: Option<&str>,
) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}",
        seq_num,
        tenant_id,
        event_type,
        actor_token_id.map_or_else(String::new, |u| u.to_string()),
        resource_type.unwrap_or(""),
        resource_id.unwrap_or(""),
        outcome,
        created_at.to_rfc3339(),
        prev_hash.unwrap_or(""),
    )
}

// ── Public functions ──────────────────────────────────────────────────────────

/// Insert one audit event atomically, computing seq_num and entry_hash.
pub(super) async fn record_audit(
    pool: &PgPool,
    audit_key: &[u8; 32],
    event: AuditEvent,
) -> Result<()> {
    let mut tx = pool.begin().await.map_err(map_sqlx)?;

    // Set tenant context for RLS.
    sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(event.tenant_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;

    // Per-tenant advisory lock to serialize concurrent inserts for this tenant.
    // hashtext() maps text → int4; add a large offset to avoid collision with
    // other advisory locks in the system.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint + 1000000000)")
        .bind(event.tenant_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;

    // Get current max seq_num and prev entry_hash for this tenant.
    let last: Option<(i64, String)> = sqlx::query_as(
        r#"SELECT seq_num, entry_hash
           FROM "01_vault"."12_fct_audit_events"
           WHERE tenant_id = $1
           ORDER BY seq_num DESC
           LIMIT 1"#,
    )
    .bind(event.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(map_sqlx)?;

    let (seq_num, prev_hash) = match last {
        Some((last_seq, last_hash)) => (last_seq + 1, Some(last_hash)),
        None => (1i64, None),
    };

    // Use DB now() so created_at is consistent.
    let created_at: DateTime<Utc> = sqlx::query_scalar("SELECT now()")
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx)?;

    let msg = canonical_msg(
        seq_num,
        event.tenant_id,
        &event.event_type,
        event.actor_token_id,
        event.resource_type.as_deref(),
        event.resource_id.as_deref(),
        &event.outcome,
        created_at,
        prev_hash.as_deref(),
    );
    let entry_hash = audit_hmac_hex(audit_key, &msg);

    sqlx::query(
        r#"INSERT INTO "01_vault"."12_fct_audit_events"
           (id, tenant_id, seq_num, event_type, actor_token_id, actor_role,
            resource_type, resource_id, outcome, actor_ip,
            prev_hash, entry_hash, created_at)
           VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9::inet, $10, $11, $12)"#,
    )
    .bind(event.tenant_id)
    .bind(seq_num)
    .bind(&event.event_type)
    .bind(event.actor_token_id)
    .bind(&event.actor_role)
    .bind(&event.resource_type)
    .bind(&event.resource_id)
    .bind(&event.outcome)
    .bind(&event.actor_ip)
    .bind(&prev_hash)
    .bind(&entry_hash)
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(map_sqlx)?;

    tx.commit().await.map_err(map_sqlx)?;
    Ok(())
}

/// List audit events for a tenant, newest first, with keyset pagination by seq_num.
pub(super) async fn list_audit(
    pool: &PgPool,
    tenant: &TenantId,
    filters: AuditFilters,
) -> Result<Page<AuditEvent>> {
    let mut tx = pool.begin().await.map_err(map_sqlx)?;

    sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(tenant.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;

    let limit = filters.limit.clamp(1, 500);

    // Build query with optional filters. Using typed parameters — inputs are typed, not raw strings.
    // ponytail: manual query with nullable params is fine here — inputs are typed, not raw strings.
    let rows: Vec<AuditRow> = sqlx::query_as(
        r#"SELECT id, tenant_id, seq_num, event_type, actor_token_id, actor_role,
                  resource_type, resource_id, outcome,
                  CAST(actor_ip AS TEXT) AS actor_ip,
                  prev_hash, entry_hash, created_at
           FROM "01_vault"."12_fct_audit_events"
           WHERE tenant_id = $1
             AND ($2::text IS NULL OR event_type = $2)
             AND ($3::timestamptz IS NULL OR created_at >= $3)
             AND ($4::timestamptz IS NULL OR created_at <= $4)
             AND ($5::uuid IS NULL OR actor_token_id = $5)
             AND ($6::bigint IS NULL OR seq_num < $6)
           ORDER BY seq_num DESC
           LIMIT $7"#,
    )
    .bind(tenant.0)
    .bind(&filters.event_type)
    .bind(filters.from)
    .bind(filters.to)
    .bind(filters.actor)
    .bind(filters.cursor)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await
    .map_err(map_sqlx)?;

    tx.commit().await.map_err(map_sqlx)?;

    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let next_cursor = if rows.len() == limit as usize {
        rows.last().map(|r| r.seq_num)
    } else {
        None
    };

    let items: Vec<AuditEvent> = rows.into_iter().map(Into::into).collect();
    Ok(Page {
        items,
        next_cursor: next_cursor.map(|s| s.to_string()),
    })
}

/// Walk the audit chain in seq_num order and verify every HMAC and prev_hash link.
pub(super) async fn verify_audit_chain(
    pool: &PgPool,
    audit_key: &[u8; 32],
    tenant: &TenantId,
) -> Result<AuditVerifyResult> {
    let mut tx = pool.begin().await.map_err(map_sqlx)?;

    sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(tenant.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;

    // Fetch all rows ordered by seq_num ASC.
    let rows: Vec<AuditRow> = sqlx::query_as(
        r#"SELECT id, tenant_id, seq_num, event_type, actor_token_id, actor_role,
                  resource_type, resource_id, outcome,
                  CAST(actor_ip AS TEXT) AS actor_ip,
                  prev_hash, entry_hash, created_at
           FROM "01_vault"."12_fct_audit_events"
           WHERE tenant_id = $1
           ORDER BY seq_num ASC"#,
    )
    .bind(tenant.0)
    .fetch_all(&mut *tx)
    .await
    .map_err(map_sqlx)?;

    tx.commit().await.map_err(map_sqlx)?;

    let mut prev_hash: Option<String> = None;
    let mut entries_checked: u64 = 0;

    for row in &rows {
        let expected_msg = canonical_msg(
            row.seq_num,
            row.tenant_id,
            &row.event_type,
            row.actor_token_id,
            row.resource_type.as_deref(),
            row.resource_id.as_deref(),
            &row.outcome,
            row.created_at,
            prev_hash.as_deref(),
        );
        let expected_hash = audit_hmac_hex(audit_key, &expected_msg);

        // Verify entry_hash matches recomputed value.
        if row.entry_hash != expected_hash {
            return Ok(AuditVerifyResult {
                ok: false,
                entries_checked,
                first_broken_seq: Some(row.seq_num),
            });
        }

        // Verify prev_hash link matches what we tracked.
        if row.prev_hash != prev_hash {
            return Ok(AuditVerifyResult {
                ok: false,
                entries_checked,
                first_broken_seq: Some(row.seq_num),
            });
        }

        prev_hash = Some(row.entry_hash.clone());
        entries_checked += 1;
    }

    Ok(AuditVerifyResult {
        ok: true,
        entries_checked,
        first_broken_seq: None,
    })
}

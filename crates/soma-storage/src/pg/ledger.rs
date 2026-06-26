use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use soma_crypto::TenantKek;

use crate::error::map_sqlx;
use crate::Result;

// ── Internal row types ────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub(super) struct SecretRow {
    #[allow(dead_code)]
    pub(super) id: Uuid,
    pub(super) current_version: i32,
    pub(super) cas_required: bool,
    #[allow(dead_code)]
    pub(super) max_versions: i32,
}

#[derive(sqlx::FromRow)]
pub(super) struct ConfigKeyRow {
    #[allow(dead_code)]
    pub(super) id: Uuid,
    pub(super) current_version: i32,
}

// ── Secret version ledger ─────────────────────────────────────────────────────

/// Advance the version pointer for a secret and insert a new version row.
///
/// Steps (all in one transaction):
/// 1. Set `app.tenant_id` so RLS policies are satisfied for the transaction.
/// 2. `SELECT FOR UPDATE` the secret header.
/// 3. CAS check if `cas_required`.
/// 4. Encrypt plaintext with the version number assigned under the row lock
///    (QW-5: guarantees AAD version == stored version even under concurrent PUTs).
/// 5. `INSERT` the version row.
/// 6. `UPDATE` the header: `current_version = new_version`.
///
/// `kek` is the per-tenant KEK derived from the master KEK before calling this
/// function.  The `seal_key_id` embedded in the stored row comes from the caller.
///
/// Returns the new version number.
pub(super) async fn advance_secret_version(
    pool: &PgPool,
    kek: &TenantKek,
    seal_key_id: &str,
    tenant_id: Uuid,
    secret_id: Uuid,
    cas: Option<i32>,
    plaintext: &[u8],
) -> Result<i32> {
    let mut tx: Transaction<'_, Postgres> = pool.begin().await.map_err(map_sqlx)?;

    // Set app.tenant_id for RLS so all queries in this transaction are scoped
    // to the correct tenant.  set_config with is_local=true is the SET LOCAL
    // equivalent that accepts a bind parameter.
    sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;

    let row: SecretRow = sqlx::query_as(
        r#"SELECT id, current_version, cas_required, max_versions
           FROM "01_vault"."05_fct_secrets"
           WHERE id = $1 AND tenant_id = $2 AND is_deleted = false
           FOR UPDATE"#,
    )
    .bind(secret_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(map_sqlx)?
    .ok_or(crate::Error::NotFound)?;

    // CAS check: enforce if the caller supplied a `cas` value OR if the secret
    // header requires it.  Checked inside the SELECT FOR UPDATE lock so the
    // comparison is race-free.
    if let Some(expected) = cas {
        if expected != row.current_version {
            return Err(crate::Error::Conflict(format!(
                "CAS mismatch: expected version {expected}, current is {}",
                row.current_version
            )));
        }
    } else if row.cas_required {
        // cas_required but no cas supplied — treat as mismatch against any version.
        return Err(crate::Error::Conflict(
            "CAS is required for this secret but was not provided".to_owned(),
        ));
    }

    let new_version = row.current_version + 1;

    // QW-5: encrypt AFTER the row lock so the version bound into AAD is the
    // exact version number we are about to write — no race possible.
    let mut sealed =
        soma_crypto::encrypt(kek, secret_id, i64::from(new_version), plaintext)?;
    // Stamp the seal_key_id provided by the caller (master KEK fingerprint).
    sealed.seal_key_id = seal_key_id.to_owned();

    sqlx::query(
        r#"INSERT INTO "01_vault"."06_fct_secret_versions"
           (id, tenant_id, secret_id, version, ciphertext, nonce, wrapped_dek, aad,
            seal_provider, seal_key_id, created_at)
           VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9, now())"#,
    )
    .bind(tenant_id)
    .bind(secret_id)
    .bind(new_version)
    .bind(&sealed.ciphertext)
    .bind(&sealed.nonce)
    .bind(&sealed.wrapped_dek)
    .bind(&sealed.aad)
    .bind(sealed.seal_provider.as_str())
    .bind(&sealed.seal_key_id)
    .execute(&mut *tx)
    .await
    .map_err(map_sqlx)?;

    sqlx::query(
        r#"UPDATE "01_vault"."05_fct_secrets"
           SET current_version = $1, updated_at = now()
           WHERE id = $2"#,
    )
    .bind(new_version)
    .bind(secret_id)
    .execute(&mut *tx)
    .await
    .map_err(map_sqlx)?;

    tx.commit().await.map_err(map_sqlx)?;
    Ok(new_version)
}

// ── Config version ledger ─────────────────────────────────────────────────────

/// Advance the version pointer for a config key and insert a new version row.
///
/// Returns the new version number.
pub(super) async fn advance_config_version(
    pool: &PgPool,
    tenant_id: Uuid,
    config_key_id: Uuid,
    value: &str,
    value_type: &str,
) -> Result<i32> {
    let mut tx: Transaction<'_, Postgres> = pool.begin().await.map_err(map_sqlx)?;

    // Set app.tenant_id for RLS so all queries in this transaction are scoped
    // to the correct tenant.
    sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;

    let row: ConfigKeyRow = sqlx::query_as(
        r#"SELECT id, current_version
           FROM "01_vault"."07_fct_config_keys"
           WHERE id = $1 AND tenant_id = $2 AND is_deleted = false
           FOR UPDATE"#,
    )
    .bind(config_key_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(map_sqlx)?
    .ok_or(crate::Error::NotFound)?;

    let new_version = row.current_version + 1;

    sqlx::query(
        r#"INSERT INTO "01_vault"."08_fct_config_versions"
           (id, tenant_id, config_key_id, version, value, value_type, created_at)
           VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, now())"#,
    )
    .bind(tenant_id)
    .bind(config_key_id)
    .bind(new_version)
    .bind(value)
    .bind(value_type)
    .execute(&mut *tx)
    .await
    .map_err(map_sqlx)?;

    sqlx::query(
        r#"UPDATE "01_vault"."07_fct_config_keys"
           SET current_version = $1, updated_at = now()
           WHERE id = $2"#,
    )
    .bind(new_version)
    .bind(config_key_id)
    .execute(&mut *tx)
    .await
    .map_err(map_sqlx)?;

    tx.commit().await.map_err(map_sqlx)?;
    Ok(new_version)
}

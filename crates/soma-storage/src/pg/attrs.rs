use std::collections::HashMap;

use sqlx::PgPool;

use crate::error::map_sqlx;
use crate::{EntityRef, Result, TenantId};

/// Upsert EAV attribute rows for either a secret or a config key.
///
/// Which detail table is used depends on `entity`:
/// - `EntityRef::Secret`  → `09_dtl_secret_attrs`
/// - `EntityRef::Config`  → `10_dtl_config_attrs`
///
/// A non-whitelisted property key causes a FK violation that is mapped to
/// [`crate::Error::WhitelistViolation`].
///
/// Each row is written inside a short transaction with `app.tenant_id` set
/// so RLS policies on the detail tables are satisfied.
pub(super) async fn set_attrs(
    pool: &PgPool,
    tenant: &TenantId,
    entity: EntityRef,
    attrs: HashMap<String, String>,
) -> Result<()> {
    match entity {
        EntityRef::Secret(secret_id) => set_secret_attrs(pool, tenant, secret_id, attrs).await,
        EntityRef::Config(config_key_id) => {
            set_config_attrs(pool, tenant, config_key_id, attrs).await
        }
    }
}

async fn set_secret_attrs(
    pool: &PgPool,
    tenant: &TenantId,
    secret_id: uuid::Uuid,
    attrs: HashMap<String, String>,
) -> Result<()> {
    for (k, v) in attrs {
        let mut tx = pool.begin().await.map_err(map_sqlx)?;
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(tenant.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx)?;
        sqlx::query(
            r#"INSERT INTO "01_vault"."09_dtl_secret_attrs"
               (id, tenant_id, secret_id, entity_type, property_key, property_value, created_at, updated_at)
               VALUES (gen_random_uuid(), $1, $2, 'secret', $3, $4, now(), now())
               ON CONFLICT (secret_id, property_key)
               DO UPDATE SET property_value = EXCLUDED.property_value, updated_at = now()"#,
        )
        .bind(tenant.0)
        .bind(secret_id)
        .bind(&k)
        .bind(&v)
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        tx.commit().await.map_err(map_sqlx)?;
    }
    Ok(())
}

async fn set_config_attrs(
    pool: &PgPool,
    tenant: &TenantId,
    config_key_id: uuid::Uuid,
    attrs: HashMap<String, String>,
) -> Result<()> {
    for (k, v) in attrs {
        let mut tx = pool.begin().await.map_err(map_sqlx)?;
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(tenant.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx)?;
        sqlx::query(
            r#"INSERT INTO "01_vault"."10_dtl_config_attrs"
               (id, tenant_id, config_key_id, entity_type, property_key, property_value, created_at, updated_at)
               VALUES (gen_random_uuid(), $1, $2, 'config_key', $3, $4, now(), now())
               ON CONFLICT (config_key_id, property_key)
               DO UPDATE SET property_value = EXCLUDED.property_value, updated_at = now()"#,
        )
        .bind(tenant.0)
        .bind(config_key_id)
        .bind(&k)
        .bind(&v)
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        tx.commit().await.map_err(map_sqlx)?;
    }
    Ok(())
}

/// Read all EAV attribute rows for an entity.
pub(super) async fn get_attrs(
    pool: &PgPool,
    tenant: &TenantId,
    entity: EntityRef,
) -> Result<HashMap<String, String>> {
    match entity {
        EntityRef::Secret(secret_id) => get_secret_attrs(pool, tenant, secret_id).await,
        EntityRef::Config(config_key_id) => get_config_attrs(pool, tenant, config_key_id).await,
    }
}

async fn get_secret_attrs(
    pool: &PgPool,
    tenant: &TenantId,
    secret_id: uuid::Uuid,
) -> Result<HashMap<String, String>> {
    let mut tx = pool.begin().await.map_err(map_sqlx)?;
    sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(tenant.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
    let rows: Vec<(String, String)> = sqlx::query_as(
        r#"SELECT property_key, property_value
           FROM "01_vault"."09_dtl_secret_attrs"
           WHERE tenant_id = $1 AND secret_id = $2"#,
    )
    .bind(tenant.0)
    .bind(secret_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(map_sqlx)?;
    tx.commit().await.map_err(map_sqlx)?;
    Ok(rows.into_iter().collect())
}

async fn get_config_attrs(
    pool: &PgPool,
    tenant: &TenantId,
    config_key_id: uuid::Uuid,
) -> Result<HashMap<String, String>> {
    let mut tx = pool.begin().await.map_err(map_sqlx)?;
    sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(tenant.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
    let rows: Vec<(String, String)> = sqlx::query_as(
        r#"SELECT property_key, property_value
           FROM "01_vault"."10_dtl_config_attrs"
           WHERE tenant_id = $1 AND config_key_id = $2"#,
    )
    .bind(tenant.0)
    .bind(config_key_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(map_sqlx)?;
    tx.commit().await.map_err(map_sqlx)?;
    Ok(rows.into_iter().collect())
}

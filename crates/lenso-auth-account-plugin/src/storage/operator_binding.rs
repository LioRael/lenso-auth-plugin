//! Private operator binding persistence; storage never resolves an authorization policy.
use super::{AccountError, AccountStore};
use crate::operator_binding::{OperatorBindingConfig, Record};
#[cfg(feature = "workers")]
use crate::workers::{D1Binding, statement};
#[cfg(feature = "workers")]
use serde_json::json;
#[cfg(feature = "postgres")]
use sqlx::Row;
const FIELDS: &str = "source_issuer,deployment,scope_kind,scope_id,binding_id,source_subject,operator_subject,revision,status,audit_event_id,policy_revision,revocation_state,revocation_audit_event_id,revoked_by,revoked_at,activation_started_at,activation_permissions";
#[cfg(feature = "postgres")]
fn pg_row(row: &sqlx::postgres::PgRow) -> Result<Record, AccountError> {
    Ok(Record {
        source_issuer: row
            .try_get("source_issuer")
            .map_err(|_| AccountError::Storage)?,
        deployment: row
            .try_get("deployment")
            .map_err(|_| AccountError::Storage)?,
        scope_kind: row
            .try_get("scope_kind")
            .map_err(|_| AccountError::Storage)?,
        scope_id: row.try_get("scope_id").map_err(|_| AccountError::Storage)?,
        binding_id: row
            .try_get("binding_id")
            .map_err(|_| AccountError::Storage)?,
        source_subject: row
            .try_get("source_subject")
            .map_err(|_| AccountError::Storage)?,
        operator_subject: row
            .try_get("operator_subject")
            .map_err(|_| AccountError::Storage)?,
        revision: row.try_get("revision").map_err(|_| AccountError::Storage)?,
        status: row.try_get("status").map_err(|_| AccountError::Storage)?,
        audit_event_id: row
            .try_get("audit_event_id")
            .map_err(|_| AccountError::Storage)?,
        revoked_by: row
            .try_get("revoked_by")
            .map_err(|_| AccountError::Storage)?,
        revoked_at: row
            .try_get("revoked_at")
            .map_err(|_| AccountError::Storage)?,
        revocation_state: row
            .try_get("revocation_state")
            .map_err(|_| AccountError::Storage)?,
        revocation_audit_event_id: row
            .try_get("revocation_audit_event_id")
            .map_err(|_| AccountError::Storage)?,
        policy_revision: row
            .try_get("policy_revision")
            .map_err(|_| AccountError::Storage)?,
        activation_started_at: row
            .try_get("activation_started_at")
            .map_err(|_| AccountError::Storage)?,
        activation_permissions: row
            .try_get("activation_permissions")
            .map_err(|_| AccountError::Storage)?,
    })
}
#[cfg(feature = "workers")]
fn d1_row(row: &serde_json::Value) -> Result<Record, AccountError> {
    serde_json::from_value(row.clone()).map_err(|_| AccountError::Storage)
}
pub(crate) async fn read(
    store: &AccountStore,
    cfg: &OperatorBindingConfig,
    column: &str,
    value: &str,
) -> Result<Option<Record>, AccountError> {
    // Column is selected exclusively by owner source, never supplied by a caller.
    let column = match column {
        "source_subject" => "source_subject",
        "operator_subject" => "operator_subject",
        "binding_id" => "binding_id",
        _ => return Err(AccountError::Storage),
    };
    match store {
 #[cfg(feature="postgres")]
 AccountStore::Postgres(pg)=>sqlx::query(sqlx::AssertSqlSafe(format!("SELECT {FIELDS} FROM auth_operator_bindings WHERE source_issuer=$1 AND deployment=$2 AND {column}=$3 AND scope_kind=$4 AND scope_id=$5"))).bind(&cfg.source_issuer).bind(&cfg.deployment).bind(value).bind(&cfg.scope_kind).bind(&cfg.scope_id).fetch_optional(pg.pool()).await.map_err(|_| AccountError::Storage)?.as_ref().map(pg_row).transpose(),
 #[cfg(feature="workers")]
 AccountStore::D1{binding,..}=>read_d1(binding,cfg,column,value).await,
 }
}
#[cfg(feature = "workers")]
async fn read_d1(
    db: &D1Binding,
    cfg: &OperatorBindingConfig,
    column: &str,
    value: &str,
) -> Result<Option<Record>, AccountError> {
    let result=db.run(vec![statement(format!("SELECT {FIELDS} FROM auth_operator_bindings WHERE source_issuer=?1 AND deployment=?2 AND {column}=?3 AND scope_kind=?4 AND scope_id=?5"),vec![json!(cfg.source_issuer),json!(cfg.deployment),json!(value),json!(cfg.scope_kind),json!(cfg.scope_id)])]).await.map_err(|()|AccountError::Storage)?;
    result[0].results.first().map(d1_row).transpose()
}
pub(crate) async fn prepare(
    store: &AccountStore,
    cfg: &OperatorBindingConfig,
    subject: &str,
    id: &str,
    operator: &str,
) -> Result<Record, AccountError> {
    match store {
        #[cfg(feature = "postgres")]
        AccountStore::Postgres(pg) => {
            sqlx::query("INSERT INTO auth_operator_bindings(binding_id,source_issuer,source_subject,deployment,operator_subject,scope_kind,scope_id,revision,status) VALUES($1,$2,$3,$4,$5,$6,$7,1,'pending') ON CONFLICT(source_issuer,source_subject,deployment) DO NOTHING").bind(id).bind(&cfg.source_issuer).bind(subject).bind(&cfg.deployment).bind(operator).bind(&cfg.scope_kind).bind(&cfg.scope_id).execute(pg.pool()).await.map_err(|_| AccountError::Storage)?;
        }
        #[cfg(feature = "workers")]
        AccountStore::D1 { binding, .. } => {
            binding.run(vec![statement("INSERT INTO auth_operator_bindings(binding_id,source_issuer,source_subject,deployment,operator_subject,scope_kind,scope_id,revision,status) VALUES(?1,?2,?3,?4,?5,?6,?7,1,'pending') ON CONFLICT(source_issuer,source_subject,deployment) DO NOTHING",vec![json!(id),json!(cfg.source_issuer),json!(subject),json!(cfg.deployment),json!(operator),json!(cfg.scope_kind),json!(cfg.scope_id)])]).await.map_err(|()|AccountError::Storage)?;
        }
    }
    read(store, cfg, "source_subject", subject)
        .await?
        .ok_or(AccountError::Storage)
}
#[cfg(feature = "workers")]
const ACTIVATION_INTENT_D1: &str = "UPDATE auth_operator_bindings SET activation_started_at=?1,activation_permissions=?2 WHERE binding_id=?3 AND revision=?4 AND status='pending' AND source_issuer=?5 AND deployment=?6 AND scope_kind=?7 AND scope_id=?8 AND activation_started_at='' AND activation_permissions=''";
#[cfg(feature = "postgres")]
const ACTIVATION_INTENT_PG: &str = "UPDATE auth_operator_bindings SET activation_started_at=$1,activation_permissions=$2 WHERE binding_id=$3 AND revision=$4 AND status='pending' AND source_issuer=$5 AND deployment=$6 AND scope_kind=$7 AND scope_id=$8 AND activation_started_at='' AND activation_permissions=''";

pub(crate) async fn prepare_activation_intent(
    store: &AccountStore,
    cfg: &OperatorBindingConfig,
    id: &str,
    revision: i64,
    occurred_at: &str,
    permissions: &str,
) -> Result<Option<Record>, AccountError> {
    match store {
        #[cfg(feature = "postgres")]
        AccountStore::Postgres(pg) => {
            sqlx::query(ACTIVATION_INTENT_PG)
                .bind(occurred_at)
                .bind(permissions)
                .bind(id)
                .bind(revision)
                .bind(&cfg.source_issuer)
                .bind(&cfg.deployment)
                .bind(&cfg.scope_kind)
                .bind(&cfg.scope_id)
                .execute(pg.pool())
                .await
                .map_err(|_| AccountError::Storage)?;
        }
        #[cfg(feature = "workers")]
        AccountStore::D1 { binding, .. } => {
            binding
                .run(vec![statement(
                    ACTIVATION_INTENT_D1,
                    vec![
                        json!(occurred_at),
                        json!(permissions),
                        json!(id),
                        json!(revision),
                        json!(cfg.source_issuer),
                        json!(cfg.deployment),
                        json!(cfg.scope_kind),
                        json!(cfg.scope_id),
                    ],
                )])
                .await
                .map_err(|()| AccountError::Storage)?;
        }
    }
    read(store, cfg, "binding_id", id).await
}

pub(crate) async fn activate(
    store: &AccountStore,
    cfg: &OperatorBindingConfig,
    id: &str,
    revision: i64,
    audit: &str,
    policy: &str,
) -> Result<Option<Record>, AccountError> {
    match store {
        #[cfg(feature = "postgres")]
        AccountStore::Postgres(pg) => {
            sqlx::query("UPDATE auth_operator_bindings SET status='active',audit_event_id=$1,policy_revision=$2 WHERE binding_id=$3 AND revision=$4 AND status='pending' AND source_issuer=$5 AND deployment=$6 AND scope_kind=$7 AND scope_id=$8").bind(audit).bind(policy).bind(id).bind(revision).bind(&cfg.source_issuer).bind(&cfg.deployment).bind(&cfg.scope_kind).bind(&cfg.scope_id).execute(pg.pool()).await.map_err(|_| AccountError::Storage)?;
        }
        #[cfg(feature = "workers")]
        AccountStore::D1 { binding, .. } => {
            binding.run(vec![statement("UPDATE auth_operator_bindings SET status='active',audit_event_id=?1,policy_revision=?2 WHERE binding_id=?3 AND revision=?4 AND status='pending' AND source_issuer=?5 AND deployment=?6 AND scope_kind=?7 AND scope_id=?8",vec![json!(audit),json!(policy),json!(id),json!(revision),json!(cfg.source_issuer),json!(cfg.deployment),json!(cfg.scope_kind),json!(cfg.scope_id)])]).await.map_err(|()|AccountError::Storage)?;
        }
    }
    read(store, cfg, "binding_id", id).await
}
pub(crate) async fn revoke(
    store: &AccountStore,
    cfg: &OperatorBindingConfig,
    id: &str,
    actor: &str,
    occurred: &str,
) -> Result<Option<Record>, AccountError> {
    match store {
        #[cfg(feature = "postgres")]
        AccountStore::Postgres(pg) => {
            sqlx::query("UPDATE auth_operator_bindings SET status='revoked',revision=revision+1,revocation_state='pending',revoked_by=$6,revoked_at=$7 WHERE binding_id=$1 AND source_issuer=$2 AND deployment=$3 AND scope_kind=$4 AND scope_id=$5 AND status!='revoked'").bind(id).bind(&cfg.source_issuer).bind(&cfg.deployment).bind(&cfg.scope_kind).bind(&cfg.scope_id).bind(actor).bind(occurred).execute(pg.pool()).await.map_err(|_| AccountError::Storage)?;
        }
        #[cfg(feature = "workers")]
        AccountStore::D1 { binding, .. } => {
            binding.run(vec![statement("UPDATE auth_operator_bindings SET status='revoked',revision=revision+1,revocation_state='pending',revoked_by=?6,revoked_at=?7 WHERE binding_id=?1 AND source_issuer=?2 AND deployment=?3 AND scope_kind=?4 AND scope_id=?5 AND status!='revoked'",vec![json!(id),json!(cfg.source_issuer),json!(cfg.deployment),json!(cfg.scope_kind),json!(cfg.scope_id),json!(actor),json!(occurred)])]).await.map_err(|()|AccountError::Storage)?;
        }
    }
    read(store, cfg, "binding_id", id).await
}

pub(crate) async fn complete_revocation(
    store: &AccountStore,
    cfg: &OperatorBindingConfig,
    id: &str,
    revision: i64,
    audit: &str,
) -> Result<Option<Record>, AccountError> {
    match store {
        #[cfg(feature = "postgres")]
        AccountStore::Postgres(pg) => {
            sqlx::query("UPDATE auth_operator_bindings SET revocation_state='complete',revocation_audit_event_id=$1 WHERE binding_id=$2 AND revision=$3 AND status='revoked' AND revocation_state='pending' AND source_issuer=$4 AND deployment=$5 AND scope_kind=$6 AND scope_id=$7").bind(audit).bind(id).bind(revision).bind(&cfg.source_issuer).bind(&cfg.deployment).bind(&cfg.scope_kind).bind(&cfg.scope_id).execute(pg.pool()).await.map_err(|_| AccountError::Storage)?;
        }
        #[cfg(feature = "workers")]
        AccountStore::D1 { binding, .. } => {
            binding.run(vec![statement("UPDATE auth_operator_bindings SET revocation_state='complete',revocation_audit_event_id=?1 WHERE binding_id=?2 AND revision=?3 AND status='revoked' AND revocation_state='pending' AND source_issuer=?4 AND deployment=?5 AND scope_kind=?6 AND scope_id=?7",vec![json!(audit),json!(id),json!(revision),json!(cfg.source_issuer),json!(cfg.deployment),json!(cfg.scope_kind),json!(cfg.scope_id)])]).await.map_err(|()|AccountError::Storage)?;
        }
    }
    read(store, cfg, "binding_id", id).await
}

#[cfg(all(feature = "postgres", test))]
#[path = "operator_binding_tests.rs"]
mod tests;

#[cfg(all(feature = "postgres", test))]
#[path = "activation_intent_tests.rs"]
mod activation_intent_tests;

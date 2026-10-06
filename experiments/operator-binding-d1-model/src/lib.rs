//! Actual Account-private operator binding SQL and D1 transport. Store and model
//! shims frame calls only; this is not a Capability, caller ACL or complete App proof.
#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wasm_bindgen::prelude::*;

#[path = "../../../crates/lenso-auth-account-plugin/src/storage/operator_binding.rs"]
mod binding_store;
#[path = "../../../crates/lenso-auth-account-plugin/src/migration.rs"]
mod migration;
#[path = "../../../crates/lenso-auth-account-plugin/src/workers.rs"]
mod workers;

#[derive(Debug, thiserror::Error)]
enum AccountError {
    #[error("Auth storage operation failed")]
    Storage,
}
enum AccountStore {
    D1 {
        binding: workers::D1Binding,
        managed_schema: bool,
    },
}
// These private owner data types are framed here so the exact storage module can
// run without importing the full Plugin/Kernel or the Access/Audit dependency cohort.
mod operator_binding {
    use super::{Deserialize, Serialize};
    #[derive(Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct OperatorBindingConfig {
        pub source_issuer: String,
        pub source_account_instance: String,
        pub scope_kind: String,
        pub scope_id: String,
        pub deployment: String,
        pub bootstrap_subject: String,
        pub bootstrap_not_before: String,
        pub bootstrap_expires_at: String,
        pub workflow_callers: Vec<String>,
    }
    #[derive(Debug, Deserialize, Serialize)]
    pub(crate) struct Record {
        pub source_issuer: String,
        pub deployment: String,
        pub scope_kind: String,
        pub scope_id: String,
        pub binding_id: String,
        pub source_subject: String,
        pub operator_subject: String,
        pub revision: i64,
        pub status: String,
        pub audit_event_id: String,
        pub policy_revision: String,
        pub revocation_state: String,
        pub revoked_by: String,
        pub revoked_at: String,
        pub revocation_audit_event_id: String,
        pub activation_started_at: String,
        pub activation_permissions: String,
    }
}
fn text(input: &Value, field: &str) -> Result<String, JsValue> {
    input[field]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| JsValue::from_str("Invalid local fixture request"))
}
fn revision(input: &Value) -> Result<i64, JsValue> {
    input["revision"]
        .as_i64()
        .ok_or_else(|| JsValue::from_str("Invalid local fixture revision"))
}
fn wire<T: Serialize>(result: Result<T, AccountError>) -> Result<String, JsValue> {
    Ok(match result {
        Ok(value) => json!({"Ok":value}),
        Err(_) => json!({"Err":"storage"}),
    }
    .to_string())
}
#[wasm_bindgen]
pub async fn invoke(input: String, batch: js_sys::Function) -> Result<String, JsValue> {
    let input: Value = serde_json::from_str(&input)
        .map_err(|_| JsValue::from_str("Invalid local fixture request"))?;
    let db = workers::D1Binding::new("LOCAL_OPERATOR_DB", batch);
    let operation = text(&input, "operation")?;
    if operation == "migration" {
        let result = match text(&input, "action")?.as_str() {
            "setup_legacy" => migration::setup(&db).await.map(|()| false),
            "upgrade_managed" => migration::upgrade_managed(&db).await.map(|()| true),
            "upgrade_operator" => migration::upgrade_operator_bound(&db).await.map(|()| true),
            "setup_operator" => migration::setup_operator_bound(&db).await.map(|()| true),
            "verify" => {
                migration::verify_features(
                    &db,
                    input["managed_required"].as_bool().unwrap_or(false),
                    input["operator_required"].as_bool().unwrap_or(false),
                )
                .await
            }
            _ => return Err(JsValue::from_str("Invalid local fixture operation")),
        };
        return Ok(match result {
            Ok(value) => json!({"Ok":value}),
            Err(lenso_migration_d1::Error::UpgradeRequired) => json!({"Err":"upgrade_required"}),
            Err(_) => json!({"Err":"migration_failure"}),
        }
        .to_string());
    }
    let cfg: operator_binding::OperatorBindingConfig =
        serde_json::from_value(input["config"].clone())
            .map_err(|_| JsValue::from_str("Invalid local fixture config"))?;
    let store = AccountStore::D1 {
        binding: db,
        managed_schema: true,
    };
    match operation.as_str() {
        "prepare" => wire(
            binding_store::prepare(
                &store,
                &cfg,
                &text(&input, "subject")?,
                &text(&input, "binding_id")?,
                &text(&input, "operator")?,
            )
            .await,
        ),
        "prepare_activation_intent" => wire(
            binding_store::prepare_activation_intent(
                &store,
                &cfg,
                &text(&input, "binding_id")?,
                revision(&input)?,
                &text(&input, "occurred")?,
                &text(&input, "permissions")?,
            )
            .await,
        ),
        "read" => wire(
            binding_store::read(
                &store,
                &cfg,
                &text(&input, "column")?,
                &text(&input, "value")?,
            )
            .await,
        ),
        "activate" => wire(
            binding_store::activate(
                &store,
                &cfg,
                &text(&input, "binding_id")?,
                revision(&input)?,
                &text(&input, "audit")?,
                &text(&input, "policy")?,
            )
            .await,
        ),
        "revoke" => wire(
            binding_store::revoke(
                &store,
                &cfg,
                &text(&input, "binding_id")?,
                &text(&input, "actor")?,
                &text(&input, "occurred")?,
            )
            .await,
        ),
        "complete" => wire(
            binding_store::complete_revocation(
                &store,
                &cfg,
                &text(&input, "binding_id")?,
                revision(&input)?,
                &text(&input, "audit")?,
            )
            .await,
        ),
        _ => Err(JsValue::from_str("Invalid local fixture operation")),
    }
}

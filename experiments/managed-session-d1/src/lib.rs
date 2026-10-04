//! Local-only storage qualification. The modules below compile the actual owner
//! SQL and actual owner D1 transport. Model/request shims frame storage calls;
//! this fixture does not qualify the Kernel, generated Capability or caller ACL.
#![allow(dead_code)]
extern crate self as lenso_capability_auth_delegation;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use wasm_bindgen::prelude::*;

#[path = "../../../crates/lenso-auth-account-plugin/src/storage/d1.rs"]
mod d1;
#[path = "../../../crates/lenso-auth-account-plugin/src/workers.rs"]
mod workers;

#[derive(Debug, thiserror::Error)]
enum AccountError {
    #[error("Auth storage operation failed")]
    Storage,
}
type RuntimeFailure = String;
fn runtime(error: impl std::fmt::Display) -> RuntimeFailure {
    error.to_string()
}
fn format_time(value: OffsetDateTime) -> Result<String, RuntimeFailure> {
    value.format(&Rfc3339).map_err(|e| e.to_string())
}
#[derive(Debug, Serialize)]
struct StoredSession {
    session_id: String,
    subject: String,
    status: String,
    actor_kind: String,
    assurance: String,
    audience: Vec<String>,
    claims: BTreeMap<String, Value>,
    expires_at: OffsetDateTime,
    revoked: bool,
}
#[derive(Debug)]
struct NewSession {
    session_id: String,
    digest: Vec<u8>,
    subject: String,
    actor_kind: String,
    assurance: String,
    audience: Vec<String>,
    claims: BTreeMap<String, Value>,
    expires_at: OffsetDateTime,
}
#[derive(Debug)]
struct NewManagedSession {
    issued_at: OffsetDateTime,
    absolute_expires_at: OffsetDateTime,
    idle_timeout_seconds: u64,
    renew_interval_seconds: u64,
    last_renew_at: OffsetDateTime,
}
#[derive(Debug, Deserialize)]
struct ManagedSessionPolicy {
    idle_timeout_seconds: u64,
    absolute_timeout_seconds: u64,
    renew_interval_seconds: u64,
}
#[derive(Debug, Serialize)]
struct SessionMetadata {
    session_id: String,
    expires_at: OffsetDateTime,
    absolute_expires_at: OffsetDateTime,
    renew_after: OffsetDateTime,
}
#[derive(Debug, Serialize)]
enum IssueSessionOutcome {
    Inserted,
    Disabled,
    InvalidSubject,
}
#[derive(Debug, Serialize)]
enum RenewSessionOutcome {
    Rotated {
        session_id: String,
        expires_at: OffsetDateTime,
        absolute_expires_at: OffsetDateTime,
        renew_after: OffsetDateTime,
    },
    InvalidCredential,
    StaleCredential,
    Expired,
    Revoked,
    TooEarly,
    Unsupported,
}
#[derive(Debug, Serialize)]
pub enum GrantError {
    InvalidCredential,
    Revoked,
    Expired,
    InvalidScope,
    NestedDelegation,
}
#[derive(Debug)]
struct GrantParent {
    subject: String,
    actor_kind: String,
    audience: Vec<String>,
    expires_at: OffsetDateTime,
    revoked: bool,
    disabled: bool,
    nested: bool,
}
fn validate_grant(
    parent: Option<&GrantParent>,
    audience: &[String],
    expiry: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<String, GrantError> {
    let p = parent.ok_or(GrantError::InvalidCredential)?;
    if p.revoked || p.disabled {
        return Err(GrantError::Revoked);
    }
    if p.actor_kind != "user" {
        return Err(GrantError::InvalidCredential);
    }
    if p.expires_at <= now {
        return Err(GrantError::Expired);
    }
    if expiry > p.expires_at || audience.iter().any(|v| !p.audience.contains(v)) {
        return Err(GrantError::InvalidScope);
    }
    if p.nested {
        return Err(GrantError::NestedDelegation);
    }
    Ok(p.subject.clone())
}
struct ListSubjectsRequest {
    cursor: Option<String>,
    limit: u32,
}
struct ListSessionsRequest {
    subject: Option<String>,
    cursor: Option<String>,
    limit: u32,
}
struct ListSubjectsResponseSubjectsItem {
    subject: String,
    status: ListSubjectsResponseSubjectsItemStatus,
    disabled_reason: Option<String>,
    disabled_until: Option<String>,
    created_at: String,
}
enum ListSubjectsResponseSubjectsItemStatus {
    Active,
    Disabled,
}
struct ListSessionsResponseSessionsItem {
    session_id: String,
    subject: String,
    actor_kind: String,
    assurance: String,
    expires_at: String,
    revoked: bool,
    created_at: String,
}
fn string(input: &Value, key: &str) -> Result<String, JsValue> {
    input[key]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| JsValue::from_str("Invalid local fixture input"))
}
fn bytes(input: &Value, key: &str) -> Result<Vec<u8>, JsValue> {
    serde_json::from_value(input[key].clone())
        .map_err(|_| JsValue::from_str("Invalid local fixture digest"))
}
fn wire<T: Serialize>(result: Result<T, AccountError>) -> Result<String, JsValue> {
    let value = result.map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_json::to_string(&value).map_err(|_| JsValue::from_str("Local fixture encoding failed"))
}

#[wasm_bindgen]
pub async fn invoke(input: String, batch: js_sys::Function) -> Result<String, JsValue> {
    let input: Value = serde_json::from_str(&input)
        .map_err(|_| JsValue::from_str("Invalid local fixture JSON"))?;
    let db = workers::D1Binding::new("LOCAL_ONLY", batch);
    match string(&input, "operation")?.as_str() {
        "ensure" => wire(
            d1::ensure_identity(
                &db,
                "fixture",
                &string(&input, "subject")?,
                &string(&input, "subject")?,
            )
            .await,
        ),
        "issue" | "managed_issue" => {
            let policy: ManagedSessionPolicy = serde_json::from_value(input["policy"].clone())
                .map_err(|_| JsValue::from_str("Invalid local fixture policy"))?;
            let now = OffsetDateTime::now_utc();
            let absolute = now
                + Duration::seconds(
                    i64::try_from(policy.absolute_timeout_seconds)
                        .map_err(|_| JsValue::from_str("Invalid local fixture timeout"))?,
                );
            let session = NewSession {
                session_id: string(&input, "session_id")?,
                digest: bytes(&input, "digest")?,
                subject: string(&input, "subject")?,
                actor_kind: "user".into(),
                assurance: "password".into(),
                audience: vec!["fixture.resource@1:read".into()],
                claims: BTreeMap::new(),
                expires_at: (now
                    + Duration::seconds(
                        i64::try_from(policy.idle_timeout_seconds)
                            .map_err(|_| JsValue::from_str("Invalid local fixture idle timeout"))?,
                    ))
                .min(absolute),
            };
            if input["operation"] == "issue" {
                return wire(d1::issue_session(&db, &session).await);
            }
            wire(
                d1::issue_managed_session(
                    &db,
                    &session,
                    &NewManagedSession {
                        issued_at: now,
                        absolute_expires_at: absolute,
                        idle_timeout_seconds: policy.idle_timeout_seconds,
                        renew_interval_seconds: policy.renew_interval_seconds,
                        last_renew_at: now,
                    },
                )
                .await,
            )
        }
        "renew" => {
            let policy: ManagedSessionPolicy = serde_json::from_value(input["policy"].clone())
                .map_err(|_| JsValue::from_str("Invalid local fixture policy"))?;
            wire(
                d1::renew_session(
                    &db,
                    &bytes(&input, "old_digest")?,
                    &bytes(&input, "new_digest")?,
                    &policy,
                )
                .await,
            )
        }
        "metadata" => {
            let policy: ManagedSessionPolicy = serde_json::from_value(input["policy"].clone())
                .map_err(|_| JsValue::from_str("Invalid local fixture policy"))?;
            wire(d1::session_metadata(&db, &bytes(&input, "digest")?, &policy).await)
        }
        "policy_expiry" => {
            let policy: ManagedSessionPolicy = serde_json::from_value(input["policy"].clone())
                .map_err(|_| JsValue::from_str("Invalid local fixture policy"))?;
            let expiry = d1::policy_expiry(&db, &string(&input, "session_id")?, &policy)
                .await
                .map_err(|error| JsValue::from_str(&error.to_string()))?;
            let text = expiry
                .map(format_time)
                .transpose()
                .map_err(|error| JsValue::from_str(&error))?;
            Ok(json!(text).to_string())
        }
        "load" => wire(d1::load_session(&db, &bytes(&input, "digest")?).await),
        "inspect" => wire(d1::inspect_session(&db, &string(&input, "session_id")?).await),
        "revoke_credential" => wire(d1::revoke_credential(&db, &bytes(&input, "digest")?).await),
        "revoke_session" => wire(d1::revoke_session(&db, &string(&input, "session_id")?).await),
        "disable" => {
            let value =
                d1::set_subject_status(&db, &string(&input, "subject")?, "disabled", None, None)
                    .await
                    .map_err(|e| JsValue::from_str(&e))?;
            Ok(json!(value).to_string())
        }
        "grant" => {
            let value = d1::create_grant(
                &db,
                &bytes(&input, "parent_digest")?,
                &string(&input, "session_id")?,
                &bytes(&input, "digest")?,
                &["fixture.resource@1:read".into()],
                OffsetDateTime::now_utc() + Duration::seconds(10),
            )
            .await
            .map_err(|e| JsValue::from_str(&e))?;
            Ok(serde_json::to_string(&value)
                .map_err(|_| JsValue::from_str("Local fixture encoding failed"))?)
        }
        _ => Err(JsValue::from_str("Unknown local fixture operation")),
    }
}

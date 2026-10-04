//! Optional Account-owned cross-realm binding. The workflow owns Access and Audit collaboration.
use super::{
    AccountAuthPlugin, AccountConfigError, Duration, InvocationContext, NativeRequestFuture,
    OffsetDateTime, Rfc3339, RuntimeFailure, Validity, random_id, runtime, storage, valid_caller,
    valid_name,
};
use lenso_capability_operator_binding as role;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
pub(crate) const CLAIM: &str = "lenso.auth.operator-binding";
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorBindingConfig {
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
impl OperatorBindingConfig {
    pub(crate) fn validate(&self) -> Result<(), AccountConfigError> {
        let valid_window = OffsetDateTime::parse(&self.bootstrap_not_before, &Rfc3339)
            .ok()
            .zip(OffsetDateTime::parse(&self.bootstrap_expires_at, &Rfc3339).ok())
            .is_some_and(|(start, end)| end > start && end - start <= Duration::minutes(15));
        if !valid_caller(&self.source_account_instance)
            || !valid_name(&self.scope_kind)
            || !valid_name(&self.scope_id)
            || !valid_name(&self.source_issuer)
            || !valid_name(&self.deployment)
            || !valid_name(&self.bootstrap_subject)
            || !valid_window
            || self.workflow_callers.is_empty()
            || self.workflow_callers.len() > 64
            || self.workflow_callers.iter().any(|v| !valid_caller(v))
            || self.workflow_callers.iter().collect::<BTreeSet<_>>().len()
                != self.workflow_callers.len()
        {
            return Err(AccountConfigError::InvalidOperatorBinding);
        }
        Ok(())
    }
    pub(crate) fn admitted(&self, c: &InvocationContext) -> bool {
        c.caller_instance()
            .is_some_and(|id| self.workflow_callers.iter().any(|v| v == id))
    }
    fn bootstrap_open(&self) -> bool {
        OffsetDateTime::parse(&self.bootstrap_not_before, &Rfc3339)
            .ok()
            .zip(OffsetDateTime::parse(&self.bootstrap_expires_at, &Rfc3339).ok())
            .is_some_and(|(start, end)| {
                start <= OffsetDateTime::now_utc() && OffsetDateTime::now_utc() < end
            })
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
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
}
impl Record {
    fn wire(&self) -> role::Binding {
        role::Binding {
            source_issuer: self.source_issuer.clone(),
            deployment: self.deployment.clone(),
            scope_kind: self.scope_kind.clone(),
            scope_id: self.scope_id.clone(),
            binding_id: self.binding_id.clone(),
            source_subject: self.source_subject.clone(),
            operator_subject: self.operator_subject.clone(),
            revision: self.revision.to_string(),
            active: self.status == "active",
            revoked: self.status == "revoked",
            revocation_pending: self.revocation_state == "pending",
            revoked_by: self.revoked_by.clone(),
            revoked_at: self.revoked_at.clone(),
            revocation_audit_event_id: self.revocation_audit_event_id.clone(),
            audit_event_id: self.audit_event_id.clone(),
            policy_revision: self.policy_revision.clone(),
        }
    }
}
impl super::AccountAuthConfig {
    pub fn with_operator_bindings(
        mut self,
        cfg: OperatorBindingConfig,
    ) -> Result<Self, AccountConfigError> {
        self.operator_bindings = Some(cfg);
        self.validate()?;
        Ok(self)
    }
}
pub(crate) fn validate_mode(config: &super::AccountAuthConfig) -> Result<(), AccountConfigError> {
    let Some(cfg) = &config.operator_bindings else {
        return Ok(());
    };
    cfg.validate()?;
    if cfg.source_issuer == config.issuer
        || config
            .management_session_ceiling
            .as_ref()
            .is_none_or(|ceiling| {
                ceiling.deployment != cfg.deployment
                    || ceiling.resource_scopes.len() != 1
                    || !ceiling
                        .resource_scopes
                        .iter()
                        .any(|scope| scope.kind == cfg.scope_kind && scope.id == cfg.scope_id)
            })
    {
        return Err(AccountConfigError::InvalidOperatorBinding);
    }
    Ok(())
}
/// Both issuance paths share the current binding, source and fixed permission ceiling checks.
pub(crate) async fn admit_issue(
    store: &storage::AccountStore,
    cfg: Option<&OperatorBindingConfig>,
    context: &InvocationContext,
    subject: &str,
    claims: &mut BTreeMap<String, serde_json::Value>,
    source: Option<&super::directory::DirectoryClient>,
    ceiling: Option<&lenso_auth_sdk::credential::ManagementCredentialCeiling>,
) -> Result<bool, RuntimeFailure> {
    if cfg.is_some()
        && claims.get("permissions").is_some_and(|value| {
            value.as_array().is_none_or(|permissions| {
                permissions.iter().any(|permission| {
                    permission.as_str().is_none_or(|p| {
                        ceiling.is_none_or(|c| !c.permissions.iter().any(|allowed| allowed == p))
                    })
                })
            })
        })
    {
        return Ok(false);
    }
    if !issue_claim(store, cfg, context, subject, claims).await? {
        return Ok(false);
    }
    if cfg.is_some() {
        session_admitted(store, cfg, subject, claims, source, context).await
    } else {
        Ok(true)
    }
}
pub(crate) async fn issue_claim(
    store: &storage::AccountStore,
    cfg: Option<&OperatorBindingConfig>,
    context: &InvocationContext,
    subject: &str,
    claims: &mut BTreeMap<String, serde_json::Value>,
) -> Result<bool, RuntimeFailure> {
    if claims.contains_key(CLAIM) {
        return Ok(false);
    }
    let Some(cfg) = cfg else {
        return Ok(true);
    };
    if !cfg.admitted(context) {
        return Ok(false);
    }
    let Some(row) = storage::operator_binding::read(store, cfg, "operator_subject", subject)
        .await
        .map_err(runtime)?
    else {
        return Ok(false);
    };
    if row.status != "active" {
        return Ok(false);
    }
    claims.insert(
        CLAIM.into(),
        serde_json::json!({"binding_id":row.binding_id,"revision":row.revision.to_string()}),
    );
    Ok(true)
}
pub(crate) async fn session_admitted(
    store: &storage::AccountStore,
    cfg: Option<&OperatorBindingConfig>,
    subject: &str,
    claims: &BTreeMap<String, serde_json::Value>,
    source_directory: Option<&super::directory::DirectoryClient>,
    context: &InvocationContext,
) -> Result<bool, RuntimeFailure> {
    let Some(cfg) = cfg else {
        return Ok(!claims.contains_key(CLAIM));
    };
    let Some(row) = storage::operator_binding::read(store, cfg, "operator_subject", subject)
        .await
        .map_err(runtime)?
    else {
        return Ok(false);
    };
    let Some(source) = source_directory else {
        return Ok(false);
    };
    let current = source
        .read_status_with_context(
            context.clone(),
            super::directory::ReadStatusRequest {
                subject: row.source_subject.clone(),
            },
        )
        .await;
    let source_active = current.is_ok_and(|value| {
        value.subject == row.source_subject
            && value.status == super::directory::ReadStatusResponseStatus::Active
    });
    Ok(source_active
        && row.status == "active"
        && claims.get(CLAIM).is_some_and(|claim| {
            claim.get("binding_id").and_then(serde_json::Value::as_str)
                == Some(row.binding_id.as_str())
                && claim.get("revision").and_then(serde_json::Value::as_str)
                    == Some(row.revision.to_string().as_str())
        }))
}
impl AccountAuthPlugin {
    pub(crate) fn prepare_bootstrap(
        &self,
        context: InvocationContext,
        request: role::PrepareBootstrapRequest,
    ) -> NativeRequestFuture<role::OperatorBindingPrepareBootstrap> {
        let cfg = self.config.operator_bindings.clone();
        let prepared = self.prepared();
        Box::pin(async move {
            let Some(cfg) = cfg else {
                return Ok(Err(role::PrepareBootstrapError::NotEnabled));
            };
            if !cfg.admitted(&context) {
                return Ok(Err(role::PrepareBootstrapError::PermissionDenied));
            }
            if !cfg.bootstrap_open() {
                return Ok(Err(role::PrepareBootstrapError::BootstrapExpired));
            }
            if request.source_issuer != cfg.source_issuer
                || request.deployment != cfg.deployment
                || request.scope_kind != cfg.scope_kind
                || request.scope_id != cfg.scope_id
                || request.source_subject != cfg.bootstrap_subject
            {
                return Ok(Err(role::PrepareBootstrapError::PermissionDenied));
            }
            let prepared = prepared?;
            let external =
                serde_json::to_vec(&(&cfg.source_issuer, &cfg.deployment, &request.source_subject))
                    .map_err(runtime)?;
            let external = format!("{:x}", sha2::Sha256::digest(external));
            let proposed = random_id("usr_").map_err(runtime)?;
            let (operator, status, _) =
                storage::ensure_identity(&prepared.store, "operator-account", &external, &proposed)
                    .await
                    .map_err(runtime)?;
            if status != "active" {
                return Ok(Err(role::PrepareBootstrapError::NotActive));
            }
            let proposed = random_id("opb_").map_err(runtime)?;
            let row = storage::operator_binding::prepare(
                &prepared.store,
                &cfg,
                &request.source_subject,
                &proposed,
                &operator,
            )
            .await
            .map_err(runtime)?;
            if row.status != "pending" {
                return Ok(Err(role::PrepareBootstrapError::BootstrapConsumed));
            }
            let now = OffsetDateTime::now_utc();
            let validity = Validity::new(now, now + Duration::seconds(5))
                .map_err(|_| runtime("invalid operator control assertion validity"))?;
            let assertion = prepared.issuer.issue(
                row.operator_subject.clone(),
                "user",
                "bootstrap",
                ["create_role", "set_role_permissions", "assign_role"]
                    .into_iter()
                    .map(|op| lenso_auth_sdk::audience("lenso.access-control-admin@1", op))
                    .collect::<Vec<_>>(),
                validity,
                BTreeMap::new(),
            );
            Ok(Ok(role::PrepareBootstrapResponse {
                binding: row.wire(),
                control_assertion: serde_json::to_string(&assertion.to_wire()).map_err(runtime)?,
            }))
        })
    }
    pub(crate) fn activate_binding(
        &self,
        context: InvocationContext,
        request: role::ActivateBindingRequest,
    ) -> NativeRequestFuture<role::OperatorBindingActivateBinding> {
        let cfg = self.config.operator_bindings.clone();
        let prepared = self.prepared();
        Box::pin(async move {
            let Some(cfg) = cfg else {
                return Ok(Err(role::ActivateBindingError::NotEnabled));
            };
            if !cfg.admitted(&context) {
                return Ok(Err(role::ActivateBindingError::PermissionDenied));
            }
            if !cfg.bootstrap_open() {
                return Ok(Err(role::ActivateBindingError::BootstrapExpired));
            }
            let Ok(revision) = request.revision.parse::<i64>() else {
                return Ok(Err(role::ActivateBindingError::InvalidRequest));
            };
            if revision < 1
                || !valid_name(&request.binding_id)
                || request.audit_event_id.is_empty()
                || request.audit_event_id.len() > 256
                || request.policy_revision.is_empty()
                || request.policy_revision.len() > 256
            {
                return Ok(Err(role::ActivateBindingError::InvalidRequest));
            }
            let prepared = prepared?;
            let Some(row) = storage::operator_binding::activate(
                &prepared.store,
                &cfg,
                &request.binding_id,
                revision,
                &request.audit_event_id,
                &request.policy_revision,
            )
            .await
            .map_err(runtime)?
            else {
                return Ok(Err(role::ActivateBindingError::NotFound));
            };
            if row.status != "active"
                || row.revision != revision
                || row.audit_event_id != request.audit_event_id
                || row.policy_revision != request.policy_revision
            {
                return Ok(Err(role::ActivateBindingError::NotActive));
            }
            Ok(Ok(row.wire()))
        })
    }
    pub(crate) fn read_binding(
        &self,
        context: InvocationContext,
        request: role::ReadBindingRequest,
    ) -> NativeRequestFuture<role::OperatorBindingReadBinding> {
        let cfg = self.config.operator_bindings.clone();
        let prepared = self.prepared();
        Box::pin(async move {
            let Some(cfg) = cfg else {
                return Ok(Err(role::ReadBindingError::NotEnabled));
            };
            if !cfg.admitted(&context) {
                return Ok(Err(role::ReadBindingError::PermissionDenied));
            }
            if !valid_name(&request.source_subject) {
                return Ok(Err(role::ReadBindingError::InvalidRequest));
            }
            let prepared = prepared?;
            let Some(row) = storage::operator_binding::read(
                &prepared.store,
                &cfg,
                "source_subject",
                &request.source_subject,
            )
            .await
            .map_err(runtime)?
            else {
                return Ok(Err(role::ReadBindingError::NotFound));
            };
            Ok(Ok(row.wire()))
        })
    }
    pub(crate) fn revoke_binding(
        &self,
        context: InvocationContext,
        request: role::RevokeBindingRequest,
    ) -> NativeRequestFuture<role::OperatorBindingRevokeBinding> {
        let cfg = self.config.operator_bindings.clone();
        let prepared = self.prepared();
        Box::pin(async move {
            let Some(cfg) = cfg else {
                return Ok(Err(role::RevokeBindingError::NotEnabled));
            };
            if !cfg.admitted(&context) {
                return Ok(Err(role::RevokeBindingError::PermissionDenied));
            }
            if !valid_name(&request.binding_id) || !valid_name(&request.actor_subject) {
                return Ok(Err(role::RevokeBindingError::InvalidRequest));
            }
            let prepared = prepared?;
            let Some(row) = storage::operator_binding::revoke(
                &prepared.store,
                &cfg,
                &request.binding_id,
                &request.actor_subject,
                &super::format_time(OffsetDateTime::now_utc())?,
            )
            .await
            .map_err(runtime)?
            else {
                return Ok(Err(role::RevokeBindingError::NotFound));
            };
            Ok(Ok(row.wire()))
        })
    }
}

impl AccountAuthPlugin {
    pub(crate) fn prepare_recovery(
        &self,
        context: InvocationContext,
        request: role::RecoveryRequest,
    ) -> NativeRequestFuture<role::OperatorBindingPrepareRecovery> {
        let cfg = self.config.operator_bindings.clone();
        let prepared = self.prepared();
        Box::pin(async move {
            let Some(cfg) = cfg else {
                return Ok(Err(role::PrepareRecoveryError::NotEnabled));
            };
            if !cfg.admitted(&context) {
                return Ok(Err(role::PrepareRecoveryError::PermissionDenied));
            }
            let prepared = prepared?;
            let Some(row) = storage::operator_binding::read(
                &prepared.store,
                &cfg,
                "binding_id",
                &request.binding_id,
            )
            .await
            .map_err(runtime)?
            else {
                return Ok(Err(role::PrepareRecoveryError::NotFound));
            };
            if row.status != "revoked" || row.source_subject != cfg.bootstrap_subject {
                return Ok(Err(role::PrepareRecoveryError::PermissionDenied));
            }
            let now = OffsetDateTime::now_utc();
            let validity = Validity::new(now, now + Duration::seconds(5))
                .map_err(|_| runtime("invalid recovery assertion validity"))?;
            let assertion = prepared.issuer.issue(
                row.operator_subject.clone(),
                "user",
                "recovery",
                vec![lenso_auth_sdk::audience(
                    "lenso.access-control-admin@1",
                    "revoke_role",
                )],
                validity,
                BTreeMap::new(),
            );
            Ok(Ok(role::PrepareBootstrapResponse {
                binding: row.wire(),
                control_assertion: serde_json::to_string(&assertion.to_wire()).map_err(runtime)?,
            }))
        })
    }
    pub(crate) fn complete_revocation(
        &self,
        context: InvocationContext,
        request: role::CompleteRevocationRequest,
    ) -> NativeRequestFuture<role::OperatorBindingCompleteRevocation> {
        let cfg = self.config.operator_bindings.clone();
        let prepared = self.prepared();
        Box::pin(async move {
            let Some(cfg) = cfg else {
                return Ok(Err(role::CompleteRevocationError::NotEnabled));
            };
            if !cfg.admitted(&context) {
                return Ok(Err(role::CompleteRevocationError::PermissionDenied));
            }
            let Ok(revision) = request.revision.parse::<i64>() else {
                return Ok(Err(role::CompleteRevocationError::InvalidRequest));
            };
            if revision < 1
                || request.audit_event_id.is_empty()
                || request.audit_event_id.len() > 256
            {
                return Ok(Err(role::CompleteRevocationError::InvalidRequest));
            }
            let prepared = prepared?;
            let Some(row) = storage::operator_binding::complete_revocation(
                &prepared.store,
                &cfg,
                &request.binding_id,
                revision,
                &request.audit_event_id,
            )
            .await
            .map_err(runtime)?
            else {
                return Ok(Err(role::CompleteRevocationError::NotFound));
            };
            if row.status != "revoked"
                || row.revision != revision
                || row.revocation_state != "complete"
            {
                return Ok(Err(role::CompleteRevocationError::NotActive));
            }
            Ok(Ok(row.wire()))
        })
    }
}

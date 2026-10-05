//! Optional Account Console UI; durable account and session facts stay with Account.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use lenso::prelude::*;
use lenso_auth_sdk::{
    ActorAssertion, ActorProjectionError, FixedClock, TypedActor,
    credential::{CredentialBinding, ManagementCredentialCeiling},
    realm::RealmAssertionVerifier,
};
use lenso_capability_access_control as access;
use lenso_capability_account_admin as admin;
use lenso_capability_credential_issuer as issuer;
use lenso_capability_credential_state as state;
use lenso_capability_ui_contribution as ui;
use lenso_capability_workspace_service as service;
use lenso_kernel::{InvocationContext, PluginDependencies, RuntimeFailure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const SERVICE_ID: &str = "account-admin";
const MODULE: &str = include_str!("../dist/assets/workspace.mjs");
const MAX_REQUEST_BYTES: usize = 4096;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccessScope {
    kind: String,
    id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum AllowedMutation {
    SetSubjectStatus,
    RevokeSession,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountConsoleConfig {
    issuer: String,
    public_key: String,
    assertion_max_ttl_seconds: u32,
    caller_instances: Vec<String>,
    deployment: String,
    access_scope: AccessScope,
    account_instance: String,
    #[serde(default)]
    allowed_mutations: Vec<AllowedMutation>,
}

fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}
fn instance(value: &str) -> bool {
    value.len() <= 256
        && value
            .split_once('/')
            .is_some_and(|(plugin, key)| plugin.contains('.') && label(plugin) && label(key))
}
fn invalid_plan() -> RuntimeFailure {
    RuntimeFailure::InvalidResolvedPlan { detail: "Account Console requires explicit verification authority, one Account instance, deployment, fixed Access scope and exact Console callers.".into() }
}
impl AccountConsoleConfig {
    fn verifier(&self) -> Result<RealmAssertionVerifier, RuntimeFailure> {
        RealmAssertionVerifier::new(
            "account-console",
            &self.issuer,
            &self.public_key,
            self.assertion_max_ttl_seconds,
            None,
        )
        .map_err(|_| invalid_plan())
    }
    fn permission(&self, operation: &str) -> Result<&'static str, service::InvokeError> {
        match operation {
            "read_policy" | "list_subjects" => Ok("auth.subject.read"),
            "list_sessions" => Ok("auth.session.read"),
            "set_subject_status"
                if self
                    .allowed_mutations
                    .contains(&AllowedMutation::SetSubjectStatus) =>
            {
                Ok("auth.subject.status")
            }
            "revoke_session"
                if self
                    .allowed_mutations
                    .contains(&AllowedMutation::RevokeSession) =>
            {
                Ok("auth.session.revoke")
            }
            _ => Err(service::InvokeError::UnknownOperation),
        }
    }
    fn actor(
        &self,
        context: &InvocationContext,
        now: OffsetDateTime,
    ) -> Result<ActorAssertion, service::InvokeError> {
        if !context.caller_instance().is_some_and(|caller| {
            self.caller_instances
                .iter()
                .any(|allowed| caller == allowed)
        }) {
            return Err(service::InvokeError::Denied);
        }
        self.verifier()
            .map_err(|_| service::InvokeError::Denied)?
            .project_context::<Human>(
                context,
                service::CAPABILITY_ID,
                service::INVOKE_OPERATION,
                &FixedClock::new(now),
            )
            .map(|Human(actor)| actor)
            .map_err(|_| service::InvokeError::Denied)
    }
    fn allows(&self, ceiling: &ManagementCredentialCeiling, permission: &str) -> bool {
        ceiling.allows(
            &self.deployment,
            permission,
            &self.access_scope.kind,
            &self.access_scope.id,
        )
    }
}
fn validate_config(config: &AccountConsoleConfig) -> Result<(), RuntimeFailure> {
    config.verifier()?;
    if !label(&config.issuer)
        || !label(&config.deployment)
        || !label(&config.access_scope.kind)
        || !label(&config.access_scope.id)
        || !instance(&config.account_instance)
        || config.caller_instances.is_empty()
        || config.caller_instances.len() > 64
        || config
            .caller_instances
            .iter()
            .any(|caller| !instance(caller))
        || config
            .caller_instances
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != config.caller_instances.len()
        || config
            .allowed_mutations
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != config.allowed_mutations.len()
    {
        return Err(invalid_plan());
    }
    Ok(())
}

struct Human(ActorAssertion);
impl TypedActor for Human {
    fn from_assertion(assertion: &ActorAssertion) -> Result<Self, ActorProjectionError> {
        if assertion.actor_kind() != "user" {
            return Err(ActorProjectionError::UnexpectedActorKind {
                expected: "user".into(),
                actual: assertion.actor_kind().into(),
            });
        }
        if assertion.to_wire().claims.as_ref().is_some_and(|claims| {
            claims.contains_key(lenso_auth_sdk::delegation::SCOPED_DELEGATION_CLAIM)
        }) {
            return Err(lenso_auth_sdk::AssertionValidationError::InvalidProof.into());
        }
        Ok(Self(assertion.clone()))
    }
}

fn current_admitted(
    config: &AccountConsoleConfig,
    actor: &ActorAssertion,
    inspected: &state::InspectResponse,
    permission: &str,
    now: OffsetDateTime,
) -> bool {
    let wire = actor.to_wire();
    let (
        Ok(binding),
        Ok(current_binding),
        Ok(signed),
        Ok(current),
        Ok(expires),
        Ok(assertion_expires),
    ) = (
        CredentialBinding::from_assertion(actor),
        CredentialBinding::from_claims(&inspected.claims),
        ManagementCredentialCeiling::from_assertion(actor),
        ManagementCredentialCeiling::from_claims(&inspected.claims),
        OffsetDateTime::parse(inspected.expires_at.as_str(), &Rfc3339),
        OffsetDateTime::parse(&wire.expires_at, &Rfc3339),
    )
    else {
        return false;
    };
    inspected.active
        && inspected.actor_kind == "user"
        && inspected.subject == actor.subject()
        && inspected.assurance == wire.assurance
        && inspected.credential_id == binding.credential_id
        && inspected.session_id == binding.session_id
        && binding == current_binding
        && expires > now
        && assertion_expires > now
        && assertion_expires <= expires
        && inspected.audience.contains(&lenso_auth_sdk::audience(
            service::CAPABILITY_ID,
            service::INVOKE_OPERATION,
        ))
        && !inspected
            .claims
            .contains_key(lenso_auth_sdk::delegation::SCOPED_DELEGATION_CLAIM)
        && config.allows(&signed, permission)
        && config.allows(&current, permission)
}

fn validate_bindings(
    config: &AccountConsoleConfig,
    dependencies: &PluginDependencies,
) -> Result<(), RuntimeFailure> {
    for capability in [
        admin::CAPABILITY_ID,
        state::CAPABILITY_ID,
        issuer::CAPABILITY_ID,
    ] {
        let selected = dependencies
            .bindings()
            .iter()
            .filter(|binding| binding.capability_id() == capability)
            .collect::<Vec<_>>();
        if selected.is_empty()
            || selected
                .iter()
                .any(|binding| binding.provider_instance() != config.account_instance)
        {
            return Err(invalid_plan());
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyRequest {}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageRequest {
    limit: i64,
    cursor: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionsRequest {
    subject: String,
    limit: i64,
    cursor: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusRequest {
    subject: String,
    status: admin::SetSubjectStatusRequestStatus,
    reason: Option<String>,
    disabled_until: Option<String>,
    confirmed: bool,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeSessionRequest {
    session_id: String,
    confirmed: bool,
}

fn decode<T: serde::de::DeserializeOwned>(body: &str) -> Result<T, service::InvokeError> {
    if body.len() > MAX_REQUEST_BYTES.div_ceil(3) * 4 {
        return Err(service::InvokeError::RequestTooLarge);
    }
    let body = STANDARD
        .decode(body)
        .map_err(|_| service::InvokeError::CodecMismatch)?;
    if body.len() > MAX_REQUEST_BYTES {
        return Err(service::InvokeError::RequestTooLarge);
    }
    serde_json::from_slice(&body).map_err(|_| service::InvokeError::CodecMismatch)
}
fn valid_page(limit: i64, cursor: Option<&str>) -> bool {
    (1..=200).contains(&limit) && cursor.is_none_or(label)
}
fn response<T: Serialize>(
    value: &T,
    outcome: service::InvokeResponseOutcome,
) -> PluginResult<service::InvokeResponse, service::InvokeError> {
    let body = serde_json::to_vec(value).map_err(|_| {
        PluginError::runtime(RuntimeFailure::PluginFailure {
            detail: "Account Console response encoding failed.".into(),
        })
    })?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(PluginError::domain(service::InvokeError::ResponseTooLarge));
    }
    Ok(service::InvokeResponse {
        body_base64: STANDARD.encode(body),
        outcome,
    })
}

#[lenso::plugin(lifecycle, configuration_schema="config.schema.json", validate=validate_config)]
#[derive(Clone, Debug)]
struct AccountConsole {
    #[config]
    config: AccountConsoleConfig,
    account_admin: lenso::Port<admin::AccountAdminClient>,
    credential_state: lenso::Port<state::CredentialStateClient>,
    issuer: lenso::Port<issuer::CredentialIssuerClient>,
    access: lenso::Port<access::AccessControlClient>,
}
impl lenso::Lifecycle for AccountConsole {
    async fn prepare(&self, context: lenso_kernel::PrepareContext) -> Result<(), RuntimeFailure> {
        validate_bindings(&self.config, context.dependencies())
    }
}

impl AccountConsole {
    async fn authorize(
        &self,
        context: &InvocationContext,
        permission: &str,
    ) -> PluginResult<(), service::InvokeError> {
        let now = OffsetDateTime::now_utc();
        let actor = self
            .config
            .actor(context, now)
            .map_err(PluginError::domain)?;
        let binding = CredentialBinding::from_assertion(&actor)
            .map_err(|_| PluginError::domain(service::InvokeError::Denied))?;
        let inspected = self
            .credential_state
            .inspect_with_context(
                context.clone(),
                state::InspectRequest {
                    credential_id: binding.credential_id,
                    session_id: binding.session_id,
                },
            )
            .await
            .map_err(|error| match error {
                state::CredentialStateInvocationError::Domain(_) => {
                    PluginError::domain(service::InvokeError::Denied)
                }
                state::CredentialStateInvocationError::Runtime(error) => {
                    PluginError::runtime(error)
                }
            })?;
        if !current_admitted(
            &self.config,
            &actor,
            &inspected,
            permission,
            OffsetDateTime::now_utc(),
        ) {
            return Err(PluginError::domain(service::InvokeError::Denied));
        }
        let allowed = self
            .access
            .check_permission_with_context(
                context.clone(),
                access::CheckPermissionRequest {
                    permission: permission.into(),
                    subject: actor.subject().into(),
                    scope: access::CheckPermissionRequestScope {
                        kind: self.config.access_scope.kind.clone(),
                        id: self.config.access_scope.id.clone(),
                    },
                },
            )
            .await
            .map_err(|error| match error {
                access::AccessControlInvocationError::Domain(_) => {
                    PluginError::domain(service::InvokeError::Denied)
                }
                access::AccessControlInvocationError::Runtime(error) => PluginError::runtime(error),
            })?;
        if !allowed.allowed {
            return Err(PluginError::domain(service::InvokeError::Denied));
        }
        Ok(())
    }
    fn operations(&self) -> Vec<&'static str> {
        let mut operations = vec!["read_policy", "list_subjects", "list_sessions"];
        if self
            .config
            .allowed_mutations
            .contains(&AllowedMutation::SetSubjectStatus)
        {
            operations.push("set_subject_status");
        }
        if self
            .config
            .allowed_mutations
            .contains(&AllowedMutation::RevokeSession)
        {
            operations.push("revoke_session");
        }
        operations
    }
}

#[lenso::provides(ui::Contribution, service::WorkspaceService)]
impl AccountConsole {
    async fn describe_contribution(
        &self,
        _context: Ctx,
        _request: ui::DescribeRequest,
    ) -> PluginResult<ui::DescribeResponse, ui::DescribeError> {
        serde_json::from_value(serde_json::json!({
            "assets":[{"path":"workspace.mjs","media_type":"text/javascript; charset=utf-8","content_base64":STANDARD.encode(MODULE)}],
            "module":"workspace.mjs","styles":[],"revision":env!("CARGO_PKG_VERSION"),"workspace_id":"accounts","title":"Accounts and sessions",
            "navigation":{"label":"Auth","items":[{"label":"Accounts and sessions","path":[]}]},
            "requirements":[{"capability_id":admin::CAPABILITY_ID,"descriptor_version":admin::DESCRIPTOR_VERSION,"operations":self.operations(),"required":true,"service_id":SERVICE_ID,"source":"owner"}],
            "subject":{"kind":"console"},"workspaces":[{"access":"administrator","id":"accounts","index":[],"navigation":{"label":"Auth","items":[{"label":"Accounts and sessions","path":[]}]},"path":"/accounts","routes":[[]],"title":"Accounts and sessions"}]
        })).map_err(|_|PluginError::runtime(RuntimeFailure::PluginFailure{detail:"Account Console contribution encoding failed.".into()}))
    }
    async fn describe_exports(
        &self,
        _context: Ctx,
        _request: service::DescribeExportsRequest,
    ) -> PluginResult<service::DescribeExportsResponse, service::DescribeExportsError> {
        Ok(service::DescribeExportsResponse{adapter_revision:env!("CARGO_PKG_VERSION").into(),services:vec![service::DescribeExportsResponseServicesItem{capability_id:admin::CAPABILITY_ID.into(),descriptor_version:admin::DESCRIPTOR_VERSION.into(),service_id:SERVICE_ID.into(),operations:self.operations().into_iter().map(|name|service::DescribeExportsResponseServicesItemOperationsItem{name:name.into(),interaction:service::DescribeExportsResponseServicesItemOperationsItemInteraction::Request}).collect()}]})
    }
    async fn invoke(
        &self,
        context: Ctx,
        request: service::InvokeRequest,
    ) -> PluginResult<service::InvokeResponse, service::InvokeError> {
        // Verify the caller before exposing configured operation availability.
        self.config
            .actor(&context, OffsetDateTime::now_utc())
            .map_err(PluginError::domain)?;
        if request.service_id != SERVICE_ID {
            return Err(PluginError::domain(service::InvokeError::UnknownService));
        }
        let permission = self
            .config
            .permission(&request.operation)
            .map_err(PluginError::domain)?;
        self.authorize(&context, permission).await?;
        macro_rules! forward {
            ($call:expr,$domain:path,$runtime:path) => {
                match $call.await {
                    Ok(value) => response(&value, service::InvokeResponseOutcome::Success),
                    Err($domain(error)) => {
                        response(&error, service::InvokeResponseOutcome::DomainError)
                    }
                    Err($runtime(error)) => Err(PluginError::runtime(error)),
                }
            };
        }
        match request.operation.as_str() {
            "read_policy" => {
                let _: PolicyRequest = decode(&request.body_base64).map_err(PluginError::domain)?;
                response(
                    &serde_json::json!({"allowed_mutations":self.config.allowed_mutations,"access_scope":self.config.access_scope,"title":"Accounts and sessions"}),
                    service::InvokeResponseOutcome::Success,
                )
            }
            "list_subjects" => {
                let page: PageRequest =
                    decode(&request.body_base64).map_err(PluginError::domain)?;
                if !valid_page(page.limit, page.cursor.as_deref()) {
                    return Err(PluginError::domain(service::InvokeError::CodecMismatch));
                }
                forward!(
                    self.account_admin.list_subjects_with_context(
                        context,
                        admin::ListSubjectsRequest {
                            limit: page.limit,
                            cursor: page.cursor
                        }
                    ),
                    admin::AccountAdminListSubjectsInvocationError::Domain,
                    admin::AccountAdminListSubjectsInvocationError::Runtime
                )
            }
            "list_sessions" => {
                let page: SessionsRequest =
                    decode(&request.body_base64).map_err(PluginError::domain)?;
                if !valid_page(page.limit, page.cursor.as_deref()) || !label(&page.subject) {
                    return Err(PluginError::domain(service::InvokeError::CodecMismatch));
                }
                forward!(
                    self.account_admin.list_sessions_with_context(
                        context,
                        admin::ListSessionsRequest {
                            subject: Some(page.subject),
                            limit: page.limit,
                            cursor: page.cursor
                        }
                    ),
                    admin::AccountAdminListSessionsInvocationError::Domain,
                    admin::AccountAdminListSessionsInvocationError::Runtime
                )
            }
            "set_subject_status" => {
                let status: StatusRequest =
                    decode(&request.body_base64).map_err(PluginError::domain)?;
                if !status.confirmed {
                    return Err(PluginError::domain(service::InvokeError::Denied));
                }
                if !label(&status.subject)
                    || status.reason.as_ref().is_some_and(|reason| {
                        reason.len() > 512 || reason.chars().any(char::is_control)
                    })
                {
                    return Err(PluginError::domain(service::InvokeError::CodecMismatch));
                }
                if status
                    .disabled_until
                    .as_ref()
                    .is_some_and(|value| OffsetDateTime::parse(value, &Rfc3339).is_err())
                {
                    return Err(PluginError::domain(service::InvokeError::CodecMismatch));
                }
                let disabled_until = status.disabled_until;
                forward!(
                    self.account_admin.set_subject_status_with_context(
                        context,
                        admin::SetSubjectStatusRequest {
                            subject: status.subject,
                            status: status.status,
                            reason: status.reason,
                            disabled_until
                        }
                    ),
                    admin::AccountAdminSetSubjectStatusInvocationError::Domain,
                    admin::AccountAdminSetSubjectStatusInvocationError::Runtime
                )
            }
            "revoke_session" => {
                let revoke: RevokeSessionRequest =
                    decode(&request.body_base64).map_err(PluginError::domain)?;
                if !revoke.confirmed {
                    return Err(PluginError::domain(service::InvokeError::Denied));
                }
                if !label(&revoke.session_id) {
                    return Err(PluginError::domain(service::InvokeError::CodecMismatch));
                }
                forward!(
                    self.issuer.revoke_with_context(
                        context,
                        issuer::RevokeRequest {
                            session_id: revoke.session_id
                        }
                    ),
                    issuer::CredentialIssuerRevokeInvocationError::Domain,
                    issuer::CredentialIssuerRevokeInvocationError::Runtime
                )
            }
            _ => Err(PluginError::domain(service::InvokeError::UnknownOperation)),
        }
    }
    fn subscribe(
        &self,
        _context: Ctx,
        _request: service::SubscribeRequest,
    ) -> futures::future::LocalBoxFuture<
        'static,
        Result<
            lenso::ProviderStream<service::WorkspaceServiceSubscribe>,
            service::WorkspaceServiceSubscribeInvocationError,
        >,
    > {
        Box::pin(futures::future::ready(Err(
            service::WorkspaceServiceSubscribeInvocationError::Domain(
                service::SubscribeError::UnknownOperation,
            ),
        )))
    }
}
/// Include this optional owner factory in the selected native App Host.
pub fn link() {}
#[cfg(test)]
mod tests;

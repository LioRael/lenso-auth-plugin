//! Optional protocol-neutral binding workflow. Ingress owns HTTP, CSRF and Cookies.
use lenso_auth_sdk::{
    ActorAssertion, ActorProjectionError, AssertionClock, AuthOutcome, TypedActor,
    credential::CredentialBinding, decode_auth_response, realm::RealmAssertionVerifier,
};
use lenso_capability_access_control as access;
use lenso_capability_access_control_admin as admin;
use lenso_capability_audit_log as audit;
use lenso_capability_credential_issuer as issuer;
use lenso_capability_credential_state as state;
use lenso_capability_operator_binding as bindings;
use lenso_capability_operator_session as role;
use lenso_kernel::{InvocationContext, RuntimeFailure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
pub const LOGIN_PERMISSION: &str = "lenso.auth.operator-login";
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, lenso::PluginConfig)]
#[serde(deny_unknown_fields)]
pub struct OperatorSessionConfig {
    pub accounts_issuer: String,
    pub accounts_public_key: String,
    pub operators_issuer: String,
    pub operators_public_key: String,
    pub maximum_assertion_ttl_seconds: u32,
    pub deployment: String,
    pub scope_kind: String,
    pub scope_id: String,
    pub bootstrap_subject: String,
    pub bootstrap_callers: Vec<String>,
    pub permissions: Vec<String>,
    pub session_ttl_seconds: u32,
    pub operator_audience: Vec<String>,
}
fn invalid() -> RuntimeFailure {
    RuntimeFailure::InvalidResolvedPlan{detail:"Operator binding requires distinct fixed realms, exact deployment scope, finite permissions/TTL and controlled bootstrap callers".into()}
}
fn label(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 256
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}
fn validate_config(c: &OperatorSessionConfig) -> Result<(), RuntimeFailure> {
    c.verifier(false)?;
    c.verifier(true)?;
    if c.accounts_issuer == c.operators_issuer
        || c.accounts_public_key == c.operators_public_key
        || ![
            &c.deployment,
            &c.scope_kind,
            &c.scope_id,
            &c.bootstrap_subject,
        ]
        .into_iter()
        .all(|v| label(v))
        || !(1..=3600).contains(&c.session_ttl_seconds)
        || c.permissions.is_empty()
        || c.permissions.len() > 64
        || c.permissions
            .iter()
            .any(|v| !label(v) || v == LOGIN_PERMISSION)
        || c.permissions.iter().collect::<BTreeSet<_>>().len() != c.permissions.len()
        || c.operator_audience.is_empty()
        || c.operator_audience.len() > 64
        || c.operator_audience
            .iter()
            .any(|v| v.is_empty() || v.len() > 256 || v.contains('*'))
        || c.operator_audience.iter().collect::<BTreeSet<_>>().len() != c.operator_audience.len()
        || c.bootstrap_callers.is_empty()
        || c.bootstrap_callers.len() > 64
        || c.bootstrap_callers.iter().any(|v| {
            v.split_once('/')
                .map_or(!label(v), |(p, i)| !label(p) || !label(i))
        })
        || c.bootstrap_callers.iter().collect::<BTreeSet<_>>().len() != c.bootstrap_callers.len()
    {
        return Err(invalid());
    }
    Ok(())
}
impl OperatorSessionConfig {
    fn verifier(&self, operators: bool) -> Result<RealmAssertionVerifier, RuntimeFailure> {
        let (realm, id, key) = if operators {
            (
                "operators",
                &self.operators_issuer,
                &self.operators_public_key,
            )
        } else {
            ("accounts", &self.accounts_issuer, &self.accounts_public_key)
        };
        RealmAssertionVerifier::new(realm, id, key, self.maximum_assertion_ttl_seconds, None)
            .map_err(|_| invalid())
    }
}
#[lenso::plugin(validate=validate_config)]
#[derive(Clone, Debug)]
struct OperatorSessionPlugin {
    #[config]
    config: OperatorSessionConfig,
    #[dependency(id = "bindings")]
    bindings: bindings::OperatorBindingClient,
    #[dependency(id = "accounts_state")]
    accounts_state: state::CredentialStateClient,
    #[dependency(id = "operators_state")]
    operators_state: state::CredentialStateClient,
    #[dependency(id = "operators_issuer")]
    operators_issuer: issuer::CredentialIssuerClient,
    #[dependency(id = "access")]
    access: access::AccessControlClient,
    #[dependency(id = "access_admin")]
    access_admin: admin::AccessControlAdminClient,
    #[dependency(id = "audit")]
    audit: audit::AuditLogClient,
}
#[lenso::provides(role::OperatorSession)]
impl OperatorSessionPlugin {
    fn binding_matches(&self, b: &bindings::Binding) -> bool {
        b.source_issuer == self.config.accounts_issuer
            && b.deployment == self.config.deployment
            && b.scope_kind == self.config.scope_kind
            && b.scope_id == self.config.scope_id
    }
}
#[derive(Debug)]
struct User(ActorAssertion);
impl TypedActor for User {
    fn from_assertion(a: &ActorAssertion) -> Result<Self, ActorProjectionError> {
        if a.actor_kind() != "user"
            || a.parent_provenance().is_some()
            || a.to_wire().claims.as_ref().is_some_and(|c| {
                c.contains_key(lenso_auth_sdk::delegation::SCOPED_DELEGATION_CLAIM)
            })
        {
            return Err(ActorProjectionError::UnexpectedActorKind {
                expected: "user".into(),
                actual: a.actor_kind().into(),
            });
        }
        Ok(Self(a.clone()))
    }
}
#[derive(Debug)]
struct Clock;
impl AssertionClock for Clock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}
#[derive(Debug)]
enum Failure {
    Runtime(RuntimeFailure),
    Unauthenticated,
    PermissionDenied,
    NotActive,
    BootstrapConsumed,
    BootstrapExpired,
    InvalidRequest,
    AuditUnavailable,
    AccessUnavailable,
}
impl From<RuntimeFailure> for Failure {
    fn from(e: RuntimeFailure) -> Self {
        Self::Runtime(e)
    }
}
macro_rules! invocation_error {
    ($e:expr,$inv:path,$domain:path) => {{
        use $domain as Domain;
        use $inv as Inv;
        match $e {
            Failure::Runtime(e) => Inv::Runtime(e),
            Failure::Unauthenticated => Inv::Domain(Domain::Unauthenticated),
            Failure::PermissionDenied => Inv::Domain(Domain::PermissionDenied),
            Failure::NotActive => Inv::Domain(Domain::NotActive),
            Failure::BootstrapConsumed => Inv::Domain(Domain::BootstrapConsumed),
            Failure::BootstrapExpired => Inv::Domain(Domain::BootstrapExpired),
            Failure::InvalidRequest => Inv::Domain(Domain::InvalidRequest),
            Failure::AuditUnavailable => Inv::Domain(Domain::AuditUnavailable),
            Failure::AccessUnavailable => Inv::Domain(Domain::AccessUnavailable),
        }
    }};
}
fn wire(b: bindings::Binding) -> role::Binding {
    role::Binding {
        source_issuer: b.source_issuer,
        deployment: b.deployment,
        scope_kind: b.scope_kind,
        scope_id: b.scope_id,
        binding_id: b.binding_id,
        source_subject: b.source_subject,
        operator_subject: b.operator_subject,
        revision: b.revision,
        active: b.active,
        revoked: b.revoked,
        revocation_pending: b.revocation_pending,
        revocation_audit_event_id: b.revocation_audit_event_id,
        revoked_by: b.revoked_by,
        revoked_at: b.revoked_at,
        audit_event_id: b.audit_event_id,
        policy_revision: b.policy_revision,
    }
}
impl OperatorSessionPlugin {
    async fn current_user(
        &self,
        c: &InvocationContext,
        operation: &str,
        operators: bool,
    ) -> Result<ActorAssertion, Failure> {
        let User(actor) = self
            .config
            .verifier(operators)?
            .project_context::<User>(c, role::CAPABILITY_ID, operation, &Clock)
            .map_err(|_| Failure::Unauthenticated)?;
        let reference =
            CredentialBinding::from_assertion(&actor).map_err(|_| Failure::Unauthenticated)?;
        let inspected = if operators {
            self.operators_state
                .inspect_with_context(
                    c.clone(),
                    state::InspectRequest {
                        credential_id: reference.credential_id.clone(),
                        session_id: reference.session_id.clone(),
                    },
                )
                .await
        } else {
            self.accounts_state
                .inspect_with_context(
                    c.clone(),
                    state::InspectRequest {
                        credential_id: reference.credential_id.clone(),
                        session_id: reference.session_id.clone(),
                    },
                )
                .await
        }
        .map_err(|_| Failure::Unauthenticated)?;
        let target = lenso_auth_sdk::audience(role::CAPABILITY_ID, operation);
        if !inspected.active
            || inspected.subject != actor.subject()
            || inspected.actor_kind != "user"
            || inspected.credential_id != reference.credential_id
            || inspected.session_id != reference.session_id
            || CredentialBinding::from_claims(&inspected.claims)
                .ok()
                .as_ref()
                != Some(&reference)
            || !inspected.audience.contains(&target)
            || OffsetDateTime::parse(&inspected.expires_at, &Rfc3339)
                .map_or(true, |v| v <= OffsetDateTime::now_utc())
            || inspected
                .claims
                .contains_key(lenso_auth_sdk::delegation::SCOPED_DELEGATION_CLAIM)
        {
            return Err(Failure::Unauthenticated);
        }
        if operators {
            let current = lenso_auth_sdk::credential::ManagementCredentialCeiling::from_claims(
                &inspected.claims,
            )
            .map_err(|_| Failure::PermissionDenied)?;
            if !current.allows(
                &self.config.deployment,
                "access-control.bindings.manage",
                &self.config.scope_kind,
                &self.config.scope_id,
            ) {
                return Err(Failure::PermissionDenied);
            }
        }
        Ok(actor)
    }
    async fn permission(
        &self,
        c: &InvocationContext,
        subject: &str,
        permission: &str,
    ) -> Result<bool, Failure> {
        self.access
            .check_permission_with_context(
                c.clone(),
                access::CheckPermissionRequest {
                    subject: subject.into(),
                    permission: permission.into(),
                    scope: access::CheckPermissionRequestScope {
                        kind: self.config.scope_kind.clone(),
                        id: self.config.scope_id.clone(),
                    },
                },
            )
            .await
            .map(|r| r.allowed)
            .map_err(|_| Failure::AccessUnavailable)
    }
    async fn append(
        &self,
        c: &InvocationContext,
        subject: &str,
        action: &str,
        binding: Option<&bindings::Binding>,
    ) -> Result<String, Failure> {
        self.append_event(c, subject, action, binding, None).await
    }
    async fn append_event(
        &self,
        c: &InvocationContext,
        subject: &str,
        action: &str,
        binding: Option<&bindings::Binding>,
        intent: Option<&bindings::PrepareActivationResponse>,
    ) -> Result<String, Failure> {
        let mut metadata = BTreeMap::from([
            (
                "deployment".into(),
                serde_json::json!(self.config.deployment),
            ),
            (
                "permissions".into(),
                serde_json::json!(intent.map_or(&self.config.permissions, |p| &p.permissions)),
            ),
        ]);
        if let Some(b) = binding {
            if action == "revoked" {
                metadata.insert("revoked_by".into(), serde_json::json!(b.revoked_by));
                metadata.insert("revoked_at".into(), serde_json::json!(b.revoked_at));
                metadata.insert("recovered_by".into(), serde_json::json!(subject));
            }
            metadata.insert("binding_id".into(), serde_json::json!(b.binding_id));
            metadata.insert(
                "operator_subject".into(),
                serde_json::json!(b.operator_subject),
            );
            metadata.insert("binding_revision".into(), serde_json::json!(b.revision));
        }
        self.audit
            .append_event_with_context(
                c.clone(),
                audit::AppendEventRequest {
                    action: action.into(),
                    event_name: format!("auth.operator-binding.{action}"),
                    actor: audit::AppendEventRequestActor {
                        kind: "user".into(),
                        id: Some(
                            binding
                                .filter(|b| action == "revoked" && !b.revoked_by.is_empty())
                                .map_or_else(|| subject.into(), |b| b.revoked_by.clone()),
                        ),
                        display: None,
                    },
                    idempotency_key: intent.map(|p| p.audit_idempotency_key.clone()),
                    metadata,
                    occurred_at: match intent {
                        Some(p) => p.audit_occurred_at.clone(),
                        None => OffsetDateTime::now_utc()
                            .format(&Rfc3339)
                            .map_err(|_| Failure::AuditUnavailable)?,
                    },
                    outcome: audit::AppendEventRequestOutcome::Success,
                    severity: audit::AppendEventRequestSeverity::Info,
                    reason: None,
                    request_context: None,
                    resource: None,
                    scope: Some(audit::AppendEventRequestScope {
                        display: None,
                        id: self.config.scope_id.clone(),
                        module: Some(self.config.deployment.clone()),
                        scope_type: self.config.scope_kind.clone(),
                    }),
                },
            )
            .await
            .map(|r| r.event.id)
            .map_err(|_| Failure::AuditUnavailable)
    }
    fn control_context(
        &self,
        raw: &str,
        binding: &bindings::Binding,
        parent: &InvocationContext,
        operation: &str,
    ) -> Result<InvocationContext, Failure> {
        self.config.control_context(raw, binding, parent, operation)
    }
    async fn bootstrap(&self, c: InvocationContext) -> Result<role::Binding, Failure> {
        if !c
            .caller_instance()
            .is_some_and(|id| self.config.bootstrap_callers.iter().any(|v| v == id))
        {
            return Err(Failure::PermissionDenied);
        }
        let actor = self.current_user(&c, "bootstrap_binding", false).await?;
        if actor.subject() != self.config.bootstrap_subject {
            return Err(Failure::PermissionDenied);
        }
        self.append(&c, actor.subject(), "requested", None).await?;
        let prepared = self
            .bindings
            .prepare_bootstrap_with_context(
                c.clone(),
                bindings::PrepareBootstrapRequest {
                    source_subject: actor.subject().into(),
                    source_issuer: self.config.accounts_issuer.clone(),
                    deployment: self.config.deployment.clone(),
                    scope_kind: self.config.scope_kind.clone(),
                    scope_id: self.config.scope_id.clone(),
                },
            )
            .await
            .map_err(|e| match e {
                bindings::OperatorBindingPrepareBootstrapInvocationError::Domain(
                    bindings::PrepareBootstrapError::BootstrapConsumed,
                ) => Failure::BootstrapConsumed,
                _ => Failure::NotActive,
            })?;
        let binding = prepared.binding;
        if !self.binding_matches(&binding) {
            return Err(Failure::PermissionDenied);
        }
        match self
            .access_admin
            .bootstrap_scope_with_context(
                c.clone(),
                admin::BootstrapScopeRequest {
                    scope: admin::BootstrapScopeRequestScope {
                        kind: self.config.scope_kind.clone(),
                        id: self.config.scope_id.clone(),
                    },
                    subject: binding.operator_subject.clone(),
                },
            )
            .await
        {
            Ok(_) => {}
            Err(admin::AccessControlAdminBootstrapScopeInvocationError::Domain(
                admin::BootstrapScopeError::ScopeAlreadyBootstrapped,
            )) => {
                if !self
                    .permission(&c, &binding.operator_subject, "access-control.roles.manage")
                    .await?
                    || !self
                        .permission(
                            &c,
                            &binding.operator_subject,
                            "access-control.bindings.manage",
                        )
                        .await?
                {
                    return Err(Failure::AccessUnavailable);
                }
            }
            Err(_) => return Err(Failure::AccessUnavailable),
        }
        self.finish_activation(&c, &binding, "bootstrap_binding")
            .await
    }
    fn bootstrap_caller(&self, c: &InvocationContext) -> Result<(), Failure> {
        if c.caller_instance()
            .is_some_and(|id| self.config.bootstrap_callers.iter().any(|v| v == id))
        {
            Ok(())
        } else {
            Err(Failure::PermissionDenied)
        }
    }
    async fn require_management(
        &self,
        c: &InvocationContext,
        b: &bindings::Binding,
    ) -> Result<(), Failure> {
        for permission in [
            "access-control.roles.manage",
            "access-control.bindings.manage",
        ] {
            if !self.permission(c, &b.operator_subject, permission).await? {
                return Err(Failure::AccessUnavailable);
            }
        }
        Ok(())
    }
    async fn activation_snapshot(
        &self,
        c: &InvocationContext,
        expected: &bindings::Binding,
        source_operation: &str,
        operation: bindings::PrepareActivationRequestOperation,
    ) -> Result<bindings::PrepareActivationResponse, Failure> {
        self.bootstrap_caller(c)?;
        let actor = self.current_user(c, source_operation, false).await?;
        if actor.subject() != self.config.bootstrap_subject
            || actor.subject() != expected.source_subject
            || !self.binding_matches(expected)
        {
            return Err(Failure::PermissionDenied);
        }
        self.require_management(c, expected).await?;
        let mut permissions = self.config.permissions.clone();
        permissions.sort();
        let prepared = self
            .bindings
            .prepare_activation_with_context(
                c.clone(),
                bindings::PrepareActivationRequest {
                    binding_id: expected.binding_id.clone(),
                    revision: expected.revision.clone(),
                    operation,
                    permissions: permissions.clone(),
                    source_assertion_expires_at: actor.to_wire().expires_at,
                },
            )
            .await
            .map_err(|error| match error {
                bindings::OperatorBindingPrepareActivationInvocationError::Domain(
                    bindings::PrepareActivationError::BootstrapExpired,
                ) => Failure::BootstrapExpired,
                bindings::OperatorBindingPrepareActivationInvocationError::Domain(
                    bindings::PrepareActivationError::InvalidRequest,
                ) => Failure::InvalidRequest,
                bindings::OperatorBindingPrepareActivationInvocationError::Domain(
                    bindings::PrepareActivationError::Unauthenticated,
                ) => Failure::Unauthenticated,
                bindings::OperatorBindingPrepareActivationInvocationError::Runtime(e) => {
                    Failure::Runtime(e)
                }
                _ => Failure::NotActive,
            })?;
        let b = &prepared.binding;
        if !self.binding_matches(b)
            || b.source_subject != actor.subject()
            || b.binding_id != expected.binding_id
            || b.revision != expected.revision
            || b.operator_subject != expected.operator_subject
            || b.revoked
            || prepared.permissions != permissions
            || prepared.audit_idempotency_key.is_empty()
            || OffsetDateTime::parse(&prepared.audit_occurred_at, &Rfc3339).is_err()
        {
            return Err(Failure::NotActive);
        }
        // Do not continue with an incoming assertion which expired during storage I/O.
        self.config
            .verifier(false)?
            .project_context::<User>(c, role::CAPABILITY_ID, source_operation, &Clock)
            .map_err(|_| Failure::Unauthenticated)?;
        Ok(prepared)
    }
    async fn fresh_control(
        &self,
        c: &InvocationContext,
        binding: &bindings::Binding,
        source_operation: &str,
        operation: bindings::PrepareActivationRequestOperation,
        audience_operation: &str,
    ) -> Result<(InvocationContext, bindings::PrepareActivationResponse), Failure> {
        let prepared = self
            .activation_snapshot(c, binding, source_operation, operation)
            .await?;
        if prepared.binding.active {
            return Err(Failure::NotActive);
        }
        let internal = self.control_context(
            &prepared.control_assertion,
            &prepared.binding,
            c,
            audience_operation,
        )?;
        Ok((internal, prepared))
    }
    async fn require_business_permissions(
        &self,
        c: &InvocationContext,
        b: &bindings::Binding,
    ) -> Result<(), Failure> {
        for permission in self
            .config
            .permissions
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(LOGIN_PERMISSION))
        {
            if !self.permission(c, &b.operator_subject, permission).await? {
                return Err(Failure::AccessUnavailable);
            }
        }
        Ok(())
    }
    async fn applied_receipt(
        &self,
        c: &InvocationContext,
        prepared: bindings::PrepareActivationResponse,
    ) -> Result<role::Binding, Failure> {
        let b = prepared.binding;
        if !b.active || b.revoked || b.audit_event_id.is_empty() || b.policy_revision.is_empty() {
            return Err(Failure::NotActive);
        }
        self.require_business_permissions(c, &b).await?;
        Ok(wire(b))
    }
    async fn resume(
        &self,
        c: InvocationContext,
        request: role::ResumeBindingRequest,
    ) -> Result<role::Binding, Failure> {
        self.bootstrap_caller(&c)?;
        let revision = request
            .revision
            .parse::<i64>()
            .map_err(|_| Failure::InvalidRequest)?;
        if revision < 1 || request.revision != revision.to_string() || !label(&request.binding_id) {
            return Err(Failure::InvalidRequest);
        }
        let actor = self.current_user(&c, "resume_binding", false).await?;
        if actor.subject() != self.config.bootstrap_subject {
            return Err(Failure::PermissionDenied);
        }
        let binding = self
            .bindings
            .read_binding_with_context(
                c.clone(),
                bindings::ReadBindingRequest {
                    source_subject: actor.subject().into(),
                },
            )
            .await
            .map_err(|_| Failure::NotActive)?;
        if binding.binding_id != request.binding_id
            || binding.revision != request.revision
            || binding.source_subject != actor.subject()
            || !self.binding_matches(&binding)
            || binding.revoked
        {
            return Err(Failure::NotActive);
        }
        // This path never prepares a new binding or replays Access.bootstrap_scope.
        let prepared = self
            .activation_snapshot(
                &c,
                &binding,
                "resume_binding",
                bindings::PrepareActivationRequestOperation::CreateRole,
            )
            .await?;
        if prepared.binding.active {
            return self.applied_receipt(&c, prepared).await;
        }
        self.finish_activation(&c, &binding, "resume_binding").await
    }
    async fn finish_activation(
        &self,
        c: &InvocationContext,
        binding: &bindings::Binding,
        source_operation: &str,
    ) -> Result<role::Binding, Failure> {
        let (policy_revision, intent) = self.grant_role(c, binding, source_operation).await?;
        let current = self
            .activation_snapshot(
                c,
                binding,
                source_operation,
                bindings::PrepareActivationRequestOperation::AssignRole,
            )
            .await?;
        if current.binding.active {
            return self.applied_receipt(c, current).await;
        }
        if current.audit_occurred_at != intent.audit_occurred_at
            || current.audit_idempotency_key != intent.audit_idempotency_key
        {
            return Err(Failure::NotActive);
        }
        self.require_business_permissions(c, binding).await?;
        let audit = self
            .append_event(
                c,
                &binding.source_subject,
                "applied",
                Some(binding),
                Some(&current),
            )
            .await?;
        // Audit can be slow; check the live source and Access again before the CAS.
        let current = self
            .activation_snapshot(
                c,
                binding,
                source_operation,
                bindings::PrepareActivationRequestOperation::AssignRole,
            )
            .await?;
        if current.binding.active {
            return self.applied_receipt(c, current).await;
        }
        self.require_business_permissions(c, binding).await?;
        self.config
            .verifier(false)?
            .project_context::<User>(c, role::CAPABILITY_ID, source_operation, &Clock)
            .map_err(|_| Failure::Unauthenticated)?;
        self.complete_activation(c, binding, source_operation, audit, policy_revision)
            .await
    }
    async fn complete_activation(
        &self,
        c: &InvocationContext,
        binding: &bindings::Binding,
        source_operation: &str,
        audit: String,
        policy_revision: String,
    ) -> Result<role::Binding, Failure> {
        let active = self
            .bindings
            .activate_binding_with_context(
                c.clone(),
                bindings::ActivateBindingRequest {
                    binding_id: binding.binding_id.clone(),
                    revision: binding.revision.clone(),
                    audit_event_id: audit.clone(),
                    policy_revision,
                },
            )
            .await;
        match active {
            Ok(active)
                if active.active
                    && !active.revoked
                    && self.binding_matches(&active)
                    && active.binding_id == binding.binding_id
                    && active.revision == binding.revision
                    && active.source_subject == binding.source_subject
                    && active.operator_subject == binding.operator_subject
                    && active.audit_event_id == audit
                    && !active.policy_revision.is_empty() =>
            {
                Ok(wire(active))
            }
            // A CAS/response can race a concurrent completion. Only durable exact receipts count.
            _ => {
                let current = self
                    .activation_snapshot(
                        c,
                        binding,
                        source_operation,
                        bindings::PrepareActivationRequestOperation::AssignRole,
                    )
                    .await?;
                if current.binding.audit_event_id != audit {
                    return Err(Failure::NotActive);
                }
                self.applied_receipt(c, current).await
            }
        }
    }
    async fn grant_role(
        &self,
        c: &InvocationContext,
        binding: &bindings::Binding,
        source_operation: &str,
    ) -> Result<(String, bindings::PrepareActivationResponse), Failure> {
        let role_id = format!("operator-binding.{}", binding.binding_id);
        let (control, _) = self
            .fresh_control(
                c,
                binding,
                source_operation,
                bindings::PrepareActivationRequestOperation::CreateRole,
                "create_role",
            )
            .await?;
        match self
            .access_admin
            .create_role_with_context(
                control,
                admin::CreateRoleRequest {
                    scope: admin::CreateRoleRequestScope {
                        kind: self.config.scope_kind.clone(),
                        id: self.config.scope_id.clone(),
                    },
                    role_id: role_id.clone(),
                    name: "Explicit operator binding".into(),
                },
            )
            .await
        {
            Ok(_)
            | Err(admin::AccessControlAdminCreateRoleInvocationError::Domain(
                admin::CreateRoleError::RoleAlreadyExists,
            )) => {}
            Err(_) => return Err(Failure::AccessUnavailable),
        }
        let (control, intent) = self
            .fresh_control(
                c,
                binding,
                source_operation,
                bindings::PrepareActivationRequestOperation::SetRolePermissions,
                "set_role_permissions",
            )
            .await?;
        let mut permissions = intent.permissions;
        permissions.push(LOGIN_PERMISSION.into());
        self.access_admin
            .set_role_permissions_with_context(
                control,
                admin::SetRolePermissionsRequest {
                    scope: admin::SetRolePermissionsRequestScope {
                        kind: self.config.scope_kind.clone(),
                        id: self.config.scope_id.clone(),
                    },
                    role_id: role_id.clone(),
                    permissions,
                },
            )
            .await
            .map_err(|_| Failure::AccessUnavailable)?;
        let (control, intent) = self
            .fresh_control(
                c,
                binding,
                source_operation,
                bindings::PrepareActivationRequestOperation::AssignRole,
                "assign_role",
            )
            .await?;
        let applied = self
            .access_admin
            .assign_role_with_context(
                control,
                admin::AssignRoleRequest {
                    scope: admin::AssignRoleRequestScope {
                        kind: self.config.scope_kind.clone(),
                        id: self.config.scope_id.clone(),
                    },
                    role_id,
                    subject: binding.operator_subject.clone(),
                },
            )
            .await
            .map_err(|_| Failure::AccessUnavailable)?;
        Ok((applied.policy_revision, intent))
    }
    async fn read(&self, c: InvocationContext) -> Result<role::Binding, Failure> {
        let actor = self.current_user(&c, "read_binding", false).await?;
        let binding = self
            .bindings
            .read_binding_with_context(
                c,
                bindings::ReadBindingRequest {
                    source_subject: actor.subject().into(),
                },
            )
            .await
            .map_err(|_| Failure::NotActive)?;
        if !self.binding_matches(&binding) || binding.source_subject != actor.subject() {
            return Err(Failure::PermissionDenied);
        }
        Ok(wire(binding))
    }
    async fn exchange(&self, c: InvocationContext) -> Result<role::SessionResponse, Failure> {
        let actor = self.current_user(&c, "exchange_session", false).await?;
        let b = self
            .bindings
            .read_binding_with_context(
                c.clone(),
                bindings::ReadBindingRequest {
                    source_subject: actor.subject().into(),
                },
            )
            .await
            .map_err(|_| Failure::NotActive)?;
        if !self.binding_matches(&b)
            || b.source_subject != actor.subject()
            || !b.active
            || !self
                .permission(&c, &b.operator_subject, LOGIN_PERMISSION)
                .await?
        {
            return Err(Failure::NotActive);
        }
        let mut granted = Vec::new();
        for p in &self.config.permissions {
            if self.permission(&c, &b.operator_subject, p).await? {
                granted.push(p.clone());
            }
        }
        let expiry = OffsetDateTime::now_utc()
            + Duration::seconds(i64::from(self.config.session_ttl_seconds));
        let issued = self
            .operators_issuer
            .issue_with_context(
                c,
                issuer::IssueRequest {
                    subject: b.operator_subject,
                    actor_kind: "user".into(),
                    assurance: actor.to_wire().assurance,
                    audience: self.config.operator_audience.clone(),
                    claims: BTreeMap::from([("permissions".into(), serde_json::json!(granted))]),
                    expires_at: expiry.format(&Rfc3339).map_err(|_| Failure::NotActive)?,
                },
            )
            .await
            .map_err(|_| Failure::NotActive)?;
        Ok(role::SessionResponse {
            session_id: issued.session_id,
            credential: issued.credential,
            expires_at: issued.expires_at,
        })
    }
    async fn revoke(
        &self,
        c: InvocationContext,
        request: role::RevokeBindingRequest,
    ) -> Result<role::Binding, Failure> {
        let actor = self.current_user(&c, "revoke_binding", true).await?;
        let ceiling =
            lenso_auth_sdk::credential::ManagementCredentialCeiling::from_assertion(&actor)
                .map_err(|_| Failure::PermissionDenied)?;
        if !ceiling.allows(
            &self.config.deployment,
            "access-control.bindings.manage",
            &self.config.scope_kind,
            &self.config.scope_id,
        ) {
            return Err(Failure::PermissionDenied);
        }

        if !self
            .permission(&c, actor.subject(), "access-control.bindings.manage")
            .await?
        {
            return Err(Failure::PermissionDenied);
        }
        // Durable denial happens first; even protected Access binding or audit failure cannot revive it.
        let revoked = self
            .bindings
            .revoke_binding_with_context(
                c.clone(),
                bindings::RevokeBindingRequest {
                    binding_id: request.binding_id,
                    actor_subject: actor.subject().into(),
                },
            )
            .await
            .map_err(|_| Failure::NotActive)?;
        if !self.binding_matches(&revoked) {
            return Err(Failure::PermissionDenied);
        }
        let role_id = format!("operator-binding.{}", revoked.binding_id);
        let cleanup = self
            .access_admin
            .revoke_role_with_context(
                c.clone(),
                admin::RevokeRoleRequest {
                    scope: admin::RevokeRoleRequestScope {
                        kind: self.config.scope_kind.clone(),
                        id: self.config.scope_id.clone(),
                    },
                    role_id,
                    subject: revoked.operator_subject.clone(),
                },
            )
            .await;
        let logged = self
            .append(&c, actor.subject(), "revoked", Some(&revoked))
            .await;
        let audit = logged?;
        if !matches!(
            cleanup,
            Ok(_)
                | Err(admin::AccessControlAdminRevokeRoleInvocationError::Domain(
                    admin::RevokeRoleError::RoleNotFound
                ))
        ) {
            return Err(Failure::AccessUnavailable);
        }
        let complete = self
            .bindings
            .complete_revocation_with_context(
                c,
                bindings::CompleteRevocationRequest {
                    binding_id: revoked.binding_id,
                    revision: revoked.revision,
                    audit_event_id: audit,
                },
            )
            .await
            .map_err(|_| Failure::NotActive)?;
        Ok(wire(complete))
    }
    async fn recover(
        &self,
        c: InvocationContext,
        request: role::RevokeBindingRequest,
    ) -> Result<role::Binding, Failure> {
        if !c
            .caller_instance()
            .is_some_and(|id| self.config.bootstrap_callers.iter().any(|v| v == id))
        {
            return Err(Failure::PermissionDenied);
        }
        let actor = self.current_user(&c, "recover_revocation", false).await?;
        if actor.subject() != self.config.bootstrap_subject {
            return Err(Failure::PermissionDenied);
        }
        let prepared = self
            .bindings
            .prepare_recovery_with_context(
                c.clone(),
                bindings::RecoveryRequest {
                    binding_id: request.binding_id,
                },
            )
            .await
            .map_err(|_| Failure::NotActive)?;
        let binding = prepared.binding;
        if !self.binding_matches(&binding)
            || !binding.revoked
            || binding.source_subject != actor.subject()
        {
            return Err(Failure::PermissionDenied);
        }
        if !binding.revocation_pending {
            return Ok(wire(binding));
        }
        let internal =
            self.control_context(&prepared.control_assertion, &binding, &c, "revoke_role")?;
        let cleanup = self
            .access_admin
            .revoke_role_with_context(
                internal,
                admin::RevokeRoleRequest {
                    role_id: format!("operator-binding.{}", binding.binding_id),
                    subject: binding.operator_subject.clone(),
                    scope: admin::RevokeRoleRequestScope {
                        kind: self.config.scope_kind.clone(),
                        id: self.config.scope_id.clone(),
                    },
                },
            )
            .await;
        if !matches!(
            cleanup,
            Ok(_)
                | Err(admin::AccessControlAdminRevokeRoleInvocationError::Domain(
                    admin::RevokeRoleError::RoleNotFound
                ))
        ) {
            return Err(Failure::AccessUnavailable);
        }
        let audit = self
            .append(&c, actor.subject(), "revoked", Some(&binding))
            .await?;
        let complete = self
            .bindings
            .complete_revocation_with_context(
                c,
                bindings::CompleteRevocationRequest {
                    binding_id: binding.binding_id,
                    revision: binding.revision,
                    audit_event_id: audit,
                },
            )
            .await
            .map_err(|_| Failure::NotActive)?;
        Ok(wire(complete))
    }
    async fn resume_binding(
        &self,
        context: InvocationContext,
        request: role::ResumeBindingRequest,
    ) -> Result<role::Binding, role::OperatorSessionResumeBindingInvocationError> {
        self.resume(context, request).await.map_err(|e| {
            invocation_error!(
                e,
                role::OperatorSessionResumeBindingInvocationError,
                role::ResumeBindingError
            )
        })
    }
    async fn recover_revocation(
        &self,
        context: InvocationContext,
        request: role::RevokeBindingRequest,
    ) -> Result<role::Binding, role::OperatorSessionRecoverRevocationInvocationError> {
        self.recover(context, request).await.map_err(|e| {
            invocation_error!(
                e,
                role::OperatorSessionRecoverRevocationInvocationError,
                role::RecoverRevocationError
            )
        })
    }
    async fn bootstrap_binding(
        &self,
        context: InvocationContext,
        _request: role::EmptyRequest,
    ) -> Result<role::Binding, role::OperatorSessionBootstrapBindingInvocationError> {
        self.bootstrap(context).await.map_err(|e| {
            invocation_error!(
                e,
                role::OperatorSessionBootstrapBindingInvocationError,
                role::BootstrapBindingError
            )
        })
    }
    async fn read_binding(
        &self,
        context: InvocationContext,
        _request: role::EmptyRequest,
    ) -> Result<role::Binding, role::OperatorSessionReadBindingInvocationError> {
        self.read(context).await.map_err(|e| {
            invocation_error!(
                e,
                role::OperatorSessionReadBindingInvocationError,
                role::ReadBindingError
            )
        })
    }
    async fn exchange_session(
        &self,
        context: InvocationContext,
        _request: role::EmptyRequest,
    ) -> Result<role::SessionResponse, role::OperatorSessionExchangeSessionInvocationError> {
        self.exchange(context).await.map_err(|e| {
            invocation_error!(
                e,
                role::OperatorSessionExchangeSessionInvocationError,
                role::ExchangeSessionError
            )
        })
    }
    async fn revoke_binding(
        &self,
        context: InvocationContext,
        request: role::RevokeBindingRequest,
    ) -> Result<role::Binding, role::OperatorSessionRevokeBindingInvocationError> {
        self.revoke(context, request).await.map_err(|e| {
            invocation_error!(
                e,
                role::OperatorSessionRevokeBindingInvocationError,
                role::RevokeBindingError
            )
        })
    }
}

impl OperatorSessionConfig {
    fn control_context(
        &self,
        raw: &str,
        binding: &bindings::Binding,
        parent: &InvocationContext,
        operation: &str,
    ) -> Result<InvocationContext, Failure> {
        let assertion_wire = serde_json::from_str(raw).map_err(|_| Failure::AccessUnavailable)?;
        let AuthOutcome::Authenticated(control) =
            decode_auth_response(lenso_capability_auth::AuthResponse {
                kind: lenso_capability_auth::AuthResponseKind::Authenticated,
                assertion: Some(assertion_wire),
            })
            .map_err(|_| Failure::AccessUnavailable)?
        else {
            return Err(Failure::AccessUnavailable);
        };
        if control.issuer() != self.operators_issuer
            || control.subject() != binding.operator_subject
        {
            return Err(Failure::AccessUnavailable);
        }
        // Authority cannot replace the sealed accounts context; use a bounded internal invocation.
        let context = control
            .attach(InvocationContext::new(
                parent.request_id(),
                parent.deadline(),
                parent.cancellation(),
            ))
            .map_err(|_| Failure::AccessUnavailable)?;
        self.verifier(true)?
            .project_context::<User>(&context, admin::CAPABILITY_ID, operation, &Clock)
            .map_err(|_| Failure::AccessUnavailable)?;
        Ok(context)
    }
}

#[cfg(test)]
#[path = "activation_context_tests.rs"]
mod activation_context_tests;

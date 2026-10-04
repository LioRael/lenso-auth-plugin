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
        let mut metadata = BTreeMap::from([
            (
                "deployment".into(),
                serde_json::json!(self.config.deployment),
            ),
            (
                "permissions".into(),
                serde_json::json!(self.config.permissions),
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
                    idempotency_key: None,
                    metadata,
                    occurred_at: OffsetDateTime::now_utc()
                        .format(&Rfc3339)
                        .map_err(|_| Failure::AuditUnavailable)?,
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
        if control.issuer() != self.config.operators_issuer
            || control.subject() != binding.operator_subject
        {
            return Err(Failure::AccessUnavailable);
        }
        // Authority cannot replace the sealed accounts context; use a bounded internal invocation.
        let context = control
            .attach(InvocationContext::new(
                parent.request_id(),
                Some(std::time::Duration::from_secs(5)),
                parent.cancellation(),
            ))
            .map_err(|_| Failure::AccessUnavailable)?;
        self.config
            .verifier(true)?
            .project_context::<User>(&context, admin::CAPABILITY_ID, operation, &Clock)
            .map_err(|_| Failure::AccessUnavailable)?;
        Ok(context)
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
        let control_context =
            self.control_context(&prepared.control_assertion, &binding, &c, "create_role")?;
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
        let policy_revision = self.grant_role(control_context, &binding).await?;
        let audit = self
            .append(&c, actor.subject(), "applied", Some(&binding))
            .await?;
        let active = self
            .bindings
            .activate_binding_with_context(
                c,
                bindings::ActivateBindingRequest {
                    binding_id: binding.binding_id,
                    revision: binding.revision,
                    audit_event_id: audit,
                    policy_revision,
                },
            )
            .await
            .map_err(|_| Failure::NotActive)?;
        if !active.active
            || !self.binding_matches(&active)
            || active.source_subject != actor.subject()
        {
            return Err(Failure::NotActive);
        }
        Ok(wire(active))
    }
    async fn grant_role(
        &self,
        control_context: InvocationContext,
        binding: &bindings::Binding,
    ) -> Result<String, Failure> {
        let role_id = format!("operator-binding.{}", binding.binding_id);
        match self
            .access_admin
            .create_role_with_context(
                control_context.clone(),
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
        let mut permissions = self.config.permissions.clone();
        permissions.push(LOGIN_PERMISSION.into());
        self.access_admin
            .set_role_permissions_with_context(
                control_context.clone(),
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
        let applied = self
            .access_admin
            .assign_role_with_context(
                control_context,
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
        Ok(applied.policy_revision)
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

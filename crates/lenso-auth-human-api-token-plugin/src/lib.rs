//! Personal token lifecycle authenticated by one bound Account realm.
use lenso::provides;
use lenso_auth_sdk::credential::{
    CredentialBinding, ManagementCredentialCeiling, ManagementResourceScope,
};
use lenso_auth_sdk::realm::RealmAssertionVerifier;
use lenso_auth_sdk::{ActorAssertion, ActorProjectionError, AssertionClock, TypedActor};
use lenso_capability_access_control as access;
use lenso_capability_api_token_admin as admin;
use lenso_capability_credential_state as state;
use lenso_capability_human_api_token as human;
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, lenso::PluginConfig)]
#[serde(deny_unknown_fields)]
pub struct HumanApiTokenConfig {
    realm: String,
    account_issuer: String,
    account_public_key: String,
    maximum_assertion_ttl_seconds: u32,
    maximum_token_ttl_seconds: u32,
    deployment: String,
    scope_kind: String,
    scope_id: String,
    token_audience: Vec<String>,
}
impl HumanApiTokenConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        realm: impl Into<String>,
        account_issuer: impl Into<String>,
        account_public_key: impl Into<String>,
        maximum_assertion_ttl_seconds: u32,
        maximum_token_ttl_seconds: u32,
        deployment: impl Into<String>,
        scope_kind: impl Into<String>,
        scope_id: impl Into<String>,
        token_audience: Vec<String>,
    ) -> Result<Self, RuntimeFailure> {
        let config = Self {
            realm: realm.into(),
            account_issuer: account_issuer.into(),
            account_public_key: account_public_key.into(),
            maximum_assertion_ttl_seconds,
            maximum_token_ttl_seconds,
            deployment: deployment.into(),
            scope_kind: scope_kind.into(),
            scope_id: scope_id.into(),
            token_audience,
        };
        validate_config(&config)?;
        Ok(config)
    }
    fn verifier(&self) -> Result<RealmAssertionVerifier, RuntimeFailure> {
        RealmAssertionVerifier::new(
            &self.realm,
            &self.account_issuer,
            &self.account_public_key,
            self.maximum_assertion_ttl_seconds,
            None,
        )
        .map_err(|_| invalid_plan())
    }
}
fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}
fn invalid_plan() -> RuntimeFailure {
    RuntimeFailure::InvalidResolvedPlan { detail:"Human API Token requires an explicit Account realm, deployment scope, token audiences and bounded TTL".into() }
}
fn validate_config(config: &HumanApiTokenConfig) -> Result<(), RuntimeFailure> {
    config.verifier()?;
    if !label(&config.deployment)
        || !label(&config.scope_kind)
        || !label(&config.scope_id)
        || !(1..=31_536_000).contains(&config.maximum_token_ttl_seconds)
        || config.token_audience.is_empty()
        || config.token_audience.len() > 64
        || config
            .token_audience
            .iter()
            .any(|aud| aud.is_empty() || aud.len() > 256 || aud.contains('*'))
        || config
            .token_audience
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != config.token_audience.len()
    {
        return Err(invalid_plan());
    }
    Ok(())
}
#[lenso::plugin(validate=validate_config)]
#[derive(Clone, Debug)]
struct HumanApiTokenPlugin {
    #[config]
    config: HumanApiTokenConfig,
    #[dependency(id = "account_state")]
    account_state: state::CredentialStateClient,
    #[dependency(id = "api_tokens")]
    api_tokens: admin::ApiTokenAdminClient,
    #[dependency(id = "access")]
    access: access::AccessControlClient,
}
#[provides(human::HumanApiToken)]
impl HumanApiTokenPlugin {}
#[derive(Debug)]
struct User(ActorAssertion);
impl TypedActor for User {
    fn from_assertion(assertion: &ActorAssertion) -> Result<Self, ActorProjectionError> {
        if assertion.actor_kind() != "user"
            || assertion.to_wire().claims.as_ref().is_some_and(|claims| {
                claims.contains_key(lenso_auth_sdk::delegation::SCOPED_DELEGATION_CLAIM)
            })
        {
            return Err(ActorProjectionError::UnexpectedActorKind {
                expected: "user".into(),
                actual: assertion.actor_kind().into(),
            });
        }
        Ok(Self(assertion.clone()))
    }
}
#[derive(Debug)]
struct WallClock;
impl AssertionClock for WallClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}
struct CurrentUser {
    subject: String,
    signed: ManagementCredentialCeiling,
    current: ManagementCredentialCeiling,
}
impl HumanApiTokenPlugin {
    async fn current_user(
        &self,
        context: &InvocationContext,
        operation: &str,
        permission: &str,
    ) -> Result<Option<CurrentUser>, RuntimeFailure> {
        let Ok(User(assertion)) = self.config.verifier()?.project_context::<User>(
            context,
            human::CAPABILITY_ID,
            operation,
            &WallClock,
        ) else {
            return Ok(None);
        };
        let (Ok(binding), Ok(signed)) = (
            CredentialBinding::from_assertion(&assertion),
            ManagementCredentialCeiling::from_assertion(&assertion),
        ) else {
            return Ok(None);
        };
        let Some(inspected) = live_inspection(
            self.account_state
                .inspect_with_context(
                    context.clone(),
                    state::InspectRequest {
                        credential_id: binding.credential_id.clone(),
                        session_id: binding.session_id.clone(),
                    },
                )
                .await,
        )?
        else {
            return Ok(None);
        };
        let (Ok(current), Ok(current_binding), Ok(expiry)) = (
            ManagementCredentialCeiling::from_claims(&inspected.claims),
            CredentialBinding::from_claims(&inspected.claims),
            OffsetDateTime::parse(&inspected.expires_at, &Rfc3339),
        ) else {
            return Ok(None);
        };
        let target = lenso_auth_sdk::audience(human::CAPABILITY_ID, operation);
        if !inspected.active
            || inspected.subject != assertion.subject()
            || inspected.actor_kind != "user"
            || inspected.credential_id != binding.credential_id
            || inspected.session_id != binding.session_id
            || current_binding != binding
            || expiry <= OffsetDateTime::now_utc()
            || !inspected.audience.contains(&target)
            || !signed.allows(
                &self.config.deployment,
                permission,
                &self.config.scope_kind,
                &self.config.scope_id,
            )
            || !current.allows(
                &self.config.deployment,
                permission,
                &self.config.scope_kind,
                &self.config.scope_id,
            )
        {
            return Ok(None);
        }
        let user = CurrentUser {
            subject: inspected.subject,
            signed,
            current,
        };
        if !self
            .permission(
                context,
                &user.subject,
                permission,
                &self.config.scope_kind,
                &self.config.scope_id,
            )
            .await?
        {
            return Ok(None);
        }
        Ok(Some(user))
    }
    async fn permission(
        &self,
        context: &InvocationContext,
        subject: &str,
        permission: &str,
        kind: &str,
        id: &str,
    ) -> Result<bool, RuntimeFailure> {
        live_permission(
            self.access
                .check_permission_with_context(
                    context.clone(),
                    access::CheckPermissionRequest {
                        subject: subject.into(),
                        permission: permission.into(),
                        scope: access::CheckPermissionRequestScope {
                            kind: kind.into(),
                            id: id.into(),
                        },
                    },
                )
                .await,
        )
    }
    fn issue(
        &self,
        context: InvocationContext,
        request: human::IssueRequest,
    ) -> NativeRequestFuture<human::HumanApiTokenIssue> {
        let plugin = self.clone();
        Box::pin(async move {
            let Some(user) = plugin
                .current_user(&context, human::ISSUE_OPERATION, "auth.pat.issue")
                .await?
            else {
                return Ok(Err(human::IssueError::PermissionDenied));
            };
            let ceiling = ManagementCredentialCeiling {
                deployment: request.deployment.clone(),
                permissions: request.permissions.clone(),
                resource_scopes: request
                    .resource_scopes
                    .iter()
                    .map(|scope| ManagementResourceScope {
                        kind: scope.kind.clone(),
                        id: scope.id.clone(),
                    })
                    .collect(),
            };
            let Ok(expiry) = OffsetDateTime::parse(&request.expires_at, &Rfc3339) else {
                return Ok(Err(human::IssueError::InvalidRequest));
            };
            let now = OffsetDateTime::now_utc();
            if !ceiling.is_attenuation_of(&user.signed)
                || !ceiling.is_attenuation_of(&user.current)
                || ceiling.deployment != plugin.config.deployment
                || expiry
                    > now
                        + time::Duration::seconds(i64::from(
                            plugin.config.maximum_token_ttl_seconds,
                        ))
            {
                return Ok(Err(human::IssueError::InvalidRequest));
            }
            for scope in &ceiling.resource_scopes {
                for permission in &ceiling.permissions {
                    if !plugin
                        .permission(&context, &user.subject, permission, &scope.kind, &scope.id)
                        .await?
                    {
                        return Ok(Err(human::IssueError::PermissionDenied));
                    }
                }
            }
            // Reinspect after asynchronous policy reads so revocation and ceiling
            // changes are observed immediately before the owning issuer is called.
            let Some(fresh) = plugin
                .current_user(&context, human::ISSUE_OPERATION, "auth.pat.issue")
                .await?
            else {
                return Ok(Err(human::IssueError::PermissionDenied));
            };
            if fresh.subject != user.subject
                || !ceiling.is_attenuation_of(&fresh.signed)
                || !ceiling.is_attenuation_of(&fresh.current)
            {
                return Ok(Err(human::IssueError::PermissionDenied));
            }
            let result = plugin
                .api_tokens
                .issue_with_context(
                    context,
                    admin::IssueRequest {
                        subject: user.subject,
                        idempotency_key: request.idempotency_key,
                        name: request.name,
                        deployment: ceiling.deployment,
                        permissions: ceiling.permissions,
                        resource_scopes: ceiling
                            .resource_scopes
                            .into_iter()
                            .map(|scope| admin::ResourceScope {
                                kind: scope.kind,
                                id: scope.id,
                            })
                            .collect(),
                        expires_at: request.expires_at,
                        audience: plugin.config.token_audience.clone(),
                    },
                )
                .await;
            match result {
                Ok(response) => Ok(Ok(translate(response)?)),
                Err(admin::ApiTokenAdminIssueInvocationError::Domain(error)) => {
                    Ok(Err(issue_error(&error)?))
                }
                Err(admin::ApiTokenAdminIssueInvocationError::Runtime(error)) => Err(error),
            }
        })
    }
    fn list(
        &self,
        context: InvocationContext,
        request: human::ListRequest,
    ) -> NativeRequestFuture<human::HumanApiTokenList> {
        let plugin = self.clone();
        Box::pin(async move {
            let Some(user) = plugin
                .current_user(&context, human::LIST_OPERATION, "auth.pat.list")
                .await?
            else {
                return Ok(Err(human::ListError::PermissionDenied));
            };
            if request.deployment != plugin.config.deployment {
                return Ok(Err(human::ListError::InvalidRequest));
            }
            match plugin
                .api_tokens
                .list_with_context(
                    context,
                    admin::ListRequest {
                        subject: user.subject,
                        deployment: request.deployment,
                        limit: request.limit,
                        after_credential_id: request.after_credential_id,
                    },
                )
                .await
            {
                Ok(response) => Ok(Ok(translate(response)?)),
                Err(admin::ApiTokenAdminListInvocationError::Domain(error)) => {
                    Ok(Err(list_error(&error)?))
                }
                Err(admin::ApiTokenAdminListInvocationError::Runtime(error)) => Err(error),
            }
        })
    }
    fn receipt(
        &self,
        context: InvocationContext,
        request: human::ReceiptRequest,
    ) -> NativeRequestFuture<human::HumanApiTokenReceipt> {
        let plugin = self.clone();
        Box::pin(async move {
            let Some(user) = plugin
                .current_user(&context, human::RECEIPT_OPERATION, "auth.pat.list")
                .await?
            else {
                return Ok(Err(human::ReceiptError::PermissionDenied));
            };
            if request.deployment != plugin.config.deployment {
                return Ok(Err(human::ReceiptError::InvalidRequest));
            }
            match plugin
                .api_tokens
                .receipt_with_context(
                    context,
                    admin::ReceiptRequest {
                        subject: user.subject,
                        deployment: request.deployment,
                        idempotency_key: request.idempotency_key,
                    },
                )
                .await
            {
                Ok(response) => Ok(Ok(translate(response)?)),
                Err(admin::ApiTokenAdminReceiptInvocationError::Domain(error)) => {
                    Ok(Err(receipt_error(&error)?))
                }
                Err(admin::ApiTokenAdminReceiptInvocationError::Runtime(error)) => Err(error),
            }
        })
    }
    fn revoke(
        &self,
        context: InvocationContext,
        request: human::RevokeRequest,
    ) -> NativeRequestFuture<human::HumanApiTokenRevoke> {
        let plugin = self.clone();
        Box::pin(async move {
            let Some(user) = plugin
                .current_user(&context, human::REVOKE_OPERATION, "auth.pat.revoke")
                .await?
            else {
                return Ok(Err(human::RevokeError::PermissionDenied));
            };
            if request.deployment != plugin.config.deployment {
                return Ok(Err(human::RevokeError::InvalidRequest));
            }
            match plugin
                .api_tokens
                .revoke_with_context(
                    context,
                    admin::RevokeRequest {
                        subject: user.subject,
                        deployment: request.deployment,
                        credential_id: request.credential_id,
                    },
                )
                .await
            {
                Ok(response) => Ok(Ok(human::RevokeResponse {
                    revoked: response.revoked,
                })),
                Err(admin::ApiTokenAdminRevokeInvocationError::Domain(error)) => {
                    Ok(Err(revoke_error(&error)?))
                }
                Err(admin::ApiTokenAdminRevokeInvocationError::Runtime(error)) => Err(error),
            }
        })
    }
}
fn unknown_owner_result() -> RuntimeFailure {
    RuntimeFailure::Unavailable {
        capability: human::CAPABILITY_ID,
    }
}
fn live_inspection(
    result: Result<state::InspectResponse, state::CredentialStateInvocationError>,
) -> Result<Option<state::InspectResponse>, RuntimeFailure> {
    match result {
        Ok(inspected) => Ok(Some(inspected)),
        Err(state::CredentialStateInvocationError::Domain(state::InspectError::Unknown(_))) => {
            Err(unknown_owner_result())
        }
        Err(state::CredentialStateInvocationError::Domain(_)) => Ok(None),
        Err(state::CredentialStateInvocationError::Runtime(error)) => Err(error),
    }
}
fn live_permission(
    result: Result<access::CheckPermissionResponse, access::AccessControlInvocationError>,
) -> Result<bool, RuntimeFailure> {
    match result {
        Ok(decision) => Ok(decision.allowed),
        Err(access::AccessControlInvocationError::Domain(
            access::CheckPermissionError::Unknown(_),
        )) => Err(unknown_owner_result()),
        Err(access::AccessControlInvocationError::Domain(_)) => Ok(false),
        Err(access::AccessControlInvocationError::Runtime(error)) => Err(error),
    }
}
fn issue_error(error: &admin::IssueError) -> Result<human::IssueError, RuntimeFailure> {
    Ok(match error {
        admin::IssueError::PermissionDenied => human::IssueError::PermissionDenied,
        admin::IssueError::Conflict => human::IssueError::Conflict,
        admin::IssueError::UnsupportedProfile => human::IssueError::UnsupportedProfile,
        admin::IssueError::InvalidRequest => human::IssueError::InvalidRequest,
        admin::IssueError::Unknown(_) => return Err(unknown_owner_result()),
    })
}
fn list_error(error: &admin::ListError) -> Result<human::ListError, RuntimeFailure> {
    Ok(match error {
        admin::ListError::PermissionDenied => human::ListError::PermissionDenied,
        admin::ListError::UnsupportedProfile => human::ListError::UnsupportedProfile,
        admin::ListError::InvalidRequest => human::ListError::InvalidRequest,
        admin::ListError::Unknown(_) => return Err(unknown_owner_result()),
    })
}
fn receipt_error(error: &admin::ReceiptError) -> Result<human::ReceiptError, RuntimeFailure> {
    Ok(match error {
        admin::ReceiptError::PermissionDenied => human::ReceiptError::PermissionDenied,
        admin::ReceiptError::UnsupportedProfile => human::ReceiptError::UnsupportedProfile,
        admin::ReceiptError::InvalidRequest => human::ReceiptError::InvalidRequest,
        admin::ReceiptError::Unknown(_) => return Err(unknown_owner_result()),
    })
}
fn revoke_error(error: &admin::RevokeError) -> Result<human::RevokeError, RuntimeFailure> {
    Ok(match error {
        admin::RevokeError::PermissionDenied => human::RevokeError::PermissionDenied,
        admin::RevokeError::NotFound => human::RevokeError::NotFound,
        admin::RevokeError::UnsupportedProfile => human::RevokeError::UnsupportedProfile,
        admin::RevokeError::InvalidRequest => human::RevokeError::InvalidRequest,
        admin::RevokeError::Unknown(_) => return Err(unknown_owner_result()),
    })
}
fn translate<T: Serialize, R: serde::de::DeserializeOwned>(value: T) -> Result<R, RuntimeFailure> {
    serde_json::to_value(value)
        .and_then(serde_json::from_value)
        .map_err(|_| RuntimeFailure::ProtocolViolation {
            capability: human::CAPABILITY_ID,
        })
}

#[cfg(test)]
mod scoped_human_tests {
    use super::*;
    #[test]
    fn unknown_owner_wire_errors_remain_unconfirmed_for_every_lifecycle_operation() {
        let unknown = serde_json::json!({
            "code": "future_owner_outcome",
            "payload": {"receipt": "not-confirmed"}
        });
        let wire = unknown.to_string();
        assert_eq!(
            live_inspection(Err(state::CredentialStateInvocationError::Domain(
                state::decode_inspect_error(&wire).unwrap(),
            )))
            .unwrap_err(),
            unknown_owner_result(),
        );
        assert_eq!(
            live_permission(Err(access::AccessControlInvocationError::Domain(
                access::decode_check_permission_error(&wire).unwrap(),
            ))),
            Err(unknown_owner_result()),
        );
        assert_eq!(
            issue_error(&admin::decode_issue_error(&wire).unwrap()),
            Err(unknown_owner_result())
        );
        assert_eq!(
            list_error(&admin::decode_list_error(&wire).unwrap()),
            Err(unknown_owner_result())
        );
        assert_eq!(
            receipt_error(&admin::decode_receipt_error(&wire).unwrap()),
            Err(unknown_owner_result())
        );
        assert_eq!(
            revoke_error(&admin::decode_revoke_error(&wire).unwrap()),
            Err(unknown_owner_result())
        );
        assert_eq!(
            issue_error(&admin::IssueError::Conflict),
            Ok(human::IssueError::Conflict)
        );
        assert_eq!(
            revoke_error(&admin::RevokeError::PermissionDenied),
            Ok(human::RevokeError::PermissionDenied)
        );
    }
    #[test]
    fn known_live_guard_denials_and_runtime_failures_keep_their_meaning() {
        for error in [
            state::InspectError::InvalidReference,
            state::InspectError::NotFound,
            state::InspectError::PermissionDenied,
        ] {
            assert!(matches!(
                live_inspection(Err(state::CredentialStateInvocationError::Domain(error))),
                Ok(None)
            ));
        }
        assert_eq!(
            live_permission(Err(access::AccessControlInvocationError::Domain(
                access::CheckPermissionError::InvalidRequest
            ))),
            Ok(false)
        );
        assert_eq!(
            live_permission(Ok(access::CheckPermissionResponse {
                allowed: false,
                policy_revision: "current".into()
            })),
            Ok(false)
        );
        for error in [
            RuntimeFailure::Unavailable {
                capability: state::CAPABILITY_ID,
            },
            RuntimeFailure::ProtocolViolation {
                capability: state::CAPABILITY_ID,
            },
        ] {
            assert_eq!(
                live_inspection(Err(state::CredentialStateInvocationError::Runtime(
                    error.clone()
                )))
                .unwrap_err(),
                error
            );
            assert_eq!(
                live_permission(Err(access::AccessControlInvocationError::Runtime(
                    error.clone()
                ))),
                Err(error)
            );
        }
    }
    #[test]
    fn scoped_agent_user_is_never_a_human_token_operator() {
        let now = OffsetDateTime::now_utc();
        let issuer = lenso_auth_sdk::ActorAssertionIssuer::new(
            "operators.account",
            b"test-only-owner-signing-key",
        );
        let root = issuer.issue(
            "usr_human",
            "user",
            "password",
            [lenso_auth_sdk::audience(human::CAPABILITY_ID, "issue")],
            lenso_auth_sdk::Validity::new(now, now + time::Duration::seconds(30)).unwrap(),
            std::collections::BTreeMap::new(),
        );
        assert!(User::from_assertion(&root).is_ok());
        let delegated=issuer.issue("usr_human","user","password",[lenso_auth_sdk::audience(human::CAPABILITY_ID,"issue")],lenso_auth_sdk::Validity::new(now,now+time::Duration::seconds(30)).unwrap(),std::collections::BTreeMap::from([(lenso_auth_sdk::delegation::SCOPED_DELEGATION_CLAIM.into(),serde_json::json!({"task_id":"task_a","agent_session_id":"agent_a","delegate_caller":"lenso.agent/default"}))]));
        assert!(User::from_assertion(&delegated).is_err());
    }
}

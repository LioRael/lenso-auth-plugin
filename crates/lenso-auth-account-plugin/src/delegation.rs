//! Account-owned restricted child sessions. Parent credentials never leave Auth.
use super::{
    AccountAuthPlugin, Duration, InvocationContext, NativeRequestFuture, OffsetDateTime, Rfc3339,
    RuntimeFailure, Zeroizing, random_id, random_token, runtime, storage, valid_audience,
    valid_session_token,
};
use lenso_capability_auth_delegation::{Delegation, GrantError, GrantRequest, GrantResponse};

impl AccountAuthPlugin {
    pub(crate) fn grant(
        &self,
        context: InvocationContext,
        request: GrantRequest,
    ) -> NativeRequestFuture<Delegation> {
        let allowed = context.caller_instance().is_some_and(|caller| {
            self.config
                .delegation_callers
                .iter()
                .any(|entry| entry == caller)
        });
        let prepared = self.prepared();
        let managed_policy = self
            .config
            .managed_sessions
            .as_ref()
            .map(|managed| managed.policy.clone());
        Box::pin(async move {
            if !allowed {
                return Ok(Err(GrantError::PermissionDenied));
            }
            if context.is_cancelled() {
                return Err(RuntimeFailure::Cancelled {
                    request_id: context.request_id(),
                });
            }
            let prepared = prepared?;
            let parent_credential = Zeroizing::new(request.parent_credential);
            if !valid_session_token(&parent_credential) {
                return Ok(Err(GrantError::InvalidCredential));
            }
            if request.audience.is_empty()
                || request.audience.len() > 64
                || request
                    .audience
                    .iter()
                    .any(|value| !valid_operation_audience(value))
            {
                return Ok(Err(GrantError::InvalidScope));
            }
            let Ok(expires_at) = OffsetDateTime::parse(&request.expires_at, &Rfc3339) else {
                return Ok(Err(GrantError::InvalidScope));
            };
            let now = OffsetDateTime::now_utc();
            if expires_at <= now {
                return Ok(Err(GrantError::Expired));
            }
            if expires_at > now + Duration::hours(1) {
                return Ok(Err(GrantError::InvalidScope));
            }
            let parent_digest =
                storage::token_digest(&prepared.pepper, &parent_credential).map_err(runtime)?;
            let token = random_token().map_err(runtime)?;
            let digest = storage::token_digest(&prepared.pepper, &token).map_err(runtime)?;
            let session_id = random_id("ses_").map_err(runtime)?;
            let result = storage::create_grant(
                &prepared.store,
                &parent_digest,
                &session_id,
                &digest,
                &request.audience,
                expires_at,
                managed_policy.as_ref(),
            )
            .await?;
            let subject = match result {
                Ok(subject) => subject,
                Err(error) => return Ok(Err(error)),
            };
            let response_expiry = if managed_policy.is_some() {
                let session = storage::inspect_session(&prepared.store, &session_id)
                    .await
                    .map_err(runtime)?
                    .ok_or_else(|| runtime("delegated session missing after committed grant"))?;
                super::format_time(session.expires_at)?
            } else {
                request.expires_at
            };
            Ok(Ok(GrantResponse {
                session_id,
                subject,
                credential: token,
                audience: request.audience,
                expires_at: response_expiry,
            }))
        })
    }
}

use lenso_auth_sdk::credential::{
    CredentialBinding, ManagementCredentialCeiling, ManagementResourceScope,
};
use lenso_auth_sdk::delegation::{SCOPED_DELEGATION_CLAIM, ScopedDelegationBinding};
use lenso_auth_sdk::realm::RealmAssertionVerifier;
use lenso_auth_sdk::{ActorAssertion, ActorProjectionError, TypedActor};
use lenso_capability_auth_delegation as scoped;

struct ScopedUser(ActorAssertion);
impl TypedActor for ScopedUser {
    fn from_assertion(assertion: &ActorAssertion) -> Result<Self, ActorProjectionError> {
        if assertion.actor_kind() != "user" {
            return Err(ActorProjectionError::UnexpectedActorKind {
                expected: "user".into(),
                actual: assertion.actor_kind().into(),
            });
        }
        Ok(Self(assertion.clone()))
    }
}
#[derive(Clone, Debug)]
struct ScopedParent {
    subject: String,
    session_id: String,
    ceiling: ManagementCredentialCeiling,
    audience: Vec<String>,
}
impl AccountAuthPlugin {
    fn scoped_parent(&self, context: &InvocationContext, operation: &str) -> Option<ScopedParent> {
        let caller = context.caller_instance()?;
        if !caller.contains('/')
            || !self
                .config
                .delegation_callers
                .iter()
                .any(|allowed| allowed == caller)
        {
            return None;
        }
        let verifier = RealmAssertionVerifier::new(
            "account",
            &self.config.issuer,
            &self.config.assertion_public_key,
            u32::try_from(self.config.assertion_ttl_seconds).ok()?,
            None,
        )
        .ok()?;
        let ScopedUser(assertion) = verifier
            .project_context::<ScopedUser>(
                context,
                scoped::CAPABILITY_ID,
                operation,
                &lenso_auth_sdk::FixedClock::new(OffsetDateTime::now_utc()),
            )
            .ok()?;
        if assertion.actor_kind() != "user"
            || assertion
                .to_wire()
                .claims
                .as_ref()
                .is_some_and(|claims| claims.contains_key(SCOPED_DELEGATION_CLAIM))
        {
            return None;
        }
        let binding = CredentialBinding::from_assertion(&assertion).ok()?;
        if binding.credential_id != binding.session_id {
            return None;
        }
        let ceiling = ManagementCredentialCeiling::from_assertion(&assertion).ok()?;
        Some(ScopedParent {
            subject: assertion.subject().into(),
            session_id: binding.session_id,
            ceiling,
            audience: assertion.audience().to_vec(),
        })
    }
    pub(crate) fn grant_scoped(
        &self,
        context: InvocationContext,
        mut request: scoped::GrantScopedRequest,
    ) -> NativeRequestFuture<scoped::DelegationGrantScoped> {
        let plugin = self.clone();
        Box::pin(async move {
            if context.is_cancelled() {
                return Err(RuntimeFailure::Cancelled {
                    request_id: context.request_id(),
                });
            }
            let Some(parent) = plugin.scoped_parent(&context, scoped::GRANT_SCOPED_OPERATION)
            else {
                return Ok(Err(scoped::GrantScopedError::PermissionDenied));
            };
            let binding = ScopedDelegationBinding {
                task_id: request.task_id.clone(),
                agent_session_id: request.agent_session_id.clone(),
                delegate_caller: request.delegate_caller.clone(),
            };
            let ceiling = requested_ceiling(&request);
            if !super::valid_name(&request.idempotency_key)
                || request.idempotency_key.len() > 128
                || binding.validate().is_err()
                || !plugin
                    .config
                    .scoped_delegation_targets
                    .contains(&binding.delegate_caller)
                || !ceiling.is_attenuation_of(&parent.ceiling)
                || request.audience.is_empty()
                || request.audience.len() > 64
                || request.audience.iter().any(|audience| {
                    !valid_operation_audience(audience) || !parent.audience.contains(audience)
                })
                || request
                    .audience
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != request.audience.len()
            {
                return Ok(Err(scoped::GrantScopedError::InvalidRequest));
            }
            let Ok(expiry) = OffsetDateTime::parse(&request.expires_at, &Rfc3339) else {
                return Ok(Err(scoped::GrantScopedError::InvalidRequest));
            };
            let expiry = expiry
                .replace_nanosecond(expiry.nanosecond() / 1000 * 1000)
                .map_err(runtime)?;
            request.expires_at = super::format_time(expiry)?;
            request.permissions.sort();
            request
                .resource_scopes
                .sort_by(|a, b| (&a.kind, &a.id).cmp(&(&b.kind, &b.id)));
            request.audience.sort();
            let prepared = plugin.prepared()?;
            match prepared.store {
                #[cfg(feature = "postgres")]
                storage::AccountStore::Postgres(pg) => {
                    scoped_postgres::grant(
                        &pg,
                        &prepared.pepper,
                        &context,
                        &parent,
                        &request,
                        plugin.config.management_session_ceiling.as_ref(),
                        expiry,
                        plugin
                            .config
                            .managed_sessions
                            .as_ref()
                            .map(|managed| &managed.policy),
                    )
                    .await
                }
                #[cfg(feature = "workers")]
                storage::AccountStore::D1 { .. } => {
                    Ok(Err(scoped::GrantScopedError::UnsupportedProfile))
                }
            }
        })
    }
    pub(crate) fn scoped_receipt(
        &self,
        context: InvocationContext,
        request: scoped::ScopedReceiptRequest,
    ) -> NativeRequestFuture<scoped::DelegationScopedReceipt> {
        let plugin = self.clone();
        Box::pin(async move {
            if context.is_cancelled() {
                return Err(RuntimeFailure::Cancelled {
                    request_id: context.request_id(),
                });
            }
            let Some(parent) = plugin.scoped_parent(&context, scoped::SCOPED_RECEIPT_OPERATION)
            else {
                return Ok(Err(scoped::ScopedReceiptError::PermissionDenied));
            };
            if !super::valid_name(&request.idempotency_key)
                || request.idempotency_key.len() > 128
                || request.task_id.is_empty()
                || request.agent_session_id.is_empty()
            {
                return Ok(Err(scoped::ScopedReceiptError::InvalidRequest));
            }
            let prepared = plugin.prepared()?;
            let current = storage::inspect_session(&prepared.store, &parent.session_id)
                .await
                .map_err(runtime)?;
            if !current.is_some_and(|session| {
                session.subject == parent.subject
                    && session.status == "active"
                    && !session.revoked
                    && session.expires_at > OffsetDateTime::now_utc()
                    && session.audience.contains(&lenso_auth_sdk::audience(
                        scoped::CAPABILITY_ID,
                        scoped::SCOPED_RECEIPT_OPERATION,
                    ))
            }) {
                return Ok(Err(scoped::ScopedReceiptError::PermissionDenied));
            }
            match prepared.store {
                #[cfg(feature = "postgres")]
                storage::AccountStore::Postgres(pg) => {
                    scoped_postgres::receipt(
                        &pg,
                        context.caller_instance().unwrap_or_default(),
                        &parent,
                        &request,
                        plugin
                            .config
                            .managed_sessions
                            .as_ref()
                            .map(|managed| &managed.policy),
                    )
                    .await
                }
                #[cfg(feature = "workers")]
                storage::AccountStore::D1 { .. } => {
                    Ok(Err(scoped::ScopedReceiptError::UnsupportedProfile))
                }
            }
        })
    }
}
fn requested_ceiling(request: &scoped::GrantScopedRequest) -> ManagementCredentialCeiling {
    ManagementCredentialCeiling {
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
    }
}
#[cfg(feature = "postgres")]
mod scoped_postgres;

fn valid_operation_audience(value: &str) -> bool {
    valid_audience(value)
        && value
            .split_once(':')
            .is_some_and(|(capability, operation)| {
                !operation.is_empty()
                    && !operation.contains(':')
                    && capability.rsplit_once('@').is_some_and(|(name, major)| {
                        !name.is_empty() && major.parse::<u32>().is_ok_and(|major| major > 0)
                    })
            })
}

#[cfg(all(test, feature = "postgres"))]
mod tests {
    use super::*;
    #[test]
    fn delegation_requires_an_exact_versioned_operation() {
        assert!(valid_operation_audience("lenso.projects@1:get_issue"));
        for invalid in [
            "lenso.projects@1",
            "lenso.projects@0:get_issue",
            "lenso.projects@1:",
            "lenso.projects@1:read:write",
            "lenso.projects:get_issue",
        ] {
            assert!(!valid_operation_audience(invalid));
        }
    }

    #[tokio::test]
    #[ignore = "requires LENSO_POSTGRES_TEST_URL"]
    #[allow(clippy::too_many_lines)] // One sequential grant and revocation lifecycle.
    async fn delegated_sessions_narrow_scope_and_follow_parent_revocation() {
        let (url, schema, postgres) = crate::tests::test_postgres("delegation").await;
        let subject = "usr_delegate";
        storage::postgres::ensure_identity(&postgres, "test", "delegate", subject)
            .await
            .unwrap();
        let parent_digest = storage::token_digest(b"pepper", "parent").unwrap();
        let mut parent = crate::tests::test_session("ses_parent", &parent_digest, subject);
        parent.audience = vec!["lenso.projects@1:get_issue".into()];
        storage::postgres::issue_session(&postgres, &parent)
            .await
            .unwrap();
        let expiry = OffsetDateTime::now_utc() + Duration::minutes(5);
        let child_digest = storage::token_digest(b"pepper", "child").unwrap();
        assert!(matches!(
            storage::postgres::create_grant(
                &postgres,
                &parent_digest,
                "ses_bad",
                &child_digest,
                &["other.app@1:write".into()],
                expiry,
                None,
            )
            .await
            .unwrap(),
            Err(GrantError::InvalidScope)
        ));
        assert!(matches!(
            storage::postgres::create_grant(
                &postgres,
                &parent_digest,
                "ses_bad",
                &child_digest,
                &parent.audience,
                parent.expires_at + Duration::seconds(1),
                None,
            )
            .await
            .unwrap(),
            Err(GrantError::InvalidScope)
        ));
        assert_eq!(
            storage::postgres::create_grant(
                &postgres,
                &parent_digest,
                "ses_child",
                &child_digest,
                &parent.audience,
                expiry,
                None,
            )
            .await
            .unwrap()
            .unwrap(),
            subject
        );
        let child = storage::postgres::load_session(&postgres, &child_digest)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(child.subject, subject);
        assert_eq!(child.audience, parent.audience);
        assert!(!child.revoked);
        assert!(matches!(
            storage::postgres::create_grant(
                &postgres,
                &child_digest,
                "ses_nested",
                &[3; 32],
                &parent.audience,
                expiry - Duration::seconds(1),
                None,
            )
            .await
            .unwrap(),
            Err(GrantError::NestedDelegation)
        ));
        storage::postgres::revoke_legacy_credential(&postgres, &parent_digest)
            .await
            .unwrap();
        assert!(
            storage::postgres::load_session(&postgres, &child_digest)
                .await
                .unwrap()
                .unwrap()
                .revoked
        );
        assert!(matches!(
            storage::postgres::create_grant(
                &postgres,
                &parent_digest,
                "ses_after",
                &[4; 32],
                &parent.audience,
                expiry,
                None,
            )
            .await
            .unwrap(),
            Err(GrantError::Revoked)
        ));
        crate::tests::cleanup_test_postgres(&url, &schema, postgres).await;
    }
}

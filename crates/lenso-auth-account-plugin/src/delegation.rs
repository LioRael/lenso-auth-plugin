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
            )
            .await?;
            let subject = match result {
                Ok(subject) => subject,
                Err(error) => return Ok(Err(error)),
            };
            Ok(Ok(GrantResponse {
                session_id,
                subject,
                credential: token,
                audience: request.audience,
                expires_at: request.expires_at,
            }))
        })
    }
}

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
                expiry
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
                parent.expires_at + Duration::seconds(1)
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
                expiry
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
                expiry - Duration::seconds(1)
            )
            .await
            .unwrap(),
            Err(GrantError::NestedDelegation)
        ));
        storage::postgres::revoke_credential(&postgres, &parent_digest)
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
                expiry
            )
            .await
            .unwrap(),
            Err(GrantError::Revoked)
        ));
        crate::tests::cleanup_test_postgres(&url, &schema, postgres).await;
    }
}

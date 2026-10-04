//! Explicit managed sessions share Account's opaque credentials and durable revocation.
use super::{
    AccountAuthPlugin, AccountConfigError, CREDENTIAL_BINDING_CLAIM, MANAGEMENT_CEILING_CLAIM,
    format_time, random_id, random_token, runtime, storage, valid_audience, valid_caller,
    valid_name, valid_session_token,
};
use lenso_capability_managed_session as contract;
use lenso_kernel::{InvocationContext, NativeRequestFuture};
use serde::{Deserialize, Serialize};
use storage::RenewSessionOutcome as Outcome;
use time::{Duration, OffsetDateTime};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedSessionPolicy {
    pub idle_timeout_seconds: u64,
    pub absolute_timeout_seconds: u64,
    pub renew_interval_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedSessionConfig {
    pub policy: ManagedSessionPolicy,
    pub issue_callers: Vec<String>,
    pub renew_callers: Vec<String>,
}

impl ManagedSessionConfig {
    pub(crate) fn validate(&self, operators: bool) -> Result<(), AccountConfigError> {
        let policy = &self.policy;
        let (max_idle, max_absolute) = if operators {
            (3600, 43_200)
        } else {
            (2_592_000, 7_776_000)
        };
        if policy.idle_timeout_seconds == 0
            || policy.idle_timeout_seconds > max_idle
            || policy.absolute_timeout_seconds < policy.idle_timeout_seconds
            || policy.absolute_timeout_seconds > max_absolute
            || policy.renew_interval_seconds == 0
            || policy.renew_interval_seconds > policy.idle_timeout_seconds / 2
        {
            return Err(AccountConfigError::InvalidManagedSessionPolicy);
        }
        for callers in [&self.issue_callers, &self.renew_callers] {
            if callers.is_empty()
                || callers.len() > 64
                || callers.iter().any(|value| !valid_caller(value))
                || callers
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != callers.len()
            {
                return Err(AccountConfigError::InvalidManagedSessionPolicy);
            }
        }
        Ok(())
    }
}

fn authorized(context: &InvocationContext, callers: &[String]) -> bool {
    context
        .caller_instance()
        .is_some_and(|caller| callers.iter().any(|allowed| allowed == caller))
}

impl AccountAuthPlugin {
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn read_managed(
        &self,
        context: InvocationContext,
        request: contract::ReadManagedRequest,
    ) -> NativeRequestFuture<contract::ManagedSessionReadManaged> {
        let config = self.config.managed_sessions.clone();
        let prepared = self.prepared();
        Box::pin(async move {
            let Some(config) = config else {
                return Ok(Err(contract::ReadManagedError::NotEnabled));
            };
            if !authorized(&context, &config.renew_callers) {
                return Ok(Err(contract::ReadManagedError::PermissionDenied));
            }
            if !valid_session_token(&request.credential) {
                return Ok(Err(contract::ReadManagedError::InvalidCredential));
            }
            let prepared = prepared?;
            let digest =
                storage::token_digest(&prepared.pepper, &request.credential).map_err(runtime)?;
            match storage::session_metadata(&prepared.store, &digest, &config.policy)
                .await
                .map_err(runtime)?
            {
                Ok(meta) => Ok(Ok(contract::ReadManagedResponse {
                    session_id: meta.session_id,
                    expires_at: format_time(meta.expires_at)?,
                    absolute_expires_at: format_time(meta.absolute_expires_at)?,
                    renew_after: format_time(meta.renew_after)?,
                })),
                Err(Outcome::InvalidCredential) => {
                    Ok(Err(contract::ReadManagedError::InvalidCredential))
                }
                Err(Outcome::StaleCredential) => {
                    Ok(Err(contract::ReadManagedError::StaleCredential))
                }
                Err(Outcome::Expired) => Ok(Err(contract::ReadManagedError::Expired)),
                Err(Outcome::Revoked) => Ok(Err(contract::ReadManagedError::Revoked)),
                Err(Outcome::Unsupported) => Ok(Err(contract::ReadManagedError::Unsupported)),
                Err(Outcome::TooEarly | Outcome::Rotated { .. }) => {
                    Err(lenso_kernel::RuntimeFailure::PluginFailure {
                        detail: "invalid managed metadata outcome".into(),
                    })
                }
            }
        })
    }
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn issue_managed(
        &self,
        context: InvocationContext,
        request: contract::IssueManagedRequest,
    ) -> NativeRequestFuture<contract::ManagedSessionIssueManaged> {
        let config = self.config.managed_sessions.clone();
        let prepared = self.prepared();
        let ceiling = self.config.management_session_ceiling.clone();
        Box::pin(async move {
            let Some(config) = config else {
                return Ok(Err(contract::IssueManagedError::NotEnabled));
            };
            if !authorized(&context, &config.issue_callers) {
                return Ok(Err(contract::IssueManagedError::PermissionDenied));
            }
            let prepared = prepared?;
            if !valid_name(&request.subject) {
                return Ok(Err(contract::IssueManagedError::InvalidSubject));
            }
            if request.actor_kind != "user"
                || !valid_name(&request.assurance)
                || request.audience.is_empty()
                || request.audience.len() > 64
                || request.audience.iter().any(|v| !valid_audience(v))
                || serde_json::to_vec(&request.claims).map_or(true, |v| v.len() > 16_384)
                || request.claims.contains_key(CREDENTIAL_BINDING_CLAIM)
                || request.claims.contains_key(MANAGEMENT_CEILING_CLAIM)
                || request
                    .claims
                    .contains_key(lenso_auth_sdk::delegation::SCOPED_DELEGATION_CLAIM)
            {
                return Ok(Err(contract::IssueManagedError::InvalidAuthority));
            }
            let now = OffsetDateTime::now_utc();
            let absolute_expires_at = now
                + Duration::seconds(
                    i64::try_from(config.policy.absolute_timeout_seconds)
                        .expect("validated policy"),
                );
            let expires_at = now
                + Duration::seconds(
                    i64::try_from(config.policy.idle_timeout_seconds).expect("validated policy"),
                );
            let renew_after = now
                + Duration::seconds(
                    i64::try_from(config.policy.renew_interval_seconds).expect("validated policy"),
                );
            let token = random_token().map_err(runtime)?;
            let session_id = random_id("ses_").map_err(runtime)?;
            let mut claims = request.claims;
            if let Some(ceiling) = ceiling {
                claims.insert(MANAGEMENT_CEILING_CLAIM.into(), serde_json::json!(ceiling));
            }
            let session = storage::NewSession {
                session_id: session_id.clone(),
                digest: storage::token_digest(&prepared.pepper, &token).map_err(runtime)?,
                subject: request.subject,
                actor_kind: request.actor_kind,
                assurance: request.assurance,
                audience: request.audience,
                claims,
                expires_at,
            };
            let managed = storage::NewManagedSession {
                issued_at: now,
                absolute_expires_at,
                idle_timeout_seconds: config.policy.idle_timeout_seconds,
                renew_interval_seconds: config.policy.renew_interval_seconds,
                last_renew_at: now,
            };
            match storage::issue_managed_session(&prepared.store, &session, &managed)
                .await
                .map_err(runtime)?
            {
                storage::IssueSessionOutcome::Inserted => (),
                storage::IssueSessionOutcome::Disabled => {
                    return Ok(Err(contract::IssueManagedError::Disabled));
                }
                storage::IssueSessionOutcome::InvalidSubject => {
                    return Ok(Err(contract::IssueManagedError::InvalidSubject));
                }
            }
            Ok(Ok(contract::IssueManagedResponse {
                session_id,
                credential: token,
                expires_at: format_time(expires_at)?,
                absolute_expires_at: format_time(absolute_expires_at)?,
                renew_after: format_time(renew_after)?,
            }))
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn renew(
        &self,
        context: InvocationContext,
        request: contract::RenewRequest,
    ) -> NativeRequestFuture<contract::ManagedSessionRenew> {
        let config = self.config.managed_sessions.clone();
        let prepared = self.prepared();
        Box::pin(async move {
            let Some(config) = config else {
                return Ok(Err(contract::RenewError::NotEnabled));
            };
            if !authorized(&context, &config.renew_callers) {
                return Ok(Err(contract::RenewError::PermissionDenied));
            }
            if !valid_session_token(&request.credential) {
                return Ok(Err(contract::RenewError::InvalidCredential));
            }
            let prepared = prepared?;
            let old_digest =
                storage::token_digest(&prepared.pepper, &request.credential).map_err(runtime)?;
            let token = random_token().map_err(runtime)?;
            let new_digest = storage::token_digest(&prepared.pepper, &token).map_err(runtime)?;
            match storage::renew_session(&prepared.store, &old_digest, &new_digest, &config.policy)
                .await
                .map_err(runtime)?
            {
                Outcome::Rotated {
                    session_id,
                    expires_at,
                    absolute_expires_at,
                    renew_after,
                } => Ok(Ok(contract::RenewResponse {
                    session_id,
                    credential: token,
                    expires_at: format_time(expires_at)?,
                    absolute_expires_at: format_time(absolute_expires_at)?,
                    renew_after: format_time(renew_after)?,
                })),
                Outcome::InvalidCredential => Ok(Err(contract::RenewError::InvalidCredential)),
                Outcome::StaleCredential => Ok(Err(contract::RenewError::StaleCredential)),
                Outcome::Expired => Ok(Err(contract::RenewError::Expired)),
                Outcome::Revoked => Ok(Err(contract::RenewError::Revoked)),
                Outcome::TooEarly => Ok(Err(contract::RenewError::TooEarly)),
                Outcome::Unsupported => Ok(Err(contract::RenewError::Unsupported)),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policies_are_explicit_finite_and_operator_is_tighter() {
        let mut config = ManagedSessionConfig {
            policy: ManagedSessionPolicy {
                idle_timeout_seconds: 86_400,
                absolute_timeout_seconds: 2_592_000,
                renew_interval_seconds: 3600,
            },
            issue_callers: vec!["auth/password".into()],
            renew_callers: vec!["auth/renewal".into()],
        };
        assert!(config.validate(false).is_ok());
        assert!(config.validate(true).is_err());
        config.policy = ManagedSessionPolicy {
            idle_timeout_seconds: 1800,
            absolute_timeout_seconds: 28_800,
            renew_interval_seconds: 300,
        };
        assert!(config.validate(true).is_ok());
        config.policy.absolute_timeout_seconds = u64::MAX;
        assert!(config.validate(false).is_err());
        config.policy.absolute_timeout_seconds = 28_800;
        config.renew_callers.clear();
        assert!(config.validate(true).is_err());
    }
}

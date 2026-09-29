//! Auth-issued task and session binding for a restricted child credential.
use crate::{ActorAssertion, credential::CredentialClaimError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SCOPED_DELEGATION_CLAIM: &str = "lenso.auth.scoped-delegation";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedDelegationBinding {
    pub task_id: String,
    pub agent_session_id: String,
    pub delegate_caller: String,
}
impl ScopedDelegationBinding {
    pub fn validate(&self) -> Result<(), CredentialClaimError> {
        fn label(value: &str, maximum: usize) -> bool {
            !value.is_empty()
                && value.len() <= maximum
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
        }
        if !label(&self.task_id, 128)
            || !label(&self.agent_session_id, 128)
            || !self
                .delegate_caller
                .split_once('/')
                .is_some_and(|(plugin, instance)| label(plugin, 256) && label(instance, 256))
        {
            return Err(CredentialClaimError::Invalid);
        }
        Ok(())
    }
    /// Use after verifying the containing assertion's issuer, proof and audience.
    pub fn from_assertion(assertion: &ActorAssertion) -> Result<Self, CredentialClaimError> {
        Self::from_claims(&assertion.to_wire().claims.unwrap_or_default())
    }
    pub fn from_claims(
        claims: &BTreeMap<String, serde_json::Value>,
    ) -> Result<Self, CredentialClaimError> {
        let binding: Self = serde_json::from_value(
            claims
                .get(SCOPED_DELEGATION_CLAIM)
                .ok_or(CredentialClaimError::Missing)?
                .clone(),
        )
        .map_err(|_| CredentialClaimError::Invalid)?;
        binding.validate()?;
        Ok(binding)
    }
}
/// Denial-only filter for a trusted human-decider caller. This does not verify
/// identity or authorize an actor; the caller must retain its realm/live checks.
/// Missing assertions retain the caller's explicit trusted-local policy.
pub fn denies_human_context(context: &lenso_kernel::InvocationContext) -> bool {
    if context
        .sealed_extension(crate::ACTOR_ASSERTION_EXTENSION)
        .is_none()
    {
        return false;
    }
    match ActorAssertion::from_context(context) {
        Ok(assertion) => {
            assertion.actor_kind() != "user"
                || assertion
                    .to_wire()
                    .claims
                    .as_ref()
                    .is_some_and(|claims| claims.contains_key(SCOPED_DELEGATION_CLAIM))
        }
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trusted_human_filter_only_narrows_asserted_context() {
        use crate::{ActorAssertionIssuer, Validity};
        use lenso_kernel::{CancellationToken, InvocationContext};
        use time::{Duration, OffsetDateTime};
        let context = || InvocationContext::new(1, None, CancellationToken::new());
        assert!(!denies_human_context(&context()));
        let issuer = ActorAssertionIssuer::new("operators", b"fixture-only-key");
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let assertion = |kind: &str, claims| {
            issuer
                .issue(
                    "usr_alice",
                    kind,
                    "authenticated",
                    ["lenso.business-approval@1:decide".into()],
                    Validity::new(now, now + Duration::minutes(1)).unwrap(),
                    claims,
                )
                .attach(context())
                .unwrap()
        };
        assert!(!denies_human_context(&assertion("user", BTreeMap::new())));
        assert!(denies_human_context(&assertion(
            "service_account",
            BTreeMap::new()
        )));
        assert!(denies_human_context(&assertion(
            "user",
            BTreeMap::from([(
                SCOPED_DELEGATION_CLAIM.into(),
                serde_json::json!({"invalid":"reserved claim still denies"})
            )])
        )));
    }
    #[test]
    fn binding_has_exact_private_task_session_and_canonical_caller() {
        let binding = ScopedDelegationBinding {
            task_id: "task_a".into(),
            agent_session_id: "agent_a".into(),
            delegate_caller: "lenso.agent/default".into(),
        };
        assert!(binding.validate().is_ok());
        let mut value = serde_json::to_value(&binding).unwrap();
        value["subject"] = serde_json::json!("forged");
        assert!(
            ScopedDelegationBinding::from_claims(&BTreeMap::from([(
                SCOPED_DELEGATION_CLAIM.into(),
                value
            )]))
            .is_err()
        );
        let mut invalid = binding;
        invalid.delegate_caller = "lenso.agent".into();
        assert!(invalid.validate().is_err());
    }
}

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
#[cfg(test)]
mod tests {
    use super::*;
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

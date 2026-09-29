//! Signed credential references and explicit management ceilings.
use crate::ActorAssertion;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const CREDENTIAL_BINDING_CLAIM: &str = "lenso.auth.credential";
pub const MANAGEMENT_CEILING_CLAIM: &str = "lenso.auth.management-ceiling";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialBinding {
    pub credential_id: String,
    pub session_id: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementResourceScope {
    pub kind: String,
    pub id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementCredentialCeiling {
    pub deployment: String,
    pub permissions: Vec<String>,
    pub resource_scopes: Vec<ManagementResourceScope>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialClaimError {
    Missing,
    Invalid,
}

fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}
impl CredentialBinding {
    pub fn validate(&self) -> Result<(), CredentialClaimError> {
        if !label(&self.credential_id) || !label(&self.session_id) {
            return Err(CredentialClaimError::Invalid);
        }
        Ok(())
    }
    /// Call only after verifying the containing assertion's issuer, proof and audience.
    pub fn from_assertion(assertion: &ActorAssertion) -> Result<Self, CredentialClaimError> {
        Self::from_claims(&assertion.to_wire().claims.unwrap_or_default())
    }
    pub fn from_claims(
        claims: &BTreeMap<String, serde_json::Value>,
    ) -> Result<Self, CredentialClaimError> {
        let binding: Self = serde_json::from_value(
            claims
                .get(CREDENTIAL_BINDING_CLAIM)
                .ok_or(CredentialClaimError::Missing)?
                .clone(),
        )
        .map_err(|_| CredentialClaimError::Invalid)?;
        binding.validate()?;
        Ok(binding)
    }
}
impl ManagementCredentialCeiling {
    pub fn validate(&self) -> Result<(), CredentialClaimError> {
        if !label(&self.deployment)
            || self.permissions.is_empty()
            || self.permissions.len() > 128
            || self.permissions.iter().any(|p| !label(p))
            || self.permissions.iter().collect::<BTreeSet<_>>().len() != self.permissions.len()
            || self.resource_scopes.is_empty()
            || self.resource_scopes.len() > 128
            || self
                .resource_scopes
                .iter()
                .any(|s| !label(&s.kind) || !label(&s.id))
            || self.resource_scopes.iter().collect::<BTreeSet<_>>().len()
                != self.resource_scopes.len()
        {
            return Err(CredentialClaimError::Invalid);
        }
        Ok(())
    }
    pub fn from_claims(
        claims: &BTreeMap<String, serde_json::Value>,
    ) -> Result<Self, CredentialClaimError> {
        let ceiling: Self = serde_json::from_value(
            claims
                .get(MANAGEMENT_CEILING_CLAIM)
                .ok_or(CredentialClaimError::Missing)?
                .clone(),
        )
        .map_err(|_| CredentialClaimError::Invalid)?;
        ceiling.validate()?;
        Ok(ceiling)
    }
    /// Call only after verifying the containing assertion's issuer, proof and audience.
    pub fn from_assertion(assertion: &ActorAssertion) -> Result<Self, CredentialClaimError> {
        Self::from_claims(&assertion.to_wire().claims.unwrap_or_default())
    }
    pub fn allows(
        &self,
        deployment: &str,
        permission: &str,
        scope_kind: &str,
        scope_id: &str,
    ) -> bool {
        self.validate().is_ok()
            && self.deployment == deployment
            && self.permissions.iter().any(|p| p == permission)
            && self
                .resource_scopes
                .iter()
                .any(|s| s.kind == scope_kind && s.id == scope_id)
    }
    pub fn is_attenuation_of(&self, parent: &Self) -> bool {
        self.validate().is_ok()
            && parent.validate().is_ok()
            && self.deployment == parent.deployment
            && self
                .permissions
                .iter()
                .all(|p| parent.permissions.contains(p))
            && self
                .resource_scopes
                .iter()
                .all(|s| parent.resource_scopes.contains(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ceilings_are_exact_nonempty_and_attenuate_without_role_semantics() {
        let parent = ManagementCredentialCeiling {
            deployment: "deployment-a".into(),
            permissions: vec!["auth.subject.read".into(), "auth.session.revoke".into()],
            resource_scopes: vec![ManagementResourceScope {
                kind: "management-deployment".into(),
                id: "deployment-a".into(),
            }],
        };
        assert!(parent.allows(
            "deployment-a",
            "auth.subject.read",
            "management-deployment",
            "deployment-a"
        ));
        assert!(!parent.allows(
            "deployment-b",
            "auth.subject.read",
            "management-deployment",
            "deployment-a"
        ));
        let mut child = parent.clone();
        child.permissions.pop();
        assert!(child.is_attenuation_of(&parent));
        assert!(!parent.is_attenuation_of(&child));
        child.resource_scopes.clear();
        assert!(child.validate().is_err());
        assert!(!child.allows(
            "deployment-a",
            "auth.subject.read",
            "management-deployment",
            "deployment-a"
        ));
        let claims = BTreeMap::from([(
            MANAGEMENT_CEILING_CLAIM.into(),
            serde_json::json!({"deployment":"deployment-a","permissions":["*"],"resource_scopes":[]}),
        )]);
        assert_eq!(
            ManagementCredentialCeiling::from_claims(&claims),
            Err(CredentialClaimError::Invalid)
        );
        assert_eq!(
            CredentialBinding::from_claims(&BTreeMap::new()),
            Err(CredentialClaimError::Missing)
        );
        assert!(
            CredentialBinding::from_claims(&BTreeMap::from([(
                CREDENTIAL_BINDING_CLAIM.into(),
                serde_json::json!({"credential_id":"tok_a","session_id":"ses_a","subject":"forged"})
            )]))
            .is_err()
        );
    }
}

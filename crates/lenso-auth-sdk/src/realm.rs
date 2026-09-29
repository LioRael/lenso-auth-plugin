//! Immutable realm admission at the assertion verification boundary.

use crate::{
    ActorAssertion, ActorAssertionVerifier, ActorProjectionError, AssertionClock,
    AssertionValidationError, TypedActor, audience,
};
use lenso_kernel::InvocationContext;
use time::Duration;

/// A local trust boundary backed by one exact issuer and public key.
///
/// Realm names are configuration labels. Neither subject equality nor a
/// `claims.realm` value can select or override this verification authority.
#[derive(Clone, Debug)]
pub struct RealmAssertionVerifier {
    realm: String,
    verifier: ActorAssertionVerifier,
    maximum_assertion_ttl: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmPolicyError {
    InvalidRealm,
    InvalidMaximumTtl,
    UnsupportedAssurance,
    InvalidVerificationAuthority(AssertionValidationError),
}

impl RealmAssertionVerifier {
    /// Selects an independent realm's exact verification authority.
    ///
    /// Step-up/MFA is rejected until an implementation can provide verified
    /// evidence; a signed assurance name alone does not establish that evidence.
    pub fn new(
        realm: impl Into<String>,
        issuer: impl Into<String>,
        public_key: &str,
        maximum_assertion_ttl_seconds: u32,
        required_assurance: Option<&str>,
    ) -> Result<Self, RealmPolicyError> {
        let realm = realm.into();
        if realm.is_empty()
            || realm.len() > 128
            || !realm
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(RealmPolicyError::InvalidRealm);
        }
        if !(1..=3600).contains(&maximum_assertion_ttl_seconds) {
            return Err(RealmPolicyError::InvalidMaximumTtl);
        }
        if required_assurance.is_some() {
            return Err(RealmPolicyError::UnsupportedAssurance);
        }
        let verifier = ActorAssertionVerifier::from_public_key_base64(issuer, public_key)
            .map_err(RealmPolicyError::InvalidVerificationAuthority)?;
        Ok(Self {
            realm,
            verifier,
            maximum_assertion_ttl: Duration::seconds(i64::from(maximum_assertion_ttl_seconds)),
        })
    }

    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Verifies current target admission before a target-owned actor projection.
    pub fn project_context<T: TypedActor>(
        &self,
        context: &InvocationContext,
        capability_id: &str,
        operation: &str,
        clock: &dyn AssertionClock,
    ) -> Result<T, ActorProjectionError> {
        let assertion = ActorAssertion::from_context(context)
            .map_err(|_| AssertionValidationError::InvalidProof)?;
        self.verifier
            .verify_for(&assertion, &audience(capability_id, operation), clock.now())?;
        if assertion.expires_at - assertion.issued_at > self.maximum_assertion_ttl {
            return Err(AssertionValidationError::InvalidValidity.into());
        }
        T::from_assertion(&assertion)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ActorAssertionIssuer, FixedClock, Validity};
    use lenso_kernel::CancellationToken;
    use std::collections::BTreeMap;
    use time::OffsetDateTime;

    struct User(String);
    impl TypedActor for User {
        fn from_assertion(assertion: &ActorAssertion) -> Result<Self, ActorProjectionError> {
            if assertion.actor_kind() != "user" {
                return Err(ActorProjectionError::UnexpectedActorKind {
                    expected: "user".into(),
                    actual: assertion.actor_kind().into(),
                });
            }
            Ok(Self(assertion.subject().into()))
        }
    }

    #[test]
    fn application_subject_and_forged_realm_claim_do_not_enter_operators() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let app = ActorAssertionIssuer::new("app", b"app-key");
        let operators = ActorAssertionIssuer::new("operators", b"operators-key");
        let policy = RealmAssertionVerifier::new(
            "operators",
            "operators",
            &operators.public_key_base64(),
            60,
            None,
        )
        .unwrap();
        let context = |issuer: &ActorAssertionIssuer, ttl: i64| {
            issuer
                .issue(
                    "same-subject",
                    "user",
                    "mfa",
                    [audience("management@1", "execute")],
                    Validity::new(now, now + Duration::seconds(ttl)).unwrap(),
                    BTreeMap::from([("realm".into(), serde_json::json!("operators"))]),
                )
                .attach(InvocationContext::new(1, None, CancellationToken::new()))
                .unwrap()
        };
        assert!(
            policy
                .project_context::<User>(
                    &context(&app, 30),
                    "management@1",
                    "execute",
                    &FixedClock::new(now)
                )
                .is_err()
        );
        assert_eq!(
            policy
                .project_context::<User>(
                    &context(&operators, 30),
                    "management@1",
                    "execute",
                    &FixedClock::new(now)
                )
                .unwrap()
                .0,
            "same-subject"
        );
        assert!(
            policy
                .project_context::<User>(
                    &context(&operators, 61),
                    "management@1",
                    "execute",
                    &FixedClock::new(now)
                )
                .is_err()
        );
        assert!(
            policy
                .project_context::<User>(
                    &context(&operators, 30),
                    "management@1",
                    "read",
                    &FixedClock::new(now)
                )
                .is_err()
        );
        assert!(
            policy
                .project_context::<User>(
                    &context(&operators, 30),
                    "management@1",
                    "execute",
                    &FixedClock::new(now + Duration::seconds(30))
                )
                .is_err()
        );
        assert_eq!(policy.realm(), "operators");
    }

    #[test]
    fn claims_cannot_enable_unimplemented_step_up() {
        let issuer = ActorAssertionIssuer::new("operators", b"operators-key");
        assert!(matches!(
            RealmAssertionVerifier::new(
                "operators",
                "operators",
                &issuer.public_key_base64(),
                60,
                Some("mfa")
            ),
            Err(RealmPolicyError::UnsupportedAssurance)
        ));
    }
}

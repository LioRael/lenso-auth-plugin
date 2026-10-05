use super::*;
use lenso_auth_sdk::{
    ActorAssertionIssuer, Validity, audience,
    credential::{CREDENTIAL_BINDING_CLAIM, MANAGEMENT_CEILING_CLAIM, ManagementResourceScope},
};
use lenso_kernel::CancellationToken;
use std::collections::BTreeMap;
use time::Duration;

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
}
fn ceiling() -> ManagementCredentialCeiling {
    ManagementCredentialCeiling {
        deployment: "deployment-a".into(),
        permissions: vec!["auth.subject.read".into(), "auth.subject.status".into()],
        resource_scopes: vec![ManagementResourceScope {
            kind: "app".into(),
            id: "alpha".into(),
        }],
    }
}
fn binding() -> CredentialBinding {
    CredentialBinding {
        credential_id: "session-a".into(),
        session_id: "session-a".into(),
    }
}
fn claims() -> BTreeMap<String, serde_json::Value> {
    BTreeMap::from([
        (
            CREDENTIAL_BINDING_CLAIM.into(),
            serde_json::json!(binding()),
        ),
        (
            MANAGEMENT_CEILING_CLAIM.into(),
            serde_json::json!(ceiling()),
        ),
    ])
}
fn config(issuer: &ActorAssertionIssuer) -> AccountConsoleConfig {
    AccountConsoleConfig {
        issuer: "auth.account".into(),
        public_key: issuer.public_key_base64(),
        assertion_max_ttl_seconds: 60,
        caller_instances: vec!["lenso.console/app".into()],
        deployment: "deployment-a".into(),
        access_scope: AccessScope {
            kind: "app".into(),
            id: "alpha".into(),
        },
        account_instance: "lenso.auth.account/default".into(),
        allowed_mutations: Vec::new(),
    }
}
fn assertion(
    issuer: &ActorAssertionIssuer,
    claims: BTreeMap<String, serde_json::Value>,
) -> ActorAssertion {
    issuer.issue(
        "user-a",
        "user",
        "session",
        [audience(service::CAPABILITY_ID, "invoke")],
        Validity::new(now(), now() + Duration::seconds(60)).unwrap(),
        claims,
    )
}
fn context(actor: &ActorAssertion, caller: &str) -> InvocationContext {
    actor
        .attach(
            InvocationContext::new(1, None, CancellationToken::new()).with_caller_instance(caller),
        )
        .unwrap()
}
fn current() -> state::InspectResponse {
    state::InspectResponse {
        active: true,
        actor_kind: "user".into(),
        assurance: "session".into(),
        audience: vec![audience(service::CAPABILITY_ID, "invoke")],
        claims: claims(),
        credential_id: "session-a".into(),
        session_id: "session-a".into(),
        expires_at: (now() + Duration::hours(1)).format(&Rfc3339).unwrap(),
        subject: "user-a".into(),
    }
}

#[test]
fn signed_user_must_be_exact_caller_and_never_delegated() {
    let issuer = ActorAssertionIssuer::new("auth.account", b"account-test");
    let config = config(&issuer);
    let actor = assertion(&issuer, claims());
    assert!(
        config
            .actor(&context(&actor, "lenso.console/app"), now())
            .is_ok()
    );
    assert_eq!(
        config.actor(&context(&actor, "lenso.console/other"), now()),
        Err(service::InvokeError::Denied)
    );
    let foreign = ActorAssertionIssuer::new("auth.account", b"foreign-test");
    assert_eq!(
        config.actor(
            &context(&assertion(&foreign, claims()), "lenso.console/app"),
            now()
        ),
        Err(service::InvokeError::Denied)
    );
    let mut delegated = claims();
    delegated.insert(lenso_auth_sdk::delegation::SCOPED_DELEGATION_CLAIM.into(),serde_json::json!({"task_id":"task","agent_session_id":"agent","delegate_caller":"example.agent/default"}));
    assert_eq!(
        config.actor(
            &context(&assertion(&issuer, delegated), "lenso.console/app"),
            now()
        ),
        Err(service::InvokeError::Denied)
    );
}

#[test]
fn revocation_live_identity_and_expiry_fail_closed() {
    let issuer = ActorAssertionIssuer::new("auth.account", b"account-test");
    let config = config(&issuer);
    let actor = assertion(&issuer, claims());
    let valid = current();
    assert!(current_admitted(
        &config,
        &actor,
        &valid,
        "auth.subject.read",
        now()
    ));
    let mut revoked = valid.clone();
    revoked.active = false;
    let mut substituted = valid.clone();
    substituted.subject = "user-b".into();
    let mut session = valid.clone();
    session.session_id = "session-b".into();
    let mut assurance = valid.clone();
    assurance.assurance = "other".into();
    let mut expired = valid.clone();
    expired.expires_at = now().format(&Rfc3339).unwrap();
    let mut audience = valid.clone();
    audience.audience = vec![lenso_auth_sdk::audience(
        service::CAPABILITY_ID,
        "describe_exports",
    )];
    let mut delegated = valid.clone();
    delegated.claims.insert(
        lenso_auth_sdk::delegation::SCOPED_DELEGATION_CLAIM.into(),
        serde_json::json!({}),
    );
    for denied in [
        revoked,
        substituted,
        session,
        assurance,
        expired,
        audience,
        delegated,
    ] {
        assert!(!current_admitted(
            &config,
            &actor,
            &denied,
            "auth.subject.read",
            now()
        ));
    }
}

#[test]
fn signed_and_current_ceiling_intersection_survives_narrowing() {
    let issuer = ActorAssertionIssuer::new("auth.account", b"account-test");
    let config = config(&issuer);
    let actor = assertion(&issuer, claims());
    let mut live = current();
    assert!(current_admitted(
        &config,
        &actor,
        &live,
        "auth.subject.status",
        now()
    ));
    let mut narrowed = ceiling();
    narrowed.permissions = vec!["auth.subject.read".into()];
    live.claims.insert(
        MANAGEMENT_CEILING_CLAIM.into(),
        serde_json::json!(&narrowed),
    );
    assert!(!current_admitted(
        &config,
        &actor,
        &live,
        "auth.subject.status",
        now()
    ));
    assert!(current_admitted(
        &config,
        &actor,
        &live,
        "auth.subject.read",
        now()
    ));
    let mut signed = claims();
    signed.insert(
        MANAGEMENT_CEILING_CLAIM.into(),
        serde_json::json!(&narrowed),
    );
    assert!(!current_admitted(
        &config,
        &assertion(&issuer, signed),
        &current(),
        "auth.subject.status",
        now()
    ));
    let mut cross_scope = config.clone();
    cross_scope.access_scope.id = "beta".into();
    assert!(!current_admitted(
        &cross_scope,
        &actor,
        &current(),
        "auth.subject.read",
        now()
    ));
}

#[test]
fn read_only_default_and_strict_confirmation_dtos() {
    let issuer = ActorAssertionIssuer::new("auth.account", b"account-test");
    let mut config = config(&issuer);
    assert!(validate_config(&config).is_ok());
    assert_eq!(
        config.permission("set_subject_status"),
        Err(service::InvokeError::UnknownOperation)
    );
    assert_eq!(
        config.permission("revoke_session"),
        Err(service::InvokeError::UnknownOperation)
    );
    config
        .allowed_mutations
        .push(AllowedMutation::RevokeSession);
    assert_eq!(
        config.permission("revoke_session"),
        Ok("auth.session.revoke")
    );
    let body = |value: serde_json::Value| STANDARD.encode(serde_json::to_vec(&value).unwrap());
    assert!(
        decode::<RevokeSessionRequest>(&body(serde_json::json!({"session_id":"session-a"})))
            .is_err()
    );
    assert!(
        decode::<RevokeSessionRequest>(&body(
            serde_json::json!({"session_id":"session-a","credential":"secret","confirmed":true})
        ))
        .is_err()
    );
    assert!(
        decode::<PageRequest>(&body(
            serde_json::json!({"cursor":null,"limit":25,"access_scope":{"kind":"app","id":"beta"}})
        ))
        .is_err()
    );
    config.account_instance = "account".into();
    assert!(validate_config(&config).is_err());
    config.account_instance = "lenso.auth.account/default".into();
    config.caller_instances = vec!["console".into()];
    assert!(validate_config(&config).is_err());
}

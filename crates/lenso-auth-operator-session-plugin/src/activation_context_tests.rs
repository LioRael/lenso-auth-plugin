use super::*;
use lenso_auth_sdk::{ACTOR_ASSERTION_EXTENSION, ActorAssertionIssuer, Validity};
use lenso_kernel::CancellationToken;

fn fixture() -> (
    OperatorSessionConfig,
    ActorAssertionIssuer,
    bindings::Binding,
) {
    let source = ActorAssertionIssuer::new("test.accounts", b"public-source-fixture");
    let operators = ActorAssertionIssuer::new("test.operators", b"public-operators-fixture");
    let config = OperatorSessionConfig {
        accounts_issuer: "test.accounts".into(),
        accounts_public_key: source.public_key_base64(),
        operators_issuer: "test.operators".into(),
        operators_public_key: operators.public_key_base64(),
        maximum_assertion_ttl_seconds: 30,
        deployment: "synthetic".into(),
        scope_kind: "deployment".into(),
        scope_id: "synthetic".into(),
        bootstrap_subject: "usr_source".into(),
        bootstrap_callers: vec!["test.owner/default".into()],
        permissions: vec!["test.read".into()],
        session_ttl_seconds: 60,
        operator_audience: vec!["test.resource@1#read".into()],
    };
    let binding = bindings::Binding {
        source_issuer: "test.accounts".into(),
        deployment: "synthetic".into(),
        scope_kind: "deployment".into(),
        scope_id: "synthetic".into(),
        binding_id: "opb_fixture".into(),
        source_subject: "usr_source".into(),
        operator_subject: "usr_operator".into(),
        revision: "1".into(),
        active: false,
        revoked: false,
        revocation_pending: false,
        revocation_audit_event_id: String::new(),
        revoked_by: String::new(),
        revoked_at: String::new(),
        audit_event_id: String::new(),
        policy_revision: String::new(),
    };
    (config, operators, binding)
}
fn assertion(
    issuer: &ActorAssertionIssuer,
    subject: &str,
    operation: &str,
    expired: bool,
) -> String {
    let now = OffsetDateTime::now_utc();
    let start = if expired {
        now - Duration::seconds(10)
    } else {
        now
    };
    let actor = issuer.issue(
        subject,
        "user",
        "bootstrap",
        vec![lenso_auth_sdk::audience(admin::CAPABILITY_ID, operation)],
        Validity::new(start, start + Duration::seconds(5)).unwrap(),
        BTreeMap::new(),
    );
    serde_json::to_string(&actor.to_wire()).unwrap()
}

#[test]
fn control_preserves_absolute_parent_deadline_and_cancellation_without_replacing_source() {
    let (config, issuer, binding) = fixture();
    let token = CancellationToken::new();
    let source = ActorAssertionIssuer::new("test.accounts", b"public-source-fixture");
    let now = OffsetDateTime::now_utc();
    let source_actor = source.issue(
        "usr_source",
        "user",
        "fixture",
        vec![lenso_auth_sdk::audience(
            role::CAPABILITY_ID,
            "resume_binding",
        )],
        Validity::new(now, now + Duration::seconds(30)).unwrap(),
        BTreeMap::new(),
    );
    let parent = source_actor
        .attach(InvocationContext::new(
            42,
            Some(std::time::Duration::from_secs(120)),
            token.clone(),
        ))
        .unwrap();
    let parent_wire = parent
        .sealed_extension(ACTOR_ASSERTION_EXTENSION)
        .unwrap()
        .value()
        .to_vec();
    let control = config
        .control_context(
            &assertion(&issuer, "usr_operator", "create_role", false),
            &binding,
            &parent,
            "create_role",
        )
        .unwrap();
    assert_eq!(control.deadline(), parent.deadline());
    assert_eq!(control.request_id(), parent.request_id());
    assert_eq!(
        parent
            .sealed_extension(ACTOR_ASSERTION_EXTENSION)
            .unwrap()
            .value(),
        parent_wire
    );
    assert_ne!(
        control
            .sealed_extension(ACTOR_ASSERTION_EXTENSION)
            .unwrap()
            .value(),
        parent_wire
    );
    token.cancel();
    assert!(control.is_cancelled());
    let unbounded = InvocationContext::new(43, None, CancellationToken::new());
    let control = config
        .control_context(
            &assertion(&issuer, "usr_operator", "create_role", false),
            &binding,
            &unbounded,
            "create_role",
        )
        .unwrap();
    assert_eq!(control.deadline(), None);
}

#[test]
fn control_does_not_widen_operation_subject_issuer_or_assertion_lifetime() {
    let (config, issuer, binding) = fixture();
    let parent = InvocationContext::new(42, None, CancellationToken::new());
    for (raw, operation) in [
        (
            assertion(&issuer, "usr_operator", "create_role", false),
            "assign_role",
        ),
        (
            assertion(&issuer, "usr_other", "create_role", false),
            "create_role",
        ),
        (
            assertion(
                &ActorAssertionIssuer::new("test.accounts", b"public-source-fixture"),
                "usr_operator",
                "create_role",
                false,
            ),
            "create_role",
        ),
        (
            assertion(&issuer, "usr_operator", "create_role", true),
            "create_role",
        ),
    ] {
        assert!(
            config
                .control_context(&raw, &binding, &parent, operation)
                .is_err()
        );
    }
}

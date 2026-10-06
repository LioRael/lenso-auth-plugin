use super::operator_binding::*;
use super::*;

fn record(status: &str) -> Record {
    serde_json::from_value(serde_json::json!({
        "source_issuer":"fixture.accounts","deployment":"synthetic","scope_kind":"deployment",
        "scope_id":"synthetic","binding_id":"opb_fixture","source_subject":"usr_source",
        "operator_subject":"usr_operator","revision":1,"status":status,"audit_event_id":"audit_fixed",
        "policy_revision":"1","revocation_state":"none","revocation_audit_event_id":"",
        "revoked_by":"","revoked_at":"","activation_started_at":"2026-10-06T10:00:00.000000000Z",
        "activation_permissions":"[\"fixture.read\"]"
    })).unwrap()
}

#[test]
fn fresh_control_has_only_selected_audience_and_respects_source_and_window_expiry() {
    let issuer = ActorAssertionIssuer::new("fixture.operators", b"public-activation-fixture");
    for (operation, expected, source_seconds, window_seconds) in [
        (
            operator_binding_contract::PrepareActivationRequestOperation::CreateRole,
            "create_role",
            2,
            30,
        ),
        (
            operator_binding_contract::PrepareActivationRequestOperation::SetRolePermissions,
            "set_role_permissions",
            30,
            2,
        ),
        (
            operator_binding_contract::PrepareActivationRequestOperation::AssignRole,
            "assign_role",
            30,
            30,
        ),
    ] {
        let now = OffsetDateTime::now_utc();
        let source_end = now + Duration::seconds(source_seconds);
        let window_end = now + Duration::seconds(window_seconds);
        let response = operator_binding::activation_response(
            &issuer,
            record("pending"),
            vec!["fixture.read".into()],
            source_end,
            window_end,
            &operation,
        )
        .unwrap()
        .unwrap();
        let wire: auth::AuthActorAssertion =
            serde_json::from_str(&response.control_assertion).unwrap();
        assert_eq!(wire.issuer, "fixture.operators");
        assert_eq!(wire.subject, "usr_operator");
        assert_eq!(
            wire.audience,
            vec![lenso_auth_sdk::audience(
                "lenso.access-control-admin@1",
                expected
            )]
        );
        let validity_start = OffsetDateTime::parse(&wire.issued_at, &Rfc3339).unwrap();
        let expires = OffsetDateTime::parse(&wire.expires_at, &Rfc3339).unwrap();
        assert!(expires - validity_start <= Duration::seconds(5));
        assert!(expires <= source_end && expires <= window_end);
    }
}

#[test]
fn durable_receipt_survives_refresh_and_completed_binding_mints_no_control() {
    let issuer = ActorAssertionIssuer::new("fixture.operators", b"public-activation-fixture");
    let end = OffsetDateTime::now_utc() + Duration::seconds(30);
    let a = operator_binding::activation_response(
        &issuer,
        record("pending"),
        vec!["fixture.read".into()],
        end,
        end,
        &operator_binding_contract::PrepareActivationRequestOperation::CreateRole,
    )
    .unwrap()
    .unwrap();
    let b = operator_binding::activation_response(
        &issuer,
        record("pending"),
        vec!["fixture.read".into()],
        end,
        end,
        &operator_binding_contract::PrepareActivationRequestOperation::AssignRole,
    )
    .unwrap()
    .unwrap();
    assert_eq!(a.audit_idempotency_key, b.audit_idempotency_key);
    assert_eq!(a.audit_occurred_at, b.audit_occurred_at);
    assert_eq!(a.permissions, b.permissions);
    let complete = operator_binding::activation_response(
        &issuer,
        record("active"),
        vec!["fixture.read".into()],
        end,
        end,
        &operator_binding_contract::PrepareActivationRequestOperation::AssignRole,
    )
    .unwrap()
    .unwrap();
    assert!(complete.control_assertion.is_empty());
    assert_eq!(complete.audit_idempotency_key, a.audit_idempotency_key);
    assert!(matches!(
        operator_binding::activation_response(
            &issuer,
            record("pending"),
            vec!["fixture.read".into()],
            OffsetDateTime::now_utc() - Duration::seconds(1),
            end,
            &operator_binding_contract::PrepareActivationRequestOperation::CreateRole
        )
        .unwrap(),
        Err(operator_binding_contract::PrepareActivationError::Unauthenticated)
    ));
}

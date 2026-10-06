use super::*;

#[tokio::test]
#[ignore = "requires isolated LENSO_POSTGRES_TEST_URL"]
async fn activation_intent_survives_response_loss_and_rejects_revision_scope_and_plan_changes() {
    let (store, url, schema) = tests::fixture().await;
    let cfg = tests::config();
    let pending = prepare(&store, &cfg, "usr_source", "opb_intent", "usr_operator")
        .await
        .unwrap();
    let first = prepare_activation_intent(
        &store,
        &cfg,
        &pending.binding_id,
        1,
        "2026-10-06T10:00:00.000000000Z",
        "[\"example.read\"]",
    )
    .await
    .unwrap()
    .unwrap();
    let retry = prepare_activation_intent(
        &store,
        &cfg,
        &pending.binding_id,
        1,
        "2026-10-06T10:01:00.000000000Z",
        "[\"example.write\"]",
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(first.activation_started_at, retry.activation_started_at);
    assert_eq!(first.activation_permissions, retry.activation_permissions);
    let wrong_revision = prepare_activation_intent(
        &store,
        &cfg,
        &pending.binding_id,
        2,
        "2026-10-06T10:02:00.000000000Z",
        "[]",
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(wrong_revision.revision, 1);
    assert_eq!(
        wrong_revision.activation_permissions,
        first.activation_permissions
    );
    let mut other = cfg.clone();
    other.scope_id = "another".into();
    assert!(
        prepare_activation_intent(
            &store,
            &other,
            &pending.binding_id,
            1,
            "2026-10-06T10:02:00.000000000Z",
            "[]"
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_completion_and_revocation_preserve_intent(&store, &cfg, &pending.binding_id, &first)
        .await;
    tests::cleanup(store, url, schema).await;
}

async fn assert_completion_and_revocation_preserve_intent(
    store: &AccountStore,
    cfg: &OperatorBindingConfig,
    binding_id: &str,
    first: &Record,
) {
    let activated = activate(store, cfg, binding_id, 1, "audit_fixed", "policy_1")
        .await
        .unwrap()
        .unwrap();
    let replay = activate(store, cfg, binding_id, 1, "audit_other", "policy_2")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replay.audit_event_id, activated.audit_event_id);
    assert_eq!(replay.policy_revision, activated.policy_revision);
    assert_eq!(replay.activation_started_at, first.activation_started_at);
    revoke(store, cfg, binding_id, "usr_source", "2026-10-06T10:03:00Z")
        .await
        .unwrap();
    let revoked = prepare_activation_intent(
        store,
        cfg,
        binding_id,
        1,
        "2026-10-06T10:04:00.000000000Z",
        "[]",
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(revoked.status, "revoked");
    assert_eq!(revoked.revision, 2);
    assert_eq!(revoked.activation_permissions, first.activation_permissions);
}

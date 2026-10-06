use super::*;
use crate::operator_binding::{OperatorBindingConfig, session_admitted};
use std::sync::atomic::{AtomicU64, Ordering};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
static SCHEMA_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn fixture_url() -> String {
    let url = std::env::var("LENSO_POSTGRES_TEST_URL").expect("isolated synthetic PG required");
    let local_fixture = url.starts_with("postgres://renewal_fixture@127.0.0.1:55494/")
        || url.starts_with("postgres://renewal_fixture@127.0.0.1:55504/");
    let ci_fixture = std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
        && url == "postgres://postgres@localhost:5432/postgres";
    assert!(local_fixture || ci_fixture, "refuse non-fixture database");
    url
}

pub(super) fn config() -> OperatorBindingConfig {
    let now = OffsetDateTime::now_utc();
    OperatorBindingConfig {
        source_issuer: "test.accounts".into(),
        source_account_instance: "lenso.auth.account/accounts".into(),
        deployment: "synthetic".into(),
        scope_kind: "deployment".into(),
        scope_id: "synthetic".into(),
        bootstrap_subject: "usr_source".into(),
        bootstrap_not_before: (now - Duration::seconds(1)).format(&Rfc3339).unwrap(),
        bootstrap_expires_at: (now + Duration::minutes(10)).format(&Rfc3339).unwrap(),
        workflow_callers: vec!["lenso.auth.operator-session/default".into()],
    }
}
pub(super) async fn fixture() -> (AccountStore, String, String) {
    let url = fixture_url();
    let schema = format!(
        "operator_binding_{}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        SCHEMA_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    crate::AccountAuthOperator::setup_operator_bound(&url, &schema)
        .await
        .unwrap();
    let pg = crate::schema::prepare_features(&url, &schema, true, true)
        .await
        .unwrap();
    let store = AccountStore::Postgres(pg);
    super::super::ensure_identity(&store, "fixture", "operator", "usr_operator")
        .await
        .unwrap();
    (store, url, schema)
}
pub(super) async fn cleanup(store: AccountStore, url: String, schema: String) {
    use sqlx::Executor;
    store.close().await;
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    pool.execute(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .await
    .unwrap();
    pool.close().await;
}
#[tokio::test]
#[ignore = "requires isolated LENSO_POSTGRES_TEST_URL"]
async fn binding_pending_activation_revocation_receipt_and_scope_are_monotonic() {
    let (store, url, schema) = fixture().await;
    let cfg = config();
    let (a, b) = tokio::join!(
        prepare(&store, &cfg, "usr_source", "opb_a", "usr_operator"),
        prepare(&store, &cfg, "usr_source", "opb_b", "usr_operator")
    );
    let initial = a.unwrap();
    let raced = b.unwrap();
    assert_eq!(initial.binding_id, raced.binding_id);
    assert_eq!(initial.status, "pending");
    let active = activate(
        &store,
        &cfg,
        &initial.binding_id,
        1,
        "audit_applied",
        "revision_1",
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(active.status, "active");
    let mut other_scope = cfg.clone();
    other_scope.scope_id = "other-deployment".into();
    assert!(
        read(&store, &other_scope, "operator_subject", "usr_operator")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        revoke(
            &store,
            &other_scope,
            &initial.binding_id,
            "usr_intruder",
            "2026-10-05T00:00:00Z"
        )
        .await
        .unwrap()
        .is_none()
    );
    let still_active = read(&store, &cfg, "binding_id", &initial.binding_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still_active.revision, 1);
    assert_eq!(still_active.status, "active");
    let revoked = revoke(
        &store,
        &cfg,
        &initial.binding_id,
        "usr_admin",
        "2026-10-05T00:00:00Z",
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(revoked.status, "revoked");
    assert_eq!(revoked.revision, 2);
    assert_eq!(revoked.revocation_state, "pending");
    assert_eq!(revoked.revoked_by, "usr_admin");
    let replay = activate(
        &store,
        &cfg,
        &initial.binding_id,
        1,
        "audit_old",
        "revision_old",
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(replay.status, "revoked");
    assert_eq!(replay.revision, 2);
    let repeated = revoke(
        &store,
        &cfg,
        &initial.binding_id,
        "usr_other",
        "2026-10-06T00:00:00Z",
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(repeated.revision, 2);
    assert_eq!(repeated.revoked_by, "usr_admin");
    let wrong = complete_revocation(&store, &cfg, &initial.binding_id, 1, "audit_wrong")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(wrong.revocation_state, "pending");
    let complete = complete_revocation(&store, &cfg, &initial.binding_id, 2, "audit_revoke")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(complete.status, "revoked");
    assert_eq!(complete.revocation_state, "complete");
    assert_eq!(complete.revocation_audit_event_id, "audit_revoke");
    cleanup(store, url, schema).await;
}
#[tokio::test]
#[ignore = "requires isolated LENSO_POSTGRES_TEST_URL"]
async fn binding_history_cannot_revive_when_configuration_is_removed() {
    let (store, url, schema) = fixture().await;
    let context =
        lenso_kernel::InvocationContext::new(1, None, lenso_kernel::CancellationToken::new());
    let ordinary = std::collections::BTreeMap::new();
    assert!(
        session_admitted(&store, None, "usr_operator", &ordinary, None, &context)
            .await
            .unwrap()
    );
    let historical = std::collections::BTreeMap::from([(
        crate::operator_binding::CLAIM.into(),
        serde_json::json!({"binding_id":"opb_old","revision":"1"}),
    )]);
    assert!(
        !session_admitted(&store, None, "usr_operator", &historical, None, &context)
            .await
            .unwrap()
    );
    assert!(
        !session_admitted(
            &store,
            Some(&config()),
            "usr_operator",
            &historical,
            None,
            &context
        )
        .await
        .unwrap()
    );
    cleanup(store, url, schema).await;
}

#[tokio::test]
#[ignore = "requires isolated LENSO_POSTGRES_TEST_URL"]
async fn operator_history_is_explicit_and_legacy_readiness_remains_compatible() {
    let url = fixture_url();
    for managed in [false, true] {
        let schema = format!(
            "operator_history_{}_{}",
            std::process::id(),
            SCHEMA_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        if managed {
            crate::AccountAuthOperator::setup_managed(&url, &schema)
                .await
                .unwrap();
        } else {
            crate::AccountAuthOperator::setup(&url, &schema)
                .await
                .unwrap();
        }
        let pg = crate::schema::prepare_features(&url, &schema, managed, false)
            .await
            .unwrap();
        let exists: bool =
            sqlx::query_scalar("SELECT to_regclass('auth_operator_bindings') IS NOT NULL")
                .fetch_one(pg.pool())
                .await
                .unwrap();
        assert!(!exists);
        pg.pool().close().await;
        assert!(matches!(
            crate::schema::prepare_features(&url, &schema, managed, true).await,
            Err(lenso_postgres_kit::PostgresKitError::UpgradeRequired { expected: 8, .. })
        ));
        let pg = crate::schema::prepare_features(&url, &schema, managed, false)
            .await
            .unwrap();
        let exists: bool =
            sqlx::query_scalar("SELECT to_regclass('auth_operator_bindings') IS NOT NULL")
                .fetch_one(pg.pool())
                .await
                .unwrap();
        assert!(!exists, "Ready must never apply operator migration");
        pg.pool().close().await;
        crate::AccountAuthOperator::upgrade_operator_bound(&url, &schema)
            .await
            .unwrap();
        for (required_managed, required_operator) in [(false, false), (true, false), (true, true)] {
            crate::schema::prepare_features(&url, &schema, required_managed, required_operator)
                .await
                .unwrap()
                .pool()
                .close()
                .await;
        }
        let pg = crate::schema::prepare_features(&url, &schema, true, true)
            .await
            .unwrap();
        cleanup(AccountStore::Postgres(pg), url.clone(), schema).await;
    }
}

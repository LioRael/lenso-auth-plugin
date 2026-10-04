use super::*;
use crate::{AccountAuthOperator, schema::schema_plan};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT_SCHEMA: AtomicU64 = AtomicU64::new(0);

async fn fixture() -> (OwnedPostgres, String, String) {
    let url = std::env::var("LENSO_POSTGRES_TEST_URL").expect("isolated test database required");
    let schema = format!(
        "managed_test_{}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed)
    );
    eprintln!("isolated fixture schema: {schema}");
    AccountAuthOperator::setup(&url, &schema).await.unwrap();
    let pg = OwnedPostgres::prepare(&url, schema_plan(schema.clone()).unwrap())
        .await
        .unwrap();
    super::super::ensure_identity(&pg, "fixture", "synthetic", "usr_fixture")
        .await
        .unwrap();
    (pg, url, schema)
}
async fn clean(pg: OwnedPostgres, url: String, schema: String) {
    use sqlx::{AssertSqlSafe, Executor};
    pg.pool().close().await;
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    pool.execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
        .await
        .unwrap();
    pool.close().await;
}
fn policy() -> ManagedSessionPolicy {
    ManagedSessionPolicy {
        idle_timeout_seconds: 60,
        absolute_timeout_seconds: 3600,
        renew_interval_seconds: 1,
    }
}
async fn seed(pg: &OwnedPostgres, id: &str, digest: &[u8]) {
    let now = OffsetDateTime::now_utc() - Duration::seconds(2);
    let session = NewSession {
        session_id: id.into(),
        digest: digest.into(),
        subject: "usr_fixture".into(),
        actor_kind: "user".into(),
        assurance: "password".into(),
        audience: vec!["test.operation".into()],
        claims: BTreeMap::new(),
        expires_at: now + Duration::seconds(60),
    };
    let metadata = NewManagedSession {
        issued_at: now,
        absolute_expires_at: now + Duration::seconds(3600),
        idle_timeout_seconds: 60,
        renew_interval_seconds: 1,
        last_renew_at: now,
    };
    assert_eq!(
        issue_managed_session(pg, &session, &metadata)
            .await
            .unwrap(),
        IssueSessionOutcome::Inserted
    );
}
async fn count(pg: &OwnedPostgres, id: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM auth_session_rotations WHERE session_id=$1")
        .bind(id)
        .fetch_one(pg.pool())
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires isolated LENSO_POSTGRES_TEST_URL"]
async fn managed_rotation_concurrency_replay_logout_and_restart() {
    let (pg, url, schema) = fixture().await;
    seed(&pg, "ses_concurrent", b"original").await;
    let p = policy();
    let initial = session_metadata(&pg, b"original", &p)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(initial.session_id, "ses_concurrent");
    assert_eq!(count(&pg, "ses_concurrent").await, 0);
    let (a, b) = tokio::join!(
        renew_session(&pg, b"original", b"new-a", &p),
        renew_session(&pg, b"original", b"new-b", &p)
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert!(matches!(
        (&a, &b),
        (
            RenewSessionOutcome::Rotated { .. },
            RenewSessionOutcome::StaleCredential
        ) | (
            RenewSessionOutcome::StaleCredential,
            RenewSessionOutcome::Rotated { .. }
        )
    ));
    let winner = if matches!(a, RenewSessionOutcome::Rotated { .. }) {
        b"new-a".as_slice()
    } else {
        b"new-b".as_slice()
    };
    assert_eq!(count(&pg, "ses_concurrent").await, 1);
    assert!(matches!(
        session_metadata(&pg, b"original", &p).await.unwrap(),
        Err(RenewSessionOutcome::StaleCredential)
    ));
    assert!(
        super::super::load_session(&pg, b"original")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        super::super::load_session(&pg, winner)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        renew_session(&pg, b"original", b"replay", &p)
            .await
            .unwrap(),
        RenewSessionOutcome::StaleCredential
    );
    assert_eq!(
        renew_session(&pg, winner, b"too-early", &p).await.unwrap(),
        RenewSessionOutcome::TooEarly
    );
    assert_eq!(count(&pg, "ses_concurrent").await, 1);
    // A lost successful response cannot recover a token from the digest ledger.
    assert_eq!(
        renew_session(&pg, b"original", b"lost-retry", &p)
            .await
            .unwrap(),
        RenewSessionOutcome::StaleCredential
    );
    let reopened = OwnedPostgres::prepare(&url, schema_plan(schema.clone()).unwrap())
        .await
        .unwrap();
    assert!(
        super::super::load_session(&reopened, winner)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        super::super::revoke_credential(&reopened, b"original")
            .await
            .unwrap(),
        Some(true)
    );
    assert!(
        super::super::load_session(&reopened, winner)
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    assert_eq!(
        renew_session(&reopened, winner, b"after-logout", &p)
            .await
            .unwrap(),
        RenewSessionOutcome::Revoked
    );
    reopened.pool().close().await;
    clean(pg, url, schema).await;
}

#[tokio::test]
#[ignore = "requires isolated LENSO_POSTGRES_TEST_URL"]
async fn managed_expiry_policy_and_legacy_are_fail_closed() {
    let (pg, url, schema) = fixture().await;
    let p = policy();
    for (id, digest, sql) in [
        (
            "ses_idle",
            b"idle".as_slice(),
            "UPDATE auth_sessions SET expires_at=clock_timestamp() WHERE session_id=$1",
        ),
        (
            "ses_absolute",
            b"absolute".as_slice(),
            "UPDATE auth_managed_sessions SET absolute_expires_at=clock_timestamp() WHERE session_id=$1",
        ),
    ] {
        seed(&pg, id, digest).await;
        sqlx::query(sql).bind(id).execute(pg.pool()).await.unwrap();
        assert_eq!(
            renew_session(&pg, digest, b"rejected", &p).await.unwrap(),
            RenewSessionOutcome::Expired
        );
        assert_eq!(count(&pg, id).await, 0);
    }
    seed(&pg, "ses_narrow", b"narrow").await;
    let narrowed = ManagedSessionPolicy {
        absolute_timeout_seconds: 2,
        idle_timeout_seconds: 2,
        ..p.clone()
    };
    assert_eq!(
        renew_session(&pg, b"narrow", b"no-widen", &narrowed)
            .await
            .unwrap(),
        RenewSessionOutcome::Expired
    );
    seed(&pg, "ses_narrow_idle", b"narrow-idle").await;
    let narrowed_idle = ManagedSessionPolicy {
        idle_timeout_seconds: 2,
        ..p.clone()
    };
    assert!(matches!(
        session_metadata(&pg, b"narrow-idle", &narrowed_idle)
            .await
            .unwrap(),
        Err(RenewSessionOutcome::Expired)
    ));
    assert_eq!(
        renew_session(&pg, b"narrow-idle", b"no-idle-revival", &narrowed_idle)
            .await
            .unwrap(),
        RenewSessionOutcome::Expired
    );
    assert_eq!(count(&pg, "ses_narrow_idle").await, 0);
    let legacy = NewSession {
        session_id: "ses_legacy".into(),
        digest: b"legacy".into(),
        subject: "usr_fixture".into(),
        actor_kind: "user".into(),
        assurance: "password".into(),
        audience: vec!["test.operation".into()],
        claims: BTreeMap::new(),
        expires_at: OffsetDateTime::now_utc() + Duration::seconds(60),
    };
    assert_eq!(
        super::super::issue_session(&pg, &legacy).await.unwrap(),
        IssueSessionOutcome::Inserted
    );
    assert_eq!(
        renew_session(&pg, b"legacy", b"new-legacy", &p)
            .await
            .unwrap(),
        RenewSessionOutcome::Unsupported
    );
    assert_eq!(
        super::super::revoke_credential(&pg, b"legacy")
            .await
            .unwrap(),
        Some(true)
    );
    clean(pg, url, schema).await;
}

#[tokio::test]
#[ignore = "requires isolated LENSO_POSTGRES_TEST_URL"]
async fn managed_frozen_policy_and_parent_limits_are_preserved() {
    let (pg, url, schema) = fixture().await;
    let p = policy();
    seed(&pg, "ses_parent", b"parent").await;
    assert!(
        super::super::create_grant(
            &pg,
            b"parent",
            "ses_child",
            b"child",
            &["test.operation".into()],
            OffsetDateTime::now_utc() + Duration::seconds(30)
        )
        .await
        .unwrap()
        .is_ok()
    );
    assert_eq!(
        renew_session(&pg, b"child", b"child-new", &p)
            .await
            .unwrap(),
        RenewSessionOutcome::Unsupported
    );
    let narrowed_parent = ManagedSessionPolicy {
        idle_timeout_seconds: 2,
        ..p.clone()
    };
    assert!(
        policy_expiry(&pg, "ses_child", &narrowed_parent)
            .await
            .unwrap()
            .unwrap()
            < OffsetDateTime::now_utc()
    );
    // Increasing current configuration cannot expand the issued policy envelope.
    seed(&pg, "ses_frozen", b"frozen").await;
    let broader = ManagedSessionPolicy {
        idle_timeout_seconds: 600,
        absolute_timeout_seconds: 7200,
        renew_interval_seconds: 1,
    };
    let renewal = renew_session(&pg, b"frozen", b"frozen-new", &broader)
        .await
        .unwrap();
    if let RenewSessionOutcome::Rotated {
        expires_at,
        absolute_expires_at,
        ..
    } = renewal
    {
        assert!(expires_at <= OffsetDateTime::now_utc() + Duration::seconds(60));
        assert!(absolute_expires_at < OffsetDateTime::now_utc() + Duration::seconds(3600));
    } else {
        panic!("valid frozen policy should rotate");
    }
    clean(pg, url, schema).await;
}

#[tokio::test]
#[ignore = "requires isolated LENSO_POSTGRES_TEST_URL"]
async fn managed_migration_upgrade_is_explicit_and_preserves_legacy_sessions() {
    use lenso_postgres_kit::{Migration, SchemaOperator, SchemaPlan, sql_migrations};
    const OLD: &[Migration] = sql_migrations![
        (
            1,
            "create-identities-and-sessions",
            "migrations/postgres/001_create_identities_and_sessions.sql"
        ),
        (
            2,
            "add-subject-disable-details",
            "migrations/postgres/002_add_subject_disable_details.sql"
        ),
        (
            3,
            "add-session-delegations",
            "migrations/postgres/003_add_session_delegations.sql"
        ),
        (
            4,
            "add-scoped-delegation-receipts",
            "migrations/postgres/004_add_scoped_delegation_receipts.sql"
        ),
        (
            5,
            "add-display-profile",
            "migrations/postgres/005_add_display_profile.sql"
        )
    ];
    let url = std::env::var("LENSO_POSTGRES_TEST_URL").unwrap();
    let schema = format!(
        "managed_upgrade_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let oldplan = SchemaPlan::new(schema.clone(), OLD).unwrap();
    SchemaOperator::connect(&url, oldplan.clone())
        .await
        .unwrap()
        .setup()
        .await
        .unwrap();
    let pg = OwnedPostgres::prepare(&url, oldplan).await.unwrap();
    super::super::ensure_identity(&pg, "fixture", "synthetic", "usr_fixture")
        .await
        .unwrap();
    let legacy = NewSession {
        session_id: "ses_before_upgrade".into(),
        digest: b"before-upgrade".into(),
        subject: "usr_fixture".into(),
        actor_kind: "user".into(),
        assurance: "password".into(),
        audience: vec!["test.operation".into()],
        claims: BTreeMap::new(),
        expires_at: OffsetDateTime::now_utc() + Duration::seconds(60),
    };
    super::super::issue_session(&pg, &legacy).await.unwrap();
    assert!(
        OwnedPostgres::prepare(&url, schema_plan(schema.clone()).unwrap())
            .await
            .is_err()
    );
    let exists: bool =
        sqlx::query_scalar("SELECT to_regclass('auth_managed_sessions') IS NOT NULL")
            .fetch_one(pg.pool())
            .await
            .unwrap();
    assert!(!exists, "readiness must not auto-migrate");
    AccountAuthOperator::upgrade(&url, &schema).await.unwrap();
    let upgraded = OwnedPostgres::prepare(&url, schema_plan(schema.clone()).unwrap())
        .await
        .unwrap();
    assert!(
        super::super::load_session(&upgraded, b"before-upgrade")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        renew_session(
            &upgraded,
            b"before-upgrade",
            b"no-implicit-managed",
            &policy()
        )
        .await
        .unwrap(),
        RenewSessionOutcome::Unsupported
    );
    upgraded.pool().close().await;
    clean(pg, url, schema).await;
}

#[tokio::test]
#[ignore = "requires isolated LENSO_POSTGRES_TEST_URL"]
async fn managed_revoke_disable_races_never_revive_and_clock_follows_lock() {
    let (pg, url, schema) = fixture().await;
    let p = policy();
    seed(&pg, "ses_revoke", b"revoking").await;
    let (renew, revoked) = tokio::join!(
        renew_session(&pg, b"revoking", b"revoked-new", &p),
        super::super::revoke_credential(&pg, b"revoking")
    );
    assert!(matches!(
        renew.unwrap(),
        RenewSessionOutcome::Rotated { .. } | RenewSessionOutcome::Revoked
    ));
    assert_eq!(revoked.unwrap(), Some(true));
    assert!(
        super::super::inspect_session(&pg, "ses_revoke")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    seed(&pg, "ses_disable", b"disabling").await;
    let (renew, disabled) = tokio::join!(
        renew_session(&pg, b"disabling", b"disabled-new", &p),
        super::super::set_subject_status(&pg, "usr_fixture", "disabled", None, None)
    );
    assert!(matches!(
        renew.unwrap(),
        RenewSessionOutcome::Rotated { .. } | RenewSessionOutcome::Revoked
    ));
    assert_eq!(disabled.unwrap(), Some(true));
    assert!(
        super::super::inspect_session(&pg, "ses_disable")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    super::super::set_subject_status(&pg, "usr_fixture", "active", None, None)
        .await
        .unwrap();
    seed(&pg, "ses_queued", b"queued").await;
    sqlx::query("UPDATE auth_sessions SET expires_at=clock_timestamp()+interval '100 milliseconds' WHERE session_id='ses_queued'").execute(pg.pool()).await.unwrap();
    let mut lock = pg.pool().begin().await.unwrap();
    sqlx::query(
        "SELECT subject_id FROM identity_subjects WHERE subject_id='usr_fixture' FOR UPDATE",
    )
    .execute(&mut *lock)
    .await
    .unwrap();
    let (result, ()) = tokio::join!(renew_session(&pg, b"queued", b"queued-new", &p), async {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        lock.commit().await.unwrap();
    });
    assert_eq!(result.unwrap(), RenewSessionOutcome::Expired);
    assert_eq!(count(&pg, "ses_queued").await, 0);
    clean(pg, url, schema).await;
}

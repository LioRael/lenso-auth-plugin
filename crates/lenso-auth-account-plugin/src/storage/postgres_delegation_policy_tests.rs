use super::*;
use crate::{
    AccountAuthOperator,
    schema::{managed_schema_plan, schema_plan},
    storage::NewManagedSession,
};
use std::sync::atomic::{AtomicU64, Ordering};
use time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(0);

async fn fixture(managed: bool) -> (OwnedPostgres, String, String) {
    let url = std::env::var("LENSO_POSTGRES_TEST_URL").expect("isolated PG required");
    let schema = format!(
        "delegation_policy_{}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let plan = if managed {
        AccountAuthOperator::setup_managed(&url, &schema)
            .await
            .unwrap();
        managed_schema_plan(schema.clone()).unwrap()
    } else {
        AccountAuthOperator::setup(&url, &schema).await.unwrap();
        schema_plan(schema.clone()).unwrap()
    };
    let pg = OwnedPostgres::prepare(&url, plan).await.unwrap();
    ensure_identity(&pg, "synthetic", "grant", "usr_policy")
        .await
        .unwrap();
    (pg, url, schema)
}
async fn clean(pg: OwnedPostgres, url: String, schema: String) {
    crate::tests::cleanup_test_postgres(&url, &schema, pg).await;
}
fn policy(idle: u64) -> ManagedSessionPolicy {
    ManagedSessionPolicy {
        idle_timeout_seconds: idle,
        absolute_timeout_seconds: 3600,
        renew_interval_seconds: 1,
    }
}
fn session(id: &str, digest: &[u8]) -> NewSession {
    NewSession {
        session_id: id.into(),
        digest: digest.into(),
        subject: "usr_policy".into(),
        actor_kind: "user".into(),
        assurance: "synthetic".into(),
        audience: vec!["test.operation@1:read".into()],
        claims: BTreeMap::new(),
        expires_at: OffsetDateTime::now_utc() + Duration::minutes(10),
    }
}
async fn seed_managed(pg: &OwnedPostgres) {
    let issued = OffsetDateTime::now_utc() - Duration::seconds(20);
    let meta = NewManagedSession {
        issued_at: issued,
        absolute_expires_at: issued + Duration::hours(1),
        idle_timeout_seconds: 600,
        renew_interval_seconds: 1,
        last_renew_at: issued,
    };
    assert_eq!(
        issue_managed_session(pg, &session("ses_parent", b"parent"), &meta)
            .await
            .unwrap(),
        IssueSessionOutcome::Inserted
    );
}
async fn count(pg: &OwnedPostgres) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM auth_sessions")
        .fetch_one(pg.pool())
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires isolated LENSO_POSTGRES_TEST_URL"]
async fn managed_parent_current_policy_expiry_denies_grant_without_writes() {
    let (pg, url, schema) = fixture(true).await;
    seed_managed(&pg).await;
    let result = create_grant(
        &pg,
        b"parent",
        "ses_denied",
        b"denied",
        &["test.operation@1:read".into()],
        OffsetDateTime::now_utc() + Duration::seconds(30),
        Some(&policy(5)),
    )
    .await
    .unwrap();
    assert!(matches!(result, Err(GrantError::Expired)));
    assert_eq!(count(&pg).await, 1);
    let links: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_session_delegations")
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert_eq!(links, 0);
    clean(pg, url, schema).await;
}

#[tokio::test]
#[ignore = "requires isolated LENSO_POSTGRES_TEST_URL"]
async fn grant_clips_expiry_to_current_parent_without_widening_original_scope() {
    let (pg, url, schema) = fixture(true).await;
    seed_managed(&pg).await;
    let current = policy(60);
    let clipped = create_grant(
        &pg,
        b"parent",
        "ses_clipped",
        b"clipped",
        &["test.operation@1:read".into()],
        OffsetDateTime::now_utc() + Duration::seconds(90),
        Some(&current),
    )
    .await
    .unwrap();
    assert!(clipped.is_ok());
    let expiry: OffsetDateTime =
        sqlx::query_scalar("SELECT expires_at FROM auth_sessions WHERE session_id='ses_clipped'")
            .fetch_one(pg.pool())
            .await
            .unwrap();
    let ceiling: OffsetDateTime = sqlx::query_scalar("SELECT last_renew_at+(60*interval '1 second') FROM auth_managed_sessions WHERE session_id='ses_parent'")
        .fetch_one(pg.pool()).await.unwrap();
    assert_eq!(expiry, ceiling);
    let expired_request = create_grant(
        &pg,
        b"parent",
        "ses_expired_request",
        b"expired-request",
        &["test.operation@1:read".into()],
        OffsetDateTime::now_utc() - Duration::seconds(1),
        Some(&current),
    )
    .await
    .unwrap();
    assert!(matches!(expired_request, Err(GrantError::Expired)));
    let widened = create_grant(
        &pg,
        b"parent",
        "ses_widened",
        b"widened",
        &["test.operation@1:read".into()],
        OffsetDateTime::now_utc() + Duration::minutes(20),
        Some(&current),
    )
    .await
    .unwrap();
    assert!(matches!(widened, Err(GrantError::InvalidScope)));
    assert_eq!(count(&pg).await, 2);
    assert!(
        create_grant(
            &pg,
            b"parent",
            "ses_short",
            b"short",
            &["test.operation@1:read".into()],
            OffsetDateTime::now_utc() + Duration::seconds(10),
            Some(&current)
        )
        .await
        .unwrap()
        .is_ok()
    );
    assert_eq!(count(&pg).await, 3);
    clean(pg, url, schema).await;
}

#[tokio::test]
#[ignore = "requires isolated LENSO_POSTGRES_TEST_URL"]
async fn policy_expiry_follows_parent_chain_in_admitting_transaction() {
    let (pg, url, schema) = fixture(true).await;
    seed_managed(&pg).await;
    assert!(
        create_grant(
            &pg,
            b"parent",
            "ses_child",
            b"child",
            &["test.operation@1:read".into()],
            OffsetDateTime::now_utc() + Duration::seconds(90),
            None
        )
        .await
        .unwrap()
        .is_ok()
    );
    issue_session(&pg, &session("ses_grandchild", b"grandchild"))
        .await
        .unwrap();
    sqlx::query("INSERT INTO auth_session_delegations(session_id,parent_session_id) VALUES('ses_grandchild','ses_child')")
        .execute(pg.pool()).await.unwrap();
    let mut tx = pg.pool().begin().await.unwrap();
    let effective = effective_delegation_expiry(
        &mut tx,
        "ses_grandchild",
        OffsetDateTime::now_utc() + Duration::minutes(10),
        Some(&policy(5)),
    )
    .await
    .unwrap();
    assert!(effective < OffsetDateTime::now_utc());
    tx.rollback().await.unwrap();
    clean(pg, url, schema).await;
}

#[tokio::test]
#[ignore = "requires isolated LENSO_POSTGRES_TEST_URL"]
async fn legacy_pg5_grant_and_digest_revoke_do_not_require_managed_tables() {
    let (pg, url, schema) = fixture(false).await;
    let managed_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('auth_managed_sessions') IS NOT NULL")
            .fetch_one(pg.pool())
            .await
            .unwrap();
    assert!(!managed_exists);
    issue_session(&pg, &session("ses_parent", b"parent"))
        .await
        .unwrap();
    assert!(
        create_grant(
            &pg,
            b"parent",
            "ses_legacy_child",
            b"child",
            &["test.operation@1:read".into()],
            OffsetDateTime::now_utc() + Duration::seconds(10),
            None
        )
        .await
        .unwrap()
        .is_ok()
    );
    assert_eq!(
        revoke_legacy_credential(&pg, b"parent").await.unwrap(),
        Some(true)
    );
    assert_eq!(
        revoke_legacy_credential(&pg, b"parent").await.unwrap(),
        Some(false)
    );
    assert_eq!(
        revoke_legacy_credential(&pg, b"unknown").await.unwrap(),
        None
    );
    assert!(load_session(&pg, b"child").await.unwrap().unwrap().revoked);
    sqlx::query("UPDATE auth_sessions SET expires_at=created_at+interval '1 microsecond' WHERE session_id='ses_parent'")
        .execute(pg.pool()).await.unwrap();
    let revoked_expired = create_grant(
        &pg,
        b"parent",
        "ses_denied_legacy",
        b"denied-legacy",
        &["test.operation@1:read".into()],
        OffsetDateTime::now_utc() + Duration::seconds(10),
        None,
    )
    .await
    .unwrap();
    assert!(matches!(revoked_expired, Err(GrantError::Revoked)));
    sqlx::query("UPDATE auth_sessions SET actor_kind='machine',revoked_at=NULL WHERE session_id='ses_parent'")
        .execute(pg.pool()).await.unwrap();
    let invalid_actor_expired = create_grant(
        &pg,
        b"parent",
        "ses_denied_actor",
        b"denied-actor",
        &["test.operation@1:read".into()],
        OffsetDateTime::now_utc() + Duration::seconds(10),
        None,
    )
    .await
    .unwrap();
    assert!(matches!(
        invalid_actor_expired,
        Err(GrantError::InvalidCredential)
    ));
    assert_eq!(count(&pg).await, 2);
    clean(pg, url, schema).await;
}

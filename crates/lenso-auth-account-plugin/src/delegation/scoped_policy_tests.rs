use super::*;
use crate::{
    AccountAuthOperator,
    schema::{managed_schema_plan, schema_plan},
    storage::{IssueSessionOutcome, NewManagedSession, NewSession},
};
use lenso_kernel::CancellationToken;
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
const CALLER: &str = "test.synthetic/browser";

fn ceiling() -> ManagementCredentialCeiling {
    ManagementCredentialCeiling {
        deployment: "fixture".into(),
        permissions: vec!["read".into()],
        resource_scopes: vec![lenso_auth_sdk::credential::ManagementResourceScope {
            kind: "fixture".into(),
            id: "fixture".into(),
        }],
    }
}
fn policy(idle: u64) -> ManagedSessionPolicy {
    ManagedSessionPolicy {
        idle_timeout_seconds: idle,
        absolute_timeout_seconds: 3600,
        renew_interval_seconds: 1,
    }
}
fn parent() -> ScopedParent {
    ScopedParent {
        subject: "usr_scoped_policy".into(),
        session_id: "ses_scoped_parent".into(),
        ceiling: ceiling(),
        audience: audience(),
    }
}
fn audience() -> Vec<String> {
    vec![
        lenso_auth_sdk::audience(scoped::CAPABILITY_ID, scoped::GRANT_SCOPED_OPERATION),
        "test.operation@1:read".into(),
    ]
}
fn request(key: &str, expiry: OffsetDateTime) -> scoped::GrantScopedRequest {
    scoped::GrantScopedRequest {
        agent_session_id: "agent_session".into(),
        audience: vec!["test.operation@1:read".into()],
        delegate_caller: "test.agent/default".into(),
        deployment: "fixture".into(),
        expires_at: crate::format_time(expiry).unwrap(),
        idempotency_key: key.into(),
        permissions: vec!["read".into()],
        resource_scopes: vec![scoped::ResourceScope {
            kind: "fixture".into(),
            id: "fixture".into(),
        }],
        task_id: "task_fixture".into(),
    }
}
fn context() -> InvocationContext {
    InvocationContext::new(1, None, CancellationToken::new()).with_caller_instance(CALLER)
}
async fn fixture(managed: bool) -> (OwnedPostgres, String, String) {
    let url = std::env::var("LENSO_POSTGRES_TEST_URL").expect("isolated PG required");
    let schema = format!(
        "scoped_policy_{}_{}_{}",
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
    storage::postgres::ensure_identity(&pg, "synthetic", "scope", "usr_scoped_policy")
        .await
        .unwrap();
    let mut claims = BTreeMap::new();
    claims.insert(
        MANAGEMENT_CEILING_CLAIM.into(),
        serde_json::json!(ceiling()),
    );
    let session = NewSession {
        session_id: "ses_scoped_parent".into(),
        digest: b"scoped-parent".into(),
        subject: "usr_scoped_policy".into(),
        actor_kind: "user".into(),
        assurance: "synthetic".into(),
        audience: audience(),
        claims,
        expires_at: OffsetDateTime::now_utc() + Duration::minutes(10),
    };
    if managed {
        let issued = OffsetDateTime::now_utc() - Duration::seconds(20);
        let metadata = NewManagedSession {
            issued_at: issued,
            absolute_expires_at: issued + Duration::hours(1),
            idle_timeout_seconds: 600,
            renew_interval_seconds: 1,
            last_renew_at: issued,
        };
        assert_eq!(
            storage::postgres::issue_managed_session(&pg, &session, &metadata)
                .await
                .unwrap(),
            IssueSessionOutcome::Inserted
        );
    } else {
        storage::postgres::issue_session(&pg, &session)
            .await
            .unwrap();
    }
    (pg, url, schema)
}
async fn clean(pg: OwnedPostgres, url: String, schema: String) {
    crate::tests::cleanup_test_postgres(&url, &schema, pg).await;
}
async fn counts(pg: &OwnedPostgres) -> (i64, i64) {
    (
        sqlx::query_scalar("SELECT count(*) FROM auth_sessions")
            .fetch_one(pg.pool())
            .await
            .unwrap(),
        sqlx::query_scalar("SELECT count(*) FROM scoped_delegation_receipts")
            .fetch_one(pg.pool())
            .await
            .unwrap(),
    )
}

#[tokio::test]
#[ignore = "requires isolated LENSO_POSTGRES_TEST_URL"]
async fn scoped_managed_policy_expiry_denies_child_and_receipt_writes() {
    let (pg, url, schema) = fixture(true).await;
    let expiry = OffsetDateTime::now_utc() + Duration::seconds(30);
    let result = grant(
        &pg,
        b"synthetic-pepper",
        &context(),
        &parent(),
        &request("expired", expiry),
        Some(&ceiling()),
        expiry,
        Some(&policy(5)),
    )
    .await
    .unwrap();
    assert!(matches!(
        result,
        Err(scoped::GrantScopedError::PermissionDenied)
    ));
    assert_eq!(counts(&pg).await, (1, 0));
    clean(pg, url, schema).await;
}

#[tokio::test]
#[ignore = "requires isolated LENSO_POSTGRES_TEST_URL"]
#[allow(clippy::too_many_lines)] // One sequential receipt expiry and idempotency lifecycle.
async fn scoped_receipt_activity_and_expiry_observe_current_parent_policy() {
    let (pg, url, schema) = fixture(true).await;
    let expiry = OffsetDateTime::now_utc() + Duration::seconds(90);
    let req = request("receipt", expiry);
    let original = grant(
        &pg,
        b"synthetic-pepper",
        &context(),
        &parent(),
        &req,
        Some(&ceiling()),
        expiry,
        Some(&policy(60)),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(original.delegation.active);
    assert!(
        OffsetDateTime::parse(
            &original.delegation.expires_at,
            &time::format_description::well_known::Rfc3339
        )
        .unwrap()
            < expiry
    );
    let query = scoped::ScopedReceiptRequest {
        agent_session_id: req.agent_session_id.clone(),
        idempotency_key: req.idempotency_key.clone(),
        task_id: req.task_id.clone(),
    };
    let healthy = receipt(&pg, CALLER, &parent(), &query, Some(&policy(600)))
        .await
        .unwrap()
        .unwrap()
        .delegation
        .unwrap()
        .unwrap();
    assert!(healthy.active);
    let stored_expiry: String = sqlx::query_scalar("SELECT metadata->>'expires_at' FROM scoped_delegation_receipts WHERE idempotency_key='receipt'")
        .fetch_one(pg.pool()).await.unwrap();
    assert_eq!(stored_expiry, original.delegation.expires_at);
    let same = grant(
        &pg,
        b"synthetic-pepper",
        &context(),
        &parent(),
        &req,
        Some(&ceiling()),
        expiry,
        Some(&policy(60)),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(same.replayed);
    assert!(same.credential.is_none());
    let changed_expiry = expiry + Duration::seconds(1);
    let changed = request("receipt", changed_expiry);
    let conflict = grant(
        &pg,
        b"synthetic-pepper",
        &context(),
        &parent(),
        &changed,
        Some(&ceiling()),
        changed_expiry,
        Some(&policy(60)),
    )
    .await
    .unwrap();
    assert!(matches!(conflict, Err(scoped::GrantScopedError::Conflict)));
    let expired = receipt(&pg, CALLER, &parent(), &query, Some(&policy(5)))
        .await
        .unwrap()
        .unwrap()
        .delegation
        .unwrap()
        .unwrap();
    assert!(!expired.active);
    assert!(
        OffsetDateTime::parse(
            &expired.expires_at,
            &time::format_description::well_known::Rfc3339
        )
        .unwrap()
            < OffsetDateTime::now_utc()
    );
    let replay = grant(
        &pg,
        b"synthetic-pepper",
        &context(),
        &parent(),
        &req,
        Some(&ceiling()),
        expiry,
        Some(&policy(5)),
    )
    .await
    .unwrap();
    assert!(matches!(
        replay,
        Err(scoped::GrantScopedError::PermissionDenied)
    ));
    assert_eq!(counts(&pg).await, (2, 1));
    clean(pg, url, schema).await;
}

#[tokio::test]
#[ignore = "requires isolated LENSO_POSTGRES_TEST_URL"]
async fn scoped_legacy_pg5_grant_and_receipt_do_not_access_managed_tables() {
    let (pg, url, schema) = fixture(false).await;
    let expiry = OffsetDateTime::now_utc() + Duration::seconds(30);
    let req = request("legacy", expiry);
    assert!(
        grant(
            &pg,
            b"synthetic-pepper",
            &context(),
            &parent(),
            &req,
            Some(&ceiling()),
            expiry,
            None
        )
        .await
        .unwrap()
        .is_ok()
    );
    let query = scoped::ScopedReceiptRequest {
        agent_session_id: req.agent_session_id,
        idempotency_key: req.idempotency_key,
        task_id: req.task_id,
    };
    assert!(
        receipt(&pg, CALLER, &parent(), &query, None)
            .await
            .unwrap()
            .unwrap()
            .delegation
            .unwrap()
            .unwrap()
            .active
    );
    assert_eq!(counts(&pg).await, (2, 1));
    clean(pg, url, schema).await;
}

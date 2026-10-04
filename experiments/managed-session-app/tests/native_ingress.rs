use lenso_auth_account_plugin::{AccountAuthOperator, ManagedSessionPolicy};
use lenso_auth_password_plugin::PasswordAuthOperator;
use lenso_capability_auth as auth;
use lenso_capability_credential_state as state;
use lenso_capability_managed_session as managed;
use lenso_capability_password_auth as password;
use lenso_kernel::{CancellationToken, Kernel, ShutdownOutcome};
use lenso_managed_session_app_proof::*;
use lenso_native_adapter::NativePluginRegistry;
use lenso_runner::TokioDriver;
use lenso_web_ingress_plugin::WebIngressEventFactory;
use sqlx::{AssertSqlSafe, Executor, PgPool};
use std::{collections::BTreeMap, time::Duration};
async fn request(
    ingress: &WebIngressEventFactory,
    method: &str,
    path: &str,
    token: &str,
    csrf_cookie: Option<&str>,
    csrf_header: Option<&str>,
    origin: &str,
) -> http::Response<bytes::Bytes> {
    let mut cookie = format!("{COOKIE}={token}");
    if let Some(csrf) = csrf_cookie {
        cookie.push_str(&format!("; {CSRF}={csrf}"));
    }
    let mut builder = http::Request::builder()
        .method(method)
        .uri(path)
        .header("cookie", cookie)
        .header("origin", origin);
    if let Some(csrf) = csrf_header {
        builder = builder.header("x-csrf-token", csrf);
    }
    ingress
        .handle(
            builder.body(bytes::Bytes::new()).unwrap(),
            CancellationToken::new(),
        )
        .await
        .unwrap()
}
fn no_cookie(response: &http::Response<bytes::Bytes>, status: u16) {
    assert_eq!(
        response.status().as_u16(),
        status,
        "unexpected status (credential material omitted)"
    );
    assert_eq!(response.headers().get_all("set-cookie").iter().count(), 0);
}
async fn rotations(pool: &PgPool, schema: &str) -> i64 {
    sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT count(*) FROM \"{schema}\".auth_session_rotations"
    )))
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires isolated synthetic PG at localhost:55494; see README"]
async fn actual_plugins_real_ingress_csrf_and_rotation() {
    tokio::task::LocalSet::new().run_until(Box::pin(async {
        let url = std::env::var("LENSO_POSTGRES_TEST_URL").expect("synthetic fixture URL required");
        let local_fixture = url.starts_with("postgres://renewal_fixture@127.0.0.1:55494/");
        let ci_fixture = std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
            && url == "postgres://postgres@localhost:5432/postgres";
        assert!(local_fixture || ci_fixture, "refuse non-fixture database");
        let account_schema = format!("renewal_app_account_{}", std::process::id());
        let password_schema = format!("renewal_app_password_{}", std::process::id());
        let pool = PgPool::connect(&url).await.unwrap();
        AccountAuthOperator::setup_managed(&url, &account_schema).await.unwrap();
        PasswordAuthOperator::setup(&url, &password_schema).await.unwrap();
        let ingress = WebIngressEventFactory::new();
        let _ = (lenso_auth_account_plugin::PLUGIN_DESCRIPTOR_JSON, lenso_auth_password_plugin::PLUGIN_DESCRIPTOR_JSON, lenso_auth_session_renewal_plugin::PLUGIN_DESCRIPTOR_JSON);
        let app = Kernel::start_native(plan(&account_schema, &password_schema), TokioDriver::new(), NativePluginRegistry::new().with_linked_factories().with_factory(ingress.clone()).with_factory(EmptyFactory).with_factory(FixtureSecrets(BTreeMap::from([("database".into(), url.clone()), ("key".into(), KEY.into()), ("pepper".into(), PEPPER.into())])))).await.unwrap();
        let session = app.invoke::<password::PasswordRegister>(CALLER, password::REGISTER_OPERATION, password::RegisterRequest { identifier: "synthetic@example.test".into(), password: "Synthetic-password-for-proof-only-123!".into() }).await.unwrap().unwrap();
        assert_eq!(rotations(&pool, &account_schema).await, 0);
        // These failures occur in real Ingress before Endpoint/Account writes.
        for (cookie, header) in [(None, None), (Some("csrf-public"), None), (None, Some("csrf-public")), (Some("csrf-public"), Some("wrong"))] {
            no_cookie(&request(&ingress, "POST", "/auth/session/renew", &session.credential, cookie, header, ORIGIN).await, 403);
            assert_eq!(rotations(&pool, &account_schema).await, 0);
        }
        no_cookie(&request(&ingress, "POST", "/auth/session/renew", &session.credential, Some("csrf-public"), Some("csrf-public"), "https://attacker.example").await, 403);
        assert_eq!(rotations(&pool, &account_schema).await, 0);
        let issue_denied=app.invoke::<managed::ManagedSessionIssueManaged>(ROGUE,managed::ISSUE_MANAGED_OPERATION,managed::IssueManagedRequest {subject:session.subject.clone(),actor_kind:"user".into(),assurance:"password".into(),audience:vec!["synthetic.app".into()],claims:BTreeMap::new()}).await.unwrap();
        assert!(matches!(issue_denied,Err(managed::IssueManagedError::PermissionDenied)));
        let denied = app.invoke::<managed::ManagedSessionRenew>(ROGUE, managed::RENEW_OPERATION, managed::RenewRequest { credential: session.credential.clone() }).await.unwrap();
        assert!(matches!(denied, Err(managed::RenewError::PermissionDenied)));
        assert_eq!(rotations(&pool, &account_schema).await, 0);
        no_cookie(&request(&ingress, "POST", "/auth/session/renew", &session.credential, Some("csrf-public"), Some("csrf-public"), ORIGIN).await, 429);
        pool.execute(AssertSqlSafe(format!("UPDATE \"{account_schema}\".auth_managed_sessions SET last_renew_at=clock_timestamp()-interval '10 seconds'"))).await.unwrap();
        let (first, second) = futures::join!(request(&ingress, "POST", "/auth/session/renew", &session.credential, Some("csrf-public"), Some("csrf-public"), ORIGIN), request(&ingress, "POST", "/auth/session/renew", &session.credential, Some("csrf-public"), Some("csrf-public"), ORIGIN));
        let (winner, loser) = if first.status() == 200 { (first, second) } else { (second, first) };
        assert_eq!(winner.status(), 200);
        no_cookie(&loser, 409);
        assert_eq!(serde_json::from_slice::<serde_json::Value>(loser.body()).unwrap()["code"], "stale_credential");
        assert_eq!(rotations(&pool, &account_schema).await, 1);
        assert_eq!(winner.headers()["cache-control"], "no-store");
        let cookies: Vec<&str> = winner.headers().get_all("set-cookie").iter().map(|h| h.to_str().unwrap()).collect();
        assert_eq!(cookies.len(), 2);
        let selected = cookies.iter().find(|c| c.starts_with(&format!("{COOKIE}="))).unwrap();
        assert!(selected.contains("; Secure; HttpOnly; SameSite=Lax"));
        let token = selected.split(';').next().unwrap().split_once('=').unwrap().1;
        assert_ne!(token, session.credential);
        assert!(!String::from_utf8_lossy(winner.body()).contains(token));
        let old = app.invoke::<auth::Auth>(CALLER, auth::AUTHENTICATE_OPERATION, auth::AuthRequest { credential: Some(auth::AuthenticateRequestCredential { scheme: "session".into(), value: session.credential.clone() }) }).await.unwrap();
        assert!(old.is_err(), "rotated old credential cannot authenticate");
        let current = app.invoke::<auth::Auth>(CALLER, auth::AUTHENTICATE_OPERATION, auth::AuthRequest { credential: Some(auth::AuthenticateRequestCredential { scheme: "session".into(), value: token.into() }) }).await.unwrap();
        assert!(current.unwrap().assertion.is_some());
        let read = request(&ingress, "GET", "/auth/session/state", token, None, None, ORIGIN).await;
        no_cookie(&read, 200);
        assert_eq!(serde_json::from_slice::<serde_json::Value>(read.body()).unwrap()["authenticated"], true);
        no_cookie(&request(&ingress, "GET", "/auth/session/state", &session.credential, None, None, ORIGIN).await, 409);
        // Controlled synthetic deadline boundary: cannot extend expired absolute maximum.
        pool.execute(AssertSqlSafe(format!("UPDATE \"{account_schema}\".auth_managed_sessions SET issued_at=clock_timestamp()-interval '1 hour', absolute_expires_at=clock_timestamp()-interval '1 second'"))).await.unwrap();
        no_cookie(&request(&ingress, "POST", "/auth/session/renew", token, Some("csrf-public"), Some("csrf-public"), ORIGIN).await, 401);
        no_cookie(&request(&ingress, "GET", "/auth/session/state", token, None, None, ORIGIN).await, 401);
        assert_eq!(rotations(&pool, &account_schema).await, 1);
        let inspected=app.invoke::<state::CredentialState>(CALLER,state::INSPECT_OPERATION,state::InspectRequest {credential_id:session.session_id.clone(),session_id:session.session_id.clone()}).await.unwrap().unwrap();
        assert!(!inspected.active);
        assert!(inspected.expires_at < session.expires_at);
        let expired_auth=app.invoke::<auth::Auth>(CALLER,auth::AUTHENTICATE_OPERATION,auth::AuthRequest {credential:Some(auth::AuthenticateRequestCredential {scheme:"session".into(),value:token.into()})}).await.unwrap();
        assert!(matches!(expired_auth,Err(auth::AuthenticateError::Expired)));
        let policy_session=app.invoke::<password::PasswordRegister>(CALLER,password::REGISTER_OPERATION,password::RegisterRequest {identifier:"policy@example.test".into(),password:"Synthetic-password-for-proof-only-123!".into()}).await.unwrap().unwrap();
        pool.execute(AssertSqlSafe(format!("UPDATE \"{account_schema}\".auth_managed_sessions SET issued_at=clock_timestamp()-interval '20 seconds',last_renew_at=clock_timestamp()-interval '20 seconds' WHERE session_id='{}'",policy_session.session_id))).await.unwrap();
        let active=app.invoke::<state::CredentialState>(CALLER,state::INSPECT_OPERATION,state::InspectRequest {credential_id:policy_session.session_id.clone(),session_id:policy_session.session_id.clone()}).await.unwrap().unwrap();assert!(active.active);
        assert_eq!(app.shutdown(Duration::from_secs(2)).await, ShutdownOutcome::Clean);
        let narrowed_ingress=WebIngressEventFactory::new();
        let narrowed_app=Kernel::start_native(plan_with_policy(&account_schema,&password_schema,ManagedSessionPolicy {idle_timeout_seconds:10,absolute_timeout_seconds:15,renew_interval_seconds:1}),TokioDriver::new(),NativePluginRegistry::new().with_linked_factories().with_factory(narrowed_ingress.clone()).with_factory(EmptyFactory).with_factory(FixtureSecrets(BTreeMap::from([("database".into(),url.clone()),("key".into(),KEY.into()),("pepper".into(),PEPPER.into())])))).await.unwrap();
        let narrowed=narrowed_app.invoke::<state::CredentialState>(CALLER,state::INSPECT_OPERATION,state::InspectRequest {credential_id:policy_session.session_id.clone(),session_id:policy_session.session_id.clone()}).await.unwrap().unwrap();assert!(!narrowed.active);assert!(narrowed.expires_at<active.expires_at);
        let auth_after=narrowed_app.invoke::<auth::Auth>(CALLER,auth::AUTHENTICATE_OPERATION,auth::AuthRequest {credential:Some(auth::AuthenticateRequestCredential {scheme:"session".into(),value:policy_session.credential.clone()})}).await.unwrap();assert!(matches!(auth_after,Err(auth::AuthenticateError::Expired)));
        no_cookie(&request(&narrowed_ingress,"POST","/auth/session/renew",&policy_session.credential,Some("csrf-public"),Some("csrf-public"),ORIGIN).await,401);
        no_cookie(&request(&narrowed_ingress,"GET","/auth/session/state",&policy_session.credential,None,None,ORIGIN).await,401);
        assert_eq!(narrowed_app.shutdown(Duration::from_secs(2)).await,ShutdownOutcome::Clean);
        for schema in [&account_schema, &password_schema] { pool.execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE"))).await.unwrap(); }
        pool.close().await;
    })).await;
}

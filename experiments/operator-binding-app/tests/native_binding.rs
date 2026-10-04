use lenso_access_control_postgres_plugin::AccessControlOperator;
use lenso_audit_log_postgres_plugin::AuditLogOperator;
use lenso_auth_account_plugin::AccountAuthOperator;
use lenso_auth_sdk::{ActorAssertion, AuthOutcome, decode_auth_response};
use lenso_capability_access_control as access;
use lenso_capability_access_control_directory as access_directory;
use lenso_capability_account_admin as account_admin;
use lenso_capability_auth as auth;
use lenso_capability_credential_issuer as issuer;
use lenso_capability_credential_state as state;
use lenso_capability_identity_directory as directory;
use lenso_capability_operator_session as workflow;
use lenso_kernel::{CancellationToken, InvocationContext, Kernel, NativeApp, ShutdownOutcome};
use lenso_native_adapter::NativePluginRegistry;
use lenso_operator_binding_app_proof::*;
use lenso_runner::TokioDriver;
use sqlx::{AssertSqlSafe, Executor, PgPool};
use std::{collections::BTreeMap, time::Duration};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

struct Database {
    name: String,
    url: String,
    admin: PgPool,
    pool: PgPool,
}
impl Database {
    async fn new(label: &str) -> Self {
        let base = std::env::var("LENSO_POSTGRES_TEST_URL").expect("synthetic PG URL required");
        assert!(
            base == "postgres://renewal_fixture@127.0.0.1:55494/postgres"
                || (std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
                    && base == "postgres://postgres@localhost:5432/postgres"),
            "refuse non-fixture PG"
        );
        let name = format!("operator_app_{}_{}", std::process::id(), label);
        let admin = PgPool::connect(&base).await.unwrap();
        admin
            .execute(AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .await
            .unwrap();
        let url = format!("{}/{}", base.rsplit_once('/').unwrap().0, name);
        let pool = PgPool::connect(&url).await.unwrap();
        AccountAuthOperator::setup(&url, "accounts").await.unwrap();
        AccountAuthOperator::setup_operator_bound(&url, "operators")
            .await
            .unwrap();
        AccessControlOperator::setup(&url, "access").await.unwrap();
        AuditLogOperator::setup(&url).await.unwrap();
        Self {
            name,
            url,
            admin,
            pool,
        }
    }
    async fn close(self) {
        self.pool.close().await;
        self.admin
            .execute(AssertSqlSafe(format!(
                "DROP DATABASE {} WITH (FORCE)",
                self.name
            )))
            .await
            .unwrap();
        self.admin.close().await;
    }
    async fn binding_status(&self) -> String {
        sqlx::query_scalar(AssertSqlSafe(
            "SELECT status FROM operators.auth_operator_bindings",
        ))
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }
    async fn bindings(&self) -> i64 {
        sqlx::query_scalar(AssertSqlSafe(
            "SELECT count(*) FROM operators.auth_operator_bindings",
        ))
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }
    async fn sessions(&self) -> i64 {
        sqlx::query_scalar(AssertSqlSafe(
            "SELECT count(*) FROM operators.auth_sessions",
        ))
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }
}
async fn start(db: &Database, subject: &str, enabled: bool) -> NativeApp {
    let _ = (
        lenso_auth_account_plugin::PLUGIN_DESCRIPTOR_JSON,
        lenso_auth_operator_session_plugin::PLUGIN_DESCRIPTOR_JSON,
        lenso_access_control_postgres_plugin::PLUGIN_DESCRIPTOR_JSON,
        lenso_audit_log_postgres_plugin::PLUGIN_DESCRIPTOR_JSON,
    );
    start_mode(db, subject, enabled, true).await
}
async fn start_mode(db: &Database, subject: &str, enabled: bool, manage: bool) -> NativeApp {
    Kernel::start_native(
        plan_with_management(subject, enabled, manage),
        TokioDriver::new(),
        NativePluginRegistry::new()
            .with_linked_factories()
            .with_factory(EmptyFactory)
            .with_factory(FixtureSecrets(BTreeMap::from([
                ("database".into(), db.url.clone()),
                ("source-key".into(), SOURCE_KEY.into()),
                ("operators-key".into(), OPERATORS_KEY.into()),
                ("pepper".into(), PEPPER.into()),
            ]))),
    )
    .await
    .unwrap()
}
async fn stop(app: NativeApp) {
    assert!(matches!(
        app.shutdown(Duration::from_secs(1)).await,
        ShutdownOutcome::Clean
    ));
}
async fn stop_failed(app: NativeApp) {
    assert!(matches!(
        app.shutdown(Duration::from_secs(1)).await,
        ShutdownOutcome::Clean | ShutdownOutcome::RuntimeFailure { .. }
    ));
}
async fn identity(app: &NativeApp, label: &str) -> String {
    app.invoke::<directory::DirectoryEnsureIdentity>(
        OWNER,
        directory::ENSURE_IDENTITY_OPERATION,
        directory::EnsureIdentityRequest {
            provider: "synthetic".into(),
            external_subject: label.into(),
        },
    )
    .await
    .unwrap()
    .unwrap()
    .subject
}
async fn issue(app: &NativeApp, subject: &str) -> issuer::IssueResponse {
    app.invoke::<issuer::CredentialIssuerIssue>(
        OWNER,
        issuer::ISSUE_OPERATION,
        issuer::IssueRequest {
            subject: subject.into(),
            actor_kind: "user".into(),
            assurance: "password".into(),
            audience: [
                "bootstrap_binding",
                "read_binding",
                "exchange_session",
                "recover_revocation",
                "revoke_binding",
            ]
            .into_iter()
            .map(|op| lenso_auth_sdk::audience(workflow::CAPABILITY_ID, op))
            .collect(),
            claims: BTreeMap::new(),
            expires_at: (OffsetDateTime::now_utc() + time::Duration::minutes(10))
                .format(&Rfc3339)
                .unwrap(),
        },
    )
    .await
    .unwrap()
    .unwrap()
}
async fn authenticate(
    app: &NativeApp,
    caller: &str,
    token: &str,
) -> Result<auth::AuthResponse, auth::AuthError> {
    app.invoke::<auth::Auth>(
        caller,
        auth::AUTHENTICATE_OPERATION,
        auth::AuthRequest {
            credential: Some(auth::AuthenticateRequestCredential {
                scheme: "session".into(),
                value: token.into(),
            }),
        },
    )
    .await
    .unwrap()
}
async fn actor(app: &NativeApp, caller: &str, token: &str) -> ActorAssertion {
    let AuthOutcome::Authenticated(actor) =
        decode_auth_response(authenticate(app, caller, token).await.unwrap()).unwrap()
    else {
        panic!("expected authenticated synthetic account")
    };
    actor
}
fn context(app: &NativeApp, actor: &ActorAssertion) -> InvocationContext {
    actor
        .attach(app.invocation_context(None, CancellationToken::new()))
        .unwrap()
}
async fn exchange(
    app: &NativeApp,
    caller: &str,
    actor: &ActorAssertion,
) -> Result<workflow::SessionResponse, workflow::ExchangeSessionError> {
    app.invoke_with_context::<workflow::OperatorSessionExchangeSession>(
        caller,
        workflow::EXCHANGE_SESSION_OPERATION,
        context(app, actor),
        workflow::EmptyRequest {},
    )
    .await
    .unwrap()
}
async fn inspect(app: &NativeApp, session: &workflow::SessionResponse) -> state::InspectResponse {
    app.invoke::<state::CredentialState>(
        OPERATOR_BROWSER,
        state::INSPECT_OPERATION,
        state::InspectRequest {
            credential_id: session.session_id.clone(),
            session_id: session.session_id.clone(),
        },
    )
    .await
    .unwrap()
    .unwrap()
}
async fn source_status(
    app: &NativeApp,
    subject: &str,
    status: account_admin::SetSubjectStatusRequestStatus,
) {
    app.invoke::<account_admin::AccountAdminSetSubjectStatus>(
        OWNER,
        account_admin::SET_SUBJECT_STATUS_OPERATION,
        account_admin::SetSubjectStatusRequest {
            subject: subject.into(),
            status,
            reason: None,
            disabled_until: None,
        },
    )
    .await
    .unwrap()
    .unwrap();
}
async fn prepared(db: &Database) -> (NativeApp, String, String, ActorAssertion, ActorAssertion) {
    let app = start(db, "public-placeholder", true).await;
    let owner = identity(&app, "confirmed-owner").await;
    let ordinary = identity(&app, "ordinary-user").await;
    stop(app).await;
    let app = start(db, &owner, true).await;
    let session = issue(&app, &owner).await;
    let ordinary_session = issue(&app, &ordinary).await;
    let owner_actor = actor(&app, OWNER, &session.credential).await;
    let ordinary_actor = actor(&app, ORDINARY, &ordinary_session.credential).await;
    (app, owner, ordinary, owner_actor, ordinary_actor)
}
async fn bootstrap(
    app: &NativeApp,
    caller: &str,
    actor: &ActorAssertion,
) -> Result<workflow::Binding, workflow::BootstrapBindingError> {
    app.invoke_with_context::<workflow::OperatorSessionBootstrapBinding>(
        caller,
        workflow::BOOTSTRAP_BINDING_OPERATION,
        context(app, actor),
        workflow::EmptyRequest {},
    )
    .await
    .unwrap()
}
fn gate(gates: &mut Vec<&'static str>, name: &'static str) {
    println!("passed: {name}");
    gates.push(name);
}
async fn append_failure(db: &Database, action: &str) {
    assert!(matches!(action, "applied" | "revoked"));
    db.pool.execute(AssertSqlSafe(format!("CREATE FUNCTION audit_log.fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action = '{action}' THEN RAISE EXCEPTION 'synthetic audit unavailable'; END IF; RETURN NEW; END $$"))).await.unwrap();
    db.pool.execute(AssertSqlSafe("CREATE TRIGGER fixture_fail BEFORE INSERT ON audit_log.events FOR EACH ROW EXECUTE FUNCTION audit_log.fixture_fail()")).await.unwrap();
}

async fn qualify() {
    let mut gates = vec![];
    let db = Database::new("success").await;
    let (mut app, owner, ordinary, owner_actor, ordinary_actor) = prepared(&db).await;
    assert!(matches!(
        exchange(&app, ORDINARY, &ordinary_actor).await,
        Err(workflow::ExchangeSessionError::NotActive)
    ));
    assert!(matches!(
        bootstrap(&app, ORDINARY, &owner_actor).await,
        Err(workflow::BootstrapBindingError::PermissionDenied)
    ));
    assert!(matches!(
        bootstrap(&app, OWNER, &ordinary_actor).await,
        Err(workflow::BootstrapBindingError::PermissionDenied)
    ));
    assert_eq!(db.bindings().await, 0);
    assert_eq!(db.sessions().await, 0);
    gate(
        &mut gates,
        "Unbound ordinary login, non-owner caller and wrong confirmed subject cannot bootstrap/exchange or write operators state",
    );
    let binding = bootstrap(&app, OWNER, &owner_actor).await.unwrap();
    assert!(binding.active);
    assert_eq!(binding.source_subject, owner);
    assert_ne!(binding.operator_subject, owner);
    assert_eq!(binding.source_issuer, SOURCE_ISSUER);
    assert_eq!(binding.scope_id, "synthetic");
    assert_eq!(db.binding_status().await, "active");
    let audits: i64 = sqlx::query_scalar(AssertSqlSafe(
        "SELECT count(*) FROM audit_log.events WHERE action IN ('requested','applied')",
    ))
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(audits, 2);
    let explicit = app
        .invoke::<access_directory::AccessControlDirectoryGetRole>(
            OWNER,
            access_directory::GET_ROLE_OPERATION,
            access_directory::GetRoleRequest {
                role_id: format!("operator-binding.{}", binding.binding_id),
                scope: access_directory::Scope {
                    kind: "deployment".into(),
                    id: "synthetic".into(),
                },
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert!(!explicit.protected);
    let mut perms = explicit.permissions;
    perms.sort();
    let mut expected = vec![
        PERMISSION.to_string(),
        BINDING_MANAGE.to_string(),
        lenso_auth_operator_session_plugin::LOGIN_PERMISSION.to_string(),
    ];
    expected.sort();
    assert_eq!(perms, expected);
    for (permission, allowed) in [(PERMISSION, true), ("synthetic.billing.delete", false)] {
        let p = app
            .invoke::<access::AccessControl>(
                OWNER,
                access::CHECK_PERMISSION_OPERATION,
                access::CheckPermissionRequest {
                    subject: binding.operator_subject.clone(),
                    permission: permission.into(),
                    scope: access::CheckPermissionRequestScope {
                        kind: "deployment".into(),
                        id: "synthetic".into(),
                    },
                },
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(p.allowed, allowed);
    }
    let wildcard = app
        .invoke::<access::AccessControl>(
            OWNER,
            access::CHECK_PERMISSION_OPERATION,
            access::CheckPermissionRequest {
                subject: binding.operator_subject.clone(),
                permission: "*".into(),
                scope: access::CheckPermissionRequestScope {
                    kind: "deployment".into(),
                    id: "synthetic".into(),
                },
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        wildcard,
        Err(access::CheckPermissionError::InvalidRequest)
    ));
    assert!(matches!(
        bootstrap(&app, OWNER, &owner_actor).await,
        Err(workflow::BootstrapBindingError::BootstrapConsumed)
    ));
    gate(
        &mut gates,
        "Confirmed owner boots actual protected Access scope plus exactly finite business/login role; durable requested/applied Audit precedes activation",
    );
    let session = exchange(&app, OWNER, &owner_actor).await.unwrap();
    let operators_actor = actor(&app, OPERATOR_BROWSER, &session.credential).await;
    assert_eq!(operators_actor.issuer(), OPERATORS_ISSUER);
    assert_eq!(operators_actor.subject(), binding.operator_subject);
    assert!(inspect(&app, &session).await.active);
    assert!(
        authenticate(&app, OWNER, &session.credential)
            .await
            .is_err()
    );
    let source_session = issue(&app, &ordinary).await;
    assert!(
        authenticate(&app, OPERATOR_BROWSER, &source_session.credential)
            .await
            .is_err()
    );
    assert!(matches!(
        app.invoke_with_context::<workflow::OperatorSessionRevokeBinding>(
            OWNER,
            workflow::REVOKE_BINDING_OPERATION,
            context(&app, &ordinary_actor),
            workflow::RevokeBindingRequest {
                binding_id: binding.binding_id.clone()
            }
        )
        .await
        .unwrap(),
        Err(workflow::RevokeBindingError::Unauthenticated)
    ));
    gate(
        &mut gates,
        "Issued operators credential is a distinct realm; accounts credential and ordinary accounts assertion cannot revoke",
    );
    let n = db.sessions().await;
    db.pool.execute(AssertSqlSafe("DELETE FROM access.access_control_role_permissions WHERE permission='lenso.auth.operator-login'")).await.unwrap();
    assert!(matches!(
        exchange(&app, OWNER, &owner_actor).await,
        Err(workflow::ExchangeSessionError::NotActive)
    ));
    assert_eq!(db.sessions().await, n);
    db.pool.execute(AssertSqlSafe("INSERT INTO access.access_control_role_permissions(scope_kind,scope_id,role_id,permission) SELECT scope_kind,scope_id,role_id,'lenso.auth.operator-login' FROM access.access_control_roles WHERE role_id LIKE 'operator-binding.%'")).await.unwrap();
    gate(
        &mut gates,
        "Exchange checks live Access login permission; removed login permission cannot create another credential",
    );
    stop(app).await;
    app = start(&db, &owner, false).await;
    assert!(
        authenticate(&app, OPERATOR_BROWSER, &session.credential)
            .await
            .is_err()
    );
    assert!(!inspect(&app, &session).await.active);
    stop(app).await;
    app = start(&db, &owner, true).await;
    gate(
        &mut gates,
        "Disabling binding feature rejects historic binding claims in real Auth and CredentialState",
    );
    source_status(
        &app,
        &owner,
        account_admin::SetSubjectStatusRequestStatus::Disabled,
    )
    .await;
    assert!(
        authenticate(&app, OPERATOR_BROWSER, &session.credential)
            .await
            .is_err()
    );
    assert!(!inspect(&app, &session).await.active);
    source_status(
        &app,
        &owner,
        account_admin::SetSubjectStatusRequestStatus::Active,
    )
    .await;
    gate(
        &mut gates,
        "Live source Account disable blocks previously issued operators Auth and Inspect",
    );
    stop(app).await;
    app = start_mode(&db, &owner, true, false).await;
    let scoped_actor = actor(&app, OPERATOR_BROWSER, &session.credential).await;
    let scoped_denied = app
        .invoke_with_context::<workflow::OperatorSessionRevokeBinding>(
            OPERATOR_BROWSER,
            workflow::REVOKE_BINDING_OPERATION,
            context(&app, &scoped_actor),
            workflow::RevokeBindingRequest {
                binding_id: binding.binding_id.clone(),
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        scoped_denied,
        Err(workflow::RevokeBindingError::PermissionDenied)
    ));
    assert_eq!(db.binding_status().await, "active");
    gate(
        &mut gates,
        "Business-only narrowed operators credential cannot revoke despite live protected Access grants",
    );
    stop(app).await;
    app = start(&db, &owner, true).await;
    let operators_actor = actor(&app, OPERATOR_BROWSER, &session.credential).await;
    db.pool.execute(AssertSqlSafe("DELETE FROM access.access_control_role_permissions WHERE permission='access-control.bindings.manage'")).await.unwrap();
    let denied = app
        .invoke_with_context::<workflow::OperatorSessionRevokeBinding>(
            OPERATOR_BROWSER,
            workflow::REVOKE_BINDING_OPERATION,
            context(&app, &operators_actor),
            workflow::RevokeBindingRequest {
                binding_id: binding.binding_id.clone(),
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        denied,
        Err(workflow::RevokeBindingError::PermissionDenied)
    ));
    assert_eq!(db.binding_status().await, "active");
    db.pool.execute(AssertSqlSafe("INSERT INTO access.access_control_role_permissions(scope_kind,scope_id,role_id,permission) SELECT scope_kind,scope_id,role_id,'access-control.bindings.manage' FROM access.access_control_roles WHERE protected=true")).await.unwrap();
    gate(
        &mut gates,
        "Even live operators assertion cannot revoke without scoped Access binding-management permission",
    );
    append_failure(&db, "revoked").await;
    let result = app
        .invoke_with_context::<workflow::OperatorSessionRevokeBinding>(
            OPERATOR_BROWSER,
            workflow::REVOKE_BINDING_OPERATION,
            context(&app, &operators_actor),
            workflow::RevokeBindingRequest {
                binding_id: binding.binding_id.clone(),
            },
        )
        .await
        .unwrap();
    assert!(
        matches!(result, Err(workflow::RevokeBindingError::AuditUnavailable)),
        "revocation result: {:?}",
        result.map(|_| ())
    );
    assert_eq!(db.binding_status().await, "revoked");
    stop_failed(app).await;
    app = start(&db, &owner, true).await;
    assert!(
        authenticate(&app, OPERATOR_BROWSER, &session.credential)
            .await
            .is_err()
    );
    assert!(!inspect(&app, &session).await.active);
    gate(
        &mut gates,
        "Revocation durable denial survives real Audit failure; old operators credentials remain rejected",
    );
    let pending: String = sqlx::query_scalar(AssertSqlSafe(
        "SELECT revocation_state FROM operators.auth_operator_bindings",
    ))
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(pending, "pending");
    db.pool
        .execute(AssertSqlSafe(
            "DROP TRIGGER fixture_fail ON audit_log.events",
        ))
        .await
        .unwrap();
    let recovery_session = issue(&app, &owner).await;
    let recovery_actor = actor(&app, OWNER, &recovery_session.credential).await;
    let wrong_recovery = app
        .invoke_with_context::<workflow::OperatorSessionRecoverRevocation>(
            ORDINARY,
            workflow::RECOVER_REVOCATION_OPERATION,
            context(&app, &recovery_actor),
            workflow::RevokeBindingRequest {
                binding_id: binding.binding_id.clone(),
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        wrong_recovery,
        Err(workflow::RecoverRevocationError::PermissionDenied)
    ));
    let recovered = app
        .invoke_with_context::<workflow::OperatorSessionRecoverRevocation>(
            OWNER,
            workflow::RECOVER_REVOCATION_OPERATION,
            context(&app, &recovery_actor),
            workflow::RevokeBindingRequest {
                binding_id: binding.binding_id.clone(),
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert!(recovered.revoked);
    assert!(!recovered.active);
    assert!(!recovered.revocation_pending);
    assert!(!recovered.revocation_audit_event_id.is_empty());
    assert_eq!(recovered.revoked_by, binding.operator_subject);
    assert!(
        authenticate(&app, OPERATOR_BROWSER, &session.credential)
            .await
            .is_err()
    );
    gate(
        &mut gates,
        "Durable revocation outbox recovers only under confirmed source owner and exact local caller; audit preserves original revoker and recovery never grants login",
    );
    stop(app).await;
    db.close().await;
    for failure in ["audit", "access"] {
        let db = Database::new(failure).await;
        let (mut app, source_owner, _, owner_actor, _) = prepared(&db).await;
        if failure == "audit" {
            append_failure(&db, "applied").await;
        } else {
            db.pool.execute(AssertSqlSafe("CREATE FUNCTION access.fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.role_id LIKE 'operator-binding.%' THEN RAISE EXCEPTION 'synthetic Access unavailable'; END IF; RETURN NEW; END $$")).await.unwrap();
            db.pool.execute(AssertSqlSafe("CREATE TRIGGER fixture_fail BEFORE INSERT ON access.access_control_roles FOR EACH ROW EXECUTE FUNCTION access.fixture_fail()")).await.unwrap();
        }
        let failed = bootstrap(&app, OWNER, &owner_actor).await;
        if failure == "audit" {
            assert!(matches!(
                failed,
                Err(workflow::BootstrapBindingError::AuditUnavailable)
            ));
        } else {
            assert!(matches!(
                failed,
                Err(workflow::BootstrapBindingError::AccessUnavailable)
            ));
        }
        assert_eq!(db.binding_status().await, "pending");
        stop_failed(app).await;
        app = start(&db, &source_owner, true).await;
        assert!(matches!(
            exchange(&app, OWNER, &owner_actor).await,
            Err(workflow::ExchangeSessionError::NotActive)
        ));
        assert_eq!(db.sessions().await, 0);
        gate(
            &mut gates,
            if failure == "audit" {
                "Actual applied Audit failure leaves binding pending and exchange denied despite Access grants"
            } else {
                "Actual Access role creation failure leaves binding pending and exchange denied"
            },
        );
        stop(app).await;
        db.close().await;
    }
    if let Ok(path) = std::env::var("LENSO_OPERATOR_BINDING_RECEIPT") {
        assert!(!path.contains(".worktrees/"));
        std::fs::write(path,serde_json::to_string_pretty(&serde_json::json!({"native_groups":gates.len(),"gates":gates,"cohort":{"kernel":"0.3.12","access_git":"94b6d06cff1e6f17a06e771df232f662cae28ad5","audit_git":"83b4e52e8c6eaf2bbe5356dccd1e3a59b872c8e9"},"limits":["Synthetic private Host invokes protocol-neutral APIs; no Relay/HTTP/CSRF qualification","Workers D1 acceptance remains separate","No production data, migration or deployment"]})).unwrap()).unwrap();
    }
    println!(
        "Native actual App operator binding: {} groups passed",
        gates.len()
    );
}
#[tokio::test(flavor = "current_thread")]
#[ignore = "isolated synthetic PG required; see README"]
async fn actual_kernel_two_realms_access_audit_binding() {
    tokio::task::LocalSet::new().run_until(qualify()).await;
}

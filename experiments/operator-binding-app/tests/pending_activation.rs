use super::*;

async fn resume(
    app: &NativeApp,
    caller: &str,
    actor: &ActorAssertion,
    id: &str,
    revision: &str,
) -> Result<workflow::Binding, workflow::ResumeBindingError> {
    app.invoke_with_context::<workflow::OperatorSessionResumeBinding>(
        caller,
        workflow::RESUME_BINDING_OPERATION,
        context(app, actor),
        workflow::ResumeBindingRequest {
            binding_id: id.into(),
            revision: revision.into(),
        },
    )
    .await
    .unwrap()
}

async fn qualify_pending() {
    for failure in ["access", "audit", "activate"] {
        let db = Database::new(&format!("pending_{failure}")).await;
        let (app, owner, _, owner_actor, ordinary_actor) = prepared(&db).await;
        if failure == "audit" {
            append_failure(&db, "applied").await;
        } else if failure == "activate" {
            db.pool.execute(AssertSqlSafe("CREATE FUNCTION operators.fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.status = 'active' THEN RAISE EXCEPTION 'synthetic activation unavailable'; END IF; RETURN NEW; END $$")).await.unwrap();
            db.pool.execute(AssertSqlSafe("CREATE TRIGGER fixture_fail BEFORE UPDATE ON operators.auth_operator_bindings FOR EACH ROW EXECUTE FUNCTION operators.fixture_fail()")).await.unwrap();
        } else {
            db.pool.execute(AssertSqlSafe("CREATE FUNCTION access.fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.role_id LIKE 'operator-binding.%' THEN RAISE EXCEPTION 'synthetic Access unavailable'; END IF; RETURN NEW; END $$")).await.unwrap();
            db.pool.execute(AssertSqlSafe("CREATE TRIGGER fixture_fail BEFORE INSERT ON access.access_control_roles FOR EACH ROW EXECUTE FUNCTION access.fixture_fail()")).await.unwrap();
        }
        // Preserve the outer Runtime failure from a real storage fault rather
        // than unwrapping it through the happy-path bootstrap helper.
        let failed = app
            .invoke_with_context::<workflow::OperatorSessionBootstrapBinding>(
                OWNER,
                workflow::BOOTSTRAP_BINDING_OPERATION,
                context(&app, &owner_actor),
                workflow::EmptyRequest {},
            )
            .await;
        match failure {
            "access" => assert!(matches!(
                failed,
                Ok(Err(workflow::BootstrapBindingError::AccessUnavailable))
            )),
            "audit" => assert!(matches!(
                failed,
                Ok(Err(workflow::BootstrapBindingError::AuditUnavailable))
            )),
            "activate" => assert!(
                matches!(
                    failed,
                    Ok(Err(workflow::BootstrapBindingError::NotActive
                        | workflow::BootstrapBindingError::Unauthenticated))
                        | Err(lenso_kernel::RuntimeFailure::PluginFailure { .. }
                            | lenso_kernel::RuntimeFailure::PluginRestartExhausted { .. }
                            | lenso_kernel::RuntimeFailure::AdmissionClosed)
                ) || matches!(
                    &failed,
                    Err(lenso_kernel::RuntimeFailure::Unavailable { capability })
                        if *capability == workflow::CAPABILITY_ID
                ),
                "unexpected activation fault: {failed:?}"
            ),
            _ => unreachable!(),
        }
        tokio::task::yield_now().await;
        let admission = app
            .invoke::<state::CredentialState>(
                OWNER,
                state::INSPECT_OPERATION,
                state::InspectRequest {
                    credential_id: "synthetic-admission-probe".into(),
                    session_id: "synthetic-admission-probe".into(),
                },
            )
            .await;
        assert!(matches!(
            admission,
            Err(lenso_kernel::RuntimeFailure::AdmissionClosed)
        ));
        assert_eq!(db.binding_status().await, "pending");
        assert_eq!(db.bindings().await, 1);
        assert_eq!(db.sessions().await, 0);
        let (revision, audit, policy): (i64, String, String) = sqlx::query_as(AssertSqlSafe(
            "SELECT revision,audit_event_id,policy_revision FROM operators.auth_operator_bindings",
        ))
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(revision, 1);
        assert!(audit.is_empty() && policy.is_empty());
        if failure == "activate" {
            let applied: i64 = sqlx::query_scalar(AssertSqlSafe(
                "SELECT count(*) FROM audit_log.events WHERE action='applied'",
            ))
            .fetch_one(&db.pool)
            .await
            .unwrap();
            assert_eq!(applied, 1);
        }
        let id: String = sqlx::query_scalar(AssertSqlSafe(
            "SELECT binding_id FROM operators.auth_operator_bindings",
        ))
        .fetch_one(&db.pool)
        .await
        .unwrap();
        let intent: String = sqlx::query_scalar(AssertSqlSafe(
            "SELECT activation_started_at FROM operators.auth_operator_bindings",
        ))
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert!(!intent.is_empty());
        // A real storage fault closed admission. Probe denials in a fresh App.
        stop_failed(app).await;
        let app = start(&db, &owner, true).await;
        assert!(
            resume(&app, ORDINARY, &owner_actor, &id, "1")
                .await
                .is_err()
        );
        assert!(
            resume(&app, OWNER, &ordinary_actor, &id, "1")
                .await
                .is_err()
        );
        assert!(resume(&app, OWNER, &owner_actor, &id, "2").await.is_err());
        assert!(matches!(
            resume(&app, OWNER, &owner_actor, &id, "01").await,
            Err(workflow::ResumeBindingError::InvalidRequest)
        ));
        assert!(
            resume(&app, OWNER, &owner_actor, "opb_wrong", "1")
                .await
                .is_err()
        );
        stop(app).await;
        let sql = if failure == "audit" {
            "DROP TRIGGER fixture_fail ON audit_log.events"
        } else if failure == "activate" {
            "DROP TRIGGER fixture_fail ON operators.auth_operator_bindings"
        } else {
            "DROP TRIGGER fixture_fail ON access.access_control_roles"
        };
        db.pool.execute(AssertSqlSafe(sql)).await.unwrap();
        // Restart: exact original pending identity and durable audit intent survive.
        let app = start(&db, &owner, true).await;
        let session = issue(&app, &owner).await;
        let fresh_actor = actor(&app, OWNER, &session.credential).await;
        db.pool.execute(AssertSqlSafe("DELETE FROM access.access_control_role_permissions WHERE permission='access-control.roles.manage' AND role_id IN (SELECT role_id FROM access.access_control_roles WHERE protected)"))
            .await.unwrap();
        assert!(matches!(
            resume(&app, OWNER, &fresh_actor, &id, "1").await,
            Err(workflow::ResumeBindingError::AccessUnavailable)
        ));
        assert_eq!(db.binding_status().await, "pending");
        assert_eq!(db.sessions().await, 0);
        db.pool.execute(AssertSqlSafe("INSERT INTO access.access_control_role_permissions(scope_kind,scope_id,role_id,permission) SELECT scope_kind,scope_id,role_id,'access-control.roles.manage' FROM access.access_control_roles WHERE protected"))
            .await.unwrap();
        let active = resume(&app, OWNER, &fresh_actor, &id, "1").await.unwrap();
        assert!(active.active);
        assert_eq!(active.binding_id, id);
        assert_eq!(active.revision, "1");
        let replay = resume(&app, OWNER, &fresh_actor, &id, "1").await.unwrap();
        assert_eq!(replay.audit_event_id, active.audit_event_id);
        assert_eq!(replay.policy_revision, active.policy_revision);
        assert_eq!(db.bindings().await, 1);
        assert_eq!(db.sessions().await, 0);
        let (applied, scopes, assignments): (i64, i64, i64) = sqlx::query_as(AssertSqlSafe(
            "SELECT (SELECT count(*) FROM audit_log.events WHERE action='applied'),(SELECT count(*) FROM access.access_control_scopes),(SELECT count(*) FROM access.access_control_subject_roles WHERE role_id LIKE 'operator-binding.%')"))
            .fetch_one(&db.pool).await.unwrap();
        assert_eq!((applied, scopes, assignments), (1, 1, 1));
        let preserved: String = sqlx::query_scalar(AssertSqlSafe(
            "SELECT activation_started_at FROM operators.auth_operator_bindings",
        ))
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(preserved, intent);
        stop(app).await;
        db.close().await;
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "isolated synthetic PG required; no production database"]
async fn original_pending_resumes_after_restart_without_bootstrap_or_duplicate_audit() {
    tokio::task::LocalSet::new()
        .run_until(qualify_pending())
        .await;
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "isolated synthetic PG required; no production database"]
async fn bootstrap_after_driver_five_seconds_and_slow_scope_commit_uses_fresh_control() {
    tokio::task::LocalSet::new().run_until(async {
        let db = Database::new("slow_bootstrap").await;
        let (app, _, _, owner_actor, _) = prepared(&db).await;
        db.pool.execute(AssertSqlSafe("CREATE FUNCTION access.fixture_slow() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(6); RETURN NEW; END $$")).await.unwrap();
        db.pool.execute(AssertSqlSafe("CREATE TRIGGER fixture_slow BEFORE INSERT ON access.access_control_scopes FOR EACH ROW EXECUTE FUNCTION access.fixture_slow()")).await.unwrap();
        let active = bootstrap(&app, OWNER, &owner_actor).await.unwrap();
        assert!(active.active);
        assert_eq!(db.sessions().await, 0);
        stop(app).await;
        db.close().await;
    }).await;
}

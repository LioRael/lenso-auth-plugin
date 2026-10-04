//! Synthetic event Host mechanical Driver, using the actual released Kernel trait.
//! This is not a qualification of the older Registry Workers Driver package.
use super::*;
use futures::{
    channel::oneshot,
    future::{AbortHandle, Abortable, LocalBoxFuture},
    task::SpawnError,
};
use lenso_kernel::{
    CancellationToken, DriverTask, Kernel, LocalTask, RuntimeDriver, ShutdownOutcome, TaskOutcome,
};
use serde::Deserialize;
use std::time::Duration;
use std::{
    cell::{Cell, RefCell},
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

#[wasm_bindgen(raw_module = "../clock.mjs")]
extern "C" {
    fn clock(operation: u32, callback: &JsValue, value: i32) -> f64;
}
#[derive(Clone, Debug)]
struct ProofDriver {
    started: f64,
    stopped: Rc<Cell<bool>>,
    tasks: Rc<RefCell<Vec<AbortHandle>>>,
}
impl ProofDriver {
    fn new() -> Self {
        Self {
            started: clock(0, &JsValue::NULL, 0),
            stopped: Rc::new(Cell::new(false)),
            tasks: Rc::default(),
        }
    }
    fn stop(&self) {
        self.stopped.set(true);
        for task in self.tasks.borrow().iter() {
            task.abort();
        }
    }
}
struct Timer {
    receiver: oneshot::Receiver<()>,
    id: i32,
    _callback: Closure<dyn FnMut()>,
}
impl Future for Timer {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        Pin::new(&mut self.receiver).poll(cx).map(|_| ())
    }
}
impl Drop for Timer {
    fn drop(&mut self) {
        clock(2, &JsValue::NULL, self.id);
    }
}
fn timer(delay: Duration) -> LocalBoxFuture<'static, ()> {
    let (tx, receiver) = oneshot::channel();
    let mut tx = Some(tx);
    let callback = Closure::new(move || {
        if let Some(tx) = tx.take() {
            let _ = tx.send(());
        }
    });
    let id = clock(
        1,
        callback.as_ref(),
        i32::try_from(delay.as_millis()).unwrap_or(i32::MAX),
    ) as i32;
    Box::pin(Timer {
        receiver,
        id,
        _callback: callback,
    })
}
impl RuntimeDriver for ProofDriver {
    fn now(&self) -> Duration {
        Duration::from_secs_f64((clock(0, &JsValue::NULL, 0) - self.started).max(0.0) / 1000.0)
    }
    fn sleep_until(&self, deadline: Duration) -> LocalBoxFuture<'static, ()> {
        timer(deadline.saturating_sub(self.now()))
    }
    fn yield_now(&self) -> LocalBoxFuture<'static, ()> {
        timer(Duration::ZERO)
    }
    fn wait_for_runtime_event(&self, deadline: Duration) -> LocalBoxFuture<'static, ()> {
        self.sleep_until(deadline)
    }
    fn spawn_local(&self, task: LocalTask) -> Result<DriverTask, SpawnError> {
        if self.stopped.get() {
            return Err(SpawnError::shutdown());
        }
        let (abort, registration) = AbortHandle::new_pair();
        self.tasks.borrow_mut().push(abort.clone());
        let (tx, receiver) = oneshot::channel();
        spawn_local(async move {
            let outcome = match Abortable::new(task, registration).await {
                Ok(()) => TaskOutcome::Completed,
                Err(_) => TaskOutcome::Cancelled,
            };
            let _ = tx.send(outcome);
        });
        Ok(DriverTask::new(abort, receiver))
    }
    fn shutdown_requested(&self) -> bool {
        self.stopped.get()
    }
}
struct DriverGuard(ProofDriver);
impl Drop for DriverGuard {
    fn drop(&mut self) {
        self.0.stop();
    }
}
fn error(_: impl std::fmt::Debug) -> JsValue {
    JsValue::from_str("synthetic operator App operation failed (credential material omitted)")
}
fn field(scope: &JsValue, name: &str) -> Result<JsValue, JsValue> {
    js_sys::Reflect::get(scope, &name.into())
}
fn function(scope: &JsValue, name: &str) -> Result<js_sys::Function, JsValue> {
    field(scope, name)?.dyn_into().map_err(error)
}
#[wasm_bindgen]
pub async fn migrate(scope: JsValue) -> Result<(), JsValue> {
    let source = lenso_auth_account_plugin::workers::D1Binding::new(
        "ACCOUNTS_DB",
        function(&field(&scope, "accounts")?, "batch")?,
    );
    let operators = lenso_auth_account_plugin::workers::D1Binding::new(
        "OPERATORS_DB",
        function(&field(&scope, "operators")?, "batch")?,
    );
    lenso_auth_account_plugin::migration::setup(&source)
        .await
        .map_err(error)?;
    lenso_auth_account_plugin::migration::setup_operator_bound(&operators)
        .await
        .map_err(error)?;
    let access = lenso_access_control_d1_plugin::workers::D1Binding(function(
        &field(&scope, "access")?,
        "batch",
    )?);
    lenso_access_control_d1_plugin::schema::plan()
        .map_err(error)?
        .setup(&access)
        .await
        .map_err(error)?;
    Ok(())
}
#[derive(Deserialize)]
struct Input {
    operation: String,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    owner_subject: String,
    #[serde(default)]
    credential: String,
    #[serde(default)]
    binding_id: String,
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    permission: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    caller: String,
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    narrowed: bool,
    #[serde(default)]
    source_disabled: bool,
}
fn value<T: serde::Serialize, E: serde::Serialize>(
    r: Result<Result<T, E>, RuntimeFailure>,
) -> Result<serde_json::Value, JsValue> {
    match r {
        Ok(domain) => serde_json::to_value(domain).map_err(error),
        Err(e) => Ok(
            serde_json::json!({"Runtime":{"kind":match e {RuntimeFailure::PluginFailure{..}=>"plugin_failure",RuntimeFailure::AdmissionClosed=>"admission_closed",_=>"runtime_failure"}}}),
        ),
    }
}
async fn actor(
    app: &lenso_kernel::NativeApp,
    caller: &str,
    credential: &str,
) -> Result<lenso_auth_sdk::ActorAssertion, JsValue> {
    let response = app
        .invoke::<auth::Auth>(
            caller,
            auth::AUTHENTICATE_OPERATION,
            auth::AuthRequest {
                credential: Some(auth::AuthenticateRequestCredential {
                    scheme: "session".into(),
                    value: credential.into(),
                }),
            },
        )
        .await
        .map_err(error)?
        .map_err(error)?;
    let lenso_auth_sdk::AuthOutcome::Authenticated(actor) =
        lenso_auth_sdk::decode_auth_response(response).map_err(error)?
    else {
        return Err(error("expected actor"));
    };
    Ok(actor)
}
#[wasm_bindgen]
pub async fn invoke(input: String, scope: JsValue) -> Result<String, JsValue> {
    let input: Input = serde_json::from_str(&input).map_err(error)?;
    let plan = plan_with_management(&input.owner_subject, !input.disabled, !input.narrowed)
        .map_err(|e| JsValue::from_str(&format!("synthetic Host resolution: {e}")))?;
    if input.operation == "resolve" {
        // Public business config consists only of synthetic policy and logical secret/storage refs.
        return serde_json::to_string(&serde_json::json!({"Ok":{"instances":plan.plugin_instances(),"bindings":plan.capability_bindings()}})).map_err(error);
    }
    let attachments = EventAttachments {
        accounts: field(&scope, "accounts")?,
        operators: field(&scope, "operators")?,
        access: field(&scope, "access")?,
        audit: field(&scope, "audit")?,
    };
    let driver = ProofDriver::new();
    let _guard = DriverGuard(driver.clone());
    let app = Kernel::start_native(plan, driver, registry(attachments).map_err(error)?)
        .await
        .map_err(|e| JsValue::from_str(&format!("synthetic App startup: {e:?}")))?;
    let caller = if input.caller.is_empty() {
        OWNER
    } else {
        &input.caller
    };
    let mut out = match input.operation.as_str() {
        "ensure" => value(
            app.invoke::<directory::DirectoryEnsureIdentity>(
                OWNER,
                directory::ENSURE_IDENTITY_OPERATION,
                directory::EnsureIdentityRequest {
                    provider: "synthetic".into(),
                    external_subject: input.label,
                },
            )
            .await,
        )?,
        "issue" => value(
            app.invoke::<issuer::CredentialIssuerIssue>(
                OWNER,
                issuer::ISSUE_OPERATION,
                issuer::IssueRequest {
                    subject: input.subject,
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
            .await,
        )?,
        "authenticate" => value(
            app.invoke::<auth::Auth>(
                caller,
                auth::AUTHENTICATE_OPERATION,
                auth::AuthRequest {
                    credential: Some(auth::AuthenticateRequestCredential {
                        scheme: "session".into(),
                        value: input.credential,
                    }),
                },
            )
            .await,
        )?,
        "inspect" => value(
            app.invoke::<state::CredentialState>(
                OPERATOR_BROWSER,
                state::INSPECT_OPERATION,
                state::InspectRequest {
                    credential_id: input.session_id.clone(),
                    session_id: input.session_id,
                },
            )
            .await,
        )?,
        "source_status" => value(
            app.invoke::<account_admin::AccountAdminSetSubjectStatus>(
                OWNER,
                account_admin::SET_SUBJECT_STATUS_OPERATION,
                account_admin::SetSubjectStatusRequest {
                    subject: input.subject,
                    status: if input.source_disabled {
                        account_admin::SetSubjectStatusRequestStatus::Disabled
                    } else {
                        account_admin::SetSubjectStatusRequestStatus::Active
                    },
                    reason: None,
                    disabled_until: None,
                },
            )
            .await,
        )?,
        "role" => value(
            app.invoke::<access_directory::AccessControlDirectoryGetRole>(
                OWNER,
                access_directory::GET_ROLE_OPERATION,
                access_directory::GetRoleRequest {
                    role_id: format!("operator-binding.{}", input.binding_id),
                    scope: access_directory::Scope {
                        kind: "deployment".into(),
                        id: "synthetic".into(),
                    },
                },
            )
            .await,
        )?,
        "permission" => value(
            app.invoke::<access::AccessControl>(
                OWNER,
                access::CHECK_PERMISSION_OPERATION,
                access::CheckPermissionRequest {
                    subject: input.subject,
                    permission: input.permission,
                    scope: access::CheckPermissionRequestScope {
                        kind: "deployment".into(),
                        id: "synthetic".into(),
                    },
                },
            )
            .await,
        )?,
        "bootstrap" | "exchange" | "read" | "revoke" | "recover" => {
            // Authentication and sealed context are real generated calls, never a fixture assertion forgery.
            let actor_caller = if input.operation == "revoke" && caller == OPERATOR_BROWSER {
                OPERATOR_BROWSER
            } else {
                OWNER
            };
            let actor = actor(&app, actor_caller, &input.credential).await?;
            let context = actor
                .attach(app.invocation_context(None, CancellationToken::new()))
                .map_err(error)?;
            match input.operation.as_str() {
                "bootstrap" => value(
                    app.invoke_with_context::<workflow::OperatorSessionBootstrapBinding>(
                        caller,
                        workflow::BOOTSTRAP_BINDING_OPERATION,
                        context,
                        workflow::EmptyRequest {},
                    )
                    .await,
                )?,
                "exchange" => value(
                    app.invoke_with_context::<workflow::OperatorSessionExchangeSession>(
                        caller,
                        workflow::EXCHANGE_SESSION_OPERATION,
                        context,
                        workflow::EmptyRequest {},
                    )
                    .await,
                )?,
                "read" => value(
                    app.invoke_with_context::<workflow::OperatorSessionReadBinding>(
                        caller,
                        workflow::READ_BINDING_OPERATION,
                        context,
                        workflow::EmptyRequest {},
                    )
                    .await,
                )?,
                "revoke" => value(
                    app.invoke_with_context::<workflow::OperatorSessionRevokeBinding>(
                        caller,
                        workflow::REVOKE_BINDING_OPERATION,
                        context,
                        workflow::RevokeBindingRequest {
                            binding_id: input.binding_id,
                        },
                    )
                    .await,
                )?,
                _ => value(
                    app.invoke_with_context::<workflow::OperatorSessionRecoverRevocation>(
                        caller,
                        workflow::RECOVER_REVOCATION_OPERATION,
                        context,
                        workflow::RevokeBindingRequest {
                            binding_id: input.binding_id,
                        },
                    )
                    .await,
                )?,
            }
        }
        _ => return Err(error("unknown fixture operation")),
    };
    if ["audit_unavailable", "access_unavailable"]
        .iter()
        .any(|e| out["Err"].as_str() == Some(e))
        || out.get("Runtime").is_some()
    {
        _guard.0.yield_now().await;
        let probe = app
            .invoke::<state::CredentialState>(
                OWNER,
                state::INSPECT_OPERATION,
                state::InspectRequest {
                    credential_id: "synthetic-admission-probe".into(),
                    session_id: "synthetic-admission-probe".into(),
                },
            )
            .await;
        out["admission_after_failure"] =
            serde_json::json!(if matches!(probe, Err(RuntimeFailure::AdmissionClosed)) {
                "closed"
            } else {
                "open_or_other_failure"
            });
    }
    let shutdown = app.shutdown(Duration::from_secs(2)).await;
    if !matches!(
        shutdown,
        ShutdownOutcome::Clean | ShutdownOutcome::RuntimeFailure { .. }
    ) {
        return Err(error("unclean shutdown"));
    }
    out["shutdown"] = serde_json::json!(match shutdown {
        ShutdownOutcome::Clean => "clean",
        ShutdownOutcome::RuntimeFailure { .. } => "runtime_failure",
        _ => "unclean",
    });
    serde_json::to_string(&out).map_err(error)
}

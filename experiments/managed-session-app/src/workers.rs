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
use lenso_native_adapter::NativePluginRegistry;
use lenso_web_ingress_plugin::WebIngressEventFactory;
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
    JsValue::from_str("synthetic App proof failed (sensitive values omitted)")
}
fn function(scope: &JsValue, name: &str) -> Result<js_sys::Function, JsValue> {
    js_sys::Reflect::get(scope, &name.into())?
        .dyn_into()
        .map_err(error)
}

#[wasm_bindgen]
pub async fn migrate(scope: JsValue) -> Result<(), JsValue> {
    let account = lenso_auth_account_plugin::workers::D1Binding::new(
        "ACCOUNT_DB",
        function(&scope, "accountBatch")?,
    );
    let password = lenso_auth_password_plugin::workers::D1Binding::new(
        "PASSWORD_DB",
        function(&scope, "passwordBatch")?,
    );
    lenso_auth_account_plugin::migration::setup_managed(&account)
        .await
        .map_err(error)?;
    lenso_auth_password_plugin::migration::setup(&password)
        .await
        .map_err(error)?;
    Ok(())
}
#[derive(Deserialize)]
struct Input {
    operation: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    uri: String,
    #[serde(default)]
    headers: Vec<(String, String)>,
    #[serde(default)]
    credential: String,
    #[serde(default)]
    identifier: String,
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    tightened_policy: bool,
}
#[wasm_bindgen]
pub async fn invoke(input: String, scope: JsValue) -> Result<String, JsValue> {
    let input: Input = serde_json::from_str(&input).map_err(error)?;
    lenso_auth_account_plugin::link_plugin();
    lenso_auth_password_plugin::link_plugin();
    lenso_auth_session_renewal_plugin::link_plugin();
    let ingress = WebIngressEventFactory::new();
    let registry = NativePluginRegistry::new()
        .with_factory_override(lenso_auth_account_plugin::workers_factory(
            "ACCOUNT_DB",
            function(&scope, "accountBatch")?,
        ))
        .map_err(error)?
        .with_factory_override(lenso_auth_password_plugin::workers_factory(
            "PASSWORD_DB",
            function(&scope, "passwordBatch")?,
        ))
        .map_err(error)?
        .with_factory(ingress.clone())
        .with_linked_factories()
        .with_factory(EmptyFactory)
        .with_factory(FixtureSecrets(BTreeMap::from([
            ("key".into(), KEY.into()),
            ("pepper".into(), PEPPER.into()),
        ])));
    let driver = ProofDriver::new();
    let _guard = DriverGuard(driver.clone());
    let app = Kernel::start_native(
        if input.tightened_policy {
            plan_with_policy(
                "proof_account",
                "proof_password",
                ManagedSessionPolicy {
                    idle_timeout_seconds: 10,
                    absolute_timeout_seconds: 15,
                    renew_interval_seconds: 1,
                },
            )
        } else {
            plan("proof_account", "proof_password")
        },
        driver,
        registry,
    )
    .await
    .map_err(error)?;
    let output = match input.operation.as_str() {
        "register" => serde_json::to_value(
            app.invoke::<password::PasswordRegister>(
                CALLER,
                password::REGISTER_OPERATION,
                password::RegisterRequest {
                    identifier: input.identifier,
                    password: "Synthetic-password-for-proof-only-123!".into(),
                },
            )
            .await
            .map_err(error)?,
        )
        .map_err(error)?,
        "authenticate" => serde_json::to_value(
            app.invoke::<auth::Auth>(
                CALLER,
                auth::AUTHENTICATE_OPERATION,
                auth::AuthRequest {
                    credential: Some(auth::AuthenticateRequestCredential {
                        scheme: "session".into(),
                        value: input.credential,
                    }),
                },
            )
            .await
            .map_err(error)?,
        )
        .map_err(error)?,
        "denied_issue" => serde_json::to_value(
            app.invoke::<managed::ManagedSessionIssueManaged>(
                ROGUE,
                managed::ISSUE_MANAGED_OPERATION,
                managed::IssueManagedRequest {
                    subject: input.identifier,
                    actor_kind: "user".into(),
                    assurance: "password".into(),
                    audience: vec!["synthetic.app".into()],
                    claims: BTreeMap::new(),
                },
            )
            .await
            .map_err(error)?,
        )
        .map_err(error)?,
        "denied" => serde_json::to_value(
            app.invoke::<managed::ManagedSessionRenew>(
                ROGUE,
                managed::RENEW_OPERATION,
                managed::RenewRequest {
                    credential: input.credential,
                },
            )
            .await
            .map_err(error)?,
        )
        .map_err(error)?,
        "inspect" => serde_json::to_value(
            app.invoke::<state::CredentialState>(
                CALLER,
                state::INSPECT_OPERATION,
                state::InspectRequest {
                    credential_id: input.session_id.clone(),
                    session_id: input.session_id,
                },
            )
            .await
            .map_err(error)?,
        )
        .map_err(error)?,
        "logout" => serde_json::to_value(
            app.invoke::<issuer::CredentialIssuerRevokeCredential>(
                CALLER,
                issuer::REVOKE_CREDENTIAL_OPERATION,
                issuer::RevokeCredentialRequest {
                    scheme: "session".into(),
                    credential: input.credential,
                },
            )
            .await
            .map_err(error)?,
        )
        .map_err(error)?,
        "http" => {
            let mut request = http::Request::builder()
                .method(input.method.as_str())
                .uri(input.uri.as_str())
                .body(bytes::Bytes::new())
                .map_err(error)?;
            for (name, value) in input.headers {
                request.headers_mut().append(
                    http::HeaderName::from_bytes(name.as_bytes()).map_err(error)?,
                    http::HeaderValue::from_str(&value).map_err(error)?,
                );
            }
            let response = ingress
                .handle(request, CancellationToken::new())
                .await
                .map_err(error)?;
            let (head, body) = response.into_parts();
            let headers = head
                .headers
                .iter()
                .map(|(k, v)| Ok((k.as_str(), v.to_str().map_err(error)?)))
                .collect::<Result<Vec<_>, JsValue>>()?;
            serde_json::json!({"status":head.status.as_u16(),"headers":headers,"body":serde_json::from_slice::<serde_json::Value>(&body).map_err(error)?})
        }
        _ => return Err(error("unknown local proof operation")),
    };
    if app.shutdown(Duration::from_secs(2)).await != ShutdownOutcome::Clean {
        return Err(error("unclean shutdown"));
    }
    serde_json::to_string(&output).map_err(error)
}

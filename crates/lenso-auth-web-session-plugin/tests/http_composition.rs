use std::{cell::RefCell, rc::Rc, time::Duration as StdDuration};

use lenso_app_plan::{
    AppComposition, CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan,
    PluginInstancePlan, ResolvedAppPlan,
};
use lenso_auth_web_session_plugin::PACKAGE_ID;
use lenso_capability_credential_issuer as credential;
use lenso_capability_credential_issuer::{
    CredentialIssuerEndpoint, CredentialIssuerIssue, CredentialIssuerProvider,
    CredentialIssuerRevoke, CredentialIssuerRevokeCredential, IssueError, IssueRequest,
    RevokeCredentialError, RevokeCredentialRequest, RevokeCredentialResponse, RevokeError,
    RevokeRequest,
};
use lenso_capability_federated_auth as federated;
use lenso_capability_federated_auth::{
    CompleteRequest, CompleteResponse, FederatedComplete, FederatedEndpoint, FederatedProvider,
    FederatedStart, StartRequest, StartResponse,
};
use lenso_capability_http_endpoint as endpoint;
use lenso_capability_http_endpoint::{HandleRequest, HandleRequestCredential, HandleResponse};
use lenso_capability_password_auth as password;
use lenso_kernel::{
    InvocationContext, Kernel, NativeRequestEndpoint, NativeRequestFuture, RuntimeFailure,
    ShutdownOutcome,
};
use lenso_native_adapter::{
    NativePluginFactory, NativePluginFactoryContext, NativePluginInstance, NativePluginRegistry,
};
use lenso_runner::TokioDriver;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

const CALLER_PACKAGE: &str = "test.auth-web-session-caller";
const DEPENDENCIES_PACKAGE: &str = "test.auth-web-session-dependencies";
const SESSION_COOKIE: &str = "__Host-lenso-session";
const CSRF_COOKIE: &str = "__Host-lenso-csrf";

#[derive(Clone, Copy, Debug)]
struct EmptyFactory;

impl NativePluginFactory for EmptyFactory {
    fn package_id(&self) -> &'static str {
        CALLER_PACKAGE
    }

    fn instantiate(
        &self,
        _: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        Ok(NativePluginInstance::default())
    }
}

#[derive(Clone, Debug)]
struct DependenciesFactory {
    observed: Rc<Observed>,
    callback_return_to: &'static str,
    recognize_credential: bool,
}

impl NativePluginFactory for DependenciesFactory {
    fn package_id(&self) -> &'static str {
        DEPENDENCIES_PACKAGE
    }

    fn instantiate(
        &self,
        _: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        let provider = FakeDependencies {
            observed: Rc::clone(&self.observed),
            callback_return_to: self.callback_return_to,
            recognize_credential: self.recognize_credential,
        };
        Ok(NativePluginInstance::new(vec![
            Rc::new(FederatedEndpoint::new(provider.clone())) as Rc<dyn NativeRequestEndpoint>,
            Rc::new(password::PasswordEndpoint::new(provider.clone()))
                as Rc<dyn NativeRequestEndpoint>,
            Rc::new(CredentialIssuerEndpoint::new(provider)) as Rc<dyn NativeRequestEndpoint>,
        ]))
    }
}

#[derive(Debug, Default)]
struct Observed {
    starts: RefCell<Vec<String>>,
    completions: RefCell<Vec<(String, String)>>,
    revocations: RefCell<Vec<(String, String)>>,
}

#[derive(Clone, Debug)]
struct FakeDependencies {
    observed: Rc<Observed>,
    callback_return_to: &'static str,
    recognize_credential: bool,
}

impl password::PasswordProvider for FakeDependencies {
    fn login(
        &self,
        _: InvocationContext,
        request: password::LoginRequest,
    ) -> NativeRequestFuture<password::PasswordLogin> {
        let result =
            if request.identifier == "alice@example.test" && request.password == "test-password" {
                Ok(password::LoginResponse {
                    subject: "alice".into(),
                    session_id: "session-1".into(),
                    credential: "opaque-password-session".into(),
                    expires_at: future_time(300),
                })
            } else {
                Err(password::LoginError::InvalidCredentials)
            };
        Box::pin(std::future::ready(Ok(result)))
    }
    fn register(
        &self,
        _: InvocationContext,
        _: password::RegisterRequest,
    ) -> NativeRequestFuture<password::PasswordRegister> {
        Box::pin(std::future::ready(Ok(Err(
            password::RegisterError::Disabled,
        ))))
    }
}

impl FederatedProvider for FakeDependencies {
    fn start(
        &self,
        _: InvocationContext,
        request: StartRequest,
    ) -> NativeRequestFuture<FederatedStart> {
        self.observed.starts.borrow_mut().push(request.return_to);
        Box::pin(std::future::ready(Ok(Ok(StartResponse {
            provider: "work-sso".to_owned(),
            authorization_url: "https://issuer.example/authorize?state=state-1&nonce=nonce-1"
                .to_owned(),
            expires_at: future_time(300),
        }))))
    }

    fn complete(
        &self,
        _: InvocationContext,
        request: CompleteRequest,
    ) -> NativeRequestFuture<FederatedComplete> {
        self.observed
            .completions
            .borrow_mut()
            .push((request.code, request.state));
        Box::pin(std::future::ready(Ok(Ok(CompleteResponse {
            provider: "work-sso".to_owned(),
            subject: "usr_1".to_owned(),
            session_id: "ses_1".to_owned(),
            credential: "opaque-session-token".to_owned(),
            expires_at: future_time(3_600),
            return_to: self.callback_return_to.to_owned(),
        }))))
    }
}

impl CredentialIssuerProvider for FakeDependencies {
    fn issue(
        &self,
        _: InvocationContext,
        _: IssueRequest,
    ) -> NativeRequestFuture<CredentialIssuerIssue> {
        Box::pin(std::future::ready(Ok(Err(IssueError::InvalidSubject))))
    }

    fn revoke(
        &self,
        _: InvocationContext,
        _: RevokeRequest,
    ) -> NativeRequestFuture<CredentialIssuerRevoke> {
        Box::pin(std::future::ready(Ok(Err(RevokeError::NotFound))))
    }

    fn revoke_credential(
        &self,
        _: InvocationContext,
        request: RevokeCredentialRequest,
    ) -> NativeRequestFuture<CredentialIssuerRevokeCredential> {
        self.observed
            .revocations
            .borrow_mut()
            .push((request.scheme, request.credential));
        if !self.recognize_credential {
            return Box::pin(std::future::ready(Ok(Err(RevokeCredentialError::NotFound))));
        }
        Box::pin(std::future::ready(Ok(Ok(RevokeCredentialResponse {
            changed: true,
        }))))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn bound_http_flow_redirects_sets_secure_cookies_and_revokes_logout_credential() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let observed = Rc::new(Observed::default());
            let app = Kernel::start_native(
                plan(),
                TokioDriver::new(),
                registry(Rc::clone(&observed), "/settings/security", true),
            )
            .await
            .unwrap();

            let start = handle(
                &app,
                request(
                    "auth.web-session.start",
                    "GET",
                    "/auth/oidc/start",
                    Some("return_to=%2Fsettings%2Fsecurity"),
                    None,
                ),
            )
            .await;
            assert_eq!(start.status, 302);
            assert_eq!(
                header_values(&start, "location"),
                ["https://issuer.example/authorize?state=state-1&nonce=nonce-1"]
            );
            assert_eq!(observed.starts.borrow().as_slice(), ["/settings/security"]);

            let callback = handle(
                &app,
                request(
                    "auth.web-session.callback",
                    "GET",
                    "/auth/oidc/callback",
                    Some("code=authorization-code&state=state-1"),
                    None,
                ),
            )
            .await;
            assert_eq!(callback.status, 303);
            assert_eq!(header_values(&callback, "location"), ["/settings/security"]);
            let set_cookies = header_values(&callback, "set-cookie");
            assert_eq!(set_cookies.len(), 2);
            assert!(set_cookies.iter().any(|cookie| {
                cookie.starts_with(&format!("{SESSION_COOKIE}=opaque-session-token;"))
                    && cookie.contains("; Secure; HttpOnly; SameSite=Lax")
                    && cookie.contains("; Path=/;")
            }));
            assert!(set_cookies.iter().any(|cookie| {
                cookie.starts_with(&format!("{CSRF_COOKIE}="))
                    && cookie.contains("; Secure; SameSite=Lax")
                    && !cookie.contains("HttpOnly")
            }));
            assert_eq!(
                observed.completions.borrow().as_slice(),
                [("authorization-code".to_owned(), "state-1".to_owned())]
            );

            let logout = handle(
                &app,
                request(
                    "auth.web-session.logout",
                    "POST",
                    "/auth/logout",
                    None,
                    Some(HandleRequestCredential {
                        scheme: "session".to_owned(),
                        value: "opaque-session-token".to_owned(),
                    }),
                ),
            )
            .await;
            assert_eq!(logout.status, 204);
            assert!(
                header_values(&logout, "set-cookie")
                    .iter()
                    .all(|cookie| cookie.contains("Max-Age=0"))
            );
            assert_eq!(
                observed.revocations.borrow().as_slice(),
                [("session".to_owned(), "opaque-session-token".to_owned())]
            );

            assert_eq!(
                app.shutdown(StdDuration::from_secs(2)).await,
                ShutdownOutcome::Clean
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn unsafe_callback_return_is_rejected_and_the_new_session_is_rolled_back() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let observed = Rc::new(Observed::default());
            let app = Kernel::start_native(
                plan(),
                TokioDriver::new(),
                registry(Rc::clone(&observed), "//attacker.example", true),
            )
            .await
            .unwrap();
            let callback = handle(
                &app,
                request(
                    "auth.web-session.callback",
                    "GET",
                    "/auth/oidc/callback",
                    Some("code=authorization-code&state=state-1"),
                    None,
                ),
            )
            .await;
            assert_eq!(callback.status, 502);
            assert!(header_values(&callback, "set-cookie").is_empty());
            assert_eq!(
                observed.revocations.borrow().as_slice(),
                [("session".to_owned(), "opaque-session-token".to_owned())]
            );
            assert_eq!(
                app.shutdown(StdDuration::from_secs(2)).await,
                ShutdownOutcome::Clean
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn unrecognized_session_is_cleared_but_never_reported_as_revoked() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let observed = Rc::new(Observed::default());
            let app = Kernel::start_native(
                plan(),
                TokioDriver::new(),
                registry(Rc::clone(&observed), "/", false),
            )
            .await
            .unwrap();
            let logout = handle(
                &app,
                request(
                    "auth.web-session.logout",
                    "POST",
                    "/auth/logout",
                    None,
                    Some(HandleRequestCredential {
                        scheme: "session".to_owned(),
                        value: "credential-from-a-different-issuer".to_owned(),
                    }),
                ),
            )
            .await;
            assert_eq!(logout.status, 401);
            assert!(
                header_values(&logout, "set-cookie")
                    .iter()
                    .all(|cookie| cookie.contains("Max-Age=0"))
            );
            assert_eq!(
                observed.revocations.borrow().as_slice(),
                [(
                    "session".to_owned(),
                    "credential-from-a-different-issuer".to_owned()
                )]
            );
            assert_eq!(
                app.shutdown(StdDuration::from_secs(2)).await,
                ShutdownOutcome::Clean
            );
        })
        .await;
}

fn registry(
    observed: Rc<Observed>,
    callback_return_to: &'static str,
    recognize_credential: bool,
) -> NativePluginRegistry {
    NativePluginRegistry::new()
        .with_linked_factories()
        .with_factory(EmptyFactory)
        .with_factory(DependenciesFactory {
            observed,
            callback_return_to,
            recognize_credential,
        })
}

fn plan() -> ResolvedAppPlan {
    method_plan(false, true)
}

fn method_plan(password_enabled: bool, sso_enabled: bool) -> ResolvedAppPlan {
    let caller = PluginInstancePlan::new("caller", CALLER_PACKAGE).with_requirement(
        CapabilityRequirementPlan::one(endpoint::CAPABILITY_ID, endpoint::DESCRIPTOR_VERSION),
    );
    let web_session = PluginInstancePlan::new("web-session", PACKAGE_ID)
        .with_configuration(
            serde_json::json!({
                "session_cookie_name": SESSION_COOKIE,
                "csrf_cookie_name": CSRF_COOKIE, "origin": "https://console.example"
            })
            .to_string(),
        )
        .with_requirement(CapabilityRequirementPlan::many(
            password::CAPABILITY_ID,
            password::DESCRIPTOR_VERSION,
        ))
        .with_requirement(CapabilityRequirementPlan::many(
            federated::CAPABILITY_ID,
            federated::DESCRIPTOR_VERSION,
        ))
        .with_requirement(CapabilityRequirementPlan::one(
            credential::CAPABILITY_ID,
            credential::DESCRIPTOR_VERSION,
        ))
        .with_capability(CapabilityEndpointPlan::new(
            endpoint::CAPABILITY_ID,
            endpoint::DESCRIPTOR_VERSION,
            [endpoint::DESCRIBE_OPERATION, endpoint::HANDLE_OPERATION],
        ));
    let dependencies = PluginInstancePlan::new("dependencies", DEPENDENCIES_PACKAGE)
        .with_capability(CapabilityEndpointPlan::new(
            password::CAPABILITY_ID,
            password::DESCRIPTOR_VERSION,
            [password::LOGIN_OPERATION, password::REGISTER_OPERATION],
        ))
        .with_capability(CapabilityEndpointPlan::new(
            federated::CAPABILITY_ID,
            federated::DESCRIPTOR_VERSION,
            [federated::COMPLETE_OPERATION, federated::START_OPERATION],
        ))
        .with_capability(CapabilityEndpointPlan::new(
            credential::CAPABILITY_ID,
            credential::DESCRIPTOR_VERSION,
            [
                credential::ISSUE_OPERATION,
                credential::REVOKE_OPERATION,
                credential::REVOKE_CREDENTIAL_OPERATION,
            ],
        ));
    AppComposition::new(
        vec![caller, web_session, dependencies],
        vec![
            CapabilityBinding::new(
                "web-session",
                password::CAPABILITY_ID,
                password::DESCRIPTOR_VERSION,
                "dependencies",
            ),
            CapabilityBinding::new(
                "caller",
                endpoint::CAPABILITY_ID,
                endpoint::DESCRIPTOR_VERSION,
                "web-session",
            ),
            CapabilityBinding::new(
                "web-session",
                federated::CAPABILITY_ID,
                federated::DESCRIPTOR_VERSION,
                "dependencies",
            ),
            CapabilityBinding::new(
                "web-session",
                credential::CAPABILITY_ID,
                credential::DESCRIPTOR_VERSION,
                "dependencies",
            ),
        ]
        .into_iter()
        .filter(|binding| {
            (password_enabled || binding.capability_id() != password::CAPABILITY_ID)
                && (sso_enabled || binding.capability_id() != federated::CAPABILITY_ID)
        })
        .collect(),
    )
    .resolve()
    .unwrap()
}

async fn handle(app: &lenso_kernel::NativeApp, request: HandleRequest) -> HandleResponse {
    app.invoke::<endpoint::EndpointHandle>("caller", endpoint::HANDLE_OPERATION, request)
        .await
        .unwrap()
        .unwrap()
}

fn request(
    route_id: &str,
    method: &str,
    path: &str,
    query: Option<&str>,
    credential: Option<HandleRequestCredential>,
) -> HandleRequest {
    HandleRequest {
        body: Vec::new().into(),
        credential,
        headers: Vec::new(),
        method: method.to_owned(),
        path: path.to_owned(),
        path_parameters: Vec::new(),
        query: query.map(ToOwned::to_owned),
        request_id: "request-1".to_owned(),
        route_id: route_id.to_owned(),
    }
}

fn header_values<'a>(response: &'a HandleResponse, name: &str) -> Vec<&'a str> {
    response
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
        .collect()
}

fn future_time(seconds: i64) -> String {
    (OffsetDateTime::now_utc() + Duration::seconds(seconds))
        .format(&Rfc3339)
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn browser_methods_follow_bindings_and_password_login_keeps_credentials_in_cookies() {
    tokio::task::LocalSet::new()
        .run_until(async {
            for (password_enabled, sso_enabled, count) in
                [(true, false, 1), (false, true, 1), (true, true, 2)]
            {
                let app = Kernel::start_native(
                    method_plan(password_enabled, sso_enabled),
                    TokioDriver::new(),
                    registry(Rc::new(Observed::default()), "/", true),
                )
                .await
                .unwrap();
                let methods = handle(
                    &app,
                    request(
                        "auth.web-session.methods",
                        "GET",
                        "/auth/methods",
                        None,
                        None,
                    ),
                )
                .await;
                let value: serde_json::Value =
                    serde_json::from_slice(&methods.body.into_shared()).unwrap();
                assert_eq!(value["methods"].as_array().unwrap().len(), count);
                assert_eq!(
                    value["methods"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|m| m["id"] == "password"),
                    password_enabled
                );
                if password_enabled {
                    let mut login = request(
                        "auth.web-session.password",
                        "POST",
                        "/auth/password/login",
                        None,
                        None,
                    );
                    login.headers = vec![endpoint::HandleRequestHeadersItem {
                        name: "content-type".into(),
                        value: "application/json".into(),
                    }];
                    login.body =
                        br#"{"identifier":"alice@example.test","password":"test-password"}"#
                            .to_vec()
                            .into();
                    assert_eq!(handle(&app, login.clone()).await.status, 403);
                    login.headers.push(endpoint::HandleRequestHeadersItem {
                        name: "origin".into(),
                        value: "https://console.example".into(),
                    });
                    let result = handle(&app, login.clone()).await;
                    assert_eq!(result.status, 204);
                    assert!(result.body.clone().into_shared().is_empty());
                    assert!(header_values(&result, "set-cookie").iter().any(|v| {
                        v.starts_with("__Host-lenso-session=opaque-password-session;")
                            && v.contains("HttpOnly")
                    }));
                    login.body = br#"{"identifier":"alice@example.test","password":"incorrect"}"#
                        .to_vec()
                        .into();
                    assert_eq!(handle(&app, login).await.status, 401);
                }
                assert_eq!(
                    app.shutdown(StdDuration::from_secs(1)).await,
                    ShutdownOutcome::Clean
                );
            }
        })
        .await;
}

use lenso_app_plan::{
    AppComposition, CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan,
    PluginInstancePlan, ResolvedAppPlan,
};
use lenso_auth_session_renewal_plugin::{
    PACKAGE_ID, RENEW_PATH, RENEW_ROUTE_ID, STATE_PATH, STATE_ROUTE_ID, SessionRenewalConfig,
};
use lenso_capability_http_endpoint::{
    self as endpoint, HandleRequest, HandleRequestCredential, HandleRequestHeadersItem,
    HandleResponse,
};
use lenso_capability_managed_session::{
    self as managed, IssueManagedError, IssueManagedRequest, ManagedSessionEndpoint,
    ManagedSessionIssueManaged, ManagedSessionProvider, ManagedSessionReadManaged,
    ManagedSessionRenew, ReadManagedError, ReadManagedRequest, ReadManagedResponse, RenewError,
    RenewRequest, SessionResponse,
};
use lenso_kernel::{
    InvocationContext, Kernel, NativeRequestEndpoint, NativeRequestFuture, RuntimeFailure,
    ShutdownOutcome,
};
use lenso_native_adapter::{
    NativePluginFactory, NativePluginFactoryContext, NativePluginInstance, NativePluginRegistry,
};
use lenso_runner::TokioDriver;
use std::{cell::RefCell, rc::Rc, time::Duration as StdDuration};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

const CALLER: &str = "test.renewal-caller";
const PROVIDER: &str = "test.managed-session";
const ORIGIN: &str = "https://app.example";
const SESSION: &str = "__Host-test-session";
const CSRF: &str = "__Host-test-csrf";

#[derive(Clone, Debug)]
struct Factory {
    outcome: Result<SessionResponse, RenewError>,
    observed: Rc<RefCell<Vec<String>>>,
}
impl NativePluginFactory for Factory {
    fn package_id(&self) -> &'static str {
        PROVIDER
    }
    fn instantiate(
        &self,
        _: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        Ok(NativePluginInstance::new(vec![
            Rc::new(ManagedSessionEndpoint::new(self.clone())) as Rc<dyn NativeRequestEndpoint>,
        ]))
    }
}
impl ManagedSessionProvider for Factory {
    fn read_managed(
        &self,
        _: InvocationContext,
        request: ReadManagedRequest,
    ) -> NativeRequestFuture<ManagedSessionReadManaged> {
        self.observed
            .borrow_mut()
            .push(format!("read:{}", request.credential));
        let result = self
            .outcome
            .clone()
            .map(|session| ReadManagedResponse {
                session_id: session.session_id,
                expires_at: session.expires_at,
                absolute_expires_at: session.absolute_expires_at,
                renew_after: session.renew_after,
            })
            .map_err(|error| match error {
                RenewError::InvalidCredential => ReadManagedError::InvalidCredential,
                RenewError::StaleCredential => ReadManagedError::StaleCredential,
                RenewError::Expired => ReadManagedError::Expired,
                RenewError::Revoked => ReadManagedError::Revoked,
                RenewError::PermissionDenied => ReadManagedError::PermissionDenied,
                RenewError::NotEnabled => ReadManagedError::NotEnabled,
                RenewError::Unsupported | RenewError::TooEarly => ReadManagedError::Unsupported,
                RenewError::Unknown(error) => ReadManagedError::Unknown(error),
            });
        Box::pin(std::future::ready(Ok(result)))
    }
    fn issue_managed(
        &self,
        _: InvocationContext,
        _: IssueManagedRequest,
    ) -> NativeRequestFuture<ManagedSessionIssueManaged> {
        Box::pin(std::future::ready(Ok(Err(IssueManagedError::NotEnabled))))
    }
    fn renew(
        &self,
        _: InvocationContext,
        request: RenewRequest,
    ) -> NativeRequestFuture<ManagedSessionRenew> {
        self.observed.borrow_mut().push(request.credential);
        Box::pin(std::future::ready(Ok(self.outcome.clone())))
    }
}
#[derive(Clone, Copy, Debug)]
struct EmptyFactory;
impl NativePluginFactory for EmptyFactory {
    fn package_id(&self) -> &'static str {
        CALLER
    }
    fn instantiate(
        &self,
        _: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        Ok(NativePluginInstance::default())
    }
}

fn plan() -> ResolvedAppPlan {
    AppComposition::new(
        vec![
            PluginInstancePlan::new("caller", CALLER).with_requirement(
                CapabilityRequirementPlan::one(
                    endpoint::CAPABILITY_ID,
                    endpoint::DESCRIPTOR_VERSION,
                ),
            ),
            PluginInstancePlan::new("renewal", PACKAGE_ID)
                .with_authoring(2, "lenso.native-authoring@2")
                .with_configuration(
                    serde_json::json!({"session_cookie_name":SESSION,
                "csrf_cookie_name":CSRF,"allowed_origin":ORIGIN})
                    .to_string(),
                )
                .with_requirement(
                    CapabilityRequirementPlan::one(
                        managed::CAPABILITY_ID,
                        managed::DESCRIPTOR_VERSION,
                    )
                    .with_requirement_id("managed_sessions"),
                )
                .with_capability(CapabilityEndpointPlan::new(
                    endpoint::CAPABILITY_ID,
                    endpoint::DESCRIPTOR_VERSION,
                    [endpoint::DESCRIBE_OPERATION, endpoint::HANDLE_OPERATION],
                )),
            PluginInstancePlan::new("account", PROVIDER).with_capability(
                CapabilityEndpointPlan::new(
                    managed::CAPABILITY_ID,
                    managed::DESCRIPTOR_VERSION,
                    [
                        managed::ISSUE_MANAGED_OPERATION,
                        managed::READ_MANAGED_OPERATION,
                        managed::RENEW_OPERATION,
                    ],
                ),
            ),
        ],
        vec![
            CapabilityBinding::new(
                "caller",
                endpoint::CAPABILITY_ID,
                endpoint::DESCRIPTOR_VERSION,
                "renewal",
            ),
            CapabilityBinding::new(
                "renewal",
                managed::CAPABILITY_ID,
                managed::DESCRIPTOR_VERSION,
                "account",
            )
            .with_requirement_id("managed_sessions"),
        ],
    )
    .resolve()
    .unwrap()
}
fn request() -> HandleRequest {
    HandleRequest {
        body: Vec::new().into(),
        credential: Some(HandleRequestCredential {
            scheme: "session".into(),
            value: "selected-synthetic".into(),
        }),
        headers: vec![HandleRequestHeadersItem {
            name: "origin".into(),
            value: ORIGIN.into(),
        }],
        method: "POST".into(),
        path: RENEW_PATH.into(),
        path_parameters: Vec::new(),
        query: None,
        request_id: "synthetic-request".into(),
        route_id: RENEW_ROUTE_ID.into(),
    }
}
fn state_request() -> HandleRequest {
    let mut input = request();
    input.method = "GET".into();
    input.path = STATE_PATH.into();
    input.route_id = STATE_ROUTE_ID.into();
    input.headers = vec![HandleRequestHeadersItem {
        name: "sec-fetch-site".into(),
        value: "same-origin".into(),
    }];
    input
}
fn future(seconds: i64) -> String {
    (OffsetDateTime::now_utc() + Duration::seconds(seconds))
        .format(&Rfc3339)
        .unwrap()
}
fn success() -> SessionResponse {
    SessionResponse {
        session_id: "ses_synthetic".into(),
        credential: "new-synthetic-token".into(),
        expires_at: future(3600),
        absolute_expires_at: future(86400),
        renew_after: future(600),
    }
}
fn headers<'a>(response: &'a HandleResponse, name: &str) -> Vec<&'a str> {
    response
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
        .collect()
}
async fn call(
    request: HandleRequest,
    outcome: Result<SessionResponse, RenewError>,
) -> (HandleResponse, Vec<String>) {
    let observed = Rc::new(RefCell::new(Vec::new()));
    let registry = NativePluginRegistry::new()
        .with_linked_factories()
        .with_factory(EmptyFactory)
        .with_factory(Factory {
            outcome,
            observed: Rc::clone(&observed),
        });
    let app = Kernel::start_native(plan(), TokioDriver::new(), registry)
        .await
        .unwrap();
    let response = app
        .invoke::<endpoint::EndpointHandle>("caller", endpoint::HANDLE_OPERATION, request)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        app.shutdown(StdDuration::from_secs(2)).await,
        ShutdownOutcome::Clean
    );
    let seen = observed.borrow().clone();
    (response, seen)
}

#[tokio::test(flavor = "current_thread")]
async fn only_success_sets_secure_cookies_and_selected_evidence_reaches_provider() {
    tokio::task::LocalSet::new()
        .run_until(Box::pin(async {
            let mut input = request();
            // These raw headers are not credential sources even when directly testing
            // the adapter outside the real ingress stripping boundary.
            input.headers.push(HandleRequestHeadersItem {
                name: "cookie".into(),
                value: "forged=ignored".into(),
            });
            let (response, seen) = call(input, Ok(success())).await;
            assert_eq!(seen, ["selected-synthetic"]);
            assert_eq!(response.status, 200);
            let cookies = headers(&response, "set-cookie");
            assert_eq!(cookies.len(), 2);
            assert!(
                cookies[0].starts_with("__Host-test-session=new-synthetic-token; Path=/; Max-Age=")
            );
            assert!(cookies[0].ends_with("; Secure; HttpOnly; SameSite=Lax"));
            assert!(cookies[1].starts_with("__Host-test-csrf="));
            assert!(cookies[1].ends_with("; Secure; SameSite=Lax"));
            assert_eq!(headers(&response, "cache-control"), ["no-store"]);
            let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
            assert!(body.get("credential").is_none());
            assert!(!String::from_utf8_lossy(&response.body).contains("new-synthetic-token"));
            assert!(body.get("renew_after").is_some());
            let mut final_rotation = success();
            final_rotation.renew_after = final_rotation.absolute_expires_at.clone();
            let (response, _) = call(request(), Ok(final_rotation)).await;
            assert_eq!(response.status, 200);
            assert_eq!(headers(&response, "set-cookie").len(), 2);
        }))
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn all_domain_failures_preserve_browser_cookies_including_stale_rotation() {
    tokio::task::LocalSet::new()
        .run_until(Box::pin(async {
            for (error, status) in [
                (RenewError::StaleCredential, 409),
                (RenewError::InvalidCredential, 401),
                (RenewError::Expired, 401),
                (RenewError::Revoked, 401),
                (RenewError::PermissionDenied, 403),
                (RenewError::TooEarly, 429),
                (RenewError::NotEnabled, 409),
                (RenewError::Unsupported, 409),
            ] {
                let (response, seen) = call(request(), Err(error)).await;
                assert_eq!(seen, ["selected-synthetic"]);
                assert_eq!(response.status, status);
                assert_eq!(headers(&response, "set-cookie"), [] as [&str; 0]);
                assert_eq!(headers(&response, "cache-control"), ["no-store"]);
            }
            let mut invalid = success();
            invalid.credential = "unsafe; Cookie=value".into();
            let (response, _) = call(request(), Ok(invalid)).await;
            assert_eq!(response.status, 502);
            assert_eq!(headers(&response, "set-cookie"), [] as [&str; 0]);
        }))
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn origin_body_and_missing_selected_session_fail_before_provider_mutation() {
    tokio::task::LocalSet::new()
        .run_until(Box::pin(async {
            let mut missing_origin = request();
            missing_origin.headers.clear();
            let mut foreign = request();
            foreign.headers[0].value = "https://attacker.example".into();
            let mut duplicate = request();
            duplicate.headers.push(duplicate.headers[0].clone());
            let mut body = request();
            body.body = br#"{"credential":"forged","profile":"operator"}"#.to_vec().into();
            let mut absent = request();
            absent.credential = None;
            let mut wrong_scheme = request();
            wrong_scheme.credential.as_mut().unwrap().scheme = "bearer".into();
            for (input, status) in [
                (missing_origin, 403),
                (foreign, 403),
                (duplicate, 403),
                (body, 400),
                (absent, 401),
                (wrong_scheme, 401),
            ] {
                let (response, seen) = call(input, Ok(success())).await;
                assert_eq!(seen, [] as [&str; 0]);
                assert_eq!(response.status, status);
                assert_eq!(headers(&response, "set-cookie"), [] as [&str; 0]);
            }
        }))
        .await;
}

#[test]
fn config_requires_exact_https_origin_and_distinct_host_cookies() {
    assert!(SessionRenewalConfig::new(SESSION, CSRF, ORIGIN).is_ok());
    for origin in [
        "https://app.example/",
        "https://app.example/path",
        "http://app.example",
        "https://user@app.example",
        "null",
    ] {
        assert!(SessionRenewalConfig::new(SESSION, CSRF, origin).is_err());
    }
    assert!(SessionRenewalConfig::new(SESSION, SESSION, ORIGIN).is_err());
    assert!(SessionRenewalConfig::new("session", CSRF, ORIGIN).is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn state_reads_current_cookie_metadata_without_rotation_or_cookie_material() {
    tokio::task::LocalSet::new()
        .run_until(Box::pin(async {
            for input in [state_request(), {
                let mut input = state_request();
                input.headers = vec![HandleRequestHeadersItem {
                    name: "origin".into(),
                    value: ORIGIN.into(),
                }];
                input
            }] {
                let (response, seen) = call(input, Ok(success())).await;
                assert_eq!(seen, ["read:selected-synthetic"]);
                assert_eq!(response.status, 200);
                assert_eq!(headers(&response, "set-cookie"), [] as [&str; 0]);
                assert_eq!(headers(&response, "cache-control"), ["no-store"]);
                let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
                assert_eq!(body["authenticated"], true);
                assert_eq!(body["session_id"], "ses_synthetic");
                assert!(body.get("credential").is_none());
                assert!(!String::from_utf8_lossy(&response.body).contains("synthetic-token"));
            }
            for (error, status) in [
                (RenewError::InvalidCredential, 401),
                (RenewError::StaleCredential, 409),
                (RenewError::Expired, 401),
                (RenewError::Revoked, 401),
                (RenewError::PermissionDenied, 403),
                (RenewError::NotEnabled, 409),
                (RenewError::Unsupported, 409),
            ] {
                let (response, seen) = call(state_request(), Err(error)).await;
                assert_eq!(seen, ["read:selected-synthetic"]);
                assert_eq!(response.status, status);
                assert_eq!(headers(&response, "set-cookie"), [] as [&str; 0]);
            }
        }))
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn state_rejects_unsafe_or_ambiguous_origin_before_reading_provider() {
    tokio::task::LocalSet::new()
        .run_until(Box::pin(async {
            let mut absent = state_request();
            absent.headers.clear();
            let mut foreign_site = state_request();
            foreign_site.headers[0].value = "cross-site".into();
            let mut foreign_origin = state_request();
            foreign_origin.headers.push(HandleRequestHeadersItem {
                name: "origin".into(),
                value: "https://attacker.example".into(),
            });
            let mut duplicate = state_request();
            duplicate.headers.push(duplicate.headers[0].clone());
            let mut body = state_request();
            body.body = b"forged".to_vec().into();
            let mut scheme = state_request();
            scheme.credential.as_mut().unwrap().scheme = "bearer".into();
            for (input, status) in [
                (absent, 403),
                (foreign_site, 403),
                (foreign_origin, 403),
                (duplicate, 403),
                (body, 400),
                (scheme, 401),
            ] {
                let (response, seen) = call(input, Ok(success())).await;
                assert_eq!(seen, [] as [&str; 0]);
                assert_eq!(response.status, status);
                assert_eq!(headers(&response, "set-cookie"), [] as [&str; 0]);
            }
        }))
        .await;
}

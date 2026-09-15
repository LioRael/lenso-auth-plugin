use super::*;
use lenso_capability_federated_auth as federated;
use lenso_capability_http_client as http_client;
use lenso_capability_http_endpoint as endpoint;
use lenso_http_egress_plugin::{HttpEgressConfig, HttpEgressEventFactory};
use lenso_web_ingress_plugin::{SessionCookieConfig, WebIngressConfig, WebIngressEventFactory};
fn ingress_config() -> WebIngressConfig {
    WebIngressConfig::default()
        .with_session_cookie(
            SessionCookieConfig::new("__Host-session", "__Host-csrf", "x-csrf-token").unwrap(),
        )
        .unwrap()
        .with_request_limits(65536, 16384)
        .unwrap()
        .with_request_timeout(Duration::from_secs(10))
        .unwrap()
}
pub(super) fn extend_plan(
    instances: &mut Vec<PluginInstancePlan>,
    bindings: &mut Vec<CapabilityBinding>,
    origin: &str,
) {
    let web = PluginInstancePlan::new("web-session", lenso_auth_web_session_plugin::PACKAGE_ID)
        .with_configuration(
            json!({"session_cookie_name":"__Host-session","csrf_cookie_name":"__Host-csrf"})
                .to_string(),
        )
        .with_requirement(CapabilityRequirementPlan::one(
            federated::CAPABILITY_ID,
            federated::DESCRIPTOR_VERSION,
        ))
        .with_requirement(CapabilityRequirementPlan::one(
            issuer::CAPABILITY_ID,
            issuer::DESCRIPTOR_VERSION,
        ))
        .with_capability(CapabilityEndpointPlan::new(
            endpoint::CAPABILITY_ID,
            endpoint::DESCRIPTOR_VERSION,
            [endpoint::DESCRIBE_OPERATION, endpoint::HANDLE_OPERATION],
        ));
    let ingress = PluginInstancePlan::new("ingress", "lenso.web-ingress")
        .with_configuration(serde_json::to_string(&ingress_config()).unwrap())
        .with_requirement(CapabilityRequirementPlan::many(
            endpoint::CAPABILITY_ID,
            endpoint::DESCRIPTOR_VERSION,
        ));
    let config = HttpEgressConfig::new(vec![origin.to_owned()])
        .unwrap()
        .with_timeouts(Duration::from_secs(10), Duration::from_secs(10))
        .unwrap();
    let egress = PluginInstancePlan::new("egress", "lenso.http-egress")
        .with_configuration(serde_json::to_string(&config).unwrap())
        .with_capability(CapabilityEndpointPlan::new(
            http_client::CAPABILITY_ID,
            http_client::DESCRIPTOR_VERSION,
            [http_client::SEND_OPERATION],
        ));
    let mut oidc=PluginInstancePlan::new("oidc",lenso_auth_oidc_client_plugin::PACKAGE_ID).with_configuration(json!({"provider":"g4-fixture","issuer":origin,"authorization_endpoint":format!("{origin}/fixture/authorize"),"token_endpoint":format!("{origin}/fixture/token"),"jwks_uri":format!("{origin}/fixture/jwks"),"client_id":"g4-proof","client_secret_ref":"oidc","redirect_uri":format!("{origin}/auth/oidc/callback"),"scopes":["openid"],"audience":["proof.resource@1:read"],"flow_ttl_seconds":300,"session_ttl_seconds":3600}).to_string()).with_capability(CapabilityEndpointPlan::new(federated::CAPABILITY_ID,federated::DESCRIPTOR_VERSION,[federated::COMPLETE_OPERATION,federated::START_OPERATION]));
    for (cap, ver, provider) in [
        (
            secrets::CAPABILITY_ID,
            secrets::DESCRIPTOR_VERSION,
            "secrets",
        ),
        (flow::CAPABILITY_ID, flow::DESCRIPTOR_VERSION, "oauth"),
        (
            http_client::CAPABILITY_ID,
            http_client::DESCRIPTOR_VERSION,
            "egress",
        ),
        (
            directory::CAPABILITY_ID,
            directory::DESCRIPTOR_VERSION,
            "account",
        ),
        (issuer::CAPABILITY_ID, issuer::DESCRIPTOR_VERSION, "account"),
    ] {
        oidc = oidc.with_requirement(CapabilityRequirementPlan::one(cap, ver));
        bindings.push(CapabilityBinding::new("oidc", cap, ver, provider));
    }
    for (consumer, cap, ver, provider) in [
        (
            "ingress",
            endpoint::CAPABILITY_ID,
            endpoint::DESCRIPTOR_VERSION,
            "web-session",
        ),
        (
            "web-session",
            federated::CAPABILITY_ID,
            federated::DESCRIPTOR_VERSION,
            "oidc",
        ),
        (
            "web-session",
            issuer::CAPABILITY_ID,
            issuer::DESCRIPTOR_VERSION,
            "account",
        ),
    ] {
        bindings.push(CapabilityBinding::new(consumer, cap, ver, provider));
    }
    instances.extend([web, ingress, egress, oidc]);
}
#[derive(Deserialize)]
struct HttpInput {
    method: String,
    uri: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}
#[wasm_bindgen]
pub async fn handle_http(input: String, scope: JsValue) -> Result<String, JsValue> {
    let input: HttpInput = serde_json::from_str(&input).map_err(err)?;
    let mut request = http::Request::builder()
        .method(input.method.as_str())
        .uri(input.uri.as_str())
        .body(bytes::Bytes::from(input.body))
        .map_err(err)?;
    for (name, value) in input.headers {
        request.headers_mut().append(
            http::HeaderName::from_bytes(name.as_bytes()).map_err(err)?,
            http::HeaderValue::from_str(&value).map_err(err)?,
        );
    }
    let signing = text(&scope, "signing")?;
    let origin = text(&scope, "origin")?;
    lenso_auth_router_plugin::link_plugin();
    lenso_auth_web_session_plugin::link_plugin();
    lenso_auth_oidc_client_plugin::link_plugin();
    let ingress = WebIngressEventFactory::new();
    lenso_auth_account_plugin::link_plugin();
    lenso_auth_oauth_flow_plugin::link_plugin();
    let registry = NativePluginRegistry::new()
        .with_factory_override(lenso_auth_account_plugin::workers_factory(
            "ACCOUNT_DB",
            property(&scope, "accountBatch")?.dyn_into().map_err(err)?,
        ))
        .map_err(err)?
        .with_factory_override(lenso_auth_oauth_flow_plugin::workers_factory(
            "OAUTH_DB",
            property(&scope, "oauthBatch")?.dyn_into().map_err(err)?,
        ))
        .map_err(err)?
        .with_factory(ingress.clone())
        .with_factory(HttpEgressEventFactory::from_js(
            property(&scope, "httpFetch")?.dyn_into().map_err(err)?,
        ))
        .with_linked_factories()
        .with_factory(Caller)
        .with_factory(Secrets(BTreeMap::from([
            ("signing".into(), signing.clone()),
            ("pepper".into(), text(&scope, "pepper")?),
            ("oauth".into(), text(&scope, "oauth")?),
            ("oidc".into(), text(&scope, "oidc")?),
        ])));
    let driver = WorkersDriver::new();
    let _event = EventGuard(driver.clone());
    let token = CancellationToken::new();
    let _cancel = CancellationGuard::new(scope, token.clone());
    let app = Kernel::start_native(plan(&signing, Some(&origin), None)?, driver, registry)
        .await
        .map_err(|e| JsValue::from_str(&format!("startup: {e:?}")))?;
    let response = ingress.handle(request, token).await;
    let ready = app.is_ready();
    let shutdown = app.shutdown(Duration::from_secs(2)).await;
    if shutdown != ShutdownOutcome::Clean {
        return Err(err("unclean shutdown"));
    }
    let (parts, body) = response.map_err(err)?.into_parts();
    let headers = parts
        .headers
        .iter()
        .map(|(k, v)| Ok((k.as_str(), v.to_str().map_err(err)?)))
        .collect::<Result<Vec<_>, JsValue>>()?;
    Ok(json!({"status":parts.status.as_u16(),"headers":headers,"body":body.as_ref(),"ready":ready,"shutdown":"clean"}).to_string())
}

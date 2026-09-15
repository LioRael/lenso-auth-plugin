//! Qualification composition: real method Plugins, controlled SMS delivery only.
use super::*;
use lenso_capability_device_auth as device;
use lenso_capability_oidc_provider as oidc;
use lenso_capability_password_auth as password;
use lenso_capability_phone_auth as phone;
use lenso_capability_sms_delivery as sms;

pub(super) fn link() {
    lenso_auth_password_plugin::link_plugin();
    lenso_auth_phone_plugin::link_plugin();
    lenso_auth_device_plugin::link_plugin();
    lenso_auth_api_token_plugin::link_plugin();
    lenso_auth_oidc_plugin::link_plugin();
}

pub(super) fn selected(operation: &str) -> Option<&str> {
    operation
        .split_once('.')
        .map(|(method, _)| method)
        .filter(|method| matches!(*method, "password" | "phone" | "device" | "api" | "oidc"))
}

pub(super) fn descriptor(package: &str) -> Option<&'static str> {
    match package {
        lenso_auth_password_plugin::PACKAGE_ID => {
            Some(lenso_auth_password_plugin::PLUGIN_DESCRIPTOR_JSON)
        }
        lenso_auth_phone_plugin::PACKAGE_ID => {
            Some(lenso_auth_phone_plugin::PLUGIN_DESCRIPTOR_JSON)
        }
        lenso_auth_device_plugin::PACKAGE_ID => {
            Some(lenso_auth_device_plugin::PLUGIN_DESCRIPTOR_JSON)
        }
        lenso_auth_api_token_plugin::PACKAGE_ID => {
            Some(lenso_auth_api_token_plugin::PLUGIN_DESCRIPTOR_JSON)
        }
        lenso_auth_oidc_plugin::PACKAGE_ID => Some(lenso_auth_oidc_plugin::PLUGIN_DESCRIPTOR_JSON),
        _ => None,
    }
}

pub(super) fn extend_plan(
    instances: &mut Vec<PluginInstancePlan>,
    bindings: &mut Vec<CapabilityBinding>,
    method: &str,
    signing: &str,
    jwks: Value,
) {
    let (package, cap, version, ops, config) = match method {
        "password" => (
            lenso_auth_password_plugin::PACKAGE_ID,
            password::CAPABILITY_ID,
            password::DESCRIPTOR_VERSION,
            vec![password::REGISTER_OPERATION, password::LOGIN_OPERATION],
            json!({"schema":"password","d1_binding":"PASSWORD_DB","audience":["proof.resource@1:read"],"session_ttl_seconds":3600,"max_failures":3,"failure_window_seconds":60}),
        ),
        "phone" => (
            lenso_auth_phone_plugin::PACKAGE_ID,
            phone::CAPABILITY_ID,
            phone::DESCRIPTOR_VERSION,
            vec![
                phone::START_OTP_OPERATION,
                phone::VERIFY_OTP_OPERATION,
                phone::SET_PASSWORD_OPERATION,
                phone::PASSWORD_LOGIN_OPERATION,
            ],
            json!({"schema":"phone","d1_binding":"PHONE_DB","otp_secret_ref":"otp","environment":"development","return_debug_code":true,"set_password_callers":["proof.caller/caller"],"audience":["proof.resource@1:read"],"otp_code_length":6,"otp_ttl_seconds":60,"resend_cooldown_seconds":30,"otp_max_attempts":3,"start_window_seconds":60,"max_starts_per_ip":3,"max_password_failures":3,"password_failure_window_seconds":60,"session_ttl_seconds":3600}),
        ),
        "device" => (
            lenso_auth_device_plugin::PACKAGE_ID,
            device::CAPABILITY_ID,
            device::DESCRIPTOR_VERSION,
            vec![
                device::OBSERVE_OPERATION,
                device::LIST_OPERATION,
                device::SET_TRUST_OPERATION,
            ],
            json!({"schema":"device","d1_binding":"DEVICE_DB"}),
        ),
        "api" => (
            lenso_auth_api_token_plugin::PACKAGE_ID,
            auth::CAPABILITY_ID,
            auth::DESCRIPTOR_VERSION,
            vec![auth::AUTHENTICATE_OPERATION],
            json!({"schema":"api","d1_binding":"API_TOKEN_DB","issuer":"api-proof","assertion_public_key":lenso_auth_api_token_plugin::assertion_public_key(signing),"assertion_signing_key_secret":"signing","token_pepper_secret":"pepper","assertion_ttl_seconds":30}),
        ),
        "oidc" => (
            lenso_auth_oidc_plugin::PACKAGE_ID,
            oidc::CAPABILITY_ID,
            oidc::DESCRIPTOR_VERSION,
            vec![
                oidc::AUTHORIZE_OPERATION,
                oidc::EXCHANGE_OPERATION,
                oidc::METADATA_OPERATION,
                oidc::JWKS_OPERATION,
            ],
            json!({"schema":"oidc","d1_binding":"OIDC_DB","signing_key_secret":"provider-signing","code_pepper_secret":"pepper","issuer":"https://oidc.proof.invalid","jwks":jwks,"key_id":"proof-rsa","client_id":"proof-client","redirect_uris":["https://client.proof.invalid/callback"],"authorize_callers":["proof.caller/caller"],"audience":["proof.resource@1:read"],"code_ttl_seconds":30,"token_ttl_seconds":60}),
        ),
        _ => unreachable!(),
    };
    let mut plugin = PluginInstancePlan::new(method, package)
        .with_configuration(config.to_string())
        .with_capability(CapabilityEndpointPlan::new(cap, version, ops))
        .with_requirement(CapabilityRequirementPlan::one(
            secrets::CAPABILITY_ID,
            secrets::DESCRIPTOR_VERSION,
        ));
    bindings.push(CapabilityBinding::new(
        method,
        secrets::CAPABILITY_ID,
        secrets::DESCRIPTOR_VERSION,
        "secrets",
    ));
    if matches!(method, "password" | "phone" | "oidc") {
        for (dependency, revision) in [
            (directory::CAPABILITY_ID, directory::DESCRIPTOR_VERSION),
            (issuer::CAPABILITY_ID, issuer::DESCRIPTOR_VERSION),
        ] {
            plugin = plugin.with_requirement(CapabilityRequirementPlan::one(dependency, revision));
            bindings.push(CapabilityBinding::new(
                method, dependency, revision, "account",
            ));
        }
    }
    if method == "phone" {
        plugin = plugin.with_requirement(CapabilityRequirementPlan::one(
            sms::CAPABILITY_ID,
            sms::DESCRIPTOR_VERSION,
        ));
        instances.push(PluginInstancePlan::new("sms", "proof.sms").with_capability(
            CapabilityEndpointPlan::new(
                sms::CAPABILITY_ID,
                sms::DESCRIPTOR_VERSION,
                [sms::SEND_OPERATION],
            ),
        ));
        bindings.push(CapabilityBinding::new(
            method,
            sms::CAPABILITY_ID,
            sms::DESCRIPTOR_VERSION,
            "sms",
        ));
    }
    if method == "api" {
        let router = instances
            .iter_mut()
            .find(|i| i.instance_key() == "router")
            .unwrap();
        *router=router.clone().with_configuration(json!({"routes":{"session":"lenso.auth.account/account","bearer":"lenso.auth.api-token/api"}}).to_string());
        bindings.push(CapabilityBinding::new(
            "router",
            auth::CAPABILITY_ID,
            auth::DESCRIPTOR_VERSION,
            "api",
        ));
    } else {
        for name in ["caller", "denied"] {
            let caller = instances
                .iter_mut()
                .find(|i| i.instance_key() == name)
                .unwrap();
            *caller = caller
                .clone()
                .with_requirement(CapabilityRequirementPlan::one(cap, version));
            bindings.push(CapabilityBinding::new(name, cap, version, method));
        }
    }
    instances.push(plugin);
}

pub(super) fn registry(
    registry: NativePluginRegistry,
    method: Option<&str>,
    scope: &JsValue,
) -> Result<NativePluginRegistry, JsValue> {
    let Some(method) = method else {
        return Ok(registry);
    };
    let batch = |name| {
        property(scope, name)?
            .dyn_into::<js_sys::Function>()
            .map_err(err)
    };
    Ok(match method {
        "password" => registry.with_factory_override(lenso_auth_password_plugin::workers_factory(
            "PASSWORD_DB",
            batch("passwordBatch")?,
        )),
        "phone" => registry.with_factory_override(lenso_auth_phone_plugin::workers_factory(
            "PHONE_DB",
            batch("phoneBatch")?,
        )),
        "device" => registry.with_factory_override(lenso_auth_device_plugin::workers_factory(
            "DEVICE_DB",
            batch("deviceBatch")?,
        )),
        "api" => registry.with_factory_override(lenso_auth_api_token_plugin::workers_factory(
            "API_TOKEN_DB",
            batch("apiBatch")?,
        )),
        "oidc" => registry.with_factory_override(lenso_auth_oidc_plugin::workers_factory(
            "OIDC_DB",
            batch("oidcBatch")?,
        )),
        _ => unreachable!(),
    }
    .map_err(err)?
    .with_factory(Sms))
}

#[derive(Clone, Debug)]
pub(super) struct Sms;
impl NativePluginFactory for Sms {
    fn package_id(&self) -> &'static str {
        "proof.sms"
    }
    fn package_version(&self) -> &'static str {
        "0.1.0"
    }
    fn instantiate(
        &self,
        _: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        Ok(NativePluginInstance::new(vec![Rc::new(
            sms::SmsEndpoint::new(self.clone()),
        )]))
    }
}
impl sms::SmsProvider for Sms {
    fn send(&self, _: InvocationContext, _: sms::SendRequest) -> NativeRequestFuture<sms::Sms> {
        Box::pin(async { Ok(Ok(sms::SendResponse { accepted: true })) })
    }
}

pub(super) async fn invoke(
    app: &lenso_kernel::NativeApp,
    caller: &str,
    operation: &str,
    request: Value,
    scope: &JsValue,
    cancellation: CancellationToken,
) -> Result<Value, JsValue> {
    macro_rules! call {($ty:ty,$op:expr)=>{{
        let q=serde_json::from_value(request).map_err(err)?;
        match app.invoke_with_context::<$ty>(caller,$op,app.invocation_context_after(Duration::from_secs(15),cancellation),q).await {
            Ok(value)=>serde_json::to_value(value).map_err(err),Err(_)=>Ok(json!({"RuntimeFailure":true})),
        }
    }}}
    match operation {
        "password.register" => call!(password::PasswordRegister, password::REGISTER_OPERATION),
        "password.login" => call!(password::PasswordLogin, password::LOGIN_OPERATION),
        "phone.start_otp" => call!(phone::PhoneStartOtp, phone::START_OTP_OPERATION),
        "phone.verify_otp" => call!(phone::PhoneVerifyOtp, phone::VERIFY_OTP_OPERATION),
        "phone.set_password" => call!(phone::PhoneSetPassword, phone::SET_PASSWORD_OPERATION),
        "phone.password_login" => call!(phone::PhonePasswordLogin, phone::PASSWORD_LOGIN_OPERATION),
        "device.observe" => call!(device::DeviceObserve, device::OBSERVE_OPERATION),
        "device.list" => call!(device::DeviceList, device::LIST_OPERATION),
        "device.set_trust" => call!(device::DeviceSetTrust, device::SET_TRUST_OPERATION),
        "oidc.authorize" => call!(oidc::OidcProviderAuthorize, oidc::AUTHORIZE_OPERATION),
        "oidc.exchange" => call!(oidc::OidcProviderExchange, oidc::EXCHANGE_OPERATION),
        "oidc.metadata" => call!(oidc::OidcProviderMetadata, oidc::METADATA_OPERATION),
        "oidc.jwks" => call!(oidc::OidcProviderJwks, oidc::JWKS_OPERATION),
        "api.authenticate" => call!(auth::Auth, auth::AUTHENTICATE_OPERATION),
        "api.verify_target" => {
            use lenso_auth_sdk::{
                ActorAssertionVerifier, AuthOutcome, FixedClock, decode_auth_response,
            };
            let request = serde_json::from_value(request).map_err(err)?;
            let response = app
                .invoke::<auth::Auth>(caller, auth::AUTHENTICATE_OPERATION, request)
                .await
                .map_err(err)?
                .map_err(err)?;
            let AuthOutcome::Authenticated(assertion) =
                decode_auth_response(response).map_err(err)?
            else {
                return Err(err("absent assertion"));
            };
            let context = assertion
                .attach(app.invocation_context_after(Duration::from_secs(2), cancellation))
                .map_err(err)?;
            let verifier = ActorAssertionVerifier::from_public_key_base64(
                "api-proof",
                &lenso_auth_api_token_plugin::assertion_public_key(&text(scope, "signing")?),
            )
            .map_err(err)?;
            let clock = FixedClock::new(time::OffsetDateTime::now_utc());
            Ok(
                json!({"valid":verifier.project_context::<ProofService>(&context,"proof.resource@1","read",&clock).is_ok(),"wrong_audience_rejected":verifier.project_context::<ProofService>(&context,"outside@1","read",&clock).is_err()}),
            )
        }
        "api.issue" | "api.revoke_token" | "api.revoke_session" => {
            use lenso_auth_api_token_plugin::{
                ApiTokenAuthOperator, IssueApiToken, workers::D1Binding,
            };
            let binding = D1Binding::new(
                "API_TOKEN_DB",
                property(scope, "apiBatch")?.dyn_into().map_err(err)?,
            );
            let operator = ApiTokenAuthOperator::connect_workers(binding)
                .await
                .map_err(err)?;
            if operation == "api.issue" {
                #[derive(Deserialize)]
                struct Spec {
                    subject: String,
                    actor_kind: String,
                    assurance: String,
                    audience: Vec<String>,
                    claims: BTreeMap<String, Value>,
                    expires_at: String,
                }
                let q: Spec = serde_json::from_value(request).map_err(err)?;
                let token = operator
                    .issue(
                        text(scope, "pepper")?.as_bytes(),
                        IssueApiToken {
                            subject: q.subject,
                            actor_kind: q.actor_kind,
                            assurance: q.assurance,
                            audience: q.audience,
                            claims: q.claims,
                            expires_at: time::OffsetDateTime::parse(
                                &q.expires_at,
                                &time::format_description::well_known::Rfc3339,
                            )
                            .map_err(err)?,
                        },
                    )
                    .await
                    .map_err(err)?;
                Ok(
                    json!({"Ok":{"token_id":token.token_id(),"session_id":token.session_id(),"credential":token.expose_secret()}}),
                )
            } else {
                let id = request["id"]
                    .as_str()
                    .ok_or_else(|| err("missing identifier"))?;
                let changed = if operation == "api.revoke_token" {
                    operator.revoke_token(id).await
                } else {
                    operator.revoke_session(id).await
                }
                .map_err(err)?;
                Ok(json!({"Ok":{"changed":changed}}))
            }
        }
        _ => Err(err("unknown method operation")),
    }
}

struct ProofService;
impl lenso_auth_sdk::TypedActor for ProofService {
    fn from_assertion(
        assertion: &lenso_auth_sdk::ActorAssertion,
    ) -> Result<Self, lenso_auth_sdk::ActorProjectionError> {
        if assertion.actor_kind() == "service" {
            Ok(Self)
        } else {
            Err(lenso_auth_sdk::ActorProjectionError::UnexpectedActorKind {
                expected: "service".into(),
                actual: assertion.actor_kind().into(),
            })
        }
    }
}

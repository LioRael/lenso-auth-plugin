#[allow(
    dead_code,
    reason = "Shared Driver includes helpers unused by this host."
)]
#[path = "../../../../../../lenso-runtime-rust/design-workers-compatibility/experiments/workers-g1/host/src/driver.rs"]
mod driver;
use driver::WorkersDriver;
use lenso_app_plan::{
    CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan, PluginInstancePlan,
    ResolvedAppPlan,
};
use lenso_capability_account_admin as admin;
use lenso_capability_auth as auth;
use lenso_capability_auth_delegation as delegation;
use lenso_capability_credential_issuer as issuer;
use lenso_capability_identity_directory as directory;
use lenso_capability_oauth_flow as flow;
use lenso_capability_secrets as secrets;
use lenso_kernel::{
    CancellationToken, InvocationContext, Kernel, NativeRequestFuture, RuntimeFailure,
    ShutdownOutcome,
};
use lenso_native_adapter::{
    NativePluginFactory, NativePluginFactoryContext, NativePluginInstance, NativePluginRegistry,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, rc::Rc, time::Duration};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(raw_module = "../cancellation.mjs")]
extern "C" {
    fn cancellation(scope: &JsValue, callback: &JsValue);
}
struct CancellationGuard {
    scope: JsValue,
    _callback: Closure<dyn FnMut()>,
}
impl CancellationGuard {
    fn new(scope: JsValue, token: CancellationToken) -> Self {
        let callback = Closure::new(move || token.cancel());
        cancellation(&scope, callback.as_ref());
        Self {
            scope,
            _callback: callback,
        }
    }
}
impl Drop for CancellationGuard {
    fn drop(&mut self) {
        cancellation(&self.scope, &JsValue::NULL);
    }
}
struct EventGuard(WorkersDriver);
impl Drop for EventGuard {
    fn drop(&mut self) {
        self.0.request_shutdown();
    }
}
fn err(_: impl std::fmt::Debug) -> JsValue {
    JsValue::from_str("Auth proof event failed")
}
fn property(scope: &JsValue, name: &str) -> Result<JsValue, JsValue> {
    js_sys::Reflect::get(scope, &JsValue::from_str(name))
}
fn text(scope: &JsValue, name: &str) -> Result<String, JsValue> {
    property(scope, name)?
        .as_string()
        .ok_or_else(|| err("missing event config"))
}
#[derive(Clone)]
struct Secrets(BTreeMap<String, String>);
impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProofSecrets(redacted)")
    }
}
impl NativePluginFactory for Secrets {
    fn package_version(&self) -> &'static str {
        "0.1.0"
    }
    fn package_id(&self) -> &'static str {
        "proof.secrets"
    }
    fn instantiate(
        &self,
        _: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        Ok(NativePluginInstance::new(vec![Rc::new(
            secrets::SecretsEndpoint::new(self.clone()),
        )]))
    }
}
impl secrets::SecretsProvider for Secrets {
    fn resolve(
        &self,
        _: InvocationContext,
        request: secrets::ResolveRequest,
    ) -> NativeRequestFuture<secrets::Secrets> {
        let value = self.0.get(&request.reference).cloned();
        Box::pin(async move {
            value
                .map(|value| Ok(secrets::ResolveResponse { value }))
                .ok_or_else(|| RuntimeFailure::PluginFailure {
                    detail: "proof secret missing".into(),
                })
        })
    }
}
#[derive(Debug)]
struct Caller;
impl NativePluginFactory for Caller {
    fn package_version(&self) -> &'static str {
        "0.1.0"
    }
    fn package_id(&self) -> &'static str {
        "proof.caller"
    }
    fn instantiate(
        &self,
        _: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        Ok(NativePluginInstance::default())
    }
}
fn plan(signing: &str, origin: Option<&str>) -> Result<ResolvedAppPlan, JsValue> {
    let account_config = json!({"schema":"auth","d1_binding":"ACCOUNT_DB","issuer":"g4-proof","assertion_public_key":lenso_auth_account_plugin::assertion_public_key(signing),"assertion_signing_key_secret":"signing","token_pepper_secret":"pepper","assertion_ttl_seconds":30,"admin_callers":["proof.caller/caller"],"delegation_callers":["proof.caller/caller"]});
    let mut account = PluginInstancePlan::new("account", lenso_auth_account_plugin::PACKAGE_ID)
        .with_configuration(account_config.to_string())
        .with_requirement(CapabilityRequirementPlan::one(
            secrets::CAPABILITY_ID,
            secrets::DESCRIPTOR_VERSION,
        ));
    let mut caller = PluginInstancePlan::new("caller", "proof.caller");
    let mut denied = PluginInstancePlan::new("denied", "proof.caller");
    let mut bindings = vec![CapabilityBinding::new(
        "account",
        secrets::CAPABILITY_ID,
        secrets::DESCRIPTOR_VERSION,
        "secrets",
    )];
    for (cap, version, ops) in [
        (
            auth::CAPABILITY_ID,
            auth::DESCRIPTOR_VERSION,
            vec![auth::AUTHENTICATE_OPERATION],
        ),
        (
            directory::CAPABILITY_ID,
            directory::DESCRIPTOR_VERSION,
            vec![
                directory::ENSURE_IDENTITY_OPERATION,
                directory::READ_STATUS_OPERATION,
            ],
        ),
        (
            issuer::CAPABILITY_ID,
            issuer::DESCRIPTOR_VERSION,
            vec![
                issuer::ISSUE_OPERATION,
                issuer::REVOKE_OPERATION,
                issuer::REVOKE_CREDENTIAL_OPERATION,
            ],
        ),
        (
            admin::CAPABILITY_ID,
            admin::DESCRIPTOR_VERSION,
            vec![
                admin::LIST_SESSIONS_OPERATION,
                admin::LIST_SUBJECTS_OPERATION,
                admin::SET_SUBJECT_STATUS_OPERATION,
            ],
        ),
        (
            delegation::CAPABILITY_ID,
            delegation::DESCRIPTOR_VERSION,
            vec![delegation::GRANT_OPERATION],
        ),
    ] {
        account = account.with_capability(CapabilityEndpointPlan::new(cap, version, ops));
        caller = caller.with_requirement(CapabilityRequirementPlan::one(cap, version));
        denied = denied.with_requirement(CapabilityRequirementPlan::one(cap, version));
        let provider = if cap == auth::CAPABILITY_ID {
            "router"
        } else {
            "account"
        };
        bindings.push(CapabilityBinding::new("caller", cap, version, provider));
        bindings.push(CapabilityBinding::new("denied", cap, version, provider));
    }
    let router = PluginInstancePlan::new("router", lenso_auth_router_plugin::PACKAGE_ID)
        .with_configuration(json!({"routes":{"session":"lenso.auth.account/account"}}).to_string())
        .with_requirement(CapabilityRequirementPlan::many(
            auth::CAPABILITY_ID,
            auth::DESCRIPTOR_VERSION,
        ))
        .with_capability(CapabilityEndpointPlan::new(
            auth::CAPABILITY_ID,
            auth::DESCRIPTOR_VERSION,
            [auth::AUTHENTICATE_OPERATION],
        ));
    bindings.push(CapabilityBinding::new(
        "router",
        auth::CAPABILITY_ID,
        auth::DESCRIPTOR_VERSION,
        "account",
    ));
    let oauth = PluginInstancePlan::new("oauth", lenso_auth_oauth_flow_plugin::PACKAGE_ID)
        .with_configuration(
            json!({"schema":"oauth","d1_binding":"OAUTH_DB","encryption_key_secret":"oauth"})
                .to_string(),
        )
        .with_requirement(CapabilityRequirementPlan::one(
            secrets::CAPABILITY_ID,
            secrets::DESCRIPTOR_VERSION,
        ))
        .with_capability(CapabilityEndpointPlan::new(
            flow::CAPABILITY_ID,
            flow::DESCRIPTOR_VERSION,
            [flow::CONSUME_OPERATION, flow::CREATE_OPERATION],
        ));
    caller = caller.with_requirement(CapabilityRequirementPlan::one(
        flow::CAPABILITY_ID,
        flow::DESCRIPTOR_VERSION,
    ));
    bindings.push(CapabilityBinding::new(
        "caller",
        flow::CAPABILITY_ID,
        flow::DESCRIPTOR_VERSION,
        "oauth",
    ));
    bindings.push(CapabilityBinding::new(
        "oauth",
        secrets::CAPABILITY_ID,
        secrets::DESCRIPTOR_VERSION,
        "secrets",
    ));
    let secrets = PluginInstancePlan::new("secrets", "proof.secrets").with_capability(
        CapabilityEndpointPlan::new(
            secrets::CAPABILITY_ID,
            secrets::DESCRIPTOR_VERSION,
            [secrets::RESOLVE_OPERATION],
        ),
    );
    let mut instances = vec![caller, denied, account, router, oauth, secrets];
    if let Some(origin) = origin {
        http_host::extend_plan(&mut instances, &mut bindings, origin);
    }
    catalog_plan::resolve(instances, bindings).map_err(|e| JsValue::from_str(&e))
}
#[derive(Deserialize)]
struct Input {
    operation: String,
    request: Value,
    #[serde(default)]
    denied: bool,
}
#[wasm_bindgen]
pub async fn invoke(input: String, scope: JsValue) -> Result<String, JsValue> {
    let input: Input = serde_json::from_str(&input).map_err(err)?;
    let signing = text(&scope, "signing")?;
    let pepper = text(&scope, "pepper")?;
    let oauth = text(&scope, "oauth")?;
    let account_batch: js_sys::Function =
        property(&scope, "accountBatch")?.dyn_into().map_err(err)?;
    let oauth_batch: js_sys::Function = property(&scope, "oauthBatch")?.dyn_into().map_err(err)?;
    // Insert explicit factories before linked defaults: stable linked-factory dedup keeps these event resources.
    lenso_auth_router_plugin::__lenso_link_auth_router_plugin();
    let registry = NativePluginRegistry::new()
        .with_factory(lenso_auth_account_plugin::workers_factory(
            "ACCOUNT_DB",
            account_batch,
        ))
        .with_factory(lenso_auth_oauth_flow_plugin::workers_factory(
            "OAUTH_DB",
            oauth_batch,
        ))
        .with_linked_factories()
        .with_factory(Caller)
        .with_factory(Secrets(BTreeMap::from([
            ("signing".into(), signing.clone()),
            ("pepper".into(), pepper),
            ("oauth".into(), oauth),
        ])));
    let driver = WorkersDriver::new();
    let _event = EventGuard(driver.clone());
    let cancellation = CancellationToken::new();
    let _cancel = CancellationGuard::new(scope, cancellation.clone());
    let app = Kernel::start_native(plan(&signing, None)?, driver, registry)
        .await
        .map_err(|failure| JsValue::from_str(&format!("startup: {failure:?}")))?;
    let caller = if input.denied {
        "proof.caller/denied"
    } else {
        "proof.caller/caller"
    };
    macro_rules! call{($ty:ty,$op:expr)=>{{
  let request=serde_json::from_value(input.request).map_err(err)?;
  match app.invoke_with_context::<$ty>(caller,$op,app.invocation_context_after(Duration::from_secs(10),cancellation.clone()),request).await {Ok(value)=>serde_json::to_value(value).map_err(err),Err(_)=>Ok(json!({"RuntimeFailure":true}))}
 }}}
    let result:Result<Value,JsValue>=async {match input.operation.as_str(){
  "verify_target"=>{
  use lenso_auth_sdk::{decode_auth_response,AuthOutcome,ActorAssertionVerifier,FixedClock};
  let request=serde_json::from_value(input.request).map_err(err)?;
  let response=app.invoke::<auth::Auth>(caller,auth::AUTHENTICATE_OPERATION,request).await.map_err(err)?.map_err(err)?;
  let AuthOutcome::Authenticated(assertion)=decode_auth_response(response).map_err(err)? else{return Err(err("absent assertion"))};
  let context=assertion.attach(app.invocation_context_after(Duration::from_secs(2),cancellation.clone())).map_err(err)?;
  let verifier=ActorAssertionVerifier::from_public_key_base64("g4-proof",&lenso_auth_account_plugin::assertion_public_key(&signing)).map_err(err)?;
  let clock=FixedClock::new(time::OffsetDateTime::now_utc());
  Ok(json!({"valid":verifier.project_context::<ProofActor>(&context,"proof.resource@1","read",&clock).is_ok(),"wrong_audience_rejected":verifier.project_context::<ProofActor>(&context,"outside@1","read",&clock).is_err()}))
 },
 "ensure_identity"=>call!(directory::DirectoryEnsureIdentity,directory::ENSURE_IDENTITY_OPERATION),
  "read_status"=>call!(directory::DirectoryReadStatus,directory::READ_STATUS_OPERATION),
  "issue"=>call!(issuer::CredentialIssuerIssue,issuer::ISSUE_OPERATION),
  "revoke"=>call!(issuer::CredentialIssuerRevoke,issuer::REVOKE_OPERATION),
  "revoke_credential"=>call!(issuer::CredentialIssuerRevokeCredential,issuer::REVOKE_CREDENTIAL_OPERATION),
  "authenticate"=>call!(auth::Auth,auth::AUTHENTICATE_OPERATION),
  "list_subjects"=>call!(admin::AccountAdminListSubjects,admin::LIST_SUBJECTS_OPERATION),
  "list_sessions"=>call!(admin::AccountAdminListSessions,admin::LIST_SESSIONS_OPERATION),
  "set_subject_status"=>call!(admin::AccountAdminSetSubjectStatus,admin::SET_SUBJECT_STATUS_OPERATION),
  "grant"=>call!(delegation::Delegation,delegation::GRANT_OPERATION),
  "create"=>call!(flow::OauthFlowCreate,flow::CREATE_OPERATION),
  "consume"=>call!(flow::OauthFlowConsume,flow::CONSUME_OPERATION),
  _=>Err(err("unknown proof operation")),
 }}.await;
    let ready = app.is_ready();
    let shutdown = app.shutdown(Duration::from_secs(2)).await;
    if shutdown != ShutdownOutcome::Clean {
        return Err(err("unclean shutdown"));
    }
    Ok(json!({"outcome":result?,"ready":ready,"shutdown":"clean"}).to_string())
}

mod catalog_plan;
mod http_host;

struct ProofActor;
impl lenso_auth_sdk::TypedActor for ProofActor {
    fn from_assertion(
        assertion: &lenso_auth_sdk::ActorAssertion,
    ) -> Result<Self, lenso_auth_sdk::ActorProjectionError> {
        if assertion.actor_kind() == "user" {
            Ok(Self)
        } else {
            Err(lenso_auth_sdk::ActorProjectionError::UnexpectedActorKind {
                expected: "user".into(),
                actual: assertion.actor_kind().into(),
            })
        }
    }
}

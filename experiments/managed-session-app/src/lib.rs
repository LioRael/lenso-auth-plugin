use lenso_app_plan::{
    AppComposition, CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan,
    PluginInstancePlan, ResolvedAppPlan,
};
use lenso_auth_account_plugin::{
    AccountAuthConfig, ManagedSessionConfig, ManagedSessionPolicy, assertion_public_key,
};
use lenso_auth_password_plugin::PasswordAuthConfig;
use lenso_capability_account_admin as admin;
use lenso_capability_auth as auth;
use lenso_capability_auth_delegation as delegation;
use lenso_capability_credential_issuer as issuer;
use lenso_capability_credential_state as state;
use lenso_capability_http_endpoint as endpoint;
use lenso_capability_identity_directory as directory;
use lenso_capability_managed_session as managed;
use lenso_capability_password_auth as password;
use lenso_capability_secrets::{
    self as secrets, ResolveError, ResolveRequest, ResolveResponse, Secrets, SecretsEndpoint,
    SecretsProvider,
};
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
use lenso_native_adapter::{NativePluginFactory, NativePluginFactoryContext, NativePluginInstance};

use lenso_web_ingress_plugin::{SessionCookieConfig, WebIngressConfig};

use std::{collections::BTreeMap, rc::Rc};

pub const CALLER: &str = "test.managed-session-app/browser";
pub const ROGUE: &str = "test.managed-session-app/unauthorized";
pub const ACCOUNT: &str = "lenso.auth.account/default";
pub const PASSWORD: &str = "lenso.auth.password/default";
pub const RENEWAL: &str = "lenso.auth.session-renewal/default";
pub const INGRESS: &str = "lenso.web-ingress/default";
pub const SECRETS: &str = "test.managed-session-secrets/default";
pub const COOKIE: &str = "__Host-proof-session";
pub const CSRF: &str = "__Host-proof-csrf";
pub const ORIGIN: &str = "https://synthetic.example";
// Public synthetic fixtures. No production credentials or environment Secrets.
pub const KEY: &str = "public-synthetic-managed-session-proof-signing-key";
pub const PEPPER: &str = "public-synthetic-managed-session-proof-pepper";

#[derive(Debug)]
pub struct EmptyFactory;
impl NativePluginFactory for EmptyFactory {
    fn package_id(&self) -> &'static str {
        "test.managed-session-app"
    }
    fn instantiate(
        &self,
        _: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        Ok(NativePluginInstance::default())
    }
}
#[derive(Clone)]
pub struct FixtureSecrets(pub BTreeMap<String, String>);
impl std::fmt::Debug for FixtureSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FixtureSecrets")
            .field("references", &self.0.keys().collect::<Vec<_>>())
            .finish()
    }
}
impl NativePluginFactory for FixtureSecrets {
    fn package_id(&self) -> &'static str {
        "test.managed-session-secrets"
    }
    fn instantiate(
        &self,
        _: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        Ok(NativePluginInstance::new(vec![Rc::new(
            SecretsEndpoint::new(self.clone()),
        )]))
    }
}
impl SecretsProvider for FixtureSecrets {
    fn resolve(
        &self,
        _: InvocationContext,
        request: ResolveRequest,
    ) -> NativeRequestFuture<Secrets> {
        let result = self
            .0
            .get(&request.reference)
            .cloned()
            .map(|value| ResolveResponse { value })
            .ok_or(ResolveError::UnknownReference);
        Box::pin(std::future::ready(Ok(result)))
    }
}
fn cap(id: &str, version: &str, ops: &[&str]) -> CapabilityEndpointPlan {
    let mut ops = ops.to_vec();
    ops.sort_unstable();
    CapabilityEndpointPlan::new(id, version, ops)
}
fn req(p: PluginInstancePlan, id: &str, version: &str) -> PluginInstancePlan {
    p.with_requirement(CapabilityRequirementPlan::one(id, version))
}
pub fn plan(account_schema: &str, password_schema: &str) -> ResolvedAppPlan {
    plan_with_policy(
        account_schema,
        password_schema,
        ManagedSessionPolicy {
            idle_timeout_seconds: 30,
            absolute_timeout_seconds: 60,
            renew_interval_seconds: 5,
        },
    )
}
pub fn plan_with_policy(
    account_schema: &str,
    password_schema: &str,
    policy: ManagedSessionPolicy,
) -> ResolvedAppPlan {
    let config = AccountAuthConfig::new(
        account_schema,
        "synthetic.account",
        assertion_public_key(KEY),
        "database",
        "key",
        "pepper",
        30,
    )
    .unwrap()
    .with_credential_state_callers(vec![CALLER.into()])
    .unwrap()
    .with_managed_sessions(ManagedSessionConfig {
        policy,
        issue_callers: vec![PASSWORD.into()],
        renew_callers: vec![RENEWAL.into()],
    })
    .unwrap();
    let mut account = req(
        PluginInstancePlan::new(ACCOUNT, "lenso.auth.account")
            .with_configuration(storage_configuration(&config, "ACCOUNT_DB")),
        secrets::CAPABILITY_ID,
        secrets::DESCRIPTOR_VERSION,
    );
    let account_caps = [
        cap(
            auth::CAPABILITY_ID,
            auth::DESCRIPTOR_VERSION,
            &["authenticate"],
        ),
        cap(
            directory::CAPABILITY_ID,
            directory::DESCRIPTOR_VERSION,
            &["ensure_identity", "read_status"],
        ),
        cap(
            issuer::CAPABILITY_ID,
            issuer::DESCRIPTOR_VERSION,
            &["issue", "revoke", "revoke_credential"],
        ),
        cap(
            admin::CAPABILITY_ID,
            admin::DESCRIPTOR_VERSION,
            &[
                "list_subjects",
                "list_sessions",
                "set_subject_status",
                "read_profile",
            ],
        ),
        cap(
            delegation::CAPABILITY_ID,
            delegation::DESCRIPTOR_VERSION,
            &["grant", "grant_scoped", "scoped_receipt"],
        ),
        cap(
            state::CAPABILITY_ID,
            state::DESCRIPTOR_VERSION,
            &["inspect"],
        ),
        cap(
            managed::CAPABILITY_ID,
            managed::DESCRIPTOR_VERSION,
            &["issue_managed", "renew", "read_managed"],
        ),
    ];
    for c in account_caps {
        account = account.with_capability(c);
    }
    let password_config = PasswordAuthConfig::new(
        password_schema,
        "database",
        vec!["synthetic.app".into()],
        3600,
        5,
        60,
    )
    .unwrap()
    .with_managed_sessions(true);
    let mut password_plugin = PluginInstancePlan::new(PASSWORD, "lenso.auth.password")
        .with_configuration(storage_configuration(&password_config, "PASSWORD_DB"))
        .with_capability(cap(
            password::CAPABILITY_ID,
            password::DESCRIPTOR_VERSION,
            &["login", "register"],
        ));
    let mut bindings = vec![CapabilityBinding::new(
        ACCOUNT,
        secrets::CAPABILITY_ID,
        secrets::DESCRIPTOR_VERSION,
        SECRETS,
    )];
    for (id, version, target) in [
        (
            directory::CAPABILITY_ID,
            directory::DESCRIPTOR_VERSION,
            ACCOUNT,
        ),
        (issuer::CAPABILITY_ID, issuer::DESCRIPTOR_VERSION, ACCOUNT),
        (secrets::CAPABILITY_ID, secrets::DESCRIPTOR_VERSION, SECRETS),
    ] {
        password_plugin = req(password_plugin, id, version);
        bindings.push(CapabilityBinding::new(PASSWORD, id, version, target));
    }
    password_plugin = password_plugin.with_requirement(CapabilityRequirementPlan::many(
        managed::CAPABILITY_ID,
        managed::DESCRIPTOR_VERSION,
    ));
    bindings.push(CapabilityBinding::new(
        PASSWORD,
        managed::CAPABILITY_ID,
        managed::DESCRIPTOR_VERSION,
        ACCOUNT,
    ));
    let renewal = PluginInstancePlan::new(RENEWAL, "lenso.auth.session-renewal")
        .with_authoring(2, "lenso.native-authoring@2")
        .with_configuration(serde_json::json!({"session_cookie_name": COOKIE, "csrf_cookie_name": CSRF, "allowed_origin": ORIGIN}).to_string())
        .with_capability(cap(endpoint::CAPABILITY_ID, endpoint::DESCRIPTOR_VERSION, &["describe", "handle"]))
        .with_requirement(CapabilityRequirementPlan::one(managed::CAPABILITY_ID, managed::DESCRIPTOR_VERSION).with_requirement_id("managed_sessions"));
    bindings.push(
        CapabilityBinding::new(
            RENEWAL,
            managed::CAPABILITY_ID,
            managed::DESCRIPTOR_VERSION,
            ACCOUNT,
        )
        .with_requirement_id("managed_sessions"),
    );
    let ingress_config = WebIngressConfig::default()
        .with_session_cookie(SessionCookieConfig::new(COOKIE, CSRF, "x-csrf-token").unwrap())
        .unwrap();
    let ingress = PluginInstancePlan::new(INGRESS, "lenso.web-ingress")
        .with_configuration(serde_json::to_string(&ingress_config).unwrap())
        .with_requirement(CapabilityRequirementPlan::many(
            endpoint::CAPABILITY_ID,
            endpoint::DESCRIPTOR_VERSION,
        ));
    bindings.push(CapabilityBinding::new(
        INGRESS,
        endpoint::CAPABILITY_ID,
        endpoint::DESCRIPTOR_VERSION,
        RENEWAL,
    ));
    let mut caller = PluginInstancePlan::new(CALLER, "test.managed-session-app");
    for (id, version, target) in [
        (
            password::CAPABILITY_ID,
            password::DESCRIPTOR_VERSION,
            PASSWORD,
        ),
        (auth::CAPABILITY_ID, auth::DESCRIPTOR_VERSION, ACCOUNT),
        (issuer::CAPABILITY_ID, issuer::DESCRIPTOR_VERSION, ACCOUNT),
        (state::CAPABILITY_ID, state::DESCRIPTOR_VERSION, ACCOUNT),
    ] {
        caller = req(caller, id, version);
        bindings.push(CapabilityBinding::new(CALLER, id, version, target));
    }
    let rogue = req(
        PluginInstancePlan::new(ROGUE, "test.managed-session-app"),
        managed::CAPABILITY_ID,
        managed::DESCRIPTOR_VERSION,
    );
    bindings.push(CapabilityBinding::new(
        ROGUE,
        managed::CAPABILITY_ID,
        managed::DESCRIPTOR_VERSION,
        ACCOUNT,
    ));
    AppComposition::new(
        vec![
            account,
            password_plugin,
            renewal,
            ingress,
            caller,
            rogue,
            PluginInstancePlan::new(SECRETS, "test.managed-session-secrets").with_capability(cap(
                secrets::CAPABILITY_ID,
                secrets::DESCRIPTOR_VERSION,
                &["resolve"],
            )),
        ],
        bindings,
    )
    .resolve()
    .unwrap()
}

#[cfg(all(feature = "workers", target_arch = "wasm32"))]
mod workers;

fn storage_configuration(config: impl serde::Serialize, binding: &str) -> String {
    let mut value = serde_json::to_value(config).unwrap();
    if cfg!(feature = "workers") {
        value["database_url_secret"] = "".into();
        value["d1_binding"] = binding.into();
    }
    value.to_string()
}

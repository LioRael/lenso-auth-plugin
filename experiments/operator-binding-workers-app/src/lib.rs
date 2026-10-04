use lenso_app_plan::{
    CapabilityEndpointPlan, CapabilityRequirementPlan, ResolvedAppPlan,
    authoring::{
        HostBinding, HostCatalog, HostDefaultPlugin, HostPluginRelease, HostSlot, PluginDescriptor,
        PluginInstanceId, PluginRootSnapshot, resolve_plugin_root,
    },
};
use lenso_auth_account_plugin::{AccountAuthConfig, OperatorBindingConfig, assertion_public_key};
use lenso_auth_operator_session_plugin::OperatorSessionConfig;
use lenso_auth_sdk::credential::{ManagementCredentialCeiling, ManagementResourceScope};
use lenso_capability_access_control as access;
use lenso_capability_access_control_admin as access_admin;
use lenso_capability_access_control_directory as access_directory;
use lenso_capability_account_admin as account_admin;
use lenso_capability_audit_log as audit;
use lenso_capability_auth as auth;
use lenso_capability_credential_issuer as issuer;
use lenso_capability_credential_state as state;
use lenso_capability_identity_directory as directory;
use lenso_capability_operator_binding as binding;
use lenso_capability_operator_session as workflow;
use lenso_capability_secrets::{
    self as secrets, ResolveError, ResolveRequest, ResolveResponse, Secrets, SecretsEndpoint,
    SecretsProvider,
};
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
use lenso_native_adapter::{NativePluginFactory, NativePluginFactoryContext, NativePluginInstance};
use std::{collections::BTreeMap, rc::Rc};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

pub const SOURCE: &str = "lenso.auth.account/accounts";
pub const OPERATORS: &str = "lenso.auth.account/operators";
pub const WORKFLOW: &str = "lenso.auth.operator-session/default";
pub const ACCESS: &str = "lenso.access-control.d1/operators";
pub const AUDIT: &str = "lenso.audit-log.d1/operators";
pub const OWNER: &str = "test.operator-binding-app/owner";
pub const ORDINARY: &str = "test.operator-binding-app/ordinary";
pub const OPERATOR_BROWSER: &str = "test.operator-binding-app/operators-browser";
pub const SECRETS: &str = "test.operator-binding-secrets/default";
pub const SOURCE_ISSUER: &str = "synthetic.accounts";
pub const OPERATORS_ISSUER: &str = "synthetic.operators";
// Public inputs for local synthetic tests only.
pub const SOURCE_KEY: &str = "public-synthetic-operator-source-key";
pub const OPERATORS_KEY: &str = "public-synthetic-operator-distinct-key";
pub const PEPPER: &str = "public-synthetic-operator-pepper";
pub const PERMISSION: &str = "synthetic.settings.write";
pub const BINDING_MANAGE: &str = "access-control.bindings.manage";
#[derive(Debug)]
pub struct EmptyFactory;
impl NativePluginFactory for EmptyFactory {
    fn package_version(&self) -> &'static str {
        "0.1.0"
    }
    fn package_id(&self) -> &'static str {
        "test.operator-binding-app"
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
    fn package_version(&self) -> &'static str {
        "0.1.0"
    }
    fn package_id(&self) -> &'static str {
        "test.operator-binding-secrets"
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
pub fn plan(subject: &str, enabled: bool) -> Result<ResolvedAppPlan, String> {
    plan_with_management(subject, enabled, true)
}
pub fn plan_with_management(
    subject: &str,
    enabled: bool,
    manage: bool,
) -> Result<ResolvedAppPlan, String> {
    let permissions = if manage {
        vec![PERMISSION.to_string(), BINDING_MANAGE.to_string()]
    } else {
        vec![PERMISSION.to_string()]
    };
    let source = AccountAuthConfig::new(
        "accounts",
        SOURCE_ISSUER,
        assertion_public_key(SOURCE_KEY),
        "database",
        "source-key",
        "pepper",
        30,
    )
    .unwrap()
    .with_admin_callers(vec![OWNER.into()])
    .unwrap()
    .with_credential_state_callers(vec![WORKFLOW.into(), OWNER.into()])
    .unwrap()
    .with_storage_ref("auth/accounts")
    .unwrap();
    let mut operators = AccountAuthConfig::new(
        "operators",
        OPERATORS_ISSUER,
        assertion_public_key(OPERATORS_KEY),
        "database",
        "operators-key",
        "pepper",
        30,
    )
    .unwrap()
    .with_credential_state_callers(vec![WORKFLOW.into(), OPERATOR_BROWSER.into()])
    .unwrap()
    .with_management_session_ceiling(ManagementCredentialCeiling {
        deployment: "synthetic".into(),
        permissions: permissions.clone(),
        resource_scopes: vec![ManagementResourceScope {
            kind: "deployment".into(),
            id: "synthetic".into(),
        }],
    })
    .unwrap()
    .with_storage_ref("auth/operators")
    .unwrap();
    if enabled {
        let now = OffsetDateTime::now_utc();
        operators = operators
            .with_operator_bindings(OperatorBindingConfig {
                source_issuer: SOURCE_ISSUER.into(),
                source_account_instance: SOURCE.into(),
                scope_kind: "deployment".into(),
                scope_id: "synthetic".into(),
                deployment: "synthetic".into(),
                bootstrap_subject: subject.into(),
                bootstrap_not_before: (now - Duration::seconds(5)).format(&Rfc3339).unwrap(),
                bootstrap_expires_at: (now + Duration::minutes(10)).format(&Rfc3339).unwrap(),
                workflow_callers: vec![WORKFLOW.into()],
            })
            .unwrap();
    }
    let config = OperatorSessionConfig {
        accounts_issuer: SOURCE_ISSUER.into(),
        accounts_public_key: assertion_public_key(SOURCE_KEY),
        operators_issuer: OPERATORS_ISSUER.into(),
        operators_public_key: assertion_public_key(OPERATORS_KEY),
        maximum_assertion_ttl_seconds: 30,
        deployment: "synthetic".into(),
        scope_kind: "deployment".into(),
        scope_id: "synthetic".into(),
        bootstrap_subject: subject.into(),
        bootstrap_callers: vec![OWNER.into()],
        permissions: permissions.clone(),
        session_ttl_seconds: 300,
        operator_audience: vec![
            lenso_auth_sdk::audience(workflow::CAPABILITY_ID, "revoke_binding"),
            lenso_auth_sdk::audience(access_admin::CAPABILITY_ID, "revoke_role"),
        ],
    };
    resolve_catalog(&source, &operators, &config, enabled)
}

fn instance(key: &str) -> PluginInstanceId {
    let (package, name) = key.split_once('/').unwrap();
    PluginInstanceId::new(package, name)
}
fn default(key: &str, configuration: serde_json::Value) -> HostDefaultPlugin {
    let (package, name) = key.split_once('/').unwrap();
    HostDefaultPlugin::new(package, name).with_configuration(configuration)
}
fn resolve_catalog(
    source: &AccountAuthConfig,
    operators: &AccountAuthConfig,
    workflow_config: &OperatorSessionConfig,
    enabled: bool,
) -> Result<ResolvedAppPlan, String> {
    let mut descriptors: Vec<PluginDescriptor> = [
        lenso_auth_account_plugin::PLUGIN_DESCRIPTOR_JSON,
        lenso_auth_operator_session_plugin::PLUGIN_DESCRIPTOR_JSON,
        lenso_access_control_d1_plugin::PLUGIN_DESCRIPTOR_JSON,
        lenso_audit_log_d1_plugin::PLUGIN_DESCRIPTOR_JSON,
    ]
    .into_iter()
    .map(|s| serde_json::from_str(s).map_err(|e| e.to_string()))
    .collect::<Result<_, _>>()?;
    let requirements = [
        (
            workflow::CAPABILITY_ID,
            workflow::DESCRIPTOR_VERSION,
            WORKFLOW,
        ),
        (auth::CAPABILITY_ID, auth::DESCRIPTOR_VERSION, SOURCE),
        (state::CAPABILITY_ID, state::DESCRIPTOR_VERSION, SOURCE),
        (
            directory::CAPABILITY_ID,
            directory::DESCRIPTOR_VERSION,
            SOURCE,
        ),
        (issuer::CAPABILITY_ID, issuer::DESCRIPTOR_VERSION, SOURCE),
        (
            account_admin::CAPABILITY_ID,
            account_admin::DESCRIPTOR_VERSION,
            SOURCE,
        ),
        (access::CAPABILITY_ID, access::DESCRIPTOR_VERSION, ACCESS),
        (
            access_directory::CAPABILITY_ID,
            access_directory::DESCRIPTOR_VERSION,
            ACCESS,
        ),
    ];
    let mut caller = PluginDescriptor::new("test.operator-binding-app", "0.1.0", "callers")
        .with_runtime_package("test.operator-binding-app", "0.1.0");
    for (id, version, _) in requirements {
        caller = caller.with_requirement(CapabilityRequirementPlan::one(id, version));
    }
    descriptors.push(caller);
    descriptors.push(
        PluginDescriptor::new("test.operator-binding-secrets", "0.1.0", "secrets")
            .with_runtime_package("test.operator-binding-secrets", "0.1.0")
            .with_capability(cap(
                secrets::CAPABILITY_ID,
                secrets::DESCRIPTOR_VERSION,
                &[secrets::RESOLVE_OPERATION],
            )),
    );
    let access_config: lenso_access_control_d1_plugin::D1Config =
        serde_json::from_value(serde_json::json!({
            "binding":"ACCESS_DB", "auth_issuer":OPERATORS_ISSUER,
            "auth_assertion_public_key":assertion_public_key(OPERATORS_KEY),
            "bootstrap_callers":[WORKFLOW],"directory_callers":[OWNER,WORKFLOW]
        }))
        .map_err(|e| e.to_string())?;
    let mut defaults = vec![
        default(SOURCE, serde_json::to_value(source).unwrap()),
        default(OPERATORS, serde_json::to_value(operators).unwrap()),
        default(WORKFLOW, serde_json::to_value(workflow_config).unwrap()),
        default(ACCESS, serde_json::to_value(access_config).unwrap()),
        default(
            AUDIT,
            serde_json::json!({"writer_instances":[WORKFLOW],"reader_instances":[OWNER],"reader_scopes":{}}),
        ),
        default(SECRETS, serde_json::json!({})),
    ];
    let mut bindings = vec![HostBinding::new(
        instance(SOURCE),
        directory::CAPABILITY_ID,
        "source_accounts",
    )];
    bindings.push(if enabled {
        HostBinding::to_instance(
            instance(OPERATORS),
            directory::CAPABILITY_ID,
            instance(SOURCE),
        )
    } else {
        HostBinding::new(
            instance(OPERATORS),
            directory::CAPABILITY_ID,
            "source_accounts",
        )
    });
    for id in [SOURCE, OPERATORS] {
        bindings.push(HostBinding::to_instance(
            instance(id),
            secrets::CAPABILITY_ID,
            instance(SECRETS),
        ));
    }
    for (name, id, provider) in [
        ("bindings", binding::CAPABILITY_ID, OPERATORS),
        ("accounts_state", state::CAPABILITY_ID, SOURCE),
        ("operators_state", state::CAPABILITY_ID, OPERATORS),
        ("operators_issuer", issuer::CAPABILITY_ID, OPERATORS),
        ("access", access::CAPABILITY_ID, ACCESS),
        ("access_admin", access_admin::CAPABILITY_ID, ACCESS),
        ("audit", audit::CAPABILITY_ID, AUDIT),
    ] {
        bindings.push(
            HostBinding::to_instance(instance(WORKFLOW), id, instance(provider))
                .with_requirement_id(name),
        );
    }
    for key in [OWNER, ORDINARY, OPERATOR_BROWSER] {
        defaults.push(default(key, serde_json::json!({})));
        for (id, _, provider) in requirements {
            let provider = if key == OPERATOR_BROWSER
                && [auth::CAPABILITY_ID, state::CAPABILITY_ID].contains(&id)
            {
                OPERATORS
            } else {
                provider
            };
            bindings.push(HostBinding::to_instance(
                instance(key),
                id,
                instance(provider),
            ));
        }
    }
    let slots: std::collections::BTreeSet<_> = descriptors
        .iter()
        .map(|d| d.root_slot().to_string())
        .collect();
    let host = HostCatalog::new(
        slots
            .into_iter()
            .map(HostSlot::many)
            .chain([HostSlot::optional("source_accounts")]),
        descriptors.into_iter().map(HostPluginRelease::new),
        defaults,
    )
    .with_bindings(bindings);
    resolve_plugin_root(&host, &PluginRootSnapshot::default())
        .map(|r| r.plan().clone())
        .map_err(|e| format!("{e:?}"))
}

/// Event-owned values created by each real owner JS adapter. No business state is mocked.
#[cfg(target_arch = "wasm32")]
#[derive(Clone)]
pub struct EventAttachments {
    /// Actual Account owner input: { name, storage_ref: "auth/accounts", batch }.
    pub accounts: wasm_bindgen::JsValue,
    /// Actual Account owner input: { name, storage_ref: "auth/operators", batch }.
    pub operators: wasm_bindgen::JsValue,
    pub access: wasm_bindgen::JsValue,
    pub audit: wasm_bindgen::JsValue,
}

#[cfg(target_arch = "wasm32")]
fn account_attachment(
    value: &wasm_bindgen::JsValue,
    reference: &str,
) -> Result<lenso_auth_account_plugin::host_facilities::EventStorageBinding, RuntimeFailure> {
    let attachment = lenso_auth_account_plugin::host_facilities::state(value)?;
    let lenso_auth_account_plugin::host_facilities::EventStorageBinding::D1 { storage_ref, .. } =
        &attachment;
    if storage_ref.as_deref() != Some(reference) {
        return Err(RuntimeFailure::InvalidResolvedPlan {
            detail: "synthetic Account attachment must match its declared logical reference".into(),
        });
    }
    Ok(attachment)
}

/// Uses actual generated linked factories and typed per-instance facility APIs.
#[cfg(target_arch = "wasm32")]
pub fn registry(
    attachments: EventAttachments,
) -> Result<lenso_native_adapter::NativePluginRegistry, RuntimeFailure> {
    use lenso_native_adapter::{NativeFacilities, NativeInstanceFacilities, NativePluginRegistry};
    lenso_auth_account_plugin::link_plugin();
    lenso_auth_operator_session_plugin::link_plugin();
    lenso_access_control_d1_plugin::link_plugin();
    lenso_audit_log_d1_plugin::link_plugin();
    let facilities = NativeInstanceFacilities::new()
        .with(
            SOURCE,
            NativeFacilities::new().with_factory("state", move || {
                account_attachment(&attachments.accounts, "auth/accounts")
            })?,
        )?
        .with(
            OPERATORS,
            NativeFacilities::new().with_factory("state", move || {
                account_attachment(&attachments.operators, "auth/operators")
            })?,
        )?
        .with(
            ACCESS,
            NativeFacilities::new().with_factory("state", move || {
                lenso_access_control_d1_plugin::host_facilities::state(&attachments.access)
            })?,
        )?
        .with(
            AUDIT,
            NativeFacilities::new().with_factory("store", move || {
                lenso_audit_log_d1_plugin::host_facilities::store(&attachments.audit)
            })?,
        )?;
    Ok(NativePluginRegistry::new()
        .with_linked_factories()
        .with_facilities(facilities)
        .with_factory(EmptyFactory)
        .with_factory(FixtureSecrets(BTreeMap::from([
            ("source-key".into(), SOURCE_KEY.into()),
            ("operators-key".into(), OPERATORS_KEY.into()),
            ("pepper".into(), PEPPER.into()),
        ]))))
}

/// Narrow compile seam for a real complete App. Execution still requires migrated bindings and a Host Driver.
#[cfg(target_arch = "wasm32")]
pub async fn start_app<D: lenso_kernel::RuntimeDriver>(
    confirmed_subject: &str,
    attachments: EventAttachments,
    driver: D,
) -> Result<lenso_kernel::NativeApp, RuntimeFailure> {
    lenso_kernel::Kernel::start_native(
        plan(confirmed_subject, true)
            .map_err(|detail| RuntimeFailure::InvalidResolvedPlan { detail })?,
        driver,
        registry(attachments)?,
    )
    .await
}

/// The public new Role is invoked through the same named-dependency App graph.
#[cfg(target_arch = "wasm32")]
pub async fn bootstrap_binding(
    app: &lenso_kernel::NativeApp,
    context: InvocationContext,
) -> Result<Result<workflow::Binding, workflow::BootstrapBindingError>, RuntimeFailure> {
    app.invoke_with_context::<workflow::OperatorSessionBootstrapBinding>(
        OWNER,
        workflow::BOOTSTRAP_BINDING_OPERATION,
        context,
        workflow::EmptyRequest {},
    )
    .await
}

#[cfg(target_arch = "wasm32")]
mod workers;

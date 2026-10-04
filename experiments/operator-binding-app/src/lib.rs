use lenso_app_plan::{
    AppComposition, CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan,
    PluginInstancePlan, ResolvedAppPlan,
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
use lenso_capability_auth_delegation as delegation;
use lenso_capability_credential_issuer as issuer;
use lenso_capability_credential_state as state;
use lenso_capability_identity_directory as directory;
use lenso_capability_managed_session as managed;
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
pub const ACCESS: &str = "lenso.access-control.postgres/operators";
pub const AUDIT: &str = "lenso.audit-log.postgres/operators";
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
fn declared(metadata: &str) -> CapabilityEndpointPlan {
    let v: serde_json::Value = serde_json::from_str(metadata).unwrap();
    let ops: Vec<&str> = v["operations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();
    cap(
        v["capability_id"].as_str().unwrap(),
        v["descriptor_version"].as_str().unwrap(),
        &ops,
    )
}
fn requirement(p: PluginInstancePlan, id: &str, version: &str) -> PluginInstancePlan {
    p.with_requirement(CapabilityRequirementPlan::one(id, version))
}
fn account_caps(mut p: PluginInstancePlan) -> PluginInstancePlan {
    for c in [
        declared(auth::__lenso_provided_auth!()),
        declared(directory::__lenso_provided_directory!()),
        declared(issuer::__lenso_provided_credential_issuer!()),
        declared(account_admin::__lenso_provided_account_admin!()),
        declared(delegation::__lenso_provided_delegation!()),
        declared(state::__lenso_provided_credential_state!()),
        declared(managed::__lenso_provided_managed_session!()),
        declared(binding::__lenso_provided_operator_binding!()),
    ] {
        p = p.with_capability(c);
    }
    p
}
pub fn plan(subject: &str, enabled: bool) -> ResolvedAppPlan {
    plan_with_management(subject, enabled, true)
}
pub fn plan_with_management(subject: &str, enabled: bool, manage: bool) -> ResolvedAppPlan {
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
    let accounts = requirement(
        account_caps(
            PluginInstancePlan::new(SOURCE, "lenso.auth.account")
                .with_configuration(serde_json::to_string(&source).unwrap()),
        ),
        secrets::CAPABILITY_ID,
        secrets::DESCRIPTOR_VERSION,
    );
    let operators = requirement(
        account_caps(
            PluginInstancePlan::new(OPERATORS, "lenso.auth.account")
                .with_configuration(serde_json::to_string(&operators).unwrap()),
        ),
        secrets::CAPABILITY_ID,
        secrets::DESCRIPTOR_VERSION,
    )
    .with_requirement(CapabilityRequirementPlan::many(
        directory::CAPABILITY_ID,
        directory::DESCRIPTOR_VERSION,
    ));
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
    let mut flow = PluginInstancePlan::new(WORKFLOW, "lenso.auth.operator-session")
        .with_authoring(2, "lenso.native-authoring@2")
        .with_configuration(serde_json::to_string(&config).unwrap())
        .with_capability(declared(workflow::__lenso_provided_operator_session!()));
    let ac = lenso_access_control_postgres_plugin::AccessControlConfig::new(
        "access",
        "database",
        OPERATORS_ISSUER,
        assertion_public_key(OPERATORS_KEY),
        vec![WORKFLOW.into()],
    )
    .unwrap()
    .with_directory_callers(vec![OWNER.into(), WORKFLOW.into()])
    .unwrap();
    let ac = requirement(
        PluginInstancePlan::new(ACCESS, "lenso.access-control.postgres")
            .with_configuration(serde_json::to_string(&ac).unwrap())
            .with_capability(declared(access::__lenso_provided_access_control!()))
            .with_capability(declared(
                access_admin::__lenso_provided_access_control_admin!(),
            ))
            .with_capability(declared(
                access_directory::__lenso_provided_access_control_directory!(),
            )),
        secrets::CAPABILITY_ID,
        secrets::DESCRIPTOR_VERSION,
    );
    let au = lenso_audit_log_postgres_plugin::AuditLogConfig::new(
        "database",
        vec![WORKFLOW.into()],
        vec![OWNER.into()],
    )
    .unwrap();
    let au = requirement(
        PluginInstancePlan::new(AUDIT, "lenso.audit-log.postgres")
            .with_configuration(serde_json::to_string(&au).unwrap())
            .with_capability(declared(audit::__lenso_provided_audit_log!())),
        secrets::CAPABILITY_ID,
        secrets::DESCRIPTOR_VERSION,
    );
    let mut bindings = vec![];
    for id in [SOURCE, OPERATORS, ACCESS, AUDIT] {
        bindings.push(CapabilityBinding::new(
            id,
            secrets::CAPABILITY_ID,
            secrets::DESCRIPTOR_VERSION,
            SECRETS,
        ));
    }
    bindings.push(CapabilityBinding::new(
        OPERATORS,
        directory::CAPABILITY_ID,
        directory::DESCRIPTOR_VERSION,
        SOURCE,
    ));
    for (name, id, version, provider) in [
        (
            "bindings",
            binding::CAPABILITY_ID,
            binding::DESCRIPTOR_VERSION,
            OPERATORS,
        ),
        (
            "accounts_state",
            state::CAPABILITY_ID,
            state::DESCRIPTOR_VERSION,
            SOURCE,
        ),
        (
            "operators_state",
            state::CAPABILITY_ID,
            state::DESCRIPTOR_VERSION,
            OPERATORS,
        ),
        (
            "operators_issuer",
            issuer::CAPABILITY_ID,
            issuer::DESCRIPTOR_VERSION,
            OPERATORS,
        ),
        (
            "access",
            access::CAPABILITY_ID,
            access::DESCRIPTOR_VERSION,
            ACCESS,
        ),
        (
            "access_admin",
            access_admin::CAPABILITY_ID,
            access_admin::DESCRIPTOR_VERSION,
            ACCESS,
        ),
        (
            "audit",
            audit::CAPABILITY_ID,
            audit::DESCRIPTOR_VERSION,
            AUDIT,
        ),
    ] {
        flow = flow.with_requirement(
            CapabilityRequirementPlan::one(id, version).with_requirement_id(name),
        );
        bindings.push(
            CapabilityBinding::new(WORKFLOW, id, version, provider).with_requirement_id(name),
        );
    }
    let mut callers = vec![];
    for id in [OWNER, ORDINARY, OPERATOR_BROWSER] {
        let mut p = PluginInstancePlan::new(id, "test.operator-binding-app");
        for (cid, version, provider) in [
            (
                workflow::CAPABILITY_ID,
                workflow::DESCRIPTOR_VERSION,
                WORKFLOW,
            ),
            (
                auth::CAPABILITY_ID,
                auth::DESCRIPTOR_VERSION,
                if id == OPERATOR_BROWSER {
                    OPERATORS
                } else {
                    SOURCE
                },
            ),
            (
                state::CAPABILITY_ID,
                state::DESCRIPTOR_VERSION,
                if id == OPERATOR_BROWSER {
                    OPERATORS
                } else {
                    SOURCE
                },
            ),
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
        ] {
            p = requirement(p, cid, version);
            bindings.push(CapabilityBinding::new(id, cid, version, provider));
        }
        callers.push(p);
    }
    let mut instances = vec![
        accounts,
        operators,
        flow,
        ac,
        au,
        PluginInstancePlan::new(SECRETS, "test.operator-binding-secrets").with_capability(cap(
            secrets::CAPABILITY_ID,
            secrets::DESCRIPTOR_VERSION,
            &["resolve"],
        )),
    ];
    instances.extend(callers);
    AppComposition::new(instances, bindings).resolve().unwrap()
}

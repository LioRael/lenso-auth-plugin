use lenso_app_plan::{
    CapabilityEndpointPlan,
    authoring::{
        HostCatalog, HostDefaultPlugin, HostPluginRelease, HostSlot, PluginDescriptor,
        PluginRootSnapshot, resolve_plugin_root,
    },
};
use lenso_auth_account_plugin::{
    AccountAuthConfig, ManagedSessionConfig, ManagedSessionPolicy, assertion_public_key,
};
use lenso_auth_sdk::credential::{ManagementCredentialCeiling, ManagementResourceScope};
use lenso_capability_secrets as secrets;

fn resolves(config: &AccountAuthConfig) -> bool {
    let descriptor: PluginDescriptor =
        serde_json::from_str(lenso_auth_account_plugin::PLUGIN_DESCRIPTOR_JSON).unwrap();
    let secret = PluginDescriptor::new("test.secrets", "0.1.0", "secrets")
        .with_runtime_package("test.secrets", "0.1.0")
        .with_capability(CapabilityEndpointPlan::new(
            secrets::CAPABILITY_ID,
            secrets::DESCRIPTOR_VERSION,
            [secrets::RESOLVE_OPERATION],
        ));
    let host = HostCatalog::new(
        [HostSlot::one("identity"), HostSlot::one("secrets")],
        [
            HostPluginRelease::new(descriptor),
            HostPluginRelease::new(secret),
        ],
        [
            HostDefaultPlugin::new(lenso_auth_account_plugin::PACKAGE_ID, "account")
                .with_configuration(serde_json::to_value(config).unwrap()),
            HostDefaultPlugin::new("test.secrets", "secrets"),
        ],
    );
    resolve_plugin_root(&host, &PluginRootSnapshot::default())
        .inspect_err(|error| eprintln!("{error:?}"))
        .is_ok()
}
#[test]
fn source_catalog_accepts_both_explicit_operators_ceiling_and_default_session_profile() {
    let default = AccountAuthConfig::new(
        "auth_account",
        "operators.account",
        assertion_public_key("0123456789abcdef0123456789abcdef"),
        "database",
        "signing",
        "pepper",
        60,
    )
    .unwrap();
    assert!(resolves(&default));
    assert!(resolves(
        &default
            .clone()
            .with_managed_sessions(ManagedSessionConfig {
                policy: ManagedSessionPolicy {
                    idle_timeout_seconds: 86400,
                    absolute_timeout_seconds: 2_592_000,
                    renew_interval_seconds: 3600
                },
                issue_callers: vec!["lenso.auth.password/password".into()],
                renew_callers: vec!["lenso.auth.session-renewal/renewal".into()],
            })
            .unwrap()
    ));
    assert!(resolves(
        &default.clone().with_storage_ref("auth/account").unwrap()
    ));
    let operators = default
        .with_credential_state_callers(vec!["lenso.auth.human-api-token/human".into()])
        .unwrap()
        .with_management_session_ceiling(ManagementCredentialCeiling {
            deployment: "deployment-a".into(),
            permissions: vec!["auth.pat.issue".into()],
            resource_scopes: vec![ManagementResourceScope {
                kind: "deployment".into(),
                id: "deployment-a".into(),
            }],
        })
        .unwrap();
    assert!(resolves(&operators));
}

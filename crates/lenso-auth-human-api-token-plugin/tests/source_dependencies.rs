use lenso_app_plan::{
    CapabilityEndpointPlan,
    authoring::{
        DependencyChoice, HostBinding, HostCatalog, HostDefaultPlugin, HostPluginRelease, HostSlot,
        PluginDescriptor, PluginInstanceId, PluginRootSnapshot, resolve_plugin_root,
    },
};
use lenso_auth_human_api_token_plugin::{HumanApiTokenConfig, PACKAGE_ID};
use lenso_capability_access_control as access;
use lenso_capability_api_token_admin as admin;
use lenso_capability_credential_state as state;

fn provider(id: &str, slot: &str, roles: &[(&str, &str, &str)]) -> HostPluginRelease {
    let descriptor = roles.iter().fold(
        PluginDescriptor::new(id, "0.1.0", slot).with_runtime_package(id, "0.1.0"),
        |descriptor, (capability, version, operation)| {
            descriptor.with_capability(CapabilityEndpointPlan::new(
                *capability,
                *version,
                [*operation],
            ))
        },
    );
    HostPluginRelease::new(descriptor)
}

fn host() -> HostCatalog {
    let human =
        serde_json::from_str(lenso_auth_human_api_token_plugin::PLUGIN_DESCRIPTOR_JSON).unwrap();
    let config = HumanApiTokenConfig::new(
        "operators",
        "operators.account",
        lenso_auth_account_plugin::assertion_public_key("test-only-account-source-key"),
        60,
        3600,
        "deployment-a",
        "management-deployment",
        "deployment-a",
        vec!["lenso.management@1:catalog".into()],
    )
    .unwrap();
    let releases = [
        HostPluginRelease::new(human),
        provider(
            "test.account",
            "credentials",
            &[(state::CAPABILITY_ID, state::DESCRIPTOR_VERSION, "inspect")],
        ),
        provider(
            "test.api",
            "credentials",
            &[
                (state::CAPABILITY_ID, state::DESCRIPTOR_VERSION, "inspect"),
                (admin::CAPABILITY_ID, admin::DESCRIPTOR_VERSION, "issue"),
            ],
        ),
        provider(
            "test.access",
            "access",
            &[(
                access::CAPABILITY_ID,
                access::DESCRIPTOR_VERSION,
                "check_permission",
            )],
        ),
    ];
    HostCatalog::new(
        [
            HostSlot::one("human-api-token"),
            HostSlot::many("credentials"),
            HostSlot::many("access"),
        ],
        releases,
        [
            HostDefaultPlugin::new(PACKAGE_ID, "default")
                .with_configuration(serde_json::to_value(config).unwrap()),
            HostDefaultPlugin::new("test.account", "default"),
            HostDefaultPlugin::new("test.api", "default"),
            HostDefaultPlugin::new("test.access", "human"),
            HostDefaultPlugin::new("test.access", "pat"),
        ],
    )
    .with_bindings(
        [
            ("account_state", state::CAPABILITY_ID, "credentials"),
            ("api_tokens", admin::CAPABILITY_ID, "credentials"),
            ("access", access::CAPABILITY_ID, "access"),
        ]
        .map(|(id, capability, slot)| {
            HostBinding::new(
                PluginInstanceId::new(PACKAGE_ID, "default"),
                capability,
                slot,
            )
            .with_requirement_id(id)
            .selectable(None)
        }),
    )
}

#[test]
fn named_owner_choices_resolve_with_two_credential_and_access_candidates() {
    let choices: Vec<DependencyChoice> = serde_json::from_value(serde_json::json!([
        {"consumer":{"plugin_id":PACKAGE_ID,"instance_key":"default"},"requirement_id":"account_state",
         "provider":{"plugin_id":"test.account","instance_key":"default"}},
        {"consumer":{"plugin_id":PACKAGE_ID,"instance_key":"default"},"requirement_id":"api_tokens",
         "provider":{"plugin_id":"test.api","instance_key":"default"}},
        {"consumer":{"plugin_id":PACKAGE_ID,"instance_key":"default"},"requirement_id":"access",
         "provider":{"plugin_id":"test.access","instance_key":"human"}}
    ]))
    .unwrap();
    let resolved = resolve_plugin_root(
        &host(),
        &PluginRootSnapshot::default().with_dependency_choices(choices),
    )
    .unwrap();
    let selected: std::collections::BTreeMap<_, _> = resolved
        .plan()
        .capability_bindings()
        .iter()
        .filter(|binding| binding.consumer_instance() == format!("{PACKAGE_ID}/default"))
        .map(|binding| (binding.requirement_id(), binding.provider_instance()))
        .collect();
    assert_eq!(selected["account_state"], "test.account/default");
    assert_eq!(selected["api_tokens"], "test.api/default");
    assert_eq!(selected["access"], "test.access/human");
    assert_eq!(selected.len(), 3);
}

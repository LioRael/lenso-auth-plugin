use lenso_app_plan::{
    CapabilityEndpointPlan,
    authoring::{
        DependencyChoice, HostBinding, HostCatalog, HostDefaultPlugin, HostPluginRelease, HostSlot,
        PluginDescriptor, PluginInstanceId, PluginRootSnapshot, resolve_plugin_root,
    },
};
use lenso_auth_account_plugin::{AccountAuthConfig, assertion_public_key};
use lenso_capability_auth_profile_cache as cache;
use lenso_capability_secrets as secrets;

fn host(include_cache: bool) -> HostCatalog {
    let account = serde_json::from_str(lenso_auth_account_plugin::PLUGIN_DESCRIPTOR_JSON).unwrap();
    let profile = serde_json::from_str(lenso_auth_profile_plugin::PLUGIN_DESCRIPTOR_JSON).unwrap();
    let secret = PluginDescriptor::new("test.secrets", "0.1.0", "secrets")
        .with_runtime_package("test.secrets", "0.1.0")
        .with_capability(CapabilityEndpointPlan::new(
            secrets::CAPABILITY_ID,
            secrets::DESCRIPTOR_VERSION,
            [secrets::RESOLVE_OPERATION],
        ));
    let mut releases = vec![
        HostPluginRelease::new(account),
        HostPluginRelease::new(profile),
        HostPluginRelease::new(secret),
    ];
    let config = AccountAuthConfig::new(
        "profile_source",
        "operators.account",
        assertion_public_key("0123456789abcdef0123456789abcdef"),
        "database",
        "signing",
        "pepper",
        60,
    )
    .unwrap()
    .with_admin_callers(vec!["lenso.auth.profile/default".into()])
    .unwrap();
    let mut defaults = vec![
        HostDefaultPlugin::new(lenso_auth_account_plugin::PACKAGE_ID, "default")
            .with_configuration(serde_json::to_value(config).unwrap()),
        HostDefaultPlugin::new(lenso_auth_profile_plugin::PACKAGE_ID, "default")
            .with_configuration(
                serde_json::to_value(
                    lenso_auth_profile_plugin::ProfileConfig::new(
                        "operators.account",
                        vec!["test.browser/default".into()],
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
        HostDefaultPlugin::new("test.secrets", "default"),
    ];
    if include_cache {
        releases.push(HostPluginRelease::new(
            serde_json::from_str(lenso_auth_profile_cache_plugin::PLUGIN_DESCRIPTOR_JSON).unwrap(),
        ));
        defaults.push(
            HostDefaultPlugin::new(lenso_auth_profile_cache_plugin::PACKAGE_ID, "default")
                .with_configuration(
                    serde_json::to_value(
                        lenso_auth_profile_cache_plugin::ProfileCacheConfig::new(
                            300,
                            64,
                            vec!["lenso.auth.profile/default".into()],
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                ),
        );
    }
    HostCatalog::new(
        [
            HostSlot::one("identity"),
            HostSlot::one("secrets"),
            HostSlot::one("auth-profile"),
            HostSlot::optional("auth-profile-cache"),
        ],
        releases,
        defaults,
    )
    .with_bindings([HostBinding::new(
        PluginInstanceId::new(lenso_auth_profile_plugin::PACKAGE_ID, "default"),
        cache::CAPABILITY_ID,
        "auth-profile-cache",
    )
    .with_requirement_id("profile_cache")
    .selectable(None)])
}

#[test]
fn auth_display_projection_keeps_persisted_none_after_cache_removal_and_return() {
    // This is the public selection document, decoded again as a new process would.
    let document = serde_json::json!({
        "schema_version": 1,
        "choices": [{
            "consumer": {"plugin_id": lenso_auth_profile_plugin::PACKAGE_ID, "instance_key": "default"},
            "requirement_id": "profile_cache", "provider": null
        }]
    });
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("lenso-auth-profile-choice-{unique}"));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join(".dependencies.json");
    std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
    for available in [true, false, true] {
        let stored: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let choices: Vec<DependencyChoice> =
            serde_json::from_value(stored["choices"].clone()).unwrap();
        let root = PluginRootSnapshot::default().with_dependency_choices(choices.clone());
        let resolved = resolve_plugin_root(&host(available), &root).unwrap();
        assert_eq!(resolved.dependency_choices(), choices);
        assert!(
            resolved
                .plan()
                .capability_bindings()
                .iter()
                .all(|binding| binding.capability_id() != cache::CAPABILITY_ID)
        );
        assert!(resolved.instances().iter().any(|instance| {
            instance.id().plugin_id() == lenso_auth_profile_plugin::PACKAGE_ID
        }));
    }
    std::fs::remove_dir_all(directory).unwrap();
}

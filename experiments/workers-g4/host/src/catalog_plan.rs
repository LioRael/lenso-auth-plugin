//! Exact owner Descriptors resolved through the normal Plugin Root path.
use super::*;
use lenso_app_plan::authoring::{
    HostBinding, HostCatalog, HostDefaultPlugin, HostPluginRelease, HostSlot, PluginDescriptor,
    PluginInstanceId, PluginRootSnapshot, resolve_plugin_root,
};
pub(super) fn resolve(
    instances: Vec<PluginInstancePlan>,
    bindings: Vec<CapabilityBinding>,
) -> Result<ResolvedAppPlan, String> {
    let ids: BTreeMap<_, _> = instances
        .iter()
        .map(|i| {
            (
                i.instance_key(),
                PluginInstanceId::new(i.package_id(), i.instance_key()),
            )
        })
        .collect();
    let mut descriptors = BTreeMap::new();
    let mut defaults = Vec::new();
    let mut slots = BTreeMap::<String, usize>::new();
    for i in &instances {
        let descriptor: PluginDescriptor = match i.package_id() {
            package if package == business::PACKAGE_ID => {
                serde_json::from_str(business::PLUGIN_DESCRIPTOR_JSON).map_err(|e| e.to_string())?
            }
            lenso_auth_account_plugin::PACKAGE_ID => {
                serde_json::from_str(lenso_auth_account_plugin::PLUGIN_DESCRIPTOR_JSON)
                    .map_err(|e| e.to_string())?
            }
            lenso_auth_router_plugin::PACKAGE_ID => {
                serde_json::from_str(lenso_auth_router_plugin::PLUGIN_DESCRIPTOR_JSON)
                    .map_err(|e| e.to_string())?
            }
            lenso_auth_oauth_flow_plugin::PACKAGE_ID => {
                serde_json::from_str(lenso_auth_oauth_flow_plugin::PLUGIN_DESCRIPTOR_JSON)
                    .map_err(|e| e.to_string())?
            }
            lenso_auth_web_session_plugin::PACKAGE_ID => {
                serde_json::from_str(lenso_auth_web_session_plugin::PLUGIN_DESCRIPTOR_JSON)
                    .map_err(|e| e.to_string())?
            }
            lenso_auth_oidc_client_plugin::PACKAGE_ID => {
                serde_json::from_str(lenso_auth_oidc_client_plugin::PLUGIN_DESCRIPTOR_JSON)
                    .map_err(|e| e.to_string())?
            }
            "lenso.web-ingress" => {
                lenso_web_ingress_plugin::WebIngressEventFactory::plugin_descriptor()
            }
            "lenso.http-egress" => {
                lenso_http_egress_plugin::HttpEgressEventFactory::plugin_descriptor()
            }
            package if methods::descriptor(package).is_some() => {
                serde_json::from_str(methods::descriptor(package).unwrap())
                    .map_err(|e| e.to_string())?
            }
            _ => {
                let source = if i.package_id() == "proof.caller" {
                    instances
                        .iter()
                        .find(|i| i.instance_key() == "caller")
                        .unwrap()
                } else {
                    i
                };
                let mut d = PluginDescriptor::new(i.package_id(), "0.1.0", "proof")
                    .with_runtime_package(i.package_id(), format!("{}@0.1.0", i.package_id()));
                for cap in source.provided_capabilities() {
                    d = d.with_capability(cap.clone())
                }
                for requirement in source.required_capabilities() {
                    d = d.with_requirement(requirement.clone())
                }
                d
            }
        };
        *slots.entry(descriptor.root_slot().to_owned()).or_default() += 1;
        descriptors.insert(i.package_id(), HostPluginRelease::new(descriptor));
        defaults.push(
            HostDefaultPlugin::new(i.package_id(), i.instance_key()).with_configuration(
                serde_json::from_str(i.configuration()).map_err(|e| e.to_string())?,
            ),
        );
    }
    let mut attachments = BTreeMap::<_, Vec<_>>::new();
    for binding in &bindings {
        attachments
            .entry((binding.consumer_instance(), binding.capability_id()))
            .or_default()
            .push(ids[binding.provider_instance()].clone());
    }
    let mut host_bindings: Vec<_> = attachments
        .into_iter()
        .map(|((consumer, capability), providers)| {
            if providers.len() == 1 {
                HostBinding::to_instance(ids[consumer].clone(), capability, providers[0].clone())
            } else {
                HostBinding::to_instances(ids[consumer].clone(), capability, providers)
            }
        })
        .collect();
    if let (Some(denied), Some(oauth)) = (ids.get("denied"), ids.get("oauth")) {
        host_bindings.push(HostBinding::to_instance(
            denied.clone(),
            flow::CAPABILITY_ID,
            oauth.clone(),
        ));
    }
    let host = HostCatalog::new(
        slots.into_iter().map(|(name, count)| {
            if count > 1 {
                HostSlot::many(name)
            } else {
                HostSlot::one(name)
            }
        }),
        descriptors.into_values(),
        defaults,
    )
    .with_bindings(host_bindings);
    resolve_plugin_root(&host, &PluginRootSnapshot::default())
        .map(|r| r.plan().clone())
        .map_err(|e| format!("{e:?}"))
}

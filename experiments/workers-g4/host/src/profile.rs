//! Local D01 fixture only: fresh normal Apps over one or seven real D1 owners.
use super::*;

#[derive(Deserialize)]
struct ProfileInput {
    owners: u8,
    operation: String,
    request: Value,
}

#[wasm_bindgen]
pub async fn profile_invoke(input: String, scope: JsValue) -> Result<String, JsValue> {
    let input: ProfileInput = serde_json::from_str(&input).map_err(err)?;
    if !matches!(input.owners, 1 | 7) || (input.owners == 1 && input.operation != "ready") {
        return Err(err("unsupported local profile"));
    }
    let signing = text(&scope, "signing")?;
    let (mut instances, mut bindings) = plan_parts(&signing, None, None);
    lenso_auth_account_plugin::link_plugin();
    let mut registry = NativePluginRegistry::new()
        .with_factory_override(lenso_auth_account_plugin::workers_factory(
            "ACCOUNT_DB",
            property(&scope, "accountBatch")?.dyn_into().map_err(err)?,
        ))
        .map_err(err)?;
    if input.owners == 1 {
        instances.retain(|i| matches!(i.instance_key(), "account" | "secrets"));
        bindings.retain(|b| b.consumer_instance() == "account");
    } else {
        lenso_auth_router_plugin::link_plugin();
        lenso_auth_oauth_flow_plugin::link_plugin();
        methods::link();
        let jwks: Value = serde_json::from_str(&text(&scope, "providerJwks")?).map_err(err)?;
        for method in ["password", "phone", "device", "api", "oidc"] {
            methods::extend_plan(
                &mut instances,
                &mut bindings,
                method,
                &signing,
                jwks.clone(),
            );
        }
        macro_rules! owner {
            ($plugin:ident, $binding:literal, $batch:literal) => {
                registry = registry
                    .with_factory_override($plugin::workers_factory(
                        $binding,
                        property(&scope, $batch)?.dyn_into().map_err(err)?,
                    ))
                    .map_err(err)?;
            };
        }
        owner!(lenso_auth_oauth_flow_plugin, "OAUTH_DB", "oauthBatch");
        owner!(lenso_auth_password_plugin, "PASSWORD_DB", "passwordBatch");
        owner!(lenso_auth_phone_plugin, "PHONE_DB", "phoneBatch");
        owner!(lenso_auth_device_plugin, "DEVICE_DB", "deviceBatch");
        owner!(lenso_auth_api_token_plugin, "API_TOKEN_DB", "apiBatch");
        owner!(lenso_auth_oidc_plugin, "OIDC_DB", "oidcBatch");
        registry = registry.with_factory(Caller).with_factory(methods::Sms);
    }
    let registry = registry
        .with_linked_factories()
        .with_factory(Secrets(BTreeMap::from([
            ("signing".into(), signing),
            ("pepper".into(), text(&scope, "pepper")?),
            ("oauth".into(), text(&scope, "oauth")?),
            ("otp".into(), text(&scope, "otp")?),
            ("provider-signing".into(), text(&scope, "providerSigning")?),
        ])));
    let driver = WorkersDriver::new();
    let _event = EventGuard(driver.clone());
    let cancellation = CancellationToken::new();
    let _cancel = CancellationGuard::new(scope.clone(), cancellation.clone());
    let app = Kernel::start_native(
        catalog_plan::resolve(instances, bindings).map_err(err)?,
        driver,
        registry,
    )
    .await
    .map_err(err)?;
    let ready = app.is_ready();
    let outcome = if input.operation == "ready" {
        Ok(json!({"Ok": {"owners": input.owners}}))
    } else {
        methods::invoke(
            &app,
            "proof.caller/caller",
            &input.operation,
            input.request,
            &scope,
            cancellation,
        )
        .await
    };
    let shutdown = app.shutdown(Duration::from_secs(2)).await;
    if shutdown != ShutdownOutcome::Clean {
        return Err(err("unclean profile shutdown"));
    }
    Ok(json!({"ready":ready,"shutdown":"clean","outcome":outcome?}).to_string())
}

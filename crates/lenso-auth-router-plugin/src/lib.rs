//! Explicit credential-scheme routing across named `many` Auth bindings.
use lenso::{Lifecycle, ManyPort, provides};
use lenso_capability_auth as auth;
use lenso_capability_auth::{
    Auth, AuthInvocationError, AuthProvider, AuthRequest, AuthResponse, AuthResponseKind,
    AuthenticateError,
};
use lenso_kernel::{
    ActivateContext, DeactivateContext, InvocationContext, NativeRequestFuture, RuntimeFailure,
};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};
type RouteMap = Rc<BTreeMap<String, usize>>;
type RouteState = Rc<RefCell<Option<RouteMap>>>;
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthRouterConfig {
    routes: BTreeMap<String, String>,
}
impl AuthRouterConfig {
    pub fn new(routes: BTreeMap<String, String>) -> Result<Self, RuntimeFailure> {
        if routes.is_empty()
            || routes
                .iter()
                .any(|(scheme, provider)| !valid(scheme) || !valid_provider(provider))
            || routes.values().collect::<BTreeSet<_>>().len() != routes.len()
        {
            return Err(RuntimeFailure::InvalidResolvedPlan {
                detail: "Auth Router routes must contain valid schemes and unique provider names"
                    .to_owned(),
            });
        }
        Ok(Self { routes })
    }
}
fn validate_config(config: &AuthRouterConfig) -> Result<(), RuntimeFailure> {
    AuthRouterConfig::new(config.routes.clone()).map(|_| ())
}

#[lenso::plugin(
    lifecycle,
    validate = validate_config,
    configuration_schema = "configuration.schema.json"
)]
#[derive(Clone, Debug)]
struct AuthRouterPlugin {
    #[config]
    config: AuthRouterConfig,
    providers: ManyPort<auth::AuthClient>,
    routes: RouteState,
}

#[provides(auth::Auth)]
impl AuthProvider for AuthRouterPlugin {
    fn authenticate(
        &self,
        context: InvocationContext,
        request: AuthRequest,
    ) -> NativeRequestFuture<Auth> {
        let routes = self.routes.borrow().clone();
        let providers = self.providers.clone();
        Box::pin(async move {
            let Some(credential) = request.credential.as_ref() else {
                return Ok(Ok(AuthResponse {
                    kind: AuthResponseKind::Absent,
                    assertion: None,
                }));
            };
            let routes = routes.ok_or(RuntimeFailure::PluginFailure {
                detail: "Auth Router is not active".to_owned(),
            })?;
            let Some(index) = routes.get(&credential.scheme) else {
                return Ok(Err(AuthenticateError::Unsupported));
            };
            match providers[*index]
                .authenticate_with_context(context, request)
                .await
            {
                Ok(response) => Ok(Ok(response)),
                Err(AuthInvocationError::Domain(error)) => Ok(Err(error)),
                Err(AuthInvocationError::Runtime(error)) => Err(error),
            }
        })
    }
}

#[allow(unknown_lints, clippy::unused_async_trait_impl)]
impl Lifecycle for AuthRouterPlugin {
    async fn activate(&self, _context: ActivateContext) -> Result<(), RuntimeFailure> {
        let routes = self.routes.clone();
        let configured = self.config.routes.clone();
        let mut by_provider = self
            .providers
            .iter()
            .enumerate()
            .map(|(index, provider)| (provider.provider_instance().to_owned(), index))
            .collect::<BTreeMap<_, _>>();
        let configured_providers = configured.values().cloned().collect::<BTreeSet<_>>();
        let bound_providers = by_provider.keys().cloned().collect::<BTreeSet<_>>();
        if configured_providers != bound_providers {
            return Err(RuntimeFailure::InvalidResolvedPlan {
                detail: "Auth Router provider names must exactly match its Auth bindings"
                    .to_owned(),
            });
        }
        let resolved = configured
            .into_iter()
            .map(|(scheme, provider)| {
                let index = by_provider.remove(&provider).ok_or_else(|| {
                    RuntimeFailure::InvalidResolvedPlan {
                        detail: format!("Auth Router provider `{provider}` is not bound"),
                    }
                })?;
                Ok((scheme, index))
            })
            .collect::<Result<BTreeMap<_, _>, RuntimeFailure>>()?;
        routes.replace(Some(Rc::new(resolved)));
        Ok(())
    }

    async fn deactivate(&self, _: DeactivateContext) -> Result<(), RuntimeFailure> {
        self.routes.borrow_mut().take();
        Ok(())
    }
}
fn valid(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn valid_provider(value: &str) -> bool {
    value.split_once('/').map_or_else(
        || valid(value),
        |(plugin, instance)| valid(plugin) && valid(instance),
    )
}
#[cfg(test)]
mod config_tests {
    use super::*;
    #[test]
    fn normal_root_provider_keys_preserve_strict_scheme_validation() {
        assert!(
            AuthRouterConfig::new(BTreeMap::from([(
                "session".into(),
                "lenso.auth.account/account".into()
            )]))
            .is_ok()
        );
        assert!(!valid_provider("plugin/instance/extra"));
        assert!(!valid_provider("/instance"));
        assert!(!valid("scheme/other"));
    }
}

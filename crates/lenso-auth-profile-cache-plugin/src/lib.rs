//! Bounded generation-local cache of stale-allowed display data only.
use lenso::provides;
use lenso_capability_auth_profile_cache as cache;
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    rc::Rc,
    time::{Duration, Instant},
};
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileCacheConfig {
    maximum_age_seconds: u32,
    maximum_entries: u32,
    caller_instances: Vec<String>,
}
impl ProfileCacheConfig {
    pub fn new(
        maximum_age_seconds: u32,
        maximum_entries: u32,
        caller_instances: Vec<String>,
    ) -> Result<Self, RuntimeFailure> {
        let config = Self {
            maximum_age_seconds,
            maximum_entries,
            caller_instances,
        };
        validate(&config)?;
        Ok(config)
    }
}
fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}
fn validate(config: &ProfileCacheConfig) -> Result<(), RuntimeFailure> {
    if !(1..=3600).contains(&config.maximum_age_seconds)
        || !(1..=10000).contains(&config.maximum_entries)
        || config.caller_instances.len() > 64
        || config.caller_instances.iter().any(|caller| {
            !caller
                .split_once('/')
                .map_or_else(|| label(caller), |(p, i)| label(p) && label(i))
        })
    {
        return Err(RuntimeFailure::InvalidResolvedPlan {
            detail: "invalid bounded display profile cache configuration".into(),
        });
    }
    Ok(())
}
type CacheEntries = BTreeMap<(String, String), (Instant, cache::PutRequest)>;

#[lenso::plugin(configuration_schema="configuration.schema.json",validate=validate)]
#[derive(Clone, Debug)]
struct ProfileCachePlugin {
    #[config]
    config: ProfileCacheConfig,
    state: Rc<RefCell<CacheEntries>>,
}
#[provides(cache::ProfileCache)]
impl ProfileCachePlugin {}
impl ProfileCachePlugin {
    fn admitted(&self, caller: Option<&str>) -> bool {
        caller.is_some_and(|caller| {
            self.config
                .caller_instances
                .iter()
                .any(|allowed| caller == allowed)
        })
    }
    fn get_at(
        &self,
        caller: Option<&str>,
        request: cache::GetRequest,
        now: Instant,
    ) -> Result<cache::GetResponse, cache::GetError> {
        if !self.admitted(caller) {
            return Err(cache::GetError::PermissionDenied);
        }
        if !label(&request.namespace) || !label(&request.subject) {
            return Err(cache::GetError::InvalidRequest);
        }
        let mut state = self.state.borrow_mut();
        state.retain(|_, (born, _)| {
            now.saturating_duration_since(*born)
                < Duration::from_secs(u64::from(self.config.maximum_age_seconds))
        });
        let result = state
            .get(&(request.namespace, request.subject))
            .map(|(_, value)| value);
        Ok(cache::GetResponse {
            found: result.is_some(),
            display_name: result.map(|value| Some(value.display_name.clone())),
            avatar_url: result.and_then(|value| value.avatar_url.clone()),
            revision: result.map(|value| Some(value.revision)),
        })
    }
    fn put_at(
        &self,
        caller: Option<&str>,
        request: cache::PutRequest,
        now: Instant,
    ) -> Result<cache::PutResponse, cache::PutError> {
        if !self.admitted(caller) {
            return Err(cache::PutError::PermissionDenied);
        }
        if !label(&request.namespace)
            || !label(&request.subject)
            || request.display_name.trim().is_empty()
            || request.display_name.len() > 256
            || request.display_name.chars().any(char::is_control)
            || request.revision < 0
            || request
                .avatar_url
                .clone()
                .flatten()
                .is_some_and(|url| !valid_avatar(&url))
        {
            return Err(cache::PutError::InvalidRequest);
        }
        let key = (request.namespace.clone(), request.subject.clone());
        let mut state = self.state.borrow_mut();
        if !state.contains_key(&key)
            && state.len() >= self.config.maximum_entries as usize
            && let Some(oldest) = state
                .iter()
                .min_by_key(|(_, value)| value.0)
                .map(|(key, _)| key.clone())
        {
            state.remove(&oldest);
        }
        state.insert(key, (now, request));
        Ok(cache::PutResponse { stored: true })
    }
    fn get(
        &self,
        context: InvocationContext,
        request: cache::GetRequest,
    ) -> NativeRequestFuture<cache::ProfileCacheGet> {
        let plugin = self.clone();
        Box::pin(
            async move { Ok(plugin.get_at(context.caller_instance(), request, Instant::now())) },
        )
    }
    fn put(
        &self,
        context: InvocationContext,
        request: cache::PutRequest,
    ) -> NativeRequestFuture<cache::ProfileCachePut> {
        let plugin = self.clone();
        Box::pin(
            async move { Ok(plugin.put_at(context.caller_instance(), request, Instant::now())) },
        )
    }
}
fn valid_avatar(value: &str) -> bool {
    value.len() <= 2048
        && url::Url::parse(value).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn display_cache_is_bounded_stale_scoped_and_expires_without_identity_facts() {
        let plugin = ProfileCachePlugin {
            config: ProfileCacheConfig::new(5, 1, vec!["lenso.auth.account/default".into()])
                .unwrap(),
            state: Rc::default(),
        };
        let now = Instant::now();
        let caller = Some("lenso.auth.account/default");
        let put = |namespace: &str, subject: &str, name: &str| cache::PutRequest {
            namespace: namespace.into(),
            subject: subject.into(),
            display_name: name.into(),
            avatar_url: None,
            revision: 1,
        };
        assert!(matches!(
            plugin.put_at(
                Some("untrusted/default"),
                put("operators", "usr_a", "Alice"),
                now
            ),
            Err(cache::PutError::PermissionDenied)
        ));
        plugin
            .put_at(caller, put("operators", "usr_a", "Alice"), now)
            .unwrap();
        let get = |namespace: &str, subject: &str| cache::GetRequest {
            namespace: namespace.into(),
            subject: subject.into(),
        };
        assert_eq!(
            plugin
                .get_at(
                    caller,
                    get("operators", "usr_a"),
                    now + Duration::from_secs(4)
                )
                .unwrap()
                .display_name
                .flatten()
                .unwrap(),
            "Alice"
        );
        assert!(
            !plugin
                .get_at(caller, get("application", "usr_a"), now)
                .unwrap()
                .found
        );
        assert!(
            !plugin
                .get_at(
                    caller,
                    get("operators", "usr_a"),
                    now + Duration::from_secs(5)
                )
                .unwrap()
                .found
        );
        plugin
            .put_at(caller, put("operators", "usr_a", "Alice"), now)
            .unwrap();
        plugin
            .put_at(
                caller,
                put("operators", "usr_b", "Bob"),
                now + Duration::from_secs(1),
            )
            .unwrap();
        assert!(
            !plugin
                .get_at(
                    caller,
                    get("operators", "usr_a"),
                    now + Duration::from_secs(1)
                )
                .unwrap()
                .found
        );
        assert!(
            plugin
                .get_at(
                    caller,
                    get("operators", "usr_b"),
                    now + Duration::from_secs(1)
                )
                .unwrap()
                .found
        );
    }
}

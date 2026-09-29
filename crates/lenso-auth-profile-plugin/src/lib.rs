//! Removable display projection; cache values never enter Auth or `CredentialState`.
use lenso::provides;
use lenso_capability_account_admin as account;
use lenso_capability_auth_profile as profile;
use lenso_capability_auth_profile_cache as cache;
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    namespace: String,
    caller_instances: Vec<String>,
}
impl ProfileConfig {
    pub fn new(
        namespace: impl Into<String>,
        caller_instances: Vec<String>,
    ) -> Result<Self, RuntimeFailure> {
        let value = Self {
            namespace: namespace.into(),
            caller_instances,
        };
        validate(&value)?;
        Ok(value)
    }
}
fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}
fn validate(config: &ProfileConfig) -> Result<(), RuntimeFailure> {
    if !label(&config.namespace)
        || config.caller_instances.len() > 64
        || config.caller_instances.iter().any(|caller| {
            !caller
                .split_once('/')
                .is_some_and(|(p, i)| label(p) && label(i))
        })
    {
        return Err(RuntimeFailure::InvalidResolvedPlan {
            detail: "invalid display profile namespace or exact caller".into(),
        });
    }
    Ok(())
}
#[lenso::plugin(configuration_schema="configuration.schema.json", validate=validate)]
#[derive(Clone, Debug)]
struct ProfilePlugin {
    #[config]
    config: ProfileConfig,
    #[dependency(id = "account")]
    account: account::AccountAdminClient,
    #[dependency(id = "profile_cache")]
    profile_cache: Option<cache::ProfileCacheClient>,
}
#[provides(profile::Profile)]
impl ProfilePlugin {}
impl ProfilePlugin {
    fn read(
        &self,
        context: InvocationContext,
        request: profile::ReadRequest,
    ) -> NativeRequestFuture<profile::Profile> {
        let plugin = self.clone();
        Box::pin(async move {
            if !context.caller_instance().is_some_and(|caller| {
                plugin
                    .config
                    .caller_instances
                    .iter()
                    .any(|allowed| caller == allowed)
            }) {
                return Ok(Err(profile::ReadError::PermissionDenied));
            }
            if !label(&request.subject) {
                return Ok(Err(profile::ReadError::InvalidRequest));
            }
            if let Some(cache) = &plugin.profile_cache
                && let Ok(value) = cache
                    .get_with_context(
                        context.clone(),
                        cache::GetRequest {
                            namespace: plugin.config.namespace.clone(),
                            subject: request.subject.clone(),
                        },
                    )
                    .await
                && let Some(profile) = cached_profile(value)
            {
                return Ok(Ok(profile));
            }
            let value = match plugin
                .account
                .read_profile_with_context(
                    context.clone(),
                    account::ReadProfileRequest {
                        subject: request.subject.clone(),
                    },
                )
                .await
            {
                Ok(value) => value,
                Err(account::AccountAdminReadProfileInvocationError::Domain(
                    account::ReadProfileError::Forbidden,
                )) => return Ok(Err(profile::ReadError::PermissionDenied)),
                Err(account::AccountAdminReadProfileInvocationError::Domain(
                    account::ReadProfileError::InvalidSubject,
                )) => return Ok(Err(profile::ReadError::InvalidRequest)),
                Err(account::AccountAdminReadProfileInvocationError::Domain(
                    account::ReadProfileError::UnsupportedProfile,
                )) => return Ok(Err(profile::ReadError::UnsupportedProfile)),
                Err(account::AccountAdminReadProfileInvocationError::Runtime(error)) => {
                    return Err(error);
                }
                Err(account::AccountAdminReadProfileInvocationError::Domain(
                    account::ReadProfileError::Unknown(_),
                )) => {
                    return Err(RuntimeFailure::PluginFailure {
                        detail: "unknown Account display profile outcome".into(),
                    });
                }
            };
            if value.found
                && let (Some(cache), Some(display_name), Some(revision)) = (
                    &plugin.profile_cache,
                    value.display_name.clone().flatten(),
                    value.revision.flatten(),
                )
            {
                let _ = cache
                    .put_with_context(
                        context,
                        cache::PutRequest {
                            namespace: plugin.config.namespace.clone(),
                            subject: request.subject,
                            display_name,
                            avatar_url: value.avatar_url.clone(),
                            revision,
                        },
                    )
                    .await;
            }
            Ok(Ok(profile::ReadResponse {
                found: value.found,
                display_name: value.display_name,
                avatar_url: value.avatar_url,
                revision: value.revision,
                cached: false,
            }))
        })
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

fn cached_profile(value: cache::GetResponse) -> Option<profile::ReadResponse> {
    let name = value.display_name.as_ref().and_then(Option::as_ref)?;
    if !value.found
        || name.trim().is_empty()
        || name.len() > 256
        || name.chars().any(char::is_control)
        || value.revision.flatten().is_none_or(|revision| revision < 0)
        || !value
            .avatar_url
            .as_ref()
            .and_then(Option::as_ref)
            .is_none_or(|url| valid_avatar(url))
    {
        return None;
    }
    Some(profile::ReadResponse {
        found: true,
        display_name: value.display_name,
        avatar_url: value.avatar_url,
        revision: value.revision,
        cached: true,
    })
}

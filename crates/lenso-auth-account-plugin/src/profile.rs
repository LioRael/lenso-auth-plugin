//! Profile display reads are independent of every authorization operation.
use super::{AccountAuthPlugin, InvocationContext, NativeRequestFuture};
use lenso_capability_account_admin as admin;
impl AccountAuthPlugin {
    pub(crate) fn read_profile(
        &self,
        context: InvocationContext,
        request: admin::ReadProfileRequest,
    ) -> NativeRequestFuture<admin::AccountAdminReadProfile> {
        let plugin = self.clone();
        Box::pin(async move {
            if !plugin.admin_authorized(&context) {
                return Ok(Err(admin::ReadProfileError::Forbidden));
            }
            if !super::valid_name(&request.subject) {
                return Ok(Err(admin::ReadProfileError::InvalidSubject));
            }
            let prepared = plugin.prepared()?;
            #[cfg(feature = "postgres")]
            {
                use super::{runtime, storage::AccountStore};
                use sqlx::Row;
                #[allow(
                    clippy::infallible_destructuring_match,
                    reason = "Workers builds add a D1 variant"
                )]
                let postgres = match &prepared.store {
                    AccountStore::Postgres(pg) => pg,
                    #[cfg(feature = "workers")]
                    AccountStore::D1(_) => {
                        return Ok(Err(admin::ReadProfileError::UnsupportedProfile));
                    }
                };
                let row=sqlx::query("SELECT display_name,avatar_url,profile_revision FROM identity_subjects WHERE subject_id=$1").bind(&request.subject).fetch_optional(postgres.pool()).await.map_err(|_|runtime("display profile read failed"))?;
                let Some(row) = row else {
                    return Ok(Ok(empty_profile()));
                };
                let display_name: Option<String> = row
                    .try_get("display_name")
                    .map_err(|_| runtime("display profile decode failed"))?;
                let Some(display_name) = display_name else {
                    return Ok(Ok(empty_profile()));
                };
                let avatar_url: Option<String> = row
                    .try_get("avatar_url")
                    .map_err(|_| runtime("display avatar decode failed"))?;
                let revision: i64 = row
                    .try_get("profile_revision")
                    .map_err(|_| runtime("display revision decode failed"))?;
                if !valid_profile(&display_name, avatar_url.as_deref()) || revision < 0 {
                    return Err(runtime("invalid stored display profile"));
                }
                Ok(Ok(admin::ReadProfileResponse {
                    found: true,
                    display_name: Some(Some(display_name)),
                    avatar_url: avatar_url.map(Some),
                    revision: Some(Some(revision)),
                    cached: false,
                }))
            }
            #[cfg(not(feature = "postgres"))]
            {
                let _ = prepared;
                Ok(Err(admin::ReadProfileError::UnsupportedProfile))
            }
        })
    }
}
#[cfg(feature = "postgres")]
fn empty_profile() -> admin::ReadProfileResponse {
    admin::ReadProfileResponse {
        found: false,
        display_name: None,
        avatar_url: None,
        revision: None,
        cached: false,
    }
}
#[cfg(feature = "postgres")]
pub(crate) fn valid_profile(display_name: &str, avatar_url: Option<&str>) -> bool {
    !display_name.trim().is_empty()
        && display_name.len() <= 256
        && !display_name.chars().any(char::is_control)
        && avatar_url.is_none_or(|value| {
            value.len() <= 2048
                && url::Url::parse(value).is_ok_and(|url| {
                    url.scheme() == "https"
                        && url.host_str().is_some()
                        && url.username().is_empty()
                        && url.password().is_none()
                })
        })
}

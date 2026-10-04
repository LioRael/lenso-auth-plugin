//! Optional browser renewal adapter over one fixed `ManagedSession` provider.
//!
//! Ingress owns credential extraction and double-submit CSRF admission. See
//! the package README for the required ingress and browser contracts.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use lenso_capability_http_endpoint::{
    self as http_endpoint_contract, EndpointHandleInvocationError, HandleRequest, HandleResponse,
    endpoint,
    response::{self, HeaderName, HeaderValue, StatusCode, header},
};
use lenso_capability_managed_session::{
    self as managed, ManagedSessionReadManagedInvocationError, ManagedSessionRenewInvocationError,
    ReadManagedError, ReadManagedRequest, RenewError, RenewRequest, RenewResponse,
};
use lenso_kernel::{InvocationContext, RuntimeFailure};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

pub const RENEW_ROUTE_ID: &str = "auth.session-renewal.renew";
pub const RENEW_PATH: &str = "/auth/session/renew";
pub const STATE_ROUTE_ID: &str = "auth.session-renewal.state";
pub const STATE_PATH: &str = "/auth/session/state";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, lenso::PluginConfig)]
#[serde(deny_unknown_fields)]
pub struct SessionRenewalConfig {
    session_cookie_name: String,
    csrf_cookie_name: String,
    allowed_origin: String,
}

impl SessionRenewalConfig {
    pub fn new(
        session_cookie_name: impl Into<String>,
        csrf_cookie_name: impl Into<String>,
        allowed_origin: impl Into<String>,
    ) -> Result<Self, RuntimeFailure> {
        let config = Self {
            session_cookie_name: session_cookie_name.into(),
            csrf_cookie_name: csrf_cookie_name.into(),
            allowed_origin: allowed_origin.into(),
        };
        validate_config(&config)?;
        Ok(config)
    }
}

fn validate_config(config: &SessionRenewalConfig) -> Result<(), RuntimeFailure> {
    let origin = Url::parse(&config.allowed_origin).ok();
    if !host_cookie_name(&config.session_cookie_name)
        || !host_cookie_name(&config.csrf_cookie_name)
        || config.session_cookie_name == config.csrf_cookie_name
        || !origin.is_some_and(|origin| {
            origin.scheme() == "https"
                && origin.host_str().is_some()
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.origin().ascii_serialization() == config.allowed_origin
        })
    {
        return Err(RuntimeFailure::InvalidResolvedPlan {
            detail: "Session renewal requires distinct __Host- Cookies and one exact HTTPS Origin"
                .into(),
        });
    }
    Ok(())
}

#[lenso::plugin(validate = validate_config)]
#[derive(Clone, Debug)]
struct SessionRenewalPlugin {
    #[config]
    config: SessionRenewalConfig,
    #[dependency(id = "managed_sessions")]
    managed_sessions: managed::ManagedSessionClient,
}

#[endpoint]
impl SessionRenewalPlugin {
    #[get("auth.session-renewal.state", "/auth/session/state")]
    #[openapi({
        summary: "Read current managed session deadlines without rotating credentials",
        responses: {
            "200": { description: "Current managed session metadata, without credentials or Cookie changes" },
            "401": { description: "Session invalid, expired or revoked" },
            "403": { description: "Request provenance or provider caller admission rejected" },
            "409": { description: "Selected credential stale or managed sessions unavailable" }
        }
    })]
    async fn state(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        if !state_origin_admitted(&request, &self.config.allowed_origin) {
            return problem(StatusCode::FORBIDDEN, "origin_rejected");
        }
        if !request.body.is_empty() {
            return problem(StatusCode::BAD_REQUEST, "empty_body_required");
        }
        let Some(credential) = request.credential else {
            return problem(StatusCode::UNAUTHORIZED, "session_required");
        };
        if credential.scheme != "session" {
            return problem(StatusCode::UNAUTHORIZED, "session_required");
        }
        match self
            .managed_sessions
            .read_managed_with_context(
                context,
                ReadManagedRequest {
                    credential: credential.value,
                },
            )
            .await
        {
            Ok(current) => {
                let now = OffsetDateTime::now_utc();
                let dates = OffsetDateTime::parse(&current.expires_at, &Rfc3339)
                    .ok()
                    .zip(OffsetDateTime::parse(&current.absolute_expires_at, &Rfc3339).ok())
                    .zip(OffsetDateTime::parse(&current.renew_after, &Rfc3339).ok());
                if current.session_id.is_empty()
                    || !dates.is_some_and(|((expiry, absolute), after)| {
                        expiry > now && expiry <= absolute && after <= absolute
                    })
                {
                    return problem(StatusCode::BAD_GATEWAY, "invalid_session_state_response");
                }
                no_store(
                    response::json(
                        StatusCode::OK,
                        &serde_json::json!({
                            "authenticated": true,
                            "session_id": current.session_id,
                            "expires_at": current.expires_at,
                            "absolute_expires_at": current.absolute_expires_at,
                            "renew_after": current.renew_after,
                        }),
                    )
                    .map_err(EndpointHandleInvocationError::from)?,
                )
            }
            Err(ManagedSessionReadManagedInvocationError::Domain(error)) => state_problem(&error),
            Err(ManagedSessionReadManagedInvocationError::Runtime(error)) => {
                Err(EndpointHandleInvocationError::Runtime(error))
            }
        }
    }

    #[post("auth.session-renewal.renew", "/auth/session/renew")]
    #[openapi({
        summary: "Rotate an active managed browser session within fixed provider limits",
        responses: {
            "200": { description: "Credential rotated; deadlines returned without credential material" },
            "401": { description: "Session invalid, expired or revoked; authenticate again" },
            "403": { description: "Origin or provider caller admission rejected" },
            "409": { description: "Another renewal won; validate the current browser Cookie once" },
            "429": { description: "Renewal interval has not elapsed" }
        }
    })]
    async fn renew(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        if !origin_admitted(&request, &self.config.allowed_origin) {
            return problem(StatusCode::FORBIDDEN, "origin_rejected");
        }
        // The transport body never supplies credentials, policy or authority.
        if !request.body.is_empty() {
            return problem(StatusCode::BAD_REQUEST, "empty_body_required");
        }
        let Some(credential) = request.credential else {
            return problem(StatusCode::UNAUTHORIZED, "session_required");
        };
        if credential.scheme != "session" {
            return problem(StatusCode::UNAUTHORIZED, "session_required");
        }
        // Obtain entropy before mutation, so a local entropy failure cannot lose
        // the committing response after Account has consumed the old credential.
        let csrf = csrf_token()?;
        match self
            .managed_sessions
            .renew_with_context(
                context,
                RenewRequest {
                    credential: credential.value,
                },
            )
            .await
        {
            Ok(renewed) => self.rotated_response(&renewed, &csrf),
            Err(ManagedSessionRenewInvocationError::Domain(error)) => renewal_problem(&error),
            Err(ManagedSessionRenewInvocationError::Runtime(error)) => {
                Err(EndpointHandleInvocationError::Runtime(error))
            }
        }
    }

    fn rotated_response(
        &self,
        renewed: &RenewResponse,
        csrf: &str,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let now = OffsetDateTime::now_utc();
        let expiry = OffsetDateTime::parse(&renewed.expires_at, &Rfc3339).ok();
        let absolute = OffsetDateTime::parse(&renewed.absolute_expires_at, &Rfc3339).ok();
        let after = OffsetDateTime::parse(&renewed.renew_after, &Rfc3339).ok();
        let Some((expiry, absolute, after)) = expiry
            .zip(absolute)
            .zip(after)
            .map(|((expiry, absolute), after)| (expiry, absolute, after))
        else {
            return problem(StatusCode::BAD_GATEWAY, "invalid_renewal_response");
        };
        let max_age = (expiry - now).whole_seconds();
        if max_age <= 0
            || expiry > absolute
            || after <= now
            || after > absolute
            || !opaque_cookie_value(&renewed.credential)
            || renewed.session_id.is_empty()
        {
            return problem(StatusCode::BAD_GATEWAY, "invalid_renewal_response");
        }
        let metadata = serde_json::json!({
            "session_id": renewed.session_id,
            "expires_at": renewed.expires_at,
            "absolute_expires_at": renewed.absolute_expires_at,
            "renew_after": renewed.renew_after,
        });
        let result = no_store(
            response::json(StatusCode::OK, &metadata)
                .map_err(EndpointHandleInvocationError::from)?,
        )?;
        let result = append_header(
            result,
            &header::SET_COOKIE,
            &format!(
                "{}={}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Lax",
                self.config.session_cookie_name, renewed.credential
            ),
        )?;
        append_header(
            result,
            &header::SET_COOKIE,
            &format!(
                "{}={csrf}; Path=/; Max-Age={max_age}; Secure; SameSite=Lax",
                self.config.csrf_cookie_name
            ),
        )
    }
}

fn renewal_problem(error: &RenewError) -> Result<HandleResponse, EndpointHandleInvocationError> {
    match error {
        RenewError::StaleCredential => problem(StatusCode::CONFLICT, "stale_credential"),
        RenewError::InvalidCredential => problem(StatusCode::UNAUTHORIZED, "invalid_credential"),
        RenewError::Expired => problem(StatusCode::UNAUTHORIZED, "session_expired"),
        RenewError::Revoked => problem(StatusCode::UNAUTHORIZED, "session_revoked"),
        RenewError::PermissionDenied => problem(StatusCode::FORBIDDEN, "renewal_denied"),
        RenewError::TooEarly => problem(StatusCode::TOO_MANY_REQUESTS, "renewal_too_early"),
        RenewError::NotEnabled | RenewError::Unsupported => {
            problem(StatusCode::CONFLICT, "managed_renewal_unavailable")
        }
        RenewError::Unknown(_) => problem(StatusCode::BAD_GATEWAY, "renewal_provider_error"),
    }
}

fn state_problem(
    error: &ReadManagedError,
) -> Result<HandleResponse, EndpointHandleInvocationError> {
    match error {
        ReadManagedError::StaleCredential => problem(StatusCode::CONFLICT, "stale_credential"),
        ReadManagedError::InvalidCredential => {
            problem(StatusCode::UNAUTHORIZED, "invalid_credential")
        }
        ReadManagedError::Expired => problem(StatusCode::UNAUTHORIZED, "session_expired"),
        ReadManagedError::Revoked => problem(StatusCode::UNAUTHORIZED, "session_revoked"),
        ReadManagedError::PermissionDenied => {
            problem(StatusCode::FORBIDDEN, "session_state_denied")
        }
        ReadManagedError::NotEnabled | ReadManagedError::Unsupported => {
            problem(StatusCode::CONFLICT, "managed_session_state_unavailable")
        }
        ReadManagedError::Unknown(_) => {
            problem(StatusCode::BAD_GATEWAY, "session_state_provider_error")
        }
    }
}

fn problem(
    status: StatusCode,
    code: &str,
) -> Result<HandleResponse, EndpointHandleInvocationError> {
    no_store(response::problem(
        status,
        code,
        "The session renewal request could not be completed.",
    ))
}

fn no_store(response: HandleResponse) -> Result<HandleResponse, EndpointHandleInvocationError> {
    let response = append_header(response, &header::CACHE_CONTROL, "no-store")?;
    append_header(response, &header::PRAGMA, "no-cache")
}

fn append_header(
    response: HandleResponse,
    name: &HeaderName,
    value: &str,
) -> Result<HandleResponse, EndpointHandleInvocationError> {
    let value = HeaderValue::from_str(value).map_err(|_| {
        EndpointHandleInvocationError::Runtime(RuntimeFailure::PluginFailure {
            detail: "Session renewal refused an unsafe response header".into(),
        })
    })?;
    response.with_header(name, &value).map_err(Into::into)
}

fn origin_admitted(request: &HandleRequest, allowed_origin: &str) -> bool {
    let mut origins = request
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("origin"));
    origins.next().is_some_and(|h| h.value == allowed_origin) && origins.next().is_none()
}

fn state_origin_admitted(request: &HandleRequest, allowed_origin: &str) -> bool {
    if request
        .headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("origin"))
    {
        return origin_admitted(request, allowed_origin);
    }
    let mut sites = request
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("sec-fetch-site"));
    sites.next().is_some_and(|h| h.value == "same-origin") && sites.next().is_none()
}

fn host_cookie_name(value: &str) -> bool {
    value.starts_with("__Host-")
        && value.len() > 7
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn opaque_cookie_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 8192
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn csrf_token() -> Result<String, EndpointHandleInvocationError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| {
        EndpointHandleInvocationError::Runtime(RuntimeFailure::PluginFailure {
            detail: "Session renewal could not create CSRF material".into(),
        })
    })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

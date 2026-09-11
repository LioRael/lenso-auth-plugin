//! Browser HTTP routes for one bound federated login and App-owned opaque session.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use lenso::{ManyPort, Port};
use lenso_capability_credential_issuer as credential_issuer;
use lenso_capability_credential_issuer::{
    CredentialIssuerRevokeCredentialInvocationError, RevokeCredentialError, RevokeCredentialRequest,
};
use lenso_capability_federated_auth as federated;
use lenso_capability_federated_auth::{
    CompleteError, CompleteRequest, FederatedCompleteInvocationError,
    FederatedStartInvocationError, StartError, StartRequest,
};
use lenso_capability_http_endpoint::{
    self as http_endpoint_contract, EndpointHandleInvocationError, HandleRequest, HandleResponse,
    QueryParams, endpoint,
    response::{self, HeaderName, HeaderValue, StatusCode, header},
};
use lenso_capability_password_auth as password;
use lenso_kernel::{InvocationContext, RuntimeFailure};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

const DEFAULT_RETURN_TO: &str = "/";
const MAX_RETURN_TO_BYTES: usize = 2_048;
const MAX_AUTHORIZATION_URL_BYTES: usize = 16_384;
const MAX_CALLBACK_CODE_BYTES: usize = 4_096;
const MAX_CALLBACK_STATE_BYTES: usize = 256;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, lenso::PluginConfig)]
#[serde(deny_unknown_fields)]
pub struct WebSessionConfig {
    session_cookie_name: String,
    csrf_cookie_name: String,
    #[serde(default)]
    origin: Option<String>,
}

impl WebSessionConfig {
    /// Creates Cookie names that must match the selected Web Ingress policy.
    pub fn new(
        session_cookie_name: impl Into<String>,
        csrf_cookie_name: impl Into<String>,
    ) -> Result<Self, RuntimeFailure> {
        let config = Self {
            session_cookie_name: session_cookie_name.into(),
            csrf_cookie_name: csrf_cookie_name.into(),
            origin: None,
        };
        config.validate()?;
        Ok(config)
    }

    /// Sets the exact browser origin required by password login.
    pub fn with_origin(mut self, origin: impl Into<String>) -> Result<Self, RuntimeFailure> {
        self.origin = Some(origin.into());
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> Result<(), RuntimeFailure> {
        if self
            .origin
            .as_ref()
            .is_some_and(|value| !valid_origin(value))
        {
            return Err(invalid_plan(
                "Auth Web Session requires an exact HTTPS or loopback origin",
            ));
        }
        if !host_cookie_name(&self.session_cookie_name)
            || !host_cookie_name(&self.csrf_cookie_name)
            || self.session_cookie_name == self.csrf_cookie_name
        {
            return Err(invalid_plan(
                "Auth Web Session requires distinct __Host- session and CSRF Cookie names",
            ));
        }
        Ok(())
    }
}

fn validate_config(config: &WebSessionConfig) -> Result<(), RuntimeFailure> {
    config.validate()
}

#[lenso::plugin(lifecycle, validate = validate_config)]
#[derive(Clone, Debug)]
struct AuthWebSessionPlugin {
    #[config]
    config: WebSessionConfig,
    federated: ManyPort<federated::FederatedClient>,
    password: ManyPort<password::PasswordClient>,
    issuer: Port<credential_issuer::CredentialIssuerClient>,
}

impl lenso::Lifecycle for AuthWebSessionPlugin {
    #[allow(clippy::unused_async_trait_impl)]
    async fn activate(&self, _context: lenso::ActivateContext) -> Result<(), RuntimeFailure> {
        let password = self.password.iter().count();
        let federated = self.federated.iter().count();
        if password > 1 || federated > 1 || password + federated == 0 {
            return Err(invalid_plan(
                "Bind one password provider, one federated provider, or both",
            ));
        }
        if password == 1 && self.config.origin.is_none() {
            return Err(invalid_plan(
                "Password browser login requires an exact App origin",
            ));
        }
        Ok(())
    }
}

impl AuthWebSessionPlugin {
    fn federated_client(
        &self,
    ) -> Result<federated::FederatedClient, EndpointHandleInvocationError> {
        self.federated
            .iter()
            .next()
            .map(|bound| bound.client().clone())
            .ok_or_else(|| {
                EndpointHandleInvocationError::Domain(http_endpoint_contract::HandleError::Rejected)
            })
    }
}

fn password_request(
    config: &WebSessionConfig,
    request: HandleRequest,
) -> Result<password::LoginRequest, Result<HandleResponse, EndpointHandleInvocationError>> {
    let origins: Vec<_> = request
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("origin"))
        .collect();
    if !matches!((config.origin.as_deref(), origins.as_slice()), (Some(expected), [actual]) if actual.value == expected)
    {
        return Err(intentional_problem(
            StatusCode::FORBIDDEN,
            "origin_rejected",
            "Login requires this App's exact Origin.",
        ));
    }
    let types: Vec<_> = request
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("content-type"))
        .collect();
    if !matches!(types.as_slice(), [value] if value.value.split(';').next().is_some_and(|value| value.trim() == "application/json"))
    {
        return Err(intentional_problem(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "json_required",
            "Login requires JSON.",
        ));
    }
    let bytes = request.body.into_shared();
    if bytes.len() > 16_384 {
        return Err(intentional_problem(
            StatusCode::PAYLOAD_TOO_LARGE,
            "login_too_large",
            "Login request exceeds the size limit.",
        ));
    }
    serde_json::from_slice(&bytes).map_err(|_| {
        intentional_problem(
            StatusCode::BAD_REQUEST,
            "invalid_login",
            "Invalid login request.",
        )
    })
}

fn valid_origin(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        url.origin().ascii_serialization() == value
            && url.username().is_empty()
            && url.password().is_none()
            && (url.scheme() == "https"
                || url.scheme() == "http"
                    && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")))
    })
}

#[derive(Debug, Deserialize)]
struct StartQuery {
    return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[endpoint]
impl AuthWebSessionPlugin {
    #[get("auth.web-session.methods", "/auth/methods")]
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
    async fn methods(&self) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let mut methods = Vec::new();
        if self.password.iter().next().is_some() {
            methods.push(serde_json::json!({"id":"password", "kind":"password", "label":"Email and password", "action":"/auth/password/login"}));
        }
        if self.federated.iter().next().is_some() {
            methods.push(serde_json::json!({"id":"sso", "kind":"redirect", "label":"Single sign-on", "action":"/auth/oidc/start"}));
        }
        no_store(response::json(
            StatusCode::OK,
            &serde_json::json!({"methods":methods,"csrf":{"cookie_name":self.config.csrf_cookie_name,"header_name":"x-csrf-token"}}),
        )?)
    }

    #[post("auth.web-session.password", "/auth/password/login")]
    async fn password_login(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let Some(provider) = self.password.iter().next() else {
            return intentional_problem(
                StatusCode::NOT_FOUND,
                "login_method_unavailable",
                "Password login is not configured.",
            );
        };
        let login = match password_request(&self.config, request) {
            Ok(login) => login,
            Err(response) => return response,
        };
        let csrf_token = random_token()?;
        let result = match provider
            .client()
            .login_with_context(context.clone(), login)
            .await
        {
            Ok(result) => result,
            Err(password::PasswordLoginInvocationError::Domain(
                password::LoginError::RateLimited,
            )) => {
                return intentional_problem(
                    StatusCode::TOO_MANY_REQUESTS,
                    "login_rate_limited",
                    "Try again later.",
                );
            }
            Err(password::PasswordLoginInvocationError::Domain(_)) => {
                return intentional_problem(
                    StatusCode::UNAUTHORIZED,
                    "invalid_credentials",
                    "Unable to sign in with these credentials.",
                );
            }
            Err(password::PasswordLoginInvocationError::Runtime(error)) => {
                return Err(EndpointHandleInvocationError::Runtime(error));
            }
        };
        let Some(max_age) =
            cookie_max_age(&result.expires_at).filter(|_| valid_cookie_value(&result.credential))
        else {
            self.rollback_credential(context, result.credential).await?;
            return intentional_problem(
                StatusCode::BAD_GATEWAY,
                "invalid_session",
                "The session issuer returned an invalid session.",
            );
        };
        let response = no_store(response::empty(StatusCode::NO_CONTENT))?;
        let response = append_header(
            response,
            &header::SET_COOKIE,
            &session_cookie(
                &self.config.session_cookie_name,
                &result.credential,
                max_age,
            ),
        )?;
        append_header(
            response,
            &header::SET_COOKIE,
            &csrf_cookie(&self.config.csrf_cookie_name, &csrf_token, max_age),
        )
    }

    #[get("auth.web-session.start", "/auth/oidc/start")]
    #[openapi({
        summary: "Start browser OIDC login",
        responses: {
            "302": { description: "Redirect to the configured identity provider" },
            "400": { description: "Invalid local return target" },
            "503": { description: "Federated login is unavailable" }
        }
    })]
    async fn start(
        &self,
        context: InvocationContext,
        QueryParams(query): QueryParams<StartQuery>,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let return_to = query
            .return_to
            .unwrap_or_else(|| DEFAULT_RETURN_TO.to_owned());
        if !valid_local_return(&return_to) {
            return intentional_problem(
                StatusCode::BAD_REQUEST,
                "invalid_return_to",
                "The login return target must be an App-local absolute path.",
            );
        }
        let started = match self
            .federated_client()?
            .start_with_context(context, StartRequest { return_to })
            .await
        {
            Ok(started) => started,
            Err(FederatedStartInvocationError::Domain(StartError::InvalidReturnTo)) => {
                return intentional_problem(
                    StatusCode::BAD_REQUEST,
                    "invalid_return_to",
                    "The login return target was rejected.",
                );
            }
            Err(FederatedStartInvocationError::Domain(StartError::ProviderUnavailable)) => {
                return intentional_problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "login_unavailable",
                    "The configured identity provider is unavailable.",
                );
            }
            Err(FederatedStartInvocationError::Domain(StartError::Unknown(_))) => {
                return intentional_problem(
                    StatusCode::BAD_GATEWAY,
                    "login_provider_error",
                    "The configured identity provider rejected the login start.",
                );
            }
            Err(FederatedStartInvocationError::Runtime(error)) => {
                return Err(EndpointHandleInvocationError::Runtime(error));
            }
        };
        if !valid_authorization_url(&started.authorization_url) {
            return intentional_problem(
                StatusCode::BAD_GATEWAY,
                "invalid_authorization_redirect",
                "The identity provider returned an unsafe authorization redirect.",
            );
        }
        redirect(StatusCode::FOUND, &started.authorization_url)
    }

    #[get("auth.web-session.callback", "/auth/oidc/callback")]
    #[openapi({
        summary: "Complete browser OIDC login",
        responses: {
            "303": { description: "Set the session and CSRF Cookies, then return locally" },
            "400": { description: "Invalid or replayed callback" },
            "401": { description: "The identity provider rejected authentication" }
        }
    })]
    async fn callback(
        &self,
        context: InvocationContext,
        QueryParams(query): QueryParams<CallbackQuery>,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        if query.error.is_some() {
            return intentional_problem(
                StatusCode::UNAUTHORIZED,
                "oidc_callback_rejected",
                "The identity provider did not authenticate this request.",
            );
        }
        let (Some(code), Some(state)) = (query.code, query.state) else {
            return intentional_problem(
                StatusCode::BAD_REQUEST,
                "invalid_oidc_callback",
                "The OIDC callback requires code and state.",
            );
        };
        if !valid_callback_value(&code, MAX_CALLBACK_CODE_BYTES)
            || !valid_callback_value(&state, MAX_CALLBACK_STATE_BYTES)
        {
            return intentional_problem(
                StatusCode::BAD_REQUEST,
                "invalid_oidc_callback",
                "The OIDC callback values are invalid.",
            );
        }
        let csrf_token = random_token()?;
        let completed = match self
            .federated_client()?
            .complete_with_context(context.clone(), CompleteRequest { code, state })
            .await
        {
            Ok(completed) => completed,
            Err(FederatedCompleteInvocationError::Domain(error)) => {
                return callback_error(&error);
            }
            Err(FederatedCompleteInvocationError::Runtime(error)) => {
                return Err(EndpointHandleInvocationError::Runtime(error));
            }
        };

        let Some(max_age) = cookie_max_age(&completed.expires_at) else {
            self.rollback_credential(context, completed.credential)
                .await?;
            return intentional_problem(
                StatusCode::BAD_GATEWAY,
                "invalid_session_expiry",
                "The session issuer returned an invalid expiry.",
            );
        };
        if !valid_local_return(&completed.return_to) || !valid_cookie_value(&completed.credential) {
            self.rollback_credential(context, completed.credential)
                .await?;
            return intentional_problem(
                StatusCode::BAD_GATEWAY,
                "invalid_login_result",
                "The federated provider returned an unsafe browser login result.",
            );
        }
        let session_cookie = session_cookie(
            &self.config.session_cookie_name,
            &completed.credential,
            max_age,
        );
        let csrf_cookie = csrf_cookie(&self.config.csrf_cookie_name, &csrf_token, max_age);
        let response = redirect(StatusCode::SEE_OTHER, &completed.return_to)?;
        let response = append_header(response, &header::SET_COOKIE, &session_cookie)?;
        append_header(response, &header::SET_COOKIE, &csrf_cookie)
    }

    #[post("auth.web-session.logout", "/auth/logout")]
    #[openapi({
        summary: "Revoke the selected opaque session and clear browser Cookies",
        responses: {
            "204": { description: "Session revoked or already absent" },
            "401": { description: "The selected credential is not a recognized session" }
        }
    })]
    async fn logout(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let Some(credential) = request.credential else {
            return self.cleared_response(StatusCode::NO_CONTENT);
        };
        if credential.scheme != "session" {
            return self.cleared_problem(
                StatusCode::UNAUTHORIZED,
                "session_credential_required",
                "Logout accepts only the selected session credential.",
            );
        }
        match self
            .issuer
            .revoke_credential_with_context(
                context,
                RevokeCredentialRequest {
                    scheme: credential.scheme,
                    credential: credential.value,
                },
            )
            .await
        {
            Ok(_) => self.cleared_response(StatusCode::NO_CONTENT),
            Err(CredentialIssuerRevokeCredentialInvocationError::Domain(
                RevokeCredentialError::InvalidCredential | RevokeCredentialError::NotFound,
            )) => self.cleared_problem(
                StatusCode::UNAUTHORIZED,
                "session_not_found",
                "The selected session credential was not recognized by the bound issuer.",
            ),
            Err(CredentialIssuerRevokeCredentialInvocationError::Domain(
                RevokeCredentialError::Unsupported | RevokeCredentialError::Unknown(_),
            )) => self.cleared_problem(
                StatusCode::BAD_GATEWAY,
                "session_revoke_unsupported",
                "The bound credential issuer cannot revoke this session credential.",
            ),
            Err(CredentialIssuerRevokeCredentialInvocationError::Runtime(error)) => {
                Err(EndpointHandleInvocationError::Runtime(error))
            }
        }
    }

    async fn rollback_credential(
        &self,
        context: InvocationContext,
        credential: String,
    ) -> Result<(), EndpointHandleInvocationError> {
        match self
            .issuer
            .revoke_credential_with_context(
                context,
                RevokeCredentialRequest {
                    scheme: "session".to_owned(),
                    credential,
                },
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(CredentialIssuerRevokeCredentialInvocationError::Domain(_)) => {
                Err(EndpointHandleInvocationError::Runtime(plugin_failure(
                    "the bound credential issuer rejected callback rollback",
                )))
            }
            Err(CredentialIssuerRevokeCredentialInvocationError::Runtime(error)) => {
                Err(EndpointHandleInvocationError::Runtime(error))
            }
        }
    }

    fn cleared_response(
        &self,
        status: StatusCode,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        self.append_cleared_cookies(no_store(response::empty(status))?)
    }

    fn cleared_problem(
        &self,
        status: StatusCode,
        code: &'static str,
        detail: &'static str,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        self.append_cleared_cookies(no_store(response::problem(status, code, detail))?)
    }

    fn append_cleared_cookies(
        &self,
        response: HandleResponse,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let response = append_header(
            response,
            &header::SET_COOKIE,
            &cleared_cookie(&self.config.session_cookie_name, true),
        )?;
        append_header(
            response,
            &header::SET_COOKIE,
            &cleared_cookie(&self.config.csrf_cookie_name, false),
        )
    }
}

fn callback_error(error: &CompleteError) -> Result<HandleResponse, EndpointHandleInvocationError> {
    match error {
        CompleteError::InvalidCallback | CompleteError::InvalidState => intentional_problem(
            StatusCode::BAD_REQUEST,
            "invalid_oidc_callback",
            "The OIDC callback is invalid, expired, or already consumed.",
        ),
        CompleteError::ProviderRejected | CompleteError::UnverifiedIdentity => intentional_problem(
            StatusCode::UNAUTHORIZED,
            "oidc_authentication_rejected",
            "The identity provider response could not be authenticated.",
        ),
        CompleteError::Disabled => intentional_problem(
            StatusCode::FORBIDDEN,
            "account_disabled",
            "This account cannot start a session.",
        ),
        CompleteError::Unknown(_) => intentional_problem(
            StatusCode::BAD_GATEWAY,
            "login_provider_error",
            "The federated provider returned an unknown error.",
        ),
    }
}

fn intentional_problem(
    status: StatusCode,
    code: &'static str,
    detail: &'static str,
) -> Result<HandleResponse, EndpointHandleInvocationError> {
    no_store(response::problem(status, code, detail))
}

fn redirect(
    status: StatusCode,
    location: &str,
) -> Result<HandleResponse, EndpointHandleInvocationError> {
    let response = no_store(response::empty(status))?;
    let response = append_header(response, &header::LOCATION, location)?;
    append_header(response, &header::REFERRER_POLICY, "no-referrer")
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
        EndpointHandleInvocationError::Runtime(plugin_failure(
            "Auth Web Session refused an unsafe response header",
        ))
    })?;
    response.with_header(name, &value).map_err(Into::into)
}

fn session_cookie(name: &str, credential: &str, max_age: i64) -> String {
    format!("{name}={credential}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Lax")
}

fn csrf_cookie(name: &str, token: &str, max_age: i64) -> String {
    format!("{name}={token}; Path=/; Max-Age={max_age}; Secure; SameSite=Lax")
}

fn cleared_cookie(name: &str, http_only: bool) -> String {
    let http_only = if http_only { "; HttpOnly" } else { "" };
    format!(
        "{name}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure{http_only}; SameSite=Lax"
    )
}

fn cookie_max_age(expires_at: &str) -> Option<i64> {
    let expiry = OffsetDateTime::parse(expires_at, &Rfc3339).ok()?;
    let seconds = (expiry - OffsetDateTime::now_utc()).whole_seconds();
    (seconds > 0).then_some(seconds)
}

fn random_token() -> Result<String, EndpointHandleInvocationError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| {
        EndpointHandleInvocationError::Runtime(plugin_failure(
            "random source unavailable for CSRF token",
        ))
    })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn valid_local_return(value: &str) -> bool {
    value.starts_with('/')
        && !value.starts_with("//")
        && value.len() <= MAX_RETURN_TO_BYTES
        && value.is_ascii()
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b'\\')
}

fn valid_authorization_url(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_AUTHORIZATION_URL_BYTES
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return false;
    }
    Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    })
}

fn valid_callback_value(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn valid_cookie_value(value: &str) -> bool {
    !value.is_empty() && value.len() <= 8_192 && value.bytes().all(cookie_octet)
}

const fn cookie_octet(byte: u8) -> bool {
    matches!(byte, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e)
}

fn valid_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn host_cookie_name(value: &str) -> bool {
    value.starts_with("__Host-") && valid_http_token(value)
}

fn invalid_plan(detail: &str) -> RuntimeFailure {
    RuntimeFailure::InvalidResolvedPlan {
        detail: detail.to_owned(),
    }
}

fn plugin_failure(detail: &str) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: detail.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_targets_are_strictly_app_local() {
        assert!(valid_local_return("/settings/security?login=complete"));
        assert!(!valid_local_return("https://attacker.example"));
        assert!(!valid_local_return("//attacker.example"));
        assert!(!valid_local_return("/\\attacker.example"));
        assert!(!valid_local_return(
            "/after\r\nlocation:https://attacker.example"
        ));
    }

    #[test]
    fn session_and_csrf_cookie_names_must_be_distinct_tokens() {
        assert!(WebSessionConfig::new("__Host-lenso-session", "__Host-lenso-csrf").is_ok());
        assert!(WebSessionConfig::new("lenso-session", "lenso-csrf").is_err());
        assert!(WebSessionConfig::new("same", "same").is_err());
        assert!(WebSessionConfig::new("session; Domain=attacker", "csrf").is_err());
    }

    #[test]
    fn emitted_session_cookie_has_fixed_security_attributes() {
        let cookie = session_cookie("__Host-lenso-session", "opaque-token", 3_600);
        assert_eq!(
            cookie,
            "__Host-lenso-session=opaque-token; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax"
        );
        let csrf = csrf_cookie("__Host-lenso-csrf", "csrf-token", 3_600);
        assert!(csrf.contains("; Secure; SameSite=Lax"));
        assert!(!csrf.contains("HttpOnly"));
    }
}

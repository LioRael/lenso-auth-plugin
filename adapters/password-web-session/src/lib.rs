//! Optional password browser adapter over existing Auth-owned capabilities.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use lenso_capability_credential_issuer::{
    self as issuer, CredentialIssuerRevokeCredentialInvocationError, RevokeCredentialError,
    RevokeCredentialRequest,
};
use lenso_capability_http_endpoint::{
    self as http_endpoint_contract, EndpointHandleInvocationError, HandleRequest, HandleResponse,
    endpoint,
    response::{self, HeaderName, HeaderValue, StatusCode, header},
};
use lenso_capability_password_auth::{
    self as passwords, LoginError, LoginRequest, LoginResponse, PasswordLoginInvocationError,
};
use lenso_kernel::{InvocationContext, RuntimeFailure};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

const MAX_LOGIN_BYTES: usize = 8192;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Config {
    allowed_origin: String,
    session_cookie_name: String,
    csrf_cookie_name: String,
}

fn validate_config(config: &Config) -> Result<(), RuntimeFailure> {
    let valid_origin = Url::parse(&config.allowed_origin).is_ok_and(|origin| {
        origin.scheme() == "https"
            && origin.host_str().is_some()
            && origin.username().is_empty()
            && origin.password().is_none()
            && origin.origin().ascii_serialization() == config.allowed_origin
    });
    if !valid_origin
        || !host_cookie_name(&config.session_cookie_name)
        || !host_cookie_name(&config.csrf_cookie_name)
        || config.session_cookie_name == config.csrf_cookie_name
    {
        return Err(RuntimeFailure::InvalidResolvedPlan {
            detail:
                "Password Web Session requires an exact HTTPS Origin and distinct __Host- Cookies"
                    .into(),
        });
    }
    Ok(())
}

#[lenso::plugin(configuration_schema = "configuration.schema.json", validate = validate_config)]
#[derive(Clone, Debug)]
struct PasswordWebSession {
    #[config]
    config: Config,
    #[dependency(id = "passwords")]
    passwords: passwords::PasswordClient,
    #[dependency(id = "issuer")]
    issuer: issuer::CredentialIssuerClient,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginInput {
    identifier: String,
    password: String,
}

fn login_input(
    request: &HandleRequest,
    config: &Config,
) -> Result<LoginInput, (StatusCode, &'static str)> {
    if !origin_admitted(request, &config.allowed_origin) {
        return Err((StatusCode::FORBIDDEN, "origin_rejected"));
    }
    if request.credential.is_some() {
        return Err((StatusCode::CONFLICT, "logout_required"));
    }
    if request.query.is_some() {
        return Err((StatusCode::BAD_REQUEST, "query_not_allowed"));
    }
    if !unique_header(request, "content-type")
        .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
    {
        return Err((StatusCode::UNSUPPORTED_MEDIA_TYPE, "json_required"));
    }
    if request.body.len() > MAX_LOGIN_BYTES {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "login_body_too_large"));
    }
    let input: LoginInput = serde_json::from_slice(request.body.as_ref())
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid_login_input"))?;
    if input.identifier.trim().is_empty()
        || input.identifier.len() > 512
        || input.identifier.chars().any(char::is_control)
        || input.password.is_empty()
        || input.password.len() > 1024
    {
        return Err((StatusCode::BAD_REQUEST, "invalid_login_input"));
    }
    Ok(input)
}

#[endpoint]
impl PasswordWebSession {
    #[post("auth.password-web-session.login", "/auth/password/login")]
    #[openapi({ summary: "Start an opaque browser session with the configured Password provider", responses: {
        "200": { description: "Session Cookies set; response contains no credential" },
        "401": { description: "Login rejected" }, "403": { description: "Origin rejected or account disabled" },
        "409": { description: "Logout the selected session before changing identity" }, "429": { description: "Login throttled" }
    } })]
    async fn login(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let input = match login_input(&request, &self.config) {
            Ok(input) => input,
            Err((status, code)) => return problem(status, code),
        };
        // Obtain entropy before Password may create a durable session.
        let csrf = csrf_token()?;
        match self
            .passwords
            .login_with_context(
                context,
                LoginRequest {
                    identifier: input.identifier,
                    password: input.password,
                },
            )
            .await
        {
            Ok(session) => login_response(&self.config, &session, &csrf),
            Err(PasswordLoginInvocationError::Domain(error)) => match error {
                LoginError::InvalidIdentifier | LoginError::InvalidCredentials => {
                    problem(StatusCode::UNAUTHORIZED, "login_rejected")
                }
                LoginError::RateLimited => {
                    problem(StatusCode::TOO_MANY_REQUESTS, "login_rate_limited")
                }
                LoginError::Disabled => problem(StatusCode::FORBIDDEN, "account_disabled"),
                LoginError::Unknown(_) => {
                    problem(StatusCode::BAD_GATEWAY, "password_provider_error")
                }
            },
            Err(PasswordLoginInvocationError::Runtime(error)) => {
                Err(EndpointHandleInvocationError::Runtime(error))
            }
        }
    }

    #[post("auth.password-web-session.logout", "/auth/logout")]
    #[openapi({ summary: "Revoke the ingress-selected opaque session", responses: {
        "204": { description: "Issuer confirmed revocation; both Cookies cleared" },
        "401": { description: "No recognized session; Cookies unchanged" },
        "403": { description: "Origin rejected" }, "502": { description: "Revocation unsupported or rejected" }
    } })]
    async fn logout(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        if !origin_admitted(&request, &self.config.allowed_origin) {
            return problem(StatusCode::FORBIDDEN, "origin_rejected");
        }
        if !request.body.is_empty() || request.query.is_some() {
            return problem(StatusCode::BAD_REQUEST, "empty_body_required");
        }
        let Some(credential) = request.credential else {
            return problem(StatusCode::UNAUTHORIZED, "session_required");
        };
        if credential.scheme != "session" || !opaque_cookie_value(&credential.value) {
            return problem(StatusCode::UNAUTHORIZED, "session_required");
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
            Ok(_) => clear_cookies(&self.config),
            Err(CredentialIssuerRevokeCredentialInvocationError::Domain(error)) => match error {
                RevokeCredentialError::InvalidCredential | RevokeCredentialError::NotFound => {
                    problem(StatusCode::UNAUTHORIZED, "session_not_found")
                }
                RevokeCredentialError::Unsupported | RevokeCredentialError::Unknown(_) => {
                    problem(StatusCode::BAD_GATEWAY, "session_revoke_rejected")
                }
            },
            Err(CredentialIssuerRevokeCredentialInvocationError::Runtime(error)) => {
                Err(EndpointHandleInvocationError::Runtime(error))
            }
        }
    }

    #[get("auth.password-web-session.methods", "/auth/methods")]
    #[openapi({ summary: "Discover the configured browser login method and CSRF transport", responses: {
        "200": { description: "Public Password action and CSRF Cookie/header names" }
    } })]
    async fn methods(
        &self,
        _context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        if !request.body.is_empty() || request.query.is_some() {
            return problem(StatusCode::BAD_REQUEST, "query_not_allowed");
        }
        no_store(
            response::json(StatusCode::OK, &serde_json::json!({
                "methods": [{ "id": "password", "kind": "password", "label": "Password", "action": "/auth/password/login" }],
                "csrf": { "cookie_name": self.config.csrf_cookie_name, "header_name": "x-csrf-token" }
            }))
            .map_err(EndpointHandleInvocationError::from)?,
        )
    }

    #[get("auth.password-web-session.page", "/auth/login")]
    #[openapi({ summary: "Auth-owned browser login page", responses: { "200": { description: "Password form and current managed session state" } } })]
    async fn page(
        &self,
        _context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        if !request.body.is_empty() || request.query.is_some() {
            return problem(StatusCode::BAD_REQUEST, "query_not_allowed");
        }
        let html = format!(
            r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in</title><script type="module" src="/auth/login/assets.js"></script></head><body data-csrf-cookie="{}"><main><h1>Sign in</h1><p id="status" role="status" aria-live="polite">Checking session…</p><form id="auth-login" hidden><p><label for="identifier">Identifier</label><input id="identifier" name="identifier" autocomplete="username" maxlength="512" required></p><p><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" maxlength="1024" required></p><button id="submit" type="submit">Sign in</button></form><section id="session" hidden><p>Your session is active.</p><p><a href="/">Open Console</a></p><button id="logout" type="button">Sign out</button></section><noscript>JavaScript is required to sign in securely.</noscript></main></body></html>"#,
            self.config.csrf_cookie_name
        );
        let response = content("text/html; charset=utf-8", html.into_bytes())?;
        append_header(
            response,
            &header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
    }

    #[get("auth.password-web-session.assets", "/auth/login/assets.js")]
    #[openapi({ summary: "Auth-owned compiled browser session client", responses: { "200": { description: "Browser JavaScript" } } })]
    async fn assets(
        &self,
        _context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        if !request.body.is_empty() || request.query.is_some() {
            return problem(StatusCode::BAD_REQUEST, "query_not_allowed");
        }
        content(
            "text/javascript; charset=utf-8",
            include_bytes!("../dist/assets.js").to_vec(),
        )
    }
}

fn login_response(
    config: &Config,
    session: &LoginResponse,
    csrf: &str,
) -> Result<HandleResponse, EndpointHandleInvocationError> {
    let Some(max_age) = OffsetDateTime::parse(&session.expires_at, &Rfc3339)
        .ok()
        .map(|expiry| (expiry - OffsetDateTime::now_utc()).whole_seconds())
        .filter(|age| *age > 0)
    else {
        return problem(StatusCode::BAD_GATEWAY, "invalid_login_response");
    };
    if !opaque_cookie_value(&session.credential)
        || session.session_id.is_empty()
        || session.subject.is_empty()
    {
        return problem(StatusCode::BAD_GATEWAY, "invalid_login_response");
    }
    let response = no_store(
        response::json(
            StatusCode::OK,
            &serde_json::json!({ "authenticated": true, "expires_at": session.expires_at }),
        )
        .map_err(EndpointHandleInvocationError::from)?,
    )?;
    let response = append_header(
        response,
        &header::SET_COOKIE,
        &format!(
            "{}={}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Lax",
            config.session_cookie_name, session.credential
        ),
    )?;
    append_header(
        response,
        &header::SET_COOKIE,
        &format!(
            "{}={csrf}; Path=/; Max-Age={max_age}; Secure; SameSite=Lax",
            config.csrf_cookie_name
        ),
    )
}

fn clear_cookies(config: &Config) -> Result<HandleResponse, EndpointHandleInvocationError> {
    let response = no_store(response::empty(StatusCode::NO_CONTENT))?;
    let response = append_header(
        response,
        &header::SET_COOKIE,
        &format!(
            "{}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
            config.session_cookie_name
        ),
    )?;
    append_header(
        response,
        &header::SET_COOKIE,
        &format!(
            "{}=; Path=/; Max-Age=0; Secure; SameSite=Lax",
            config.csrf_cookie_name
        ),
    )
}

fn host_cookie_name(value: &str) -> bool {
    value.starts_with("__Host-")
        && (8..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
fn opaque_cookie_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 8192
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
fn unique_header<'a>(request: &'a HandleRequest, name: &str) -> Option<&'a str> {
    let mut headers = request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name));
    let value = headers.next()?.value.as_str();
    headers.next().is_none().then_some(value)
}
fn origin_admitted(request: &HandleRequest, allowed: &str) -> bool {
    unique_header(request, "origin") == Some(allowed)
}
fn csrf_token() -> Result<String, EndpointHandleInvocationError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| {
        EndpointHandleInvocationError::Runtime(RuntimeFailure::PluginFailure {
            detail: "Password Web Session entropy unavailable".into(),
        })
    })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
fn problem(
    status: StatusCode,
    code: &str,
) -> Result<HandleResponse, EndpointHandleInvocationError> {
    no_store(response::problem(
        status,
        code,
        "The browser session request could not be completed.",
    ))
}
fn content(
    media_type: &str,
    body: Vec<u8>,
) -> Result<HandleResponse, EndpointHandleInvocationError> {
    let mut response = response::empty(StatusCode::OK);
    response.body = body.into();
    let response = no_store(append_header(response, &header::CONTENT_TYPE, media_type)?)?;
    // Web Ingress owns nosniff and rejects an Endpoint that supplies it.
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
        EndpointHandleInvocationError::Runtime(RuntimeFailure::PluginFailure {
            detail: "Password Web Session refused an unsafe response header".into(),
        })
    })?;
    response.with_header(name, &value).map_err(Into::into)
}

#[cfg(test)]
mod tests;

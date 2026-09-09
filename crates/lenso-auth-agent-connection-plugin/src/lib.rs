//! Generation-local browser consent for a bounded, Account-owned Agent grant.
mod state;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use lenso::Port;
use lenso_auth_sdk::{AuthOutcome, decode_auth_response};
use lenso_capability_auth as auth;
use lenso_capability_auth_delegation as delegation;
use lenso_capability_http_endpoint::{
    self as http_endpoint_contract, EndpointHandleInvocationError, HandleRequest, HandleResponse,
    HandleResponseHeadersItem, QueryParams, endpoint,
    response::{self, StatusCode},
};
use lenso_kernel::{InvocationContext, RuntimeFailure};
use serde::Deserialize;
use serde_json::json;
use std::{cell::RefCell, rc::Rc};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, lenso::PluginConfig)]
#[serde(deny_unknown_fields)]
pub struct AgentConnectionConfig {
    pub origin: String,
    pub label: String,
    pub audience: Vec<String>,
    pub grant_ttl_seconds: u32,
}
fn validate_config(config: &AgentConnectionConfig) -> Result<(), RuntimeFailure> {
    let url = url::Url::parse(&config.origin).map_err(|_| invalid("Invalid App origin"))?;
    let local = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    if url.origin().ascii_serialization() != config.origin
        || !(url.scheme() == "https" || url.scheme() == "http" && local)
        || config.grant_ttl_seconds == 0
        || config.grant_ttl_seconds > 3600
        || config.label.trim().is_empty()
        || config.label.len() > 100
        || config.audience.is_empty()
        || config.audience.len() > 64
    {
        return Err(invalid(
            "Agent consent requires a clean HTTPS or loopback origin, label and bounded scope",
        ));
    }
    Ok(())
}
#[lenso::plugin(validate=validate_config)]
#[derive(Clone, Debug)]
struct AgentConnectionPlugin {
    #[config]
    config: AgentConnectionConfig,
    auth: Port<auth::AuthClient>,
    delegation: Port<delegation::DelegationClient>,
    attempts: Rc<RefCell<state::Attempts>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizeQuery {
    attempt: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PollRequest {
    attempt_id: String,
    polling_secret: String,
}

#[endpoint]
impl AgentConnectionPlugin {
    #[post("auth.agent-connection.begin", "/auth/agent/connection/begin")]
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
    async fn begin(
        &self,
        _context: InvocationContext,
        _request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let id = random()?;
        let secret = random()?;
        let now = now();
        if self
            .attempts
            .borrow_mut()
            .insert(id.clone(), &secret, now)
            .is_err()
        {
            return Ok(problem(StatusCode::TOO_MANY_REQUESTS, "attempt_capacity"));
        }
        json_response(
            &json!({"attempt_id":id,"polling_secret":secret,"authorization_url":format!("{}/auth/agent/authorize?attempt={id}",self.config.origin),"expires_at_millis":((now+300)*1000).to_string()}),
        )
    }
    #[get("auth.agent-connection.authorize", "/auth/agent/authorize")]
    async fn authorize(
        &self,
        context: InvocationContext,
        request: HandleRequest,
        QueryParams(query): QueryParams<AuthorizeQuery>,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let Some(credential) = request
            .credential
            .filter(|credential| credential.scheme == "session")
        else {
            return Ok(problem(StatusCode::UNAUTHORIZED, "login_required"));
        };
        let result = self
            .auth
            .authenticate_with_context(
                context,
                auth::AuthRequest {
                    credential: Some(auth::AuthenticateRequestCredential {
                        scheme: "session".into(),
                        value: credential.value.clone(),
                    }),
                },
            )
            .await;
        let assertion = match result {
            Ok(value) => match decode_auth_response(value) {
                Ok(AuthOutcome::Authenticated(assertion)) if assertion.actor_kind() == "user" => {
                    assertion
                }
                _ => return Ok(problem(StatusCode::UNAUTHORIZED, "login_required")),
            },
            Err(auth::AuthInvocationError::Runtime(error)) => {
                return Err(EndpointHandleInvocationError::Runtime(error));
            }
            Err(auth::AuthInvocationError::Domain(_)) => {
                return Ok(problem(StatusCode::UNAUTHORIZED, "login_required"));
            }
        };
        let nonce = random()?;
        if self
            .attempts
            .borrow_mut()
            .consent(&query.attempt, &nonce, &credential.value, now())
            .is_err()
        {
            return Ok(problem(StatusCode::NOT_FOUND, "attempt_unavailable"));
        }
        let scopes = self
            .config
            .audience
            .iter()
            .fold(String::new(), |mut html, scope| {
                html.push_str("<li>");
                html.push_str(&escape(scope));
                html.push_str("</li>");
                html
            });
        let html = format!(
            r#"<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Connect Agent</title><body><main><h1>Connect Agent to {}</h1><p>Continue as <strong>{}</strong>. The Agent can use the following operations for up to one hour, within your existing permissions.</p><ul>{scopes}</ul><p>Only approve a connection you just started. Closing this page leaves it unapproved.</p><form method="post" action="/auth/agent/approve"><input type="hidden" name="attempt" value="{}"><input type="hidden" name="consent" value="{}"><button type="submit">Allow connection</button></form></main></body></html>"#,
            escape(&self.config.label),
            escape(assertion.subject()),
            escape(&query.attempt),
            nonce
        );
        Ok(html_response(html))
    }
    #[post("auth.agent-connection.approve", "/auth/agent/approve")]
    async fn approve(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let origins = request
            .headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("origin"))
            .collect::<Vec<_>>();
        if origins.len() != 1 || origins[0].value != self.config.origin {
            return Ok(problem(StatusCode::FORBIDDEN, "origin_rejected"));
        }
        let Some(credential) = request
            .credential
            .filter(|credential| credential.scheme == "session")
        else {
            return Ok(problem(StatusCode::UNAUTHORIZED, "login_required"));
        };
        if request.body.len() > 1024 {
            return Ok(problem(StatusCode::BAD_REQUEST, "invalid_consent"));
        }
        let values = url::form_urlencoded::parse(request.body.as_ref()).collect::<Vec<_>>();
        let attempts = values
            .iter()
            .filter(|(key, _)| key == "attempt")
            .collect::<Vec<_>>();
        let nonces = values
            .iter()
            .filter(|(key, _)| key == "consent")
            .collect::<Vec<_>>();
        if values.len() != 2 || attempts.len() != 1 || nonces.len() != 1 {
            return Ok(problem(StatusCode::BAD_REQUEST, "invalid_consent"));
        }
        let id = attempts[0].1.as_ref();
        if self
            .attempts
            .borrow_mut()
            .claim(id, nonces[0].1.as_ref(), &credential.value, now())
            .is_err()
        {
            return Ok(problem(StatusCode::FORBIDDEN, "consent_rejected"));
        }
        let response = self
            .delegation
            .grant_with_context(
                context,
                delegation::GrantRequest {
                    parent_credential: credential.value,
                    audience: self.config.audience.clone(),
                    expires_at: (OffsetDateTime::now_utc()
                        + Duration::seconds(i64::from(self.config.grant_ttl_seconds)))
                    .format(&Rfc3339)
                    .map_err(|_| internal("Invalid grant expiration"))?,
                },
            )
            .await;
        match response {
            Ok(grant) => {
                let value = serde_json::to_string(&grant)
                    .map_err(|_| internal("Could not encode Agent grant"))?;
                self.attempts.borrow_mut().finish(id, Some(value), now());
                Ok(html_response("<!doctype html><title>Agent connected</title><p>Connection approved. Return to the Agent.</p>".into()))
            }
            Err(delegation::DelegationInvocationError::Runtime(error)) => {
                self.attempts.borrow_mut().finish(id, None, now());
                Err(EndpointHandleInvocationError::Runtime(error))
            }
            Err(delegation::DelegationInvocationError::Domain(_)) => {
                self.attempts.borrow_mut().finish(id, None, now());
                Ok(problem(StatusCode::FORBIDDEN, "grant_rejected"))
            }
        }
    }
    #[post("auth.agent-connection.poll", "/auth/agent/connection/poll")]
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
    async fn poll(
        &self,
        _context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        if request.body.len() > 1024 {
            return Ok(problem(StatusCode::BAD_REQUEST, "invalid_poll"));
        }
        let Ok(body) = serde_json::from_slice::<PollRequest>(request.body.as_ref()) else {
            return Ok(problem(StatusCode::BAD_REQUEST, "invalid_poll"));
        };
        match self
            .attempts
            .borrow_mut()
            .poll(&body.attempt_id, &body.polling_secret, now())
        {
            Ok(state::Poll::Pending) => json_response(&json!({"state":"pending"})),
            Ok(state::Poll::Failed) => json_response(&json!({"state":"failed"})),
            Ok(state::Poll::Ready(value)) => {
                let grant: serde_json::Value = serde_json::from_str(&value)
                    .map_err(|_| internal("Could not decode Agent grant"))?;
                json_response(&json!({"state":"connected","grant":grant}))
            }
            Err(_) => Ok(problem(StatusCode::NOT_FOUND, "attempt_unavailable")),
        }
    }
}
fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}
fn random() -> Result<String, EndpointHandleInvocationError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| internal("Could not create connection challenge"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn invalid(detail: &str) -> RuntimeFailure {
    RuntimeFailure::InvalidResolvedPlan {
        detail: detail.into(),
    }
}
fn internal(detail: &str) -> EndpointHandleInvocationError {
    EndpointHandleInvocationError::Runtime(RuntimeFailure::PluginFailure {
        detail: detail.into(),
    })
}
fn secure(mut response: HandleResponse) -> HandleResponse {
    response.headers.extend(
        [
            ("cache-control", "no-store"),
            ("referrer-policy", "no-referrer"),
            ("x-content-type-options", "nosniff"),
            (
                "content-security-policy",
                "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            ),
        ]
        .map(|(name, value)| HandleResponseHeadersItem {
            name: name.into(),
            value: value.into(),
        }),
    );
    response
}
fn problem(status: StatusCode, code: &str) -> HandleResponse {
    secure(response::problem(
        status,
        code,
        "The Agent connection request could not be completed.",
    ))
}
fn json_response(
    value: &serde_json::Value,
) -> Result<HandleResponse, EndpointHandleInvocationError> {
    response::json(StatusCode::OK, value)
        .map(secure)
        .map_err(Into::into)
}
fn html_response(html: String) -> HandleResponse {
    secure(HandleResponse {
        status: 200,
        headers: vec![HandleResponseHeadersItem {
            name: "content-type".into(),
            value: "text/html; charset=utf-8".into(),
        }],
        body: html.into_bytes().into(),
    })
}

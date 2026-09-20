//! Private Host-to-PostgreSQL bridge for Workers Auth composition.
//!
//! This module deliberately names PostgreSQL semantics, not Cloudflare or a
//! Hyperdrive binding. A Workers Host owns its transport/resource choice and
//! injects one event-owned callback. The callback must preserve the two Auth
//! operations' exact durable semantics, especially one transactional `consume`
//! with no retry after an uncertain mutation outcome.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;

use crate::{ConsumeError, RevokeError, RuntimeFailure, failure, storage::EncryptedFlow};

/// An event-owned private PostgreSQL persistence bridge supplied by the Host.
#[derive(Clone)]
pub struct PostgresBinding {
    execute: js_sys::Function,
}

impl std::fmt::Debug for PostgresBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresBinding")
            .finish_non_exhaustive()
    }
}

impl PostgresBinding {
    /// `execute` accepts canonical Auth PostgreSQL operation JSON and returns a
    /// Promise resolving to one canonical outcome JSON string.
    pub fn new(execute: js_sys::Function) -> Self {
        Self { execute }
    }

    async fn run(&self, request: PostgresRequest) -> Result<PostgresResponse, ()> {
        let input = serde_json::to_string(&request).map_err(|_| ())?;
        let promise = self
            .execute
            .call1(&JsValue::NULL, &JsValue::from_str(&input))
            .map_err(|_| ())?;
        let value = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::resolve(&promise))
            .await
            .map_err(|_| ())?;
        serde_json::from_str(&value.as_string().ok_or(())?).map_err(|_| ())
    }
}

#[derive(Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum PostgresRequest {
    Create {
        flow: PostgresFlow,
    },
    Consume {
        state_digest: String,
        provider: String,
    },
    Revoke {
        state_digest: String,
        provider: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PostgresFlow {
    state_digest: String,
    provider: String,
    verifier_nonce: String,
    encrypted_verifier: String,
    return_to: String,
    expires_at: String,
    oidc_nonce: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum PostgresResponse {
    Created,
    Consumed { flow: PostgresFlow },
    Revoked,
    Domain { error: PostgresDomainError },
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum PostgresDomainError {
    InvalidState,
    ProviderMismatch,
    AlreadyConsumed,
    Revoked,
    AlreadyRevoked,
    Expired,
}

pub(crate) async fn postgres_create(
    binding: &PostgresBinding,
    flow: EncryptedFlow,
) -> Result<(), RuntimeFailure> {
    match binding
        .run(PostgresRequest::Create {
            flow: into_postgres_flow(flow),
        })
        .await
        .map_err(|()| failure("OAuth storage operation failed"))?
    {
        PostgresResponse::Created => Ok(()),
        PostgresResponse::Consumed { .. }
        | PostgresResponse::Revoked
        | PostgresResponse::Domain { .. } => Err(failure("OAuth storage operation failed")),
    }
}

pub(crate) async fn postgres_consume(
    binding: &PostgresBinding,
    digest: &[u8],
    provider: &str,
) -> Result<Result<EncryptedFlow, ConsumeError>, RuntimeFailure> {
    let response = binding
        .run(PostgresRequest::Consume {
            state_digest: URL_SAFE_NO_PAD.encode(digest),
            provider: provider.to_owned(),
        })
        .await
        .map_err(|()| failure("OAuth storage operation failed"))?;
    match response {
        PostgresResponse::Created | PostgresResponse::Revoked => {
            Err(failure("OAuth storage operation failed"))
        }
        PostgresResponse::Consumed { flow } => into_encrypted_flow(flow)
            .map(Ok)
            .map_err(|()| failure("OAuth storage operation failed")),
        PostgresResponse::Domain { error } => Ok(Err(match error {
            PostgresDomainError::InvalidState => ConsumeError::InvalidState,
            PostgresDomainError::ProviderMismatch => ConsumeError::ProviderMismatch,
            PostgresDomainError::AlreadyConsumed => ConsumeError::AlreadyConsumed,
            PostgresDomainError::Revoked => ConsumeError::Revoked,
            PostgresDomainError::AlreadyRevoked => {
                return Err(failure("OAuth storage operation failed"));
            }
            PostgresDomainError::Expired => ConsumeError::Expired,
        })),
    }
}

pub(crate) async fn postgres_revoke(
    binding: &PostgresBinding,
    digest: &[u8],
    provider: &str,
) -> Result<Result<(), RevokeError>, RuntimeFailure> {
    let response = binding
        .run(PostgresRequest::Revoke {
            state_digest: URL_SAFE_NO_PAD.encode(digest),
            provider: provider.to_owned(),
        })
        .await
        .map_err(|()| failure("OAuth storage operation failed"))?;
    match response {
        PostgresResponse::Revoked => Ok(Ok(())),
        PostgresResponse::Created | PostgresResponse::Consumed { .. } => {
            Err(failure("OAuth storage operation failed"))
        }
        PostgresResponse::Domain { error } => Ok(Err(match error {
            PostgresDomainError::InvalidState => RevokeError::InvalidState,
            PostgresDomainError::ProviderMismatch => RevokeError::ProviderMismatch,
            PostgresDomainError::AlreadyConsumed => RevokeError::AlreadyConsumed,
            PostgresDomainError::AlreadyRevoked => RevokeError::AlreadyRevoked,
            PostgresDomainError::Expired => RevokeError::Expired,
            PostgresDomainError::Revoked => return Err(failure("OAuth storage operation failed")),
        })),
    }
}

fn into_postgres_flow(flow: EncryptedFlow) -> PostgresFlow {
    PostgresFlow {
        state_digest: URL_SAFE_NO_PAD.encode(flow.digest),
        provider: flow.provider,
        verifier_nonce: URL_SAFE_NO_PAD.encode(flow.nonce),
        encrypted_verifier: URL_SAFE_NO_PAD.encode(flow.encrypted),
        return_to: flow.return_to,
        expires_at: rfc3339_timestamp(flow.expiry),
        oidc_nonce: flow.oidc_nonce,
    }
}

fn into_encrypted_flow(flow: PostgresFlow) -> Result<EncryptedFlow, ()> {
    Ok(EncryptedFlow {
        digest: URL_SAFE_NO_PAD.decode(flow.state_digest).map_err(|_| ())?,
        provider: flow.provider,
        nonce: URL_SAFE_NO_PAD
            .decode(flow.verifier_nonce)
            .map_err(|_| ())?,
        encrypted: URL_SAFE_NO_PAD
            .decode(flow.encrypted_verifier)
            .map_err(|_| ())?,
        return_to: flow.return_to,
        expiry: time::OffsetDateTime::parse(
            &flow.expires_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| ())?,
        oidc_nonce: flow.oidc_nonce,
    })
}

fn rfc3339_timestamp(value: time::OffsetDateTime) -> String {
    let value = value.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second(),
        value.nanosecond()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_wire_preserves_only_encrypted_auth_material() {
        let expiry = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let wire = into_postgres_flow(EncryptedFlow {
            digest: vec![1; 32],
            provider: "github".to_owned(),
            nonce: vec![2; 12],
            encrypted: vec![3; 24],
            return_to: "/settings/security".to_owned(),
            expiry,
            oidc_nonce: Some("nonce".to_owned()),
        });
        assert_eq!(wire.state_digest, URL_SAFE_NO_PAD.encode(vec![1; 32]));
        assert_eq!(wire.verifier_nonce, URL_SAFE_NO_PAD.encode(vec![2; 12]));
        assert_eq!(wire.encrypted_verifier, URL_SAFE_NO_PAD.encode(vec![3; 24]));
        assert!(into_encrypted_flow(wire).is_ok());
    }

    #[test]
    fn postgres_wire_has_a_distinct_atomic_revoke_operation() {
        let value = serde_json::to_value(PostgresRequest::Revoke {
            state_digest: "digest".to_owned(),
            provider: "github".to_owned(),
        })
        .unwrap();
        assert_eq!(value["operation"], "revoke");
        assert_eq!(value["state_digest"], "digest");
        assert_eq!(value["provider"], "github");

        let response: PostgresResponse =
            serde_json::from_str(r#"{"outcome":"domain","error":"already_revoked"}"#).unwrap();
        assert!(matches!(
            response,
            PostgresResponse::Domain {
                error: PostgresDomainError::AlreadyRevoked
            }
        ));
    }
}

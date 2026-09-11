//! Opaque API-token Auth Plugin with Plugin-owned `PostgreSQL` state.

mod operator;
mod schema;
mod storage;

use std::{cell::RefCell, fmt, rc::Rc, time::Duration as StdDuration};

use lenso::{ActivateContext, DeactivateContext, Lifecycle, Port, provides};
use lenso_auth_sdk::{ActorAssertionIssuer, Validity, absent_response, authenticated_response};
use lenso_capability_auth as auth;
use lenso_capability_auth::{
    Auth, AuthInvocationError, AuthProvider, AuthRequest, AuthResponse, AuthenticateError,
};
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsClient, SecretsInvocationError};
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

pub use operator::{ApiTokenAuthOperator, AuthOperatorError, IssueApiToken, IssuedApiToken};

use crate::{schema::schema_plan, storage::load_credential};

/// Package identity for the linked Rust API Token Auth Plugin.
/// Exact Cargo package version linked into the Host.
const MAX_REFERENCE_LENGTH: usize = 256;
const MAX_ASSERTION_TTL_SECONDS: u64 = 3_600;
const PREPARE_DEPENDENCY_TIMEOUT: StdDuration = StdDuration::from_secs(10);

/// Immutable Plan configuration. It contains only secret references and public data.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize, lenso::PluginConfig)]
#[serde(deny_unknown_fields)]
pub struct ApiTokenAuthConfig {
    schema: String,
    issuer: String,
    assertion_public_key: String,
    database_url_secret: String,
    assertion_signing_key_secret: String,
    token_pepper_secret: String,
    assertion_ttl_seconds: u64,
}

impl ApiTokenAuthConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        schema: impl Into<String>,
        issuer: impl Into<String>,
        assertion_public_key: impl Into<String>,
        database_url_secret: impl Into<String>,
        assertion_signing_key_secret: impl Into<String>,
        token_pepper_secret: impl Into<String>,
        assertion_ttl_seconds: u64,
    ) -> Result<Self, AuthConfigError> {
        let config = Self {
            schema: schema.into(),
            issuer: issuer.into(),
            assertion_public_key: assertion_public_key.into(),
            database_url_secret: database_url_secret.into(),
            assertion_signing_key_secret: assertion_signing_key_secret.into(),
            token_pepper_secret: token_pepper_secret.into(),
            assertion_ttl_seconds,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn assertion_public_key(&self) -> &str {
        &self.assertion_public_key
    }

    fn validate(&self) -> Result<(), AuthConfigError> {
        schema_plan(self.schema.clone()).map_err(|_| AuthConfigError::InvalidSchema)?;
        if !valid_identity(&self.issuer) {
            return Err(AuthConfigError::InvalidIssuer);
        }
        lenso_auth_sdk::ActorAssertionVerifier::from_public_key_base64(
            self.issuer.clone(),
            &self.assertion_public_key,
        )
        .map_err(|_| AuthConfigError::InvalidPublicKey)?;
        for reference in [
            &self.database_url_secret,
            &self.assertion_signing_key_secret,
            &self.token_pepper_secret,
        ] {
            if !valid_secret_reference(reference) {
                return Err(AuthConfigError::InvalidSecretReference);
            }
        }
        if self.database_url_secret == self.assertion_signing_key_secret
            || self.database_url_secret == self.token_pepper_secret
            || self.assertion_signing_key_secret == self.token_pepper_secret
        {
            return Err(AuthConfigError::DuplicateSecretReference);
        }
        if self.assertion_ttl_seconds == 0 || self.assertion_ttl_seconds > MAX_ASSERTION_TTL_SECONDS
        {
            return Err(AuthConfigError::InvalidAssertionTtl);
        }
        Ok(())
    }
}

impl fmt::Debug for ApiTokenAuthConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiTokenAuthConfig")
            .field("schema", &self.schema)
            .field("issuer", &self.issuer)
            .field("assertion_public_key", &self.assertion_public_key)
            .field("database_url_secret", &self.database_url_secret)
            .field(
                "assertion_signing_key_secret",
                &self.assertion_signing_key_secret,
            )
            .field("token_pepper_secret", &self.token_pepper_secret)
            .field("assertion_ttl_seconds", &self.assertion_ttl_seconds)
            .finish()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AuthConfigError {
    #[error("invalid owned PostgreSQL schema")]
    InvalidSchema,
    #[error("invalid Auth assertion issuer")]
    InvalidIssuer,
    #[error("invalid Ed25519 assertion public key")]
    InvalidPublicKey,
    #[error("invalid logical secret reference")]
    InvalidSecretReference,
    #[error("database, signing key, and token pepper require distinct secret references")]
    DuplicateSecretReference,
    #[error("assertion TTL must be between 1 and 3600 seconds")]
    InvalidAssertionTtl,
}

/// Returns the public verification key matching one signing secret.
pub fn assertion_public_key(signing_secret: impl AsRef<[u8]>) -> String {
    ActorAssertionIssuer::new("key-derivation", signing_secret).public_key_base64()
}

fn validate_config(config: &ApiTokenAuthConfig) -> Result<(), RuntimeFailure> {
    config
        .validate()
        .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: format!("API Token Auth configuration is invalid: {error}"),
        })
}

#[derive(Clone)]
struct PreparedAuth {
    postgres: OwnedPostgres,
    issuer: ActorAssertionIssuer,
    token_pepper: Zeroizing<Vec<u8>>,
    assertion_ttl: Duration,
}

impl fmt::Debug for PreparedAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedAuth")
            .field("schema", &self.postgres.schema())
            .field("issuer", &self.issuer)
            .field("token_pepper", &"<redacted>")
            .field("assertion_ttl", &self.assertion_ttl)
            .finish()
    }
}

#[lenso::plugin(lifecycle, validate = validate_config)]
#[derive(Clone)]
struct ApiTokenAuthPlugin {
    #[config]
    config: ApiTokenAuthConfig,
    secrets: Port<secrets::SecretsClient>,
    state: Rc<RefCell<Option<PreparedAuth>>>,
}

#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for ApiTokenAuthPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiTokenAuthProvider")
            .field("prepared", &self.state.borrow().is_some())
            .finish()
    }
}

#[provides(auth::Auth)]
impl AuthProvider for ApiTokenAuthPlugin {
    fn authenticate(
        &self,
        _context: InvocationContext,
        request: AuthRequest,
    ) -> NativeRequestFuture<Auth> {
        let prepared = self.state.borrow().clone();
        Box::pin(async move {
            let Some(prepared) = prepared else {
                return Err(RuntimeFailure::PluginFailure {
                    detail: "API Token Auth is not prepared".to_owned(),
                });
            };
            match authenticate(&prepared, request).await {
                Ok(response) => Ok(Ok(response)),
                Err(AuthInvocationError::Domain(error)) => Ok(Err(error)),
                Err(AuthInvocationError::Runtime(error)) => Err(error),
            }
        })
    }
}

impl Lifecycle for ApiTokenAuthPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let config = self.config.clone();
        let state = self.state.clone();
        let dependencies = context.dependencies().clone();
        let cancellation = context.cancellation();
        let database_url = resolve_secret(
            &self.secrets,
            &dependencies,
            cancellation.clone(),
            &config.database_url_secret,
        )
        .await?;
        let signing_secret = resolve_secret(
            &self.secrets,
            &dependencies,
            cancellation.clone(),
            &config.assertion_signing_key_secret,
        )
        .await?;
        let token_pepper = resolve_secret(
            &self.secrets,
            &dependencies,
            cancellation,
            &config.token_pepper_secret,
        )
        .await?;
        if signing_secret.len() < 32 || token_pepper.len() < 32 {
            return Err(RuntimeFailure::PluginFailure {
                detail: "Auth signing key and token pepper must each contain at least 32 bytes"
                    .to_owned(),
            });
        }
        let issuer = ActorAssertionIssuer::new(&config.issuer, signing_secret.as_bytes());
        if issuer.public_key_base64() != config.assertion_public_key {
            return Err(RuntimeFailure::PluginFailure {
                detail: "configured Auth signing key does not match its public key".to_owned(),
            });
        }
        let postgres = OwnedPostgres::prepare(
            &database_url,
            schema_plan(config.schema.clone()).map_err(|error| {
                RuntimeFailure::InvalidResolvedPlan {
                    detail: format!("API Token Auth schema plan is invalid: {error}"),
                }
            })?,
        )
        .await
        .map_err(|error| RuntimeFailure::PluginFailure {
            detail: format!("API Token Auth storage is unavailable: {error}"),
        })?;
        state.replace(Some(PreparedAuth {
            postgres,
            issuer,
            token_pepper: Zeroizing::new(token_pepper.as_bytes().to_vec()),
            assertion_ttl: Duration::seconds(
                i64::try_from(config.assertion_ttl_seconds)
                    .expect("validated assertion TTL fits i64"),
            ),
        }));
        Ok(())
    }

    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        let prepared = self.state.borrow_mut().take();
        if let Some(prepared) = prepared {
            prepared.postgres.pool().close().await;
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
enum AuthPluginError {
    #[error("Auth secret material is invalid")]
    InvalidSecretMaterial,
    #[error("PostgreSQL operation `{operation}` failed")]
    Database {
        operation: &'static str,
        #[source]
        source: lenso_postgres_kit::sqlx::Error,
    },
}

async fn authenticate(
    prepared: &PreparedAuth,
    request: AuthRequest,
) -> Result<AuthResponse, AuthInvocationError> {
    let Some(credential) = request.credential else {
        return Ok(absent_response());
    };
    if credential.scheme != "bearer" {
        return Err(AuthInvocationError::Domain(AuthenticateError::Unsupported));
    }
    if !valid_token(&credential.value) {
        return Err(AuthInvocationError::Domain(AuthenticateError::Invalid));
    }
    let digest = storage::token_digest(&prepared.token_pepper, &credential.value)
        .map_err(|error| runtime_failure(&error))?;
    let stored = load_credential(&prepared.postgres, &digest)
        .await
        .map_err(|error| runtime_failure(&error))?
        .ok_or(AuthInvocationError::Domain(AuthenticateError::Invalid))?;
    let now = OffsetDateTime::now_utc();
    if stored.revoked {
        return Err(AuthInvocationError::Domain(AuthenticateError::Revoked));
    }
    if stored.expires_at <= now {
        return Err(AuthInvocationError::Domain(AuthenticateError::Expired));
    }
    let expires_at = std::cmp::min(stored.expires_at, now + prepared.assertion_ttl);
    let validity = Validity::new(now, expires_at)
        .map_err(|_| AuthInvocationError::Domain(AuthenticateError::Expired))?;
    let assertion = prepared.issuer.issue(
        stored.subject,
        stored.actor_kind,
        stored.assurance,
        stored.audience,
        validity,
        stored.claims,
    );
    Ok(authenticated_response(&assertion))
}

async fn resolve_secret(
    secrets: &SecretsClient,
    dependencies: &lenso_kernel::PluginDependencies,
    cancellation: lenso_kernel::CancellationToken,
    reference: &str,
) -> Result<Zeroizing<String>, RuntimeFailure> {
    let context =
        dependencies.invocation_context_after(PREPARE_DEPENDENCY_TIMEOUT, cancellation)?;
    secrets
        .resolve_with_context(
            context,
            ResolveRequest {
                reference: reference.to_owned(),
            },
        )
        .await
        .map(|response| Zeroizing::new(response.value))
        .map_err(|error| match error {
            SecretsInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                detail: format!("required Auth secret reference `{reference}` was rejected"),
            },
            SecretsInvocationError::Runtime(error) => error,
        })
}

fn runtime_failure(error: &AuthPluginError) -> AuthInvocationError {
    AuthInvocationError::Runtime(RuntimeFailure::PluginFailure {
        detail: error.to_string(),
    })
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn valid_secret_reference(reference: &str) -> bool {
    !reference.is_empty()
        && reference.len() <= MAX_REFERENCE_LENGTH
        && !reference.starts_with('/')
        && !reference.ends_with('/')
        && !reference.contains("//")
        && reference
            .split('/')
            .all(|segment| segment != "." && segment != "..")
        && reference
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
}

fn valid_token(token: &str) -> bool {
    let Some(encoded) = token.strip_prefix("lenso_at_") else {
        return false;
    };
    encoded.len() == 43
        && encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_contains_references_and_public_key_only() {
        let signing_secret = "test-signing-secret";
        let config = ApiTokenAuthConfig::new(
            "auth_api",
            "auth.api-token",
            assertion_public_key(signing_secret),
            "auth/database-url",
            "auth/assertion-signing-key",
            "auth/token-pepper",
            60,
        )
        .unwrap();
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains(signing_secret));
        assert!(!format!("{config:?}").contains(signing_secret));
        assert_eq!(config.schema(), "auth_api");
    }

    #[test]
    fn tokens_have_one_exact_supported_shape() {
        assert!(valid_token(&format!("lenso_at_{}", "a".repeat(43))));
        assert!(!valid_token("bearer secret"));
        assert!(!valid_token(&format!("lenso_at_{}", "a".repeat(42))));
    }
}

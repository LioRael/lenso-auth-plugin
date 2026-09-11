use std::{collections::BTreeMap, fmt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use lenso_postgres_kit::sqlx::types::Json;
use lenso_postgres_kit::{
    OwnedPostgres, PostgresKitError, SchemaOperator, SetupOutcome, UpgradeOutcome,
};
use serde_json::Value;
use thiserror::Error;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::{schema::schema_plan, storage::token_digest};

const TOKEN_PREFIX: &str = "lenso_at_";
const MAX_IDENTITY_LENGTH: usize = 256;
const MAX_AUDIENCES: usize = 64;
const MAX_CLAIMS_BYTES: usize = 16 * 1_024;

/// Explicit setup and credential-administration API for the owning Auth Plugin.
#[derive(Clone, Debug)]
pub struct ApiTokenAuthOperator {
    postgres: OwnedPostgres,
}

impl ApiTokenAuthOperator {
    /// Creates the missing owned schema. It never adopts an unmanaged schema.
    pub async fn setup(
        database_url: &str,
        schema: &str,
    ) -> Result<SetupOutcome, AuthOperatorError> {
        Ok(SchemaOperator::connect(database_url, schema_plan(schema)?)
            .await?
            .setup()
            .await?)
    }

    /// Applies pending owned migrations explicitly.
    pub async fn upgrade(
        database_url: &str,
        schema: &str,
    ) -> Result<UpgradeOutcome, AuthOperatorError> {
        Ok(SchemaOperator::connect(database_url, schema_plan(schema)?)
            .await?
            .upgrade()
            .await?)
    }

    /// Connects only when the exact owned schema is ready.
    pub async fn connect(database_url: &str, schema: &str) -> Result<Self, AuthOperatorError> {
        Ok(Self {
            postgres: OwnedPostgres::prepare(database_url, schema_plan(schema)?).await?,
        })
    }

    /// Creates one session and one opaque API token, returning the token only once.
    pub async fn issue(
        &self,
        token_pepper: &[u8],
        spec: IssueApiToken,
    ) -> Result<IssuedApiToken, AuthOperatorError> {
        spec.validate()?;
        let secret = random_identifier(TOKEN_PREFIX, 32)?;
        let token_id = random_identifier("tok_", 16)?;
        let session_id = random_identifier("ses_", 16)?;
        let digest = token_digest(token_pepper, &secret)
            .map_err(|_| AuthOperatorError::InvalidTokenPepper)?;
        let mut transaction =
            self.postgres
                .pool()
                .begin()
                .await
                .map_err(|source| AuthOperatorError::Database {
                    operation: "begin API token issuance",
                    source,
                })?;
        lenso_postgres_kit::sqlx::query(
            "INSERT INTO auth_sessions\n\
               (session_id, subject, actor_kind, assurance, audience, claims, expires_at)\n\
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&session_id)
        .bind(&spec.subject)
        .bind(&spec.actor_kind)
        .bind(&spec.assurance)
        .bind(&spec.audience)
        .bind(Json(&spec.claims))
        .bind(spec.expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(|source| AuthOperatorError::Database {
            operation: "create Auth session",
            source,
        })?;
        lenso_postgres_kit::sqlx::query(
            "INSERT INTO api_tokens (token_id, token_digest, session_id, expires_at)\n\
             VALUES ($1, $2, $3, $4)",
        )
        .bind(&token_id)
        .bind(&digest)
        .bind(&session_id)
        .bind(spec.expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(|source| AuthOperatorError::Database {
            operation: "create opaque API token",
            source,
        })?;
        transaction
            .commit()
            .await
            .map_err(|source| AuthOperatorError::Database {
                operation: "commit API token issuance",
                source,
            })?;
        Ok(IssuedApiToken {
            token_id,
            session_id,
            secret: Zeroizing::new(secret),
        })
    }

    /// Revokes one complete session and every credential attached to it.
    pub async fn revoke_session(&self, session_id: &str) -> Result<bool, AuthOperatorError> {
        let result = lenso_postgres_kit::sqlx::query(
            "UPDATE auth_sessions SET revoked_at = transaction_timestamp()\n\
             WHERE session_id = $1 AND revoked_at IS NULL",
        )
        .bind(session_id)
        .execute(self.postgres.pool())
        .await
        .map_err(|source| AuthOperatorError::Database {
            operation: "revoke Auth session",
            source,
        })?;
        Ok(result.rows_affected() == 1)
    }

    /// Revokes one token while leaving its owning session intact.
    pub async fn revoke_token(&self, token_id: &str) -> Result<bool, AuthOperatorError> {
        let result = lenso_postgres_kit::sqlx::query(
            "UPDATE api_tokens SET revoked_at = transaction_timestamp()\n\
             WHERE token_id = $1 AND revoked_at IS NULL",
        )
        .bind(token_id)
        .execute(self.postgres.pool())
        .await
        .map_err(|source| AuthOperatorError::Database {
            operation: "revoke API token",
            source,
        })?;
        Ok(result.rows_affected() == 1)
    }
}

/// Immutable subject and authority attached to one issued API token session.
#[derive(Clone, Debug)]
pub struct IssueApiToken {
    pub subject: String,
    pub actor_kind: String,
    pub assurance: String,
    pub audience: Vec<String>,
    pub claims: BTreeMap<String, Value>,
    pub expires_at: OffsetDateTime,
}

impl IssueApiToken {
    fn validate(&self) -> Result<(), AuthOperatorError> {
        for value in [&self.subject, &self.actor_kind, &self.assurance] {
            if value.is_empty() || value.len() > MAX_IDENTITY_LENGTH {
                return Err(AuthOperatorError::InvalidIssueSpec);
            }
        }
        if self.audience.is_empty()
            || self.audience.len() > MAX_AUDIENCES
            || self
                .audience
                .iter()
                .any(|entry| entry.is_empty() || entry.len() > MAX_IDENTITY_LENGTH)
            || self.expires_at <= OffsetDateTime::now_utc()
            || serde_json::to_vec(&self.claims)
                .map_or(true, |claims| claims.len() > MAX_CLAIMS_BYTES)
        {
            return Err(AuthOperatorError::InvalidIssueSpec);
        }
        let unique_audiences = self
            .audience
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        if unique_audiences.len() != self.audience.len() {
            return Err(AuthOperatorError::InvalidIssueSpec);
        }
        Ok(())
    }
}

/// One opaque API token returned only at issuance time.
pub struct IssuedApiToken {
    token_id: String,
    session_id: String,
    secret: Zeroizing<String>,
}

impl IssuedApiToken {
    pub fn token_id(&self) -> &str {
        &self.token_id
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Exposes the one-time token to the operator who requested issuance.
    pub fn expose_secret(&self) -> &str {
        &self.secret
    }
}

impl fmt::Debug for IssuedApiToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedApiToken")
            .field("token_id", &self.token_id)
            .field("session_id", &self.session_id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum AuthOperatorError {
    #[error(transparent)]
    Plan(#[from] lenso_postgres_kit::PlanError),
    #[error(transparent)]
    Postgres(#[from] PostgresKitError),
    #[error("invalid API token issue specification")]
    InvalidIssueSpec,
    #[error("token pepper must contain secret material")]
    InvalidTokenPepper,
    #[error("operating-system randomness is unavailable")]
    RandomUnavailable,
    #[error("PostgreSQL operation `{operation}` failed")]
    Database {
        operation: &'static str,
        #[source]
        source: lenso_postgres_kit::sqlx::Error,
    },
}

fn random_identifier(prefix: &str, bytes: usize) -> Result<String, AuthOperatorError> {
    let mut random = Zeroizing::new(vec![0_u8; bytes]);
    getrandom::fill(&mut random).map_err(|_| AuthOperatorError::RandomUnavailable)?;
    Ok(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(random)))
}

use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use lenso_postgres_kit::OwnedPostgres;
use lenso_postgres_kit::sqlx::Row;
use serde_json::Value;
use sha2::Sha256;
use time::OffsetDateTime;

use crate::AuthPluginError;

#[derive(Clone, Debug)]
pub(crate) struct StoredCredential {
    pub(crate) subject: String,
    pub(crate) actor_kind: String,
    pub(crate) assurance: String,
    pub(crate) audience: Vec<String>,
    pub(crate) claims: BTreeMap<String, Value>,
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) revoked: bool,
}

pub(crate) async fn load_credential(
    postgres: &OwnedPostgres,
    digest: &[u8],
) -> Result<Option<StoredCredential>, AuthPluginError> {
    let row = lenso_postgres_kit::sqlx::query(
        "SELECT sessions.subject, sessions.actor_kind, sessions.assurance,\n\
                sessions.audience, sessions.claims,\n\
                LEAST(sessions.expires_at, tokens.expires_at) AS expires_at,\n\
                (sessions.revoked_at IS NOT NULL OR tokens.revoked_at IS NOT NULL) AS revoked\n\
         FROM api_tokens AS tokens\n\
         JOIN auth_sessions AS sessions ON sessions.session_id = tokens.session_id\n\
         WHERE tokens.token_digest = $1",
    )
    .bind(digest)
    .fetch_optional(postgres.pool())
    .await
    .map_err(|source| AuthPluginError::Database {
        operation: "load API token credential",
        source,
    })?;
    let Some(row) = row else {
        return Ok(None);
    };
    let claims: lenso_postgres_kit::sqlx::types::Json<BTreeMap<String, Value>> = row
        .try_get("claims")
        .map_err(|source| AuthPluginError::Database {
            operation: "decode API token claims",
            source,
        })?;
    Ok(Some(StoredCredential {
        subject: decode(&row, "subject")?,
        actor_kind: decode(&row, "actor_kind")?,
        assurance: decode(&row, "assurance")?,
        audience: decode(&row, "audience")?,
        claims: claims.0,
        expires_at: decode(&row, "expires_at")?,
        revoked: decode(&row, "revoked")?,
    }))
}

pub(crate) fn token_digest(pepper: &[u8], token: &str) -> Result<Vec<u8>, AuthPluginError> {
    if pepper.len() < 32 {
        return Err(AuthPluginError::InvalidSecretMaterial);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(pepper)
        .map_err(|_| AuthPluginError::InvalidSecretMaterial)?;
    mac.update(token.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn decode<T>(
    row: &lenso_postgres_kit::sqlx::postgres::PgRow,
    column: &'static str,
) -> Result<T, AuthPluginError>
where
    for<'row> T: lenso_postgres_kit::sqlx::Decode<'row, lenso_postgres_kit::sqlx::Postgres>
        + lenso_postgres_kit::sqlx::Type<lenso_postgres_kit::sqlx::Postgres>,
{
    row.try_get(column)
        .map_err(|source| AuthPluginError::Database {
            operation: "decode API token credential",
            source,
        })
}

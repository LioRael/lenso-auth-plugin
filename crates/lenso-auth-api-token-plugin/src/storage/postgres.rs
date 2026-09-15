use super::{AuthPluginError, BTreeMap, StoredCredential, Value};
use lenso_postgres_kit::OwnedPostgres;
use sqlx::Row;
pub(crate) async fn load_credential(
    postgres: &OwnedPostgres,
    digest: &[u8],
) -> Result<Option<StoredCredential>, AuthPluginError> {
    let row = sqlx::query(
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
    let claims: sqlx::types::Json<BTreeMap<String, Value>> =
        row.try_get("claims")
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

fn decode<T>(row: &sqlx::postgres::PgRow, column: &'static str) -> Result<T, AuthPluginError>
where
    for<'row> T: sqlx::Decode<'row, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(column)
        .map_err(|source| AuthPluginError::Database {
            operation: "decode API token credential",
            source,
        })
}

use super::{AuthPluginError, BTreeMap, StoredCredential, Value};
use lenso_postgres_kit::OwnedPostgres;
use sqlx::Row;
pub(crate) async fn load_credential(
    postgres: &OwnedPostgres,
    digest: &[u8],
) -> Result<Option<StoredCredential>, AuthPluginError> {
    let row = sqlx::query(
        "SELECT tokens.token_id, tokens.session_id, sessions.subject, sessions.actor_kind, sessions.assurance,\n\
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
    decode_credential(&row).map(Some)
}

fn decode_credential(row: &sqlx::postgres::PgRow) -> Result<StoredCredential, AuthPluginError> {
    let claims: sqlx::types::Json<BTreeMap<String, Value>> =
        row.try_get("claims")
            .map_err(|source| AuthPluginError::Database {
                operation: "decode API token claims",
                source,
            })?;
    Ok(StoredCredential {
        credential_id: decode(row, "token_id")?,
        session_id: decode(row, "session_id")?,
        subject: decode(row, "subject")?,
        actor_kind: decode(row, "actor_kind")?,
        assurance: decode(row, "assurance")?,
        audience: decode(row, "audience")?,
        claims: claims.0,
        expires_at: decode(row, "expires_at")?,
        revoked: decode(row, "revoked")?,
    })
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

pub(super) async fn inspect_credential(
    postgres: &OwnedPostgres,
    credential_id: &str,
    session_id: &str,
) -> Result<Option<StoredCredential>, AuthPluginError> {
    let row=sqlx::query("SELECT tokens.token_id,tokens.session_id,sessions.subject,sessions.actor_kind,sessions.assurance,sessions.audience,sessions.claims,LEAST(sessions.expires_at,tokens.expires_at) AS expires_at,(sessions.revoked_at IS NOT NULL OR tokens.revoked_at IS NOT NULL) AS revoked FROM api_tokens tokens JOIN auth_sessions sessions ON sessions.session_id=tokens.session_id WHERE tokens.token_id=$1 AND tokens.session_id=$2")
        .bind(credential_id).bind(session_id).fetch_optional(postgres.pool()).await.map_err(|source| AuthPluginError::Database{operation:"inspect API token state",source})?;
    row.as_ref().map(decode_credential).transpose()
}

pub(super) async fn attenuate_management_credential(
    postgres: &OwnedPostgres,
    binding: &lenso_auth_sdk::credential::CredentialBinding,
    ceiling: &lenso_auth_sdk::credential::ManagementCredentialCeiling,
) -> Result<bool, crate::AuthOperatorError> {
    use lenso_auth_sdk::credential::{MANAGEMENT_CEILING_CLAIM, ManagementCredentialCeiling};
    let database = |source| crate::AuthOperatorError::Database {
        operation: "attenuate management credential",
        source,
    };
    let mut transaction = postgres.pool().begin().await.map_err(database)?;
    let row=sqlx::query("SELECT sessions.claims,LEAST(sessions.expires_at,tokens.expires_at) AS expires_at,(sessions.revoked_at IS NOT NULL OR tokens.revoked_at IS NOT NULL) AS revoked FROM api_tokens tokens JOIN auth_sessions sessions ON sessions.session_id=tokens.session_id WHERE tokens.token_id=$1 AND tokens.session_id=$2 FOR UPDATE OF tokens,sessions")
        .bind(&binding.credential_id).bind(&binding.session_id).fetch_optional(&mut *transaction).await.map_err(database)?;
    let Some(row) = row else {
        return Ok(false);
    };
    let revoked: bool = row.try_get("revoked").map_err(database)?;
    let expires_at: time::OffsetDateTime = row.try_get("expires_at").map_err(database)?;
    if revoked || expires_at <= time::OffsetDateTime::now_utc() {
        return Ok(false);
    }
    let mut claims: sqlx::types::Json<BTreeMap<String, Value>> =
        row.try_get("claims").map_err(database)?;
    let parent = ManagementCredentialCeiling::from_claims(&claims.0)
        .map_err(|_| crate::AuthOperatorError::InvalidIssueSpec)?;
    if !ceiling.is_attenuation_of(&parent) {
        return Err(crate::AuthOperatorError::InvalidIssueSpec);
    }
    claims.0.insert(
        MANAGEMENT_CEILING_CLAIM.into(),
        serde_json::to_value(ceiling).expect("ceiling serializes"),
    );
    let changed = sqlx::query("UPDATE auth_sessions SET claims=$1 WHERE session_id=$2")
        .bind(claims)
        .bind(&binding.session_id)
        .execute(&mut *transaction)
        .await
        .map_err(database)?
        .rows_affected()
        == 1;
    transaction.commit().await.map_err(database)?;
    Ok(changed)
}

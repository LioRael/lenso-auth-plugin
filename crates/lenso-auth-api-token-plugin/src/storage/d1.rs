use super::{AuthPluginError, OffsetDateTime, StoredCredential};
use crate::{
    AuthOperatorError, IssueApiToken,
    workers::{D1Binding, decode_time, field, statement, timestamp},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
fn fail(_: ()) -> AuthPluginError {
    AuthPluginError::Storage
}
fn operator(_: ()) -> AuthOperatorError {
    AuthOperatorError::Storage
}

pub(super) async fn load_credential(
    db: &D1Binding,
    digest: &[u8],
) -> Result<Option<StoredCredential>, AuthPluginError> {
    let results=db.run(vec![statement("SELECT t.token_id,t.session_id,s.subject,s.actor_kind,s.assurance,s.audience,s.claims,MIN(s.expires_at,t.expires_at) AS expires_at,(s.revoked_at IS NOT NULL OR t.revoked_at IS NOT NULL) AS revoked FROM api_tokens t JOIN auth_sessions s ON s.session_id=t.session_id WHERE t.token_digest=?1",vec![json!(URL_SAFE_NO_PAD.encode(digest))])]).await.map_err(fail)?;
    decode_result(&results)
}

fn decode_result(
    results: &[crate::workers::BatchResult],
) -> Result<Option<StoredCredential>, AuthPluginError> {
    results[0]
        .results
        .first()
        .map(|row| {
            Ok(StoredCredential {
                credential_id: field(row, "token_id").map_err(fail)?,
                session_id: field(row, "session_id").map_err(fail)?,
                subject: field(row, "subject").map_err(fail)?,
                actor_kind: field(row, "actor_kind").map_err(fail)?,
                assurance: field(row, "assurance").map_err(fail)?,
                audience: serde_json::from_str(&field::<String>(row, "audience").map_err(fail)?)
                    .map_err(|_| AuthPluginError::Storage)?,
                claims: serde_json::from_str(&field::<String>(row, "claims").map_err(fail)?)
                    .map_err(|_| AuthPluginError::Storage)?,
                expires_at: decode_time(row, "expires_at").map_err(fail)?,
                revoked: field::<i64>(row, "revoked").map_err(fail)? != 0,
            })
        })
        .transpose()
}

pub(crate) async fn issue(
    db: &D1Binding,
    spec: &IssueApiToken,
    token_id: &str,
    digest: &[u8],
    session_id: &str,
) -> Result<(), AuthOperatorError> {
    let created = timestamp(OffsetDateTime::now_utc());
    let expires = timestamp(spec.expires_at);
    db.run(vec![
        statement("INSERT INTO auth_sessions(session_id,subject,actor_kind,assurance,audience,claims,expires_at,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",vec![json!(session_id),json!(spec.subject),json!(spec.actor_kind),json!(spec.assurance),json!(serde_json::to_string(&spec.audience).map_err(|_|AuthOperatorError::InvalidIssueSpec)?),json!(serde_json::to_string(&spec.claims).map_err(|_|AuthOperatorError::InvalidIssueSpec)?),expires.clone(),created.clone()]),
        statement("INSERT INTO api_tokens(token_id,token_digest,session_id,expires_at,created_at) VALUES(?1,?2,?3,?4,?5)",vec![json!(token_id),json!(URL_SAFE_NO_PAD.encode(digest)),json!(session_id),expires,created]),
    ]).await.map_err(operator)?;
    Ok(())
}

pub(crate) async fn revoke_session(db: &D1Binding, id: &str) -> Result<bool, AuthOperatorError> {
    let result = db
        .run(vec![statement(
            "UPDATE auth_sessions SET revoked_at=?2 WHERE session_id=?1 AND revoked_at IS NULL",
            vec![json!(id), timestamp(OffsetDateTime::now_utc())],
        )])
        .await
        .map_err(operator)?;
    Ok(result[0].meta.changes == 1)
}
pub(crate) async fn revoke_token(db: &D1Binding, id: &str) -> Result<bool, AuthOperatorError> {
    let result = db
        .run(vec![statement(
            "UPDATE api_tokens SET revoked_at=?2 WHERE token_id=?1 AND revoked_at IS NULL",
            vec![json!(id), timestamp(OffsetDateTime::now_utc())],
        )])
        .await
        .map_err(operator)?;
    Ok(result[0].meta.changes == 1)
}

pub(super) async fn inspect_credential(
    db: &D1Binding,
    credential_id: &str,
    session_id: &str,
) -> Result<Option<StoredCredential>, AuthPluginError> {
    let results=db.run(vec![statement("SELECT t.token_id,t.session_id,s.subject,s.actor_kind,s.assurance,s.audience,s.claims,MIN(s.expires_at,t.expires_at) AS expires_at,(s.revoked_at IS NOT NULL OR t.revoked_at IS NOT NULL) AS revoked FROM api_tokens t JOIN auth_sessions s ON s.session_id=t.session_id WHERE t.token_id=?1 AND t.session_id=?2",vec![json!(credential_id),json!(session_id)])]).await.map_err(fail)?;
    decode_result(&results)
}

pub(super) async fn attenuate_management_credential(
    db: &D1Binding,
    binding: &lenso_auth_sdk::credential::CredentialBinding,
    ceiling: &lenso_auth_sdk::credential::ManagementCredentialCeiling,
) -> Result<bool, AuthOperatorError> {
    use lenso_auth_sdk::credential::{MANAGEMENT_CEILING_CLAIM, ManagementCredentialCeiling};
    let Some(stored) = inspect_credential(db, &binding.credential_id, &binding.session_id)
        .await
        .map_err(|_| AuthOperatorError::Storage)?
    else {
        return Ok(false);
    };
    let now = OffsetDateTime::now_utc();
    if stored.revoked || stored.expires_at <= now {
        return Ok(false);
    }
    let parent = ManagementCredentialCeiling::from_claims(&stored.claims)
        .map_err(|_| AuthOperatorError::InvalidIssueSpec)?;
    if !ceiling.is_attenuation_of(&parent) {
        return Err(AuthOperatorError::InvalidIssueSpec);
    }
    let expected =
        serde_json::to_string(&stored.claims).map_err(|_| AuthOperatorError::InvalidIssueSpec)?;
    let mut claims = stored.claims;
    claims.insert(
        MANAGEMENT_CEILING_CLAIM.into(),
        serde_json::to_value(ceiling).expect("ceiling serializes"),
    );
    let narrowed =
        serde_json::to_string(&claims).map_err(|_| AuthOperatorError::InvalidIssueSpec)?;
    let result=db.run(vec![statement("UPDATE auth_sessions SET claims=?1 WHERE session_id=?2 AND claims=?3 AND revoked_at IS NULL AND expires_at>?4 AND EXISTS(SELECT 1 FROM api_tokens WHERE token_id=?5 AND session_id=?2 AND revoked_at IS NULL AND expires_at>?4)",vec![json!(narrowed),json!(binding.session_id),json!(expected),timestamp(now),json!(binding.credential_id)])]).await.map_err(operator)?;
    Ok(result[0].meta.changes == 1)
}

pub(super) async fn list_management_credentials(
    db: &D1Binding,
    subject: &str,
    deployment: &str,
    limit: u32,
    after: Option<&str>,
) -> Result<Vec<crate::ApiTokenMetadata>, AuthOperatorError> {
    let results=db.run(vec![statement(r#"SELECT t.token_id,t.session_id,s.subject,s.actor_kind,s.assurance,s.audience,MIN(s.expires_at,t.expires_at) AS expires_at,(s.revoked_at IS NOT NULL OR t.revoked_at IS NOT NULL) AS revoked FROM api_tokens t JOIN auth_sessions s ON s.session_id=t.session_id WHERE s.subject=?1 AND json_extract(s.claims,'$."lenso.auth.management-ceiling".deployment')=?2 AND (?3 IS NULL OR t.token_id>?3) ORDER BY t.token_id LIMIT ?4"#,vec![json!(subject),json!(deployment),json!(after),json!(limit)])]).await.map_err(operator)?;
    results[0]
        .results
        .iter()
        .map(|row| {
            let expires_at = decode_time(row, "expires_at").map_err(operator)?;
            let revoked = field::<i64>(row, "revoked").map_err(operator)? != 0;
            Ok(crate::ApiTokenMetadata {
                credential_id: field(row, "token_id").map_err(operator)?,
                session_id: field(row, "session_id").map_err(operator)?,
                subject: field(row, "subject").map_err(operator)?,
                actor_kind: field(row, "actor_kind").map_err(operator)?,
                assurance: field(row, "assurance").map_err(operator)?,
                audience: serde_json::from_str(
                    &field::<String>(row, "audience").map_err(operator)?,
                )
                .map_err(|_| AuthOperatorError::Storage)?,
                expires_at,
                active: !revoked && expires_at > OffsetDateTime::now_utc(),
            })
        })
        .collect()
}

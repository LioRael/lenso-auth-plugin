use super::{
    AuthorizeRequest, ConsumedCode, ExchangeRequest, OffsetDateTime, RuntimeFailure, pkce,
};
use crate::workers::{D1Binding, field, statement, timestamp};
use crate::{Engine, URL_SAFE_NO_PAD, failure};
use serde_json::json;
fn fail(_: ()) -> RuntimeFailure {
    failure("OIDC storage unavailable")
}
pub(super) async fn insert(
    db: &D1Binding,
    digest: &[u8],
    r: &AuthorizeRequest,
    expires: OffsetDateTime,
) -> Result<(), RuntimeFailure> {
    db.run(vec![statement("INSERT INTO oidc_authorization_codes(code_digest,subject_id,client_id,redirect_uri,scope,code_challenge,nonce,expires_at,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",vec![json!(URL_SAFE_NO_PAD.encode(digest)),json!(r.subject),json!(r.client_id),json!(r.redirect_uri),json!(r.scope),json!(r.code_challenge),json!(r.nonce),timestamp(expires),timestamp(OffsetDateTime::now_utc())])]).await.map_err(fail)?;
    Ok(())
}
pub(super) async fn consume(
    db: &D1Binding,
    digest: &[u8],
    r: &ExchangeRequest,
) -> Result<Option<ConsumedCode>, RuntimeFailure> {
    // One conditional mutation decides the winner. A rejected redirect, client,
    // verifier, expiry, or replay does not consume an otherwise valid code.
    let result=db.run(vec![statement("UPDATE oidc_authorization_codes SET consumed_at=strftime('%Y-%m-%dT%H:%M:%f000000Z','now') WHERE code_digest=?1 AND client_id=?2 AND redirect_uri=?3 AND code_challenge=?4 AND expires_at>?5 AND expires_at>strftime('%Y-%m-%dT%H:%M:%f000000Z','now') AND consumed_at IS NULL RETURNING subject_id,scope,nonce",vec![json!(URL_SAFE_NO_PAD.encode(digest)),json!(r.client_id),json!(r.redirect_uri),json!(pkce(&r.code_verifier)),timestamp(OffsetDateTime::now_utc())])]).await.map_err(fail)?;
    result[0]
        .results
        .first()
        .map(|row| {
            Ok(ConsumedCode {
                subject: field(row, "subject_id").map_err(fail)?,
                scope: field(row, "scope").map_err(fail)?,
                nonce: field(row, "nonce").map_err(fail)?,
            })
        })
        .transpose()
}

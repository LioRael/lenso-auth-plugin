//! Single-use OAuth state and PKCE secret custody.
mod operator;
mod schema;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use lenso::{ActivateContext, DeactivateContext, Lifecycle, Port, provides};
use lenso_capability_oauth_flow as oauth_flow;
use lenso_capability_oauth_flow::{
    ConsumeError, ConsumeRequest, ConsumeResponse, CreateError, CreateRequest, CreateResponse,
    OauthFlowConsume, OauthFlowCreate, OauthFlowProvider,
};
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsClient, SecretsInvocationError};
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
use lenso_postgres_kit::OwnedPostgres;
use lenso_postgres_kit::sqlx::Row;
pub use operator::{OAuthFlowOperator, OAuthFlowOperatorError};
use schema::schema_plan;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, fmt, rc::Rc, time::Duration as StdDuration};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;
const TIMEOUT: StdDuration = StdDuration::from_secs(10);
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, lenso::PluginConfig)]
#[serde(deny_unknown_fields)]
pub struct OAuthFlowConfig {
    schema: String,
    database_url_secret: String,
    encryption_key_secret: String,
}
fn validate_config(config: &OAuthFlowConfig) -> Result<(), RuntimeFailure> {
    schema_plan(config.schema.clone()).map_err(|error| RuntimeFailure::InvalidResolvedPlan {
        detail: error.to_string(),
    })?;
    if config.database_url_secret == config.encryption_key_secret
        || config.database_url_secret.is_empty()
        || config.encryption_key_secret.is_empty()
    {
        return Err(RuntimeFailure::InvalidResolvedPlan {
            detail: "invalid OAuth Flow secret references".to_owned(),
        });
    }
    Ok(())
}
#[derive(Clone)]
struct Prepared {
    postgres: OwnedPostgres,
    key: Zeroizing<Vec<u8>>,
}
impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prepared")
            .field("schema", &self.postgres.schema())
            .finish_non_exhaustive()
    }
}
#[lenso::plugin(lifecycle, validate = validate_config)]
#[derive(Clone)]
struct OAuthFlowPlugin {
    #[config]
    config: OAuthFlowConfig,
    secrets: Port<secrets::SecretsClient>,
    state: Rc<RefCell<Option<Prepared>>>,
}
impl fmt::Debug for OAuthFlowPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthFlowProvider").finish_non_exhaustive()
    }
}
impl OAuthFlowPlugin {
    fn prepared(&self) -> Result<Prepared, RuntimeFailure> {
        self.state
            .borrow()
            .clone()
            .ok_or(RuntimeFailure::PluginFailure {
                detail: "OAuth Flow is not prepared".to_owned(),
            })
    }
}
#[provides(oauth_flow::OauthFlow)]
impl OauthFlowProvider for OAuthFlowPlugin {
    fn create(
        &self,
        _: InvocationContext,
        request: CreateRequest,
    ) -> NativeRequestFuture<OauthFlowCreate> {
        let prepared = self.prepared();
        Box::pin(async move {
            let prepared = prepared?;
            if !valid_name(&request.provider) {
                return Ok(Err(CreateError::InvalidProvider));
            }
            if !valid_return(&request.return_to) {
                return Ok(Err(CreateError::InvalidReturnTo));
            }
            let expiry = OffsetDateTime::parse(&request.expires_at, &Rfc3339).map_err(|_| {
                RuntimeFailure::ProtocolViolation {
                    capability: lenso_capability_oauth_flow::CAPABILITY_ID,
                }
            })?;
            if expiry <= OffsetDateTime::now_utc() {
                return Ok(Err(CreateError::InvalidExpiry));
            }
            let state = random(32)?;
            let verifier = random(32)?;
            let oidc_nonce = random(32)?;
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            let digest = digest(&prepared.key, &state)?;
            let mut cipher_nonce = [0u8; 12];
            getrandom::fill(&mut cipher_nonce).map_err(|_| failure("random source unavailable"))?;
            let cipher = Aes256Gcm::new_from_slice(&prepared.key)
                .map_err(|_| failure("invalid OAuth encryption key"))?;
            let encrypted = cipher
                .encrypt(Nonce::from_slice(&cipher_nonce), verifier.as_bytes())
                .map_err(|_| failure("OAuth verifier encryption failed"))?;
            lenso_postgres_kit::sqlx::query("INSERT INTO oauth_flows(state_digest,provider,verifier_nonce,encrypted_verifier,return_to,expires_at,oidc_nonce) VALUES($1,$2,$3,$4,$5,$6,$7)").bind(digest).bind(&request.provider).bind(cipher_nonce.as_slice()).bind(encrypted).bind(&request.return_to).bind(expiry).bind(&oidc_nonce).execute(prepared.postgres.pool()).await.map_err(db)?;
            Ok(Ok(CreateResponse {
                state,
                code_verifier: verifier,
                code_challenge: challenge,
                nonce: Some(Some(oidc_nonce)),
                expires_at: request.expires_at,
            }))
        })
    }
    fn consume(
        &self,
        _: InvocationContext,
        request: ConsumeRequest,
    ) -> NativeRequestFuture<OauthFlowConsume> {
        let prepared = self.prepared();
        Box::pin(async move {
            let prepared = prepared?;
            if !valid_name(&request.provider) || request.state.len() > 256 {
                return Ok(Err(ConsumeError::InvalidState));
            }
            let digest = digest(&prepared.key, &request.state)?;
            let mut transaction = prepared.postgres.pool().begin().await.map_err(db)?;
            let row=lenso_postgres_kit::sqlx::query("SELECT provider,verifier_nonce,encrypted_verifier,oidc_nonce,return_to,expires_at,consumed_at IS NOT NULL AS consumed FROM oauth_flows WHERE state_digest=$1 FOR UPDATE").bind(&digest).fetch_optional(&mut*transaction).await.map_err(db)?;
            let Some(row) = row else {
                return Ok(Err(ConsumeError::InvalidState));
            };
            let provider: String = row.try_get("provider").map_err(db)?;
            if provider != request.provider {
                return Ok(Err(ConsumeError::ProviderMismatch));
            }
            if row.try_get::<bool, _>("consumed").map_err(db)? {
                return Ok(Err(ConsumeError::AlreadyConsumed));
            }
            let expiry: OffsetDateTime = row.try_get("expires_at").map_err(db)?;
            if expiry <= OffsetDateTime::now_utc() {
                return Ok(Err(ConsumeError::Expired));
            }
            lenso_postgres_kit::sqlx::query(
                "UPDATE oauth_flows SET consumed_at=transaction_timestamp() WHERE state_digest=$1",
            )
            .bind(&digest)
            .execute(&mut *transaction)
            .await
            .map_err(db)?;
            transaction.commit().await.map_err(db)?;
            let nonce: Vec<u8> = row.try_get("verifier_nonce").map_err(db)?;
            let encrypted: Vec<u8> = row.try_get("encrypted_verifier").map_err(db)?;
            if nonce.len() != 12 {
                return Err(failure("invalid stored OAuth nonce"));
            }
            let cipher = Aes256Gcm::new_from_slice(&prepared.key)
                .map_err(|_| failure("invalid OAuth encryption key"))?;
            let verifier = cipher
                .decrypt(Nonce::from_slice(&nonce), encrypted.as_ref())
                .map_err(|_| failure("OAuth verifier decryption failed"))?;
            let verifier = String::from_utf8(verifier)
                .map_err(|_| failure("invalid stored OAuth verifier"))?;
            Ok(Ok(ConsumeResponse {
                code_verifier: verifier,
                nonce: row
                    .try_get::<Option<String>, _>("oidc_nonce")
                    .map_err(db)?
                    .map(Some),
                return_to: row.try_get("return_to").map_err(db)?,
                expires_at: expiry
                    .format(&Rfc3339)
                    .map_err(|error| failure(&error.to_string()))?,
            }))
        })
    }
}
impl Lifecycle for OAuthFlowPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let config = self.config.clone();
        let dependencies = context.dependencies().clone();
        let cancellation = context.cancellation();
        let state = self.state.clone();
        let db = resolve(
            &self.secrets,
            &dependencies,
            cancellation.clone(),
            &config.database_url_secret,
        )
        .await?;
        let key = resolve(
            &self.secrets,
            &dependencies,
            cancellation,
            &config.encryption_key_secret,
        )
        .await?;
        if key.len() != 32 {
            return Err(failure(
                "OAuth encryption key must contain exactly 32 bytes",
            ));
        }
        let postgres = OwnedPostgres::prepare(
            &db,
            schema_plan(config.schema).map_err(|error| RuntimeFailure::InvalidResolvedPlan {
                detail: error.to_string(),
            })?,
        )
        .await
        .map_err(|error| failure(&error.to_string()))?;
        state.replace(Some(Prepared {
            postgres,
            key: Zeroizing::new(key.as_bytes().to_vec()),
        }));
        Ok(())
    }

    async fn deactivate(&self, _: DeactivateContext) -> Result<(), RuntimeFailure> {
        let prepared = self.state.borrow_mut().take();
        if let Some(prepared) = prepared {
            prepared.postgres.pool().close().await;
        }
        Ok(())
    }
}
async fn resolve(
    client: &SecretsClient,
    deps: &lenso_kernel::PluginDependencies,
    cancel: lenso_kernel::CancellationToken,
    reference: &str,
) -> Result<Zeroizing<String>, RuntimeFailure> {
    let context = deps.invocation_context_after(TIMEOUT, cancel)?;
    client
        .resolve_with_context(
            context,
            ResolveRequest {
                reference: reference.to_owned(),
            },
        )
        .await
        .map(|value| Zeroizing::new(value.value))
        .map_err(|error| match error {
            SecretsInvocationError::Domain(_) => failure("OAuth Flow secret was rejected"),
            SecretsInvocationError::Runtime(error) => error,
        })
}
fn random(bytes: usize) -> Result<String, RuntimeFailure> {
    let mut value = Zeroizing::new(vec![0u8; bytes]);
    getrandom::fill(&mut value).map_err(|_| failure("random source unavailable"))?;
    Ok(URL_SAFE_NO_PAD.encode(value))
}
fn digest(key: &[u8], state: &str) -> Result<Vec<u8>, RuntimeFailure> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .map_err(|_| failure("invalid OAuth state key"))?;
    mac.update(state.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}
fn valid_name(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 128
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
fn valid_return(v: &str) -> bool {
    v.starts_with('/')
        && !v.starts_with("//")
        && v.len() <= 2048
        && !v
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\\')
}
fn failure(detail: &str) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: detail.to_owned(),
    }
}
fn db(error: impl fmt::Display) -> RuntimeFailure {
    failure(&format!("OAuth Flow storage operation failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::valid_return;

    #[test]
    fn return_targets_reject_authority_and_backslash_ambiguity() {
        assert!(valid_return("/settings/security?connected=work-sso"));
        assert!(!valid_return("//attacker.example"));
        assert!(!valid_return("/\\attacker.example"));
        assert!(!valid_return("/after\r\nlocation:https://attacker.example"));
    }
}

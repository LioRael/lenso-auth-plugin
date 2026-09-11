//! Protocol-neutral OIDC authorization-code provider with PKCE.
mod operator;
mod schema;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use lenso::{ActivateContext, DeactivateContext, Lifecycle, Port, provides};
use lenso_capability_credential_issuer as credential_issuer;
use lenso_capability_credential_issuer::{
    CredentialIssuerIssueInvocationError, IssueError, IssueRequest,
};
use lenso_capability_identity_directory as directory;
use lenso_capability_identity_directory::{
    DirectoryReadStatusInvocationError, ReadStatusError, ReadStatusRequest,
    ReadStatusResponseStatus,
};
use lenso_capability_oidc_provider as oidc;
use lenso_capability_oidc_provider::{
    AuthorizeError, AuthorizeRequest, AuthorizeResponse, EmptyRequest, ExchangeError,
    ExchangeRequest, ExchangeResponse, JwksResponse, MetadataResponse, OidcProviderAuthorize,
    OidcProviderExchange, OidcProviderJwks, OidcProviderMetadata, OidcProviderProvider,
};
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsClient, SecretsInvocationError};
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
use lenso_postgres_kit::OwnedPostgres;
use lenso_postgres_kit::sqlx::Row;
pub use operator::{OidcOperator, OidcOperatorError};
use schema::schema_plan;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fmt,
    rc::Rc,
    time::Duration as StdDuration,
};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;
const TIMEOUT: StdDuration = StdDuration::from_secs(10);
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    schema: String,
    database_url_secret: String,
    signing_key_secret: String,
    code_pepper_secret: String,
    issuer: String,
    jwks: PublicJwks,
    key_id: Option<String>,
    client_id: String,
    redirect_uris: Vec<String>,
    authorize_callers: Vec<String>,
    audience: Vec<String>,
    code_ttl_seconds: u64,
    token_ttl_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicJwks {
    keys: Vec<PublicRsaJwk>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicRsaJwk {
    kty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(rename = "use")]
    key_use: String,
    alg: String,
    n: String,
    e: String,
}

impl PublicJwks {
    fn validate(&self, key_id: Option<&str>) -> Result<(), RuntimeFailure> {
        if self.keys.is_empty() || self.keys.len() > 16 || key_id.is_some_and(|id| !valid_name(id))
        {
            return Err(invalid("invalid OIDC public JWKS"));
        }
        let mut key_ids = BTreeSet::new();
        for key in &self.keys {
            key.validate()?;
            if let Some(key_id) = key.kid.as_deref()
                && !key_ids.insert(key_id)
            {
                return Err(invalid("OIDC public JWKS contains duplicate key ids"));
            }
        }
        self.selected_key(key_id)?;
        Ok(())
    }

    fn selected_key(&self, key_id: Option<&str>) -> Result<&PublicRsaJwk, RuntimeFailure> {
        let matches = self
            .keys
            .iter()
            .filter(|key| key_id.is_none_or(|expected| key.kid.as_deref() == Some(expected)))
            .collect::<Vec<_>>();
        let [key] = matches.as_slice() else {
            return Err(invalid(
                "OIDC public JWKS must select exactly one key for the configured key id",
            ));
        };
        Ok(key)
    }

    fn response_map(&self) -> Result<BTreeMap<String, serde_json::Value>, RuntimeFailure> {
        let keys = serde_json::to_value(&self.keys)
            .map_err(|_| failure("OIDC public JWKS serialization failed"))?;
        Ok(BTreeMap::from([("keys".to_owned(), keys)]))
    }
}

impl PublicRsaJwk {
    fn validate(&self) -> Result<(), RuntimeFailure> {
        if self.kty != "RSA"
            || self.alg != "RS256"
            || self.key_use != "sig"
            || self.kid.as_deref().is_some_and(|id| !valid_name(id))
        {
            return Err(invalid("OIDC public JWKS contains an unsupported key"));
        }
        let modulus = decode_public_component(&self.n, 256, 1024)?;
        let exponent = decode_public_component(&self.e, 1, 8)?;
        if modulus.last().is_none_or(|byte| byte & 1 == 0)
            || exponent.first() == Some(&0)
            || exponent
                .iter()
                .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte))
                < 3
            || exponent.last().is_none_or(|byte| byte & 1 == 0)
        {
            return Err(invalid("OIDC public JWKS contains an invalid RSA key"));
        }
        DecodingKey::from_rsa_components(&self.n, &self.e)
            .map_err(|_| invalid("OIDC public JWKS contains an invalid RSA key"))?;
        Ok(())
    }
}

fn decode_public_component(
    value: &str,
    minimum_bytes: usize,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RuntimeFailure> {
    if value.is_empty() || value.len() > 2048 {
        return Err(invalid("OIDC public JWKS contains an invalid RSA key"));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid("OIDC public JWKS contains an invalid RSA key"))?;
    if !(minimum_bytes..=maximum_bytes).contains(&decoded.len())
        || URL_SAFE_NO_PAD.encode(&decoded) != value
    {
        return Err(invalid("OIDC public JWKS contains an invalid RSA key"));
    }
    Ok(decoded)
}

impl OidcConfig {
    fn validate(&self) -> Result<(), RuntimeFailure> {
        schema_plan(self.schema.clone()).map_err(|e| invalid(&e.to_string()))?;
        if self.database_url_secret.is_empty()
            || self.signing_key_secret.is_empty()
            || self.code_pepper_secret.is_empty()
            || self.database_url_secret == self.signing_key_secret
            || self.database_url_secret == self.code_pepper_secret
            || self.signing_key_secret == self.code_pepper_secret
        {
            return Err(invalid(
                "OIDC secret references must be non-empty and distinct",
            ));
        }
        self.jwks.validate(self.key_id.as_deref())?;
        if self.client_id.is_empty()
            || self.redirect_uris.is_empty()
            || self.redirect_uris.iter().any(|v| v.contains('#'))
            || self.authorize_callers.is_empty()
            || self.authorize_callers.iter().any(|v| !valid_name(v))
            || self.audience.is_empty()
            || !(30..=600).contains(&self.code_ttl_seconds)
            || !(1..=86400).contains(&self.token_ttl_seconds)
        {
            return Err(invalid("invalid OIDC provider configuration"));
        }
        Ok(())
    }
}
fn validate_config(config: &OidcConfig) -> Result<(), RuntimeFailure> {
    config.validate()
}
#[derive(Clone)]
struct Prepared {
    postgres: OwnedPostgres,
    signing_key: Rc<EncodingKey>,
    pepper: Zeroizing<Vec<u8>>,
}
impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prepared")
            .field("schema", &self.postgres.schema())
            .finish_non_exhaustive()
    }
}
struct Active {
    prepared: Prepared,
    config: OidcConfig,
}
impl fmt::Debug for Active {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Active")
            .field("issuer", &self.config.issuer)
            .finish_non_exhaustive()
    }
}
#[lenso::plugin(
    lifecycle,
    validate = validate_config,
    configuration_schema = "configuration.schema.json"
)]
#[derive(Clone)]
struct OidcPlugin {
    #[config]
    config: OidcConfig,
    secrets: Port<secrets::SecretsClient>,
    directory: Port<directory::DirectoryClient>,
    issuer: Port<credential_issuer::CredentialIssuerClient>,
    prepared: Rc<RefCell<Option<Prepared>>>,
    active: Rc<RefCell<Option<Rc<Active>>>>,
}
#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for OidcPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcProvider")
            .field("active", &self.active.borrow().is_some())
            .finish()
    }
}
impl OidcPlugin {
    fn active(&self) -> Result<Rc<Active>, RuntimeFailure> {
        self.active
            .borrow()
            .clone()
            .ok_or_else(|| failure("OIDC Provider is not active"))
    }
}
#[provides(oidc::OidcProvider)]
impl OidcProviderProvider for OidcPlugin {
    fn metadata(
        &self,
        _: InvocationContext,
        _: EmptyRequest,
    ) -> NativeRequestFuture<OidcProviderMetadata> {
        let active = self.active();
        Box::pin(async move {
            let a = active?;
            Ok(Ok(MetadataResponse {
                issuer: a.config.issuer.clone(),
                authorization_endpoint: format!(
                    "{}/oauth/authorize",
                    a.config.issuer.trim_end_matches('/')
                ),
                token_endpoint: format!("{}/oauth/token", a.config.issuer.trim_end_matches('/')),
                jwks_uri: format!(
                    "{}/.well-known/jwks.json",
                    a.config.issuer.trim_end_matches('/')
                ),
                client_id: a.config.client_id.clone(),
                scopes_supported: vec!["openid".to_owned()],
            }))
        })
    }
    fn jwks(&self, _: InvocationContext, _: EmptyRequest) -> NativeRequestFuture<OidcProviderJwks> {
        let active = self.active();
        Box::pin(async move {
            let a = active?;
            Ok(Ok(JwksResponse {
                jwks: a.config.jwks.response_map()?,
            }))
        })
    }
    fn authorize(
        &self,
        context: InvocationContext,
        r: AuthorizeRequest,
    ) -> NativeRequestFuture<OidcProviderAuthorize> {
        let active = self.active();
        let directory = self.directory.clone();
        Box::pin(async move {
            let a = active?;
            if !context
                .caller_instance()
                .is_some_and(|c| a.config.authorize_callers.iter().any(|v| v == c))
            {
                return Ok(Err(AuthorizeError::Forbidden));
            }
            if r.response_type != "code" || r.code_challenge_method != "S256" {
                return Ok(Err(AuthorizeError::InvalidRequest));
            }
            if r.client_id != a.config.client_id {
                return Ok(Err(AuthorizeError::InvalidClient));
            }
            if !a.config.redirect_uris.contains(&r.redirect_uri) {
                return Ok(Err(AuthorizeError::InvalidRedirectUri));
            }
            let scopes = r.scope.split_whitespace().collect::<BTreeSet<_>>();
            if scopes != BTreeSet::from(["openid"]) {
                return Ok(Err(AuthorizeError::InvalidScope));
            }
            if !valid_pkce(&r.code_challenge) {
                return Ok(Err(AuthorizeError::InvalidPkce));
            }
            match directory
                .read_status_with_context(
                    context,
                    ReadStatusRequest {
                        subject: r.subject.clone(),
                    },
                )
                .await
            {
                Ok(v) if v.status == ReadStatusResponseStatus::Active => {}
                Ok(_)
                | Err(DirectoryReadStatusInvocationError::Domain(ReadStatusError::NotFound)) => {
                    return Ok(Err(AuthorizeError::DisabledSubject));
                }
                Err(DirectoryReadStatusInvocationError::Domain(_)) => {
                    return Ok(Err(AuthorizeError::InvalidRequest));
                }
                Err(DirectoryReadStatusInvocationError::Runtime(e)) => return Err(e),
            }
            let code = random_code()?;
            let digest = code_digest(&a.prepared.pepper, &code)?;
            let expires = OffsetDateTime::now_utc()
                + Duration::seconds(i64::try_from(a.config.code_ttl_seconds).expect("validated"));
            lenso_postgres_kit::sqlx::query("INSERT INTO oidc_authorization_codes(code_digest,subject_id,client_id,redirect_uri,scope,code_challenge,nonce,expires_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8)").bind(digest).bind(&r.subject).bind(&r.client_id).bind(&r.redirect_uri).bind(&r.scope).bind(&r.code_challenge).bind(&r.nonce).bind(expires).execute(a.prepared.postgres.pool()).await.map_err(db)?;
            Ok(Ok(AuthorizeResponse {
                code,
                redirect_uri: r.redirect_uri,
                state: r.state,
                expires_at: format_time(expires)?,
            }))
        })
    }
    fn exchange(
        &self,
        context: InvocationContext,
        r: ExchangeRequest,
    ) -> NativeRequestFuture<OidcProviderExchange> {
        let active = self.active();
        let issuer = self.issuer.clone();
        Box::pin(async move {
            let a = active?;
            if r.grant_type != "authorization_code"
                || r.client_id != a.config.client_id
                || r.code.len() > 256
                || !(43..=128).contains(&r.code_verifier.len())
            {
                return Ok(Err(ExchangeError::InvalidRequest));
            }
            let digest = code_digest(&a.prepared.pepper, &r.code)?;
            let mut tx = a.prepared.postgres.pool().begin().await.map_err(db)?;
            let row=lenso_postgres_kit::sqlx::query("SELECT subject_id,client_id,redirect_uri,scope,code_challenge,nonce,expires_at,consumed_at IS NOT NULL AS consumed FROM oidc_authorization_codes WHERE code_digest=$1 FOR UPDATE").bind(&digest).fetch_optional(&mut*tx).await.map_err(db)?;
            let Some(row) = row else {
                return Ok(Err(ExchangeError::InvalidGrant));
            };
            let expires: OffsetDateTime = row.try_get("expires_at").map_err(db)?;
            if row.try_get::<bool, _>("consumed").map_err(db)?
                || expires <= OffsetDateTime::now_utc()
                || row.try_get::<String, _>("client_id").map_err(db)? != r.client_id
                || row.try_get::<String, _>("redirect_uri").map_err(db)? != r.redirect_uri
                || pkce(&r.code_verifier)
                    != row.try_get::<String, _>("code_challenge").map_err(db)?
            {
                return Ok(Err(ExchangeError::InvalidGrant));
            }
            lenso_postgres_kit::sqlx::query("UPDATE oidc_authorization_codes SET consumed_at=transaction_timestamp() WHERE code_digest=$1").bind(&digest).execute(&mut*tx).await.map_err(db)?;
            tx.commit().await.map_err(db)?;
            let subject: String = row.try_get("subject_id").map_err(db)?;
            let scope: String = row.try_get("scope").map_err(db)?;
            let nonce: Option<String> = row.try_get("nonce").map_err(db)?;
            let token_exp = OffsetDateTime::now_utc()
                + Duration::seconds(i64::try_from(a.config.token_ttl_seconds).expect("validated"));
            let credential = issuer
                .issue_with_context(
                    context,
                    IssueRequest {
                        subject: subject.clone(),
                        actor_kind: "user".to_owned(),
                        assurance: "oidc".to_owned(),
                        audience: a.config.audience.clone(),
                        claims: BTreeMap::from([(
                            "client_id".to_owned(),
                            serde_json::Value::String(r.client_id.clone()),
                        )]),
                        expires_at: format_time(token_exp)?,
                    },
                )
                .await;
            let credential = match credential {
                Ok(v) => v,
                Err(CredentialIssuerIssueInvocationError::Domain(IssueError::Disabled)) => {
                    return Ok(Err(ExchangeError::DisabledSubject));
                }
                Err(CredentialIssuerIssueInvocationError::Domain(_)) => {
                    return Ok(Err(ExchangeError::InvalidGrant));
                }
                Err(CredentialIssuerIssueInvocationError::Runtime(e)) => return Err(e),
            };
            let claims = IdClaims {
                iss: a.config.issuer.clone(),
                sub: subject,
                aud: r.client_id,
                iat: OffsetDateTime::now_utc().unix_timestamp(),
                exp: token_exp.unix_timestamp(),
                nonce,
            };
            let mut header = Header::new(Algorithm::RS256);
            header.kid.clone_from(&a.config.key_id);
            let id_token = jsonwebtoken::encode(&header, &claims, &a.prepared.signing_key)
                .map_err(|e| failure(&format!("OIDC ID token signing failed: {e}")))?;
            Ok(Ok(ExchangeResponse {
                access_token: credential.credential,
                token_type: "Bearer".to_owned(),
                expires_in: i64::try_from(a.config.token_ttl_seconds).expect("validated"),
                id_token,
                scope,
                session_id: credential.session_id,
            }))
        })
    }
}
#[derive(Debug, Serialize)]
struct IdClaims {
    iss: String,
    sub: String,
    aud: String,
    iat: i64,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
}
impl Lifecycle for OidcPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let c = self.config.clone();
        let deps = context.dependencies().clone();
        let cancel = context.cancellation();
        let prepared = self.prepared.clone();
        let dbs = resolve(&self.secrets, &deps, cancel.clone(), &c.database_url_secret).await?;
        let pem = resolve(&self.secrets, &deps, cancel.clone(), &c.signing_key_secret).await?;
        let pepper = resolve(&self.secrets, &deps, cancel, &c.code_pepper_secret).await?;
        if pepper.len() < 32 {
            return Err(failure("OIDC code pepper must contain at least 32 bytes"));
        }
        let signing = EncodingKey::from_rsa_pem(pem.as_bytes())
            .map_err(|e| failure(&format!("invalid OIDC RSA signing key: {e}")))?;
        verify_signing_key(&signing, &c.jwks, c.key_id.as_deref())?;
        let postgres = OwnedPostgres::prepare(
            &dbs,
            schema_plan(c.schema.clone()).map_err(|e| invalid(&e.to_string()))?,
        )
        .await
        .map_err(|e| failure(&e.to_string()))?;
        let prepared_value = Prepared {
            postgres,
            signing_key: Rc::new(signing),
            pepper: Zeroizing::new(pepper.as_bytes().to_vec()),
        };
        prepared.replace(Some(prepared_value.clone()));
        let active = self.active.clone();
        active.replace(Some(Rc::new(Active {
            prepared: prepared_value,
            config: c,
        })));
        Ok(())
    }

    async fn deactivate(&self, _: DeactivateContext) -> Result<(), RuntimeFailure> {
        self.active.borrow_mut().take();
        let prepared = self.prepared.borrow_mut().take();
        if let Some(p) = prepared {
            p.postgres.pool().close().await;
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
        .map(|v| Zeroizing::new(v.value))
        .map_err(|e| match e {
            SecretsInvocationError::Domain(_) => failure("OIDC secret reference was rejected"),
            SecretsInvocationError::Runtime(e) => e,
        })
}
fn random_code() -> Result<String, RuntimeFailure> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|_| failure("random source unavailable"))?;
    Ok(format!("oidc_ac_{}", URL_SAFE_NO_PAD.encode(b)))
}
fn code_digest(key: &[u8], code: &str) -> Result<Vec<u8>, RuntimeFailure> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .map_err(|_| failure("invalid OIDC code pepper"))?;
    mac.update(code.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}
fn pkce(v: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()))
}
fn valid_pkce(v: &str) -> bool {
    (43..=128).contains(&v.len())
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
fn valid_name(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 256
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}
fn verify_signing_key(
    signing: &EncodingKey,
    jwks: &PublicJwks,
    key_id: Option<&str>,
) -> Result<(), RuntimeFailure> {
    let jwk = jwks.selected_key(key_id)?;
    let decoding = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .map_err(|_| failure("OIDC JWKS contains an invalid RSA public key"))?;
    let mut header = Header::new(Algorithm::RS256);
    header.kid = key_id.map(ToOwned::to_owned);
    let probe = serde_json::json!({
        "exp": OffsetDateTime::now_utc().unix_timestamp() + 60,
        "purpose": "lenso-oidc-key-verification"
    });
    let token = jsonwebtoken::encode(&header, &probe, signing)
        .map_err(|_| failure("OIDC signing-key verification failed"))?;
    jsonwebtoken::decode::<serde_json::Value>(
        &token,
        &decoding,
        &Validation::new(Algorithm::RS256),
    )
    .map_err(|_| failure("OIDC signing key does not match the configured JWKS"))?;
    Ok(())
}
fn format_time(v: OffsetDateTime) -> Result<String, RuntimeFailure> {
    v.format(&Rfc3339).map_err(|e| failure(&e.to_string()))
}
fn invalid(d: &str) -> RuntimeFailure {
    RuntimeFailure::InvalidResolvedPlan {
        detail: d.to_owned(),
    }
}
fn failure(d: &str) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: d.to_owned(),
    }
}
#[allow(clippy::needless_pass_by_value)]
fn db(e: lenso_postgres_kit::sqlx::Error) -> RuntimeFailure {
    failure(&format!("OIDC storage operation failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_is_base64url_sha256_and_verifier_is_strict() {
        let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
        let challenge = pkce(verifier);
        assert_eq!(challenge.len(), 43);
        assert!(!challenge.contains('='));
        assert!(valid_pkce(verifier));
        assert!(!valid_pkce("too-short"));
        assert!(!valid_pkce(&format!("{}!", "a".repeat(42))));
    }

    #[test]
    fn authorization_code_digest_is_keyed() {
        let code = "oidc_ac_secret";
        let first = code_digest(&[1_u8; 32], code).unwrap();
        assert_eq!(first, code_digest(&[1_u8; 32], code).unwrap());
        assert_ne!(first, code_digest(&[2_u8; 32], code).unwrap());
        assert_ne!(first, code.as_bytes());
    }

    fn public_key(key_id: &str) -> PublicRsaJwk {
        let mut modulus = vec![1_u8; 256];
        *modulus.last_mut().unwrap() = 3;
        PublicRsaJwk {
            kty: "RSA".to_owned(),
            kid: Some(key_id.to_owned()),
            key_use: "sig".to_owned(),
            alg: "RS256".to_owned(),
            n: URL_SAFE_NO_PAD.encode(modulus),
            e: URL_SAFE_NO_PAD.encode([1_u8, 0, 1]),
        }
    }

    #[test]
    fn private_jwk_members_are_rejected_during_deserialization() {
        let key = public_key("current");
        let mut value = serde_json::to_value(PublicJwks { keys: vec![key] }).unwrap();
        value["keys"][0]["d"] = serde_json::Value::String("not-public".to_owned());

        assert!(serde_json::from_value::<PublicJwks>(value).is_err());
    }

    #[test]
    fn public_jwks_rejects_unsupported_or_ambiguous_keys() {
        let mut unsupported = public_key("current");
        unsupported.alg = "RS512".to_owned();
        assert!(
            PublicJwks {
                keys: vec![unsupported]
            }
            .validate(Some("current"))
            .is_err()
        );

        let duplicate = PublicJwks {
            keys: vec![public_key("current"), public_key("current")],
        };
        assert!(duplicate.validate(Some("current")).is_err());
    }

    #[test]
    fn jwks_response_is_reconstructed_from_public_fields() {
        let jwks = PublicJwks {
            keys: vec![public_key("current")],
        };
        jwks.validate(Some("current")).unwrap();

        let response = jwks.response_map().unwrap();
        let top_level = response.keys().map(String::as_str).collect::<Vec<_>>();
        let key = response["keys"].as_array().unwrap()[0].as_object().unwrap();
        let fields = key.keys().map(String::as_str).collect::<BTreeSet<_>>();

        assert_eq!(top_level, vec!["keys"]);
        assert_eq!(
            fields,
            BTreeSet::from(["alg", "e", "kid", "kty", "n", "use"])
        );
    }
}

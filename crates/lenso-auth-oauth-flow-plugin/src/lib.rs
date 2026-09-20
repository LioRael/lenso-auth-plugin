//! Single-use OAuth state and PKCE secret custody.
#[cfg(feature = "postgres")]
mod operator;
#[cfg(feature = "workers")]
mod postgres_transport;
#[cfg(feature = "postgres")]
mod schema;
#[cfg(feature = "simulator-test-support")]
pub mod simulated;
mod storage;
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
    OauthFlowConsume, OauthFlowCreate, OauthFlowProvider, OauthFlowRevoke, RevokeError,
    RevokeRequest, RevokeResponse,
};
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsClient, SecretsInvocationError};
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
#[cfg(feature = "postgres")]
use lenso_postgres_kit::OwnedPostgres;
#[cfg(feature = "postgres")]
pub use operator::{OAuthFlowOperator, OAuthFlowOperatorError};
#[cfg(feature = "postgres")]
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
    #[serde(default)]
    #[lenso(default = "")]
    database_url_secret: String,
    #[serde(default)]
    #[lenso(default = "")]
    d1_binding: String,
    encryption_key_secret: String,
}
fn validate_config(config: &OAuthFlowConfig) -> Result<(), RuntimeFailure> {
    #[cfg(feature = "postgres")]
    schema_plan(config.schema.clone()).map_err(|error| RuntimeFailure::InvalidResolvedPlan {
        detail: error.to_string(),
    })?;
    if config.schema.is_empty()
        || !config
            .schema
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(failure("invalid OAuth schema"));
    }
    if !config.d1_binding.is_empty()
        && (!valid_name(&config.d1_binding) || !config.database_url_secret.is_empty())
    {
        return Err(failure("invalid OAuth D1 binding"));
    }
    // An empty database secret is valid only for a Host-injected private
    // PostgreSQL transport (for example a Workers Host backed by Hyperdrive).
    // Native activation still rejects the absence of its direct secret below.
    if config.database_url_secret == config.encryption_key_secret
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
    store: storage::FlowStore,
    key: Zeroizing<Vec<u8>>,
    sources: OAuthSources,
}
impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prepared")
            .field("storage", &self.store)
            .finish_non_exhaustive()
    }
}

/// The production sources remain the only default. A deterministic source can
/// exist only when a test Host enables and injects every simulation input.
#[derive(Clone, Debug)]
enum OAuthSources {
    Secure,
    #[cfg(feature = "simulator-test-support")]
    Simulated(simulated::OAuthSimulation),
}

impl OAuthSources {
    fn now(&self) -> OffsetDateTime {
        match self {
            Self::Secure => OffsetDateTime::now_utc(),
            #[cfg(feature = "simulator-test-support")]
            Self::Simulated(simulation) => simulation.now(),
        }
    }

    fn fill(&self, output: &mut [u8]) -> Result<(), RuntimeFailure> {
        match self {
            Self::Secure => {
                getrandom::fill(output).map_err(|_| failure("random source unavailable"))
            }
            #[cfg(feature = "simulator-test-support")]
            Self::Simulated(simulation) => {
                simulation.fill(output);
                Ok(())
            }
        }
    }

    #[cfg(feature = "simulator-test-support")]
    fn simulated_fault(
        &self,
        boundary: simulated::OAuthSimulationBoundary,
    ) -> Result<(), RuntimeFailure> {
        let Self::Simulated(simulation) = self else {
            return Ok(());
        };
        let Some(fault) = simulation.fault(boundary) else {
            return Ok(());
        };
        let detail = match fault {
            simulated::OAuthSimulationFault::Timeout => "simulated OAuth deadline elapsed",
            simulated::OAuthSimulationFault::Cancellation => {
                "simulated OAuth operation was cancelled"
            }
            simulated::OAuthSimulationFault::DroppedConnection => {
                "simulated OAuth caller disconnected after an uncertain result"
            }
            simulated::OAuthSimulationFault::CleanupFailure => "simulated OAuth cleanup failed",
            simulated::OAuthSimulationFault::ResourceUnavailable => {
                "simulated OAuth resource unavailable"
            }
        };
        Err(failure(detail))
    }
}
#[lenso::plugin(lifecycle, validate = validate_config)]
#[derive(Clone)]
struct OAuthFlowPlugin {
    #[config]
    config: OAuthFlowConfig,
    secrets: Port<secrets::SecretsClient>,
    state: Rc<RefCell<Option<Prepared>>>,
    #[cfg_attr(not(feature = "workers"), allow(dead_code))]
    d1: EventStorageBinding,
    #[cfg_attr(not(feature = "workers"), allow(dead_code))]
    postgres: EventPostgresBinding,
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
            #[cfg(feature = "simulator-test-support")]
            prepared
                .sources
                .simulated_fault(simulated::OAuthSimulationBoundary::BeforeCreate)?;
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
            if expiry <= prepared.sources.now() {
                return Ok(Err(CreateError::InvalidExpiry));
            }
            let state = random(&prepared.sources, 32)?;
            let verifier = random(&prepared.sources, 32)?;
            let oidc_nonce = random(&prepared.sources, 32)?;
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            let digest = digest(&prepared.key, &state)?;
            let mut cipher_nonce = [0u8; 12];
            prepared.sources.fill(&mut cipher_nonce)?;
            let cipher = Aes256Gcm::new_from_slice(&prepared.key)
                .map_err(|_| failure("invalid OAuth encryption key"))?;
            let encrypted = cipher
                .encrypt(Nonce::from_slice(&cipher_nonce), verifier.as_bytes())
                .map_err(|_| failure("OAuth verifier encryption failed"))?;
            storage::create(
                &prepared.store,
                storage::EncryptedFlow {
                    digest,
                    provider: request.provider,
                    nonce: cipher_nonce.to_vec(),
                    encrypted,
                    return_to: request.return_to,
                    expiry,
                    oidc_nonce: Some(oidc_nonce.clone()),
                },
            )
            .await?;
            #[cfg(feature = "simulator-test-support")]
            prepared
                .sources
                .simulated_fault(simulated::OAuthSimulationBoundary::AfterCreateDurableCommit)?;
            #[cfg(feature = "simulator-test-support")]
            prepared
                .sources
                .simulated_fault(simulated::OAuthSimulationBoundary::BeforeCreateResponse)?;
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
            #[cfg(feature = "simulator-test-support")]
            prepared
                .sources
                .simulated_fault(simulated::OAuthSimulationBoundary::BeforeConsume)?;
            if !valid_name(&request.provider) || request.state.len() > 256 {
                return Ok(Err(ConsumeError::InvalidState));
            }
            let digest = digest(&prepared.key, &request.state)?;
            let row = match storage::consume(&prepared.store, &digest, &request.provider).await? {
                Ok(row) => row,
                Err(error) => return Ok(Err(error)),
            };
            #[cfg(feature = "simulator-test-support")]
            prepared
                .sources
                .simulated_fault(simulated::OAuthSimulationBoundary::AfterConsumeDurableCommit)?;
            let nonce = row.nonce;
            let encrypted = row.encrypted;
            let expiry = row.expiry;
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
            #[cfg(feature = "simulator-test-support")]
            prepared
                .sources
                .simulated_fault(simulated::OAuthSimulationBoundary::BeforeConsumeResponse)?;
            Ok(Ok(ConsumeResponse {
                code_verifier: verifier,
                nonce: row.oidc_nonce.map(Some),
                return_to: row.return_to,
                expires_at: expiry
                    .format(&Rfc3339)
                    .map_err(|error| failure(&error.to_string()))?,
            }))
        })
    }

    fn revoke(
        &self,
        _: InvocationContext,
        request: RevokeRequest,
    ) -> NativeRequestFuture<OauthFlowRevoke> {
        let prepared = self.prepared();
        Box::pin(async move {
            let prepared = prepared?;
            #[cfg(feature = "simulator-test-support")]
            prepared
                .sources
                .simulated_fault(simulated::OAuthSimulationBoundary::BeforeRevoke)?;
            if !valid_name(&request.provider) || request.state.len() > 256 {
                return Ok(Err(RevokeError::InvalidState));
            }
            let digest = digest(&prepared.key, &request.state)?;
            match storage::revoke(&prepared.store, &digest, &request.provider).await? {
                Ok(()) => {}
                Err(error) => return Ok(Err(error)),
            }
            #[cfg(feature = "simulator-test-support")]
            prepared
                .sources
                .simulated_fault(simulated::OAuthSimulationBoundary::AfterRevokeDurableCommit)?;
            #[cfg(feature = "simulator-test-support")]
            prepared
                .sources
                .simulated_fault(simulated::OAuthSimulationBoundary::BeforeRevokeResponse)?;
            Ok(Ok(RevokeResponse {}))
        })
    }
}
impl Lifecycle for OAuthFlowPlugin {
    #[expect(
        clippy::too_many_lines,
        reason = "one lifecycle transaction keeps target-specific private store admission and cleanup atomic"
    )]
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let config = self.config.clone();
        let dependencies = context.dependencies().clone();
        let cancellation = context.cancellation();
        let state = self.state.clone();
        #[cfg(feature = "simulator-test-support")]
        if state.borrow().is_some() {
            return Ok(());
        }
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
        let store = {
            #[cfg(feature = "workers")]
            if let Some(binding) = self.postgres.as_ref() {
                if !config.d1_binding.is_empty() || !config.database_url_secret.is_empty() {
                    return Err(RuntimeFailure::InvalidResolvedPlan {
                        detail: "Host-injected OAuth PostgreSQL transport cannot be combined with D1 or a direct database secret".to_owned(),
                    });
                }
                storage::FlowStore::PostgresTransport(binding.clone())
            } else if config.d1_binding.is_empty() {
                #[cfg(feature = "postgres")]
                {
                    if config.database_url_secret.is_empty() {
                        return Err(failure("OAuth PostgreSQL transport unavailable"));
                    }
                    let db = resolve(
                        &self.secrets,
                        &dependencies,
                        context.cancellation(),
                        &config.database_url_secret,
                    )
                    .await?;
                    let pg =
                        OwnedPostgres::prepare(&db, schema_plan(config.schema).map_err(db_error)?)
                            .await
                            .map_err(db_error)?;
                    storage::FlowStore::Postgres(pg)
                }
                #[cfg(not(feature = "postgres"))]
                {
                    return Err(failure("OAuth PostgreSQL transport unavailable"));
                }
            } else {
                let name = &config.d1_binding;
                let binding = self
                    .d1
                    .as_ref()
                    .filter(|binding| binding.name() == name)
                    .ok_or_else(|| failure("configured OAuth D1 binding unavailable"))?
                    .clone();
                migration::verify(&binding)
                    .await
                    .map_err(|_| failure("OAuth D1 migration verification failed"))?;
                storage::FlowStore::D1(binding)
            }
            #[cfg(not(feature = "workers"))]
            if config.d1_binding.is_empty() {
                #[cfg(feature = "postgres")]
                {
                    if config.database_url_secret.is_empty() {
                        return Err(failure("OAuth PostgreSQL secret reference is required"));
                    }
                    let db = resolve(
                        &self.secrets,
                        &dependencies,
                        context.cancellation(),
                        &config.database_url_secret,
                    )
                    .await?;
                    let pg =
                        OwnedPostgres::prepare(&db, schema_plan(config.schema).map_err(db_error)?)
                            .await
                            .map_err(db_error)?;
                    storage::FlowStore::Postgres(pg)
                }
                #[cfg(not(feature = "postgres"))]
                {
                    return Err(failure("OAuth PostgreSQL implementation not enabled"));
                }
            } else {
                return Err(failure("OAuth D1 implementation not enabled"));
            }
        };
        state.replace(Some(Prepared {
            store,
            key: Zeroizing::new(key.as_bytes().to_vec()),
            sources: OAuthSources::Secure,
        }));
        Ok(())
    }

    async fn deactivate(&self, _: DeactivateContext) -> Result<(), RuntimeFailure> {
        let prepared = self.state.borrow_mut().take();
        if let Some(prepared) = prepared {
            prepared.store.close().await;
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
fn random(sources: &OAuthSources, bytes: usize) -> Result<String, RuntimeFailure> {
    let mut value = Zeroizing::new(vec![0u8; bytes]);
    sources.fill(&mut value)?;
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
#[cfg(feature = "postgres")]
fn db_error(error: impl fmt::Display) -> RuntimeFailure {
    failure(&format!("OAuth Flow storage operation failed: {error}"))
}

#[cfg(feature = "workers")]
pub mod migration;
#[cfg(feature = "workers")]
pub mod workers;

/// Builds the native PostgreSQL Auth implementation without exposing its
/// private storage handle. The resolved Plan still supplies the database
/// secret through the Secrets Capability; this factory exists so a Native Host
/// can register the generated Plugin in an ordinary registry.
#[cfg(feature = "postgres")]
pub fn native_postgres_factory() -> impl lenso_native_adapter::NativePluginFactory {
    lenso_native_adapter::ConfiguredPluginFactory::<OAuthFlowPlugin, _>::new(|_| Ok(()))
}

/// Build the selected Auth implementation with a request-owned D1 binding.
/// The caller must create a fresh registry/factory for each Workers event.
#[cfg(feature = "workers")]
pub fn workers_factory(
    binding_name: impl Into<Rc<str>>,
    batch: js_sys::Function,
) -> impl lenso_native_adapter::NativePluginFactory {
    let binding = workers::D1Binding::new(binding_name, batch);
    lenso_native_adapter::ConfiguredPluginFactory::<OAuthFlowPlugin, _>::new(move |value| {
        if value.config.d1_binding != binding.name() {
            return Err(RuntimeFailure::InvalidResolvedPlan {
                detail: "Auth factory requires its exact configured D1 binding".to_owned(),
            });
        }
        if !value.config.database_url_secret.is_empty() {
            return Err(RuntimeFailure::InvalidResolvedPlan {
                detail: "Auth D1 factory cannot accept a direct PostgreSQL secret".to_owned(),
            });
        }
        value.d1 = Some(binding.clone());
        Ok(())
    })
}

/// Builds OAuth Flow for one Workers event with a Host-owned PostgreSQL
/// transport. The Host may back the callback with Hyperdrive, but Auth receives
/// neither binding identity nor connection material and has no retry authority.
#[cfg(feature = "workers")]
pub fn workers_postgres_factory(
    execute: js_sys::Function,
) -> impl lenso_native_adapter::NativePluginFactory {
    let binding = postgres_transport::PostgresBinding::new(execute);
    lenso_native_adapter::ConfiguredPluginFactory::<OAuthFlowPlugin, _>::new(move |value| {
        if !value.config.d1_binding.is_empty() || !value.config.database_url_secret.is_empty() {
            return Err(RuntimeFailure::InvalidResolvedPlan {
                detail: "Auth PostgreSQL factory requires an empty D1 binding and no direct database secret".to_owned(),
            });
        }
        value.postgres = Some(binding.clone());
        Ok(())
    })
}

/// Builds the exact OAuth Plugin with an explicitly supplied simulated world.
///
/// This exists only under `simulator-test-support`; it is intended for a real
/// `TestApp`/Host composition and still boots the generated Plugin lifecycle,
/// Capability endpoint, immutable Plan bindings, and Auth business rules.
/// It never changes the public OAuth Capability or installs a production
/// clock/entropy fallback.
#[cfg(feature = "simulator-test-support")]
pub fn simulated_factory(
    simulation: simulated::OAuthSimulation,
) -> impl lenso_native_adapter::NativePluginFactory {
    lenso_native_adapter::ConfiguredPluginFactory::<OAuthFlowPlugin, _>::new(move |value| {
        let sources = OAuthSources::Simulated(simulation.clone());
        value.state.replace(Some(Prepared {
            store: storage::FlowStore::Simulated(simulation.store()),
            key: Zeroizing::new(simulation.encryption_key().to_vec()),
            sources,
        }));
        Ok(())
    })
}

#[cfg(feature = "workers")]
type EventStorageBinding = Option<workers::D1Binding>;
#[cfg(not(feature = "workers"))]
type EventStorageBinding = ();
#[cfg(feature = "workers")]
type EventPostgresBinding = Option<postgres_transport::PostgresBinding>;
#[cfg(not(feature = "workers"))]
type EventPostgresBinding = ();

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

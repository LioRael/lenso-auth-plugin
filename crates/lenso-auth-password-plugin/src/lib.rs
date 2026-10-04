//! Password authentication as a removable Plugin over Directory and Credential Issuer contracts.
pub mod host_facilities;
pub use host_facilities::EventStorageBinding;

#[cfg(feature = "workers")]
pub mod migration;
#[cfg(feature = "postgres")]
mod operator;
#[cfg(feature = "postgres")]
mod schema;
mod storage;
#[cfg(feature = "workers")]
pub mod workers;

use std::{cell::RefCell, collections::BTreeMap, fmt, future::Future, rc::Rc, sync::Arc};

#[cfg(feature = "postgres")]
use std::time::Duration as StdDuration;

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use lenso::{ActivateContext, DeactivateContext, Lifecycle, ManyPort, Port, provides};
use lenso_capability_credential_issuer as credential_issuer;
use lenso_capability_credential_issuer::{
    CredentialIssuerClient, CredentialIssuerIssueInvocationError, IssueError, IssueRequest,
};
use lenso_capability_identity_directory as directory;
use lenso_capability_identity_directory::{
    DirectoryEnsureIdentityInvocationError, EnsureIdentityError, EnsureIdentityRequest,
};
use lenso_capability_managed_session as managed;
use lenso_capability_managed_session::{
    IssueManagedError, IssueManagedRequest, ManagedSessionClient,
    ManagedSessionIssueManagedInvocationError,
};
use lenso_capability_password_auth as password;
use lenso_capability_password_auth::{
    LoginError, LoginRequest, LoginResponse, PasswordLogin, PasswordProvider, PasswordRegister,
    RegisterError, RegisterRequest, RegisterResponse,
};
use lenso_capability_secrets as secrets;
#[cfg(feature = "postgres")]
use lenso_capability_secrets::{ResolveRequest, SecretsInvocationError};
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
#[cfg(feature = "postgres")]
use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::Semaphore;
#[cfg(feature = "postgres")]
use zeroize::Zeroizing;

#[cfg(feature = "postgres")]
use crate::schema::schema_plan;

#[cfg(feature = "postgres")]
pub use operator::{PasswordAuthOperator, PasswordOperatorError};

#[cfg(feature = "postgres")]
const DEPENDENCY_TIMEOUT: StdDuration = StdDuration::from_secs(10);
const MAX_PASSWORD_WORK_JOBS: usize = 4;
#[cfg(test)]
const DUMMY_PASSWORD_INPUT: &str = "lenso-auth-password-dummy-input";
// Public timing fixture, not a credential. Generated with Argon2::default() and
// the public salt b"lenso-dummy-salt"; preparation validates its exact policy.
const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$bGVuc28tZHVtbXktc2FsdA$ebQ9RdZkGmHlYhZWTNykFgZWxf5wuNrQzpCGDoXz9D0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, lenso::PluginConfig)]
#[serde(deny_unknown_fields)]
pub struct PasswordAuthConfig {
    schema: String,
    #[serde(default)]
    #[lenso(default = "")]
    database_url_secret: String,
    #[serde(default)]
    #[lenso(default = "")]
    d1_binding: String,
    #[serde(default)]
    #[lenso(default = "")]
    storage_ref: String,
    audience: Vec<String>,
    session_ttl_seconds: u64,
    #[serde(default)]
    #[lenso(default = false)]
    managed_sessions: bool,
    max_failures: u32,
    failure_window_seconds: u64,
}

impl PasswordAuthConfig {
    pub fn new(
        schema: impl Into<String>,
        database_url_secret: impl Into<String>,
        audience: Vec<String>,
        session_ttl_seconds: u64,
        max_failures: u32,
        failure_window_seconds: u64,
    ) -> Result<Self, PasswordConfigError> {
        let value = Self {
            schema: schema.into(),
            database_url_secret: database_url_secret.into(),
            d1_binding: String::new(),
            storage_ref: String::new(),
            audience,
            session_ttl_seconds,
            managed_sessions: false,
            max_failures,
            failure_window_seconds,
        };
        value.validate()?;
        Ok(value)
    }
    /// Select one logical storage reference; target attachments retain transport custody.
    pub fn with_storage_ref(
        mut self,
        reference: impl Into<String>,
    ) -> Result<Self, PasswordConfigError> {
        self.storage_ref = reference.into();
        self.database_url_secret.clear();
        self.d1_binding.clear();
        self.validate()?;
        Ok(self)
    }

    /// Opt in to Account-owned managed issuance through an explicit capability binding.
    /// The legacy TTL remains configured for compatibility, but is not sent in this mode.
    #[must_use]
    pub fn with_managed_sessions(mut self, enabled: bool) -> Self {
        self.managed_sessions = enabled;
        self
    }

    fn validate(&self) -> Result<(), PasswordConfigError> {
        if self.schema.is_empty()
            || self.schema.len() > 63
            || !self.schema.as_bytes()[0].is_ascii_lowercase()
            || !self
                .schema
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || matches!(self.schema.as_str(), "public" | "information_schema")
            || self.schema.starts_with("pg_")
        {
            return Err(PasswordConfigError::InvalidSchema);
        }
        if !self.storage_ref.is_empty() {
            if !host_facilities::valid_reference(&self.storage_ref)
                || !self.database_url_secret.is_empty()
                || !self.d1_binding.is_empty()
            {
                return Err(PasswordConfigError::InvalidSecretReference);
            }
        } else if (self.d1_binding.is_empty() && self.database_url_secret.is_empty())
            || self.database_url_secret.len() > 256
            || (!self.d1_binding.is_empty()
                && (!self.database_url_secret.is_empty()
                    || self.d1_binding.len() > 128
                    || !self
                        .d1_binding
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')))
        {
            return Err(PasswordConfigError::InvalidSecretReference);
        }
        if self.audience.is_empty() || self.audience.iter().any(|value| !valid_audience(value)) {
            return Err(PasswordConfigError::InvalidAudience);
        }
        if self.session_ttl_seconds == 0 || self.session_ttl_seconds > 2_592_000 {
            return Err(PasswordConfigError::InvalidSessionTtl);
        }
        if self.max_failures == 0
            || self.max_failures > 100
            || self.failure_window_seconds == 0
            || self.failure_window_seconds > 86_400
        {
            return Err(PasswordConfigError::InvalidRateLimit);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PasswordConfigError {
    #[error("invalid owned PostgreSQL schema")]
    InvalidSchema,
    #[error("invalid database secret reference")]
    InvalidSecretReference,
    #[error("at least one valid audience is required")]
    InvalidAudience,
    #[error("session TTL must be between 1 and 2592000 seconds")]
    InvalidSessionTtl,
    #[error("invalid login rate limit")]
    InvalidRateLimit,
}

fn validate_config(config: &PasswordAuthConfig) -> Result<(), RuntimeFailure> {
    config
        .validate()
        .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: error.to_string(),
        })
}

struct ActivePassword {
    store: storage::PasswordStore,
    config: PasswordAuthConfig,
    password_work: PasswordWork,
}
impl fmt::Debug for ActivePassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActivePassword")
            .field("schema", &self.config.schema)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct PasswordWork {
    permits: Arc<Semaphore>,
    dummy_hash: Arc<str>,
}

impl fmt::Debug for PasswordWork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordWork")
            .field("available", &self.permits.available_permits())
            .finish_non_exhaustive()
    }
}

impl PasswordWork {
    fn prepare() -> Result<Self, PasswordWorkError> {
        Self::prepare_with_limit(MAX_PASSWORD_WORK_JOBS)
    }

    fn prepare_with_limit(limit: usize) -> Result<Self, PasswordWorkError> {
        validate_dummy_hash(DUMMY_PASSWORD_HASH)?;
        Ok(Self {
            permits: Arc::new(Semaphore::new(limit)),
            dummy_hash: Arc::from(DUMMY_PASSWORD_HASH),
        })
    }

    async fn hash(&self, password: String) -> Result<String, PasswordWorkError> {
        self.run(move || hash_password_sync(&password)).await
    }

    async fn verify(
        &self,
        password: String,
        stored_hash: Option<String>,
    ) -> Result<bool, PasswordWorkError> {
        let dummy_hash = Arc::clone(&self.dummy_hash);
        verify_candidate_with(password, stored_hash, dummy_hash, |password, encoded| {
            self.run(move || Ok(verify_password_sync(&password, &encoded)))
        })
        .await
    }

    async fn run<T, F>(&self, job: F) -> Result<T, PasswordWorkError>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, PasswordPluginError> + Send + 'static,
    {
        run_password_job(Arc::clone(&self.permits), job).await
    }
}

#[derive(Debug, Error)]
enum PasswordWorkError {
    #[error("password work capacity is exhausted")]
    Saturated,
    #[cfg(not(target_arch = "wasm32"))]
    #[error("password worker terminated")]
    Join,
    #[error(transparent)]
    Password(#[from] PasswordPluginError),
}

#[cfg_attr(
    target_arch = "wasm32",
    allow(
        clippy::unused_async,
        reason = "Native password jobs await the blocking executor"
    )
)]
async fn run_password_job<T, F>(permits: Arc<Semaphore>, job: F) -> Result<T, PasswordWorkError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, PasswordPluginError> + Send + 'static,
{
    let permit = permits
        .try_acquire_owned()
        .map_err(|_| PasswordWorkError::Saturated)?;
    #[cfg(target_arch = "wasm32")]
    {
        let _permit = permit;
        job().map_err(PasswordWorkError::from)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            job()
        })
        .await
        .map_err(|_| PasswordWorkError::Join)?
        .map_err(PasswordWorkError::from)
    }
}

async fn verify_candidate_with<E, F, Fut>(
    password: String,
    stored_hash: Option<String>,
    dummy_hash: Arc<str>,
    verify: F,
) -> Result<bool, E>
where
    F: FnOnce(String, String) -> Fut,
    Fut: Future<Output = Result<bool, E>>,
{
    let credential_exists = stored_hash.is_some();
    let encoded = stored_hash.unwrap_or_else(|| dummy_hash.to_string());
    let verified = verify(password, encoded).await?;
    Ok(credential_exists && verified)
}

#[lenso::plugin(lifecycle, validate = validate_config)]
#[derive(Clone)]
struct PasswordAuthPlugin {
    #[config]
    config: PasswordAuthConfig,
    secrets: Port<secrets::SecretsClient>,
    directory: Port<directory::DirectoryClient>,
    issuer: Port<credential_issuer::CredentialIssuerClient>,
    // Existing lifecycle authoring exposes zero-or-many Ports; activation narrows this
    // optional role to at most one provider instead of silently picking among bindings.
    managed_sessions: ManyPort<managed::ManagedSessionClient>,
    store: Rc<RefCell<Option<storage::PasswordStore>>>,
    #[allow(dead_code)]
    #[facility(id = "state")]
    d1: Option<EventStorageBinding>,
    active: Rc<RefCell<Option<Rc<ActivePassword>>>>,
}
#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for PasswordAuthPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordAuthProvider")
            .field("active", &self.active.borrow().is_some())
            .finish()
    }
}
impl PasswordAuthPlugin {
    fn active(&self) -> Result<Rc<ActivePassword>, RuntimeFailure> {
        self.active
            .borrow()
            .clone()
            .ok_or(RuntimeFailure::PluginFailure {
                detail: "Password Auth is not active".to_owned(),
            })
    }
}

#[provides(password::Password)]
impl PasswordProvider for PasswordAuthPlugin {
    fn register(
        &self,
        context: InvocationContext,
        request: RegisterRequest,
    ) -> NativeRequestFuture<PasswordRegister> {
        let active = self.active();
        let directory = self.directory.clone();
        let issuer = self.issuer.clone();
        let managed_sessions = self.managed_sessions.clone();
        Box::pin(async move {
            let active = active?;
            let identifier =
                normalize_identifier(&request.identifier).ok_or(RegisterError::InvalidIdentifier);
            let identifier = match identifier {
                Ok(value) => value,
                Err(error) => return Ok(Err(error)),
            };
            if !valid_password(&request.password) {
                return Ok(Err(RegisterError::WeakPassword));
            }
            let hash = active
                .password_work
                .hash(request.password)
                .await
                .map_err(runtime)?;
            let identity = directory
                .ensure_identity_with_context(
                    context.clone(),
                    EnsureIdentityRequest {
                        provider: "password".to_owned(),
                        external_subject: identifier.clone(),
                    },
                )
                .await;
            let identity = match identity {
                Ok(value) => value,
                Err(DirectoryEnsureIdentityInvocationError::Domain(
                    EnsureIdentityError::Disabled,
                )) => return Ok(Err(RegisterError::Disabled)),
                Err(DirectoryEnsureIdentityInvocationError::Domain(_)) => {
                    return Ok(Err(RegisterError::InvalidIdentifier));
                }
                Err(DirectoryEnsureIdentityInvocationError::Runtime(error)) => return Err(error),
            };
            if !storage::insert_credential(&active.store, &identifier, &identity.subject, &hash)
                .await
                .map_err(runtime)?
            {
                return Ok(Err(RegisterError::IdentifierTaken));
            }
            let credential = issue(
                &active.config,
                &issuer,
                managed_sessions
                    .first()
                    .map(lenso::BoundCapabilityClient::client),
                context,
                &identity.subject,
            )
            .await;
            match credential {
                Ok(value) => Ok(Ok(RegisterResponse {
                    subject: identity.subject,
                    credential: value.credential,
                    session_id: value.session_id,
                    expires_at: value.expires_at,
                })),
                Err(IssueCallError::Disabled) => Ok(Err(RegisterError::Disabled)),
                Err(IssueCallError::Runtime(error)) => Err(error),
            }
        })
    }

    fn login(
        &self,
        context: InvocationContext,
        request: LoginRequest,
    ) -> NativeRequestFuture<PasswordLogin> {
        let active = self.active();
        let issuer = self.issuer.clone();
        let managed_sessions = self.managed_sessions.clone();
        Box::pin(async move {
            let active = active?;
            let Some(identifier) = normalize_identifier(&request.identifier) else {
                return Ok(Err(LoginError::InvalidIdentifier));
            };
            let since = OffsetDateTime::now_utc()
                - Duration::seconds(
                    i64::try_from(active.config.failure_window_seconds).expect("validated"),
                );
            if storage::failure_limit_reached(
                &active.store,
                &identifier,
                since,
                active.config.max_failures,
            )
            .await
            .map_err(runtime)?
            {
                return Ok(Err(LoginError::RateLimited));
            }
            let credential = storage::load_credential(&active.store, &identifier)
                .await
                .map_err(runtime)?;
            let (subject, stored_hash) =
                credential.map_or((None, None), |(subject, hash)| (Some(subject), Some(hash)));
            let valid = match active
                .password_work
                .verify(request.password, stored_hash)
                .await
            {
                Ok(valid) => valid,
                Err(PasswordWorkError::Saturated) => return Ok(Err(LoginError::RateLimited)),
                Err(error) => return Err(runtime(error)),
            };
            if !valid {
                return match storage::record_failure_if_allowed(
                    &active.store,
                    &identifier,
                    since,
                    active.config.max_failures,
                )
                .await
                .map_err(runtime)?
                {
                    storage::FailureAdmission::Recorded => Ok(Err(LoginError::InvalidCredentials)),
                    storage::FailureAdmission::RateLimited => Ok(Err(LoginError::RateLimited)),
                };
            }
            storage::clear_failures(&active.store, &identifier)
                .await
                .map_err(runtime)?;
            let subject = subject.expect("verified credential has a subject");
            match issue(
                &active.config,
                &issuer,
                managed_sessions
                    .first()
                    .map(lenso::BoundCapabilityClient::client),
                context,
                &subject,
            )
            .await
            {
                Ok(value) => Ok(Ok(LoginResponse {
                    subject,
                    credential: value.credential,
                    session_id: value.session_id,
                    expires_at: value.expires_at,
                })),
                Err(IssueCallError::Disabled) => Ok(Err(LoginError::Disabled)),
                Err(IssueCallError::Runtime(error)) => Err(error),
            }
        })
    }
}

async fn issue(
    config: &PasswordAuthConfig,
    issuer: &CredentialIssuerClient,
    managed_sessions: Option<&ManagedSessionClient>,
    context: InvocationContext,
    subject: &str,
) -> Result<lenso_capability_credential_issuer::IssueResponse, IssueCallError> {
    validate_managed_binding(config, usize::from(managed_sessions.is_some()))
        .map_err(IssueCallError::Runtime)?;
    if config.managed_sessions {
        let managed_sessions = managed_sessions.expect("validated managed session binding");
        return managed_sessions
            .issue_managed_with_context(
                context,
                IssueManagedRequest {
                    subject: subject.to_owned(),
                    actor_kind: "user".to_owned(),
                    assurance: "password".to_owned(),
                    audience: config.audience.clone(),
                    claims: BTreeMap::default(),
                },
            )
            .await
            .map(|value| credential_issuer::IssueResponse {
                session_id: value.session_id,
                credential: value.credential,
                expires_at: value.expires_at,
            })
            .map_err(|error| match error {
                ManagedSessionIssueManagedInvocationError::Domain(IssueManagedError::Disabled) => {
                    IssueCallError::Disabled
                }
                ManagedSessionIssueManagedInvocationError::Domain(error) => {
                    IssueCallError::Runtime(RuntimeFailure::PluginFailure {
                        detail: format!(
                            "managed session issuer rejected password session: {error:?}"
                        ),
                    })
                }
                ManagedSessionIssueManagedInvocationError::Runtime(error) => {
                    IssueCallError::Runtime(error)
                }
            });
    }
    let expires_at = (OffsetDateTime::now_utc()
        + Duration::seconds(i64::try_from(config.session_ttl_seconds).expect("validated")))
    .format(&Rfc3339)
    .map_err(|error| {
        IssueCallError::Runtime(RuntimeFailure::PluginFailure {
            detail: error.to_string(),
        })
    })?;
    issuer
        .issue_with_context(
            context,
            IssueRequest {
                subject: subject.to_owned(),
                actor_kind: "user".to_owned(),
                assurance: "password".to_owned(),
                audience: config.audience.clone(),
                claims: BTreeMap::default(),
                expires_at,
            },
        )
        .await
        .map_err(|error| match error {
            CredentialIssuerIssueInvocationError::Domain(IssueError::Disabled) => {
                IssueCallError::Disabled
            }
            CredentialIssuerIssueInvocationError::Domain(error) => {
                IssueCallError::Runtime(RuntimeFailure::PluginFailure {
                    detail: format!("credential issuer rejected password session: {error:?}"),
                })
            }
            CredentialIssuerIssueInvocationError::Runtime(error) => IssueCallError::Runtime(error),
        })
}

enum IssueCallError {
    Disabled,
    Runtime(RuntimeFailure),
}

fn validate_managed_binding(
    config: &PasswordAuthConfig,
    bindings: usize,
) -> Result<(), RuntimeFailure> {
    if bindings > 1 || (config.managed_sessions && bindings != 1) {
        return Err(RuntimeFailure::InvalidResolvedPlan {
            detail: "Password permits at most one ManagedSession provider and managed_sessions requires exactly one binding".to_owned(),
        });
    }
    Ok(())
}

impl Lifecycle for PasswordAuthPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let config = self.config.clone();
        validate_managed_binding(&config, self.managed_sessions.len())?;
        let state = self.store.clone();
        let selected = host_facilities::select(
            &config.storage_ref,
            &config.database_url_secret,
            &config.d1_binding,
            self.d1.as_ref(),
        )?;
        let store = match selected {
            host_facilities::StorageSelection::Postgres(database_url_secret) => {
                #[cfg(feature = "postgres")]
                {
                    let dependencies = context.dependencies().clone();
                    let cancellation = context.cancellation();
                    let invocation =
                        dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation)?;
                    let database_url = self
                        .secrets
                        .resolve_with_context(
                            invocation,
                            ResolveRequest {
                                reference: database_url_secret.to_owned(),
                            },
                        )
                        .await
                        .map(|value| Zeroizing::new(value.value))
                        .map_err(|error| match error {
                            SecretsInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                                detail: "password database secret was rejected".to_owned(),
                            },
                            SecretsInvocationError::Runtime(error) => error,
                        })?;
                    let postgres = OwnedPostgres::prepare(
                        &database_url,
                        schema_plan(config.schema.clone()).map_err(|error| {
                            RuntimeFailure::InvalidResolvedPlan {
                                detail: error.to_string(),
                            }
                        })?,
                    )
                    .await
                    .map_err(|error| RuntimeFailure::PluginFailure {
                        detail: error.to_string(),
                    })?;

                    storage::PasswordStore::Postgres(postgres)
                }
                #[cfg(not(feature = "postgres"))]
                {
                    let _ = context;
                    let _ = database_url_secret;
                    return Err(runtime("Password PostgreSQL support is disabled"));
                }
            }
            #[cfg(feature = "workers")]
            host_facilities::StorageSelection::D1(binding) => {
                migration::verify(binding)
                    .await
                    .map_err(|_| runtime("D1 migration verification failed"))?;
                storage::PasswordStore::D1(binding.clone())
            }
        };
        let password_work = PasswordWork::prepare().map_err(runtime)?;
        state.replace(Some(store.clone()));
        let active = self.active.clone();
        active.replace(Some(Rc::new(ActivePassword {
            store,
            config,
            password_work,
        })));
        Ok(())
    }

    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        self.active.borrow_mut().take();
        let postgres = self.store.borrow_mut().take();
        if let Some(postgres) = postgres {
            postgres.close().await;
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
enum PasswordPluginError {
    #[cfg(feature = "postgres")]
    #[error("PostgreSQL operation `{operation}` failed")]
    Database {
        operation: &'static str,
        #[source]
        source: sqlx::Error,
    },
    #[cfg(feature = "workers")]
    #[error("Password Auth storage unavailable")]
    Storage,
    #[error("password hashing failed")]
    Hash,
    #[error("random source unavailable")]
    Random,
}
fn runtime(error: impl fmt::Display) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: error.to_string(),
    }
}
fn normalize_identifier(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        None
    } else {
        Some(value.to_lowercase())
    }
}
fn valid_password(value: &str) -> bool {
    (8..=1024).contains(&value.len())
}
// Fail closed if a dependency update changes the actual hashing policy. Checking
// the PHC metadata is cheap; verifying the public fixture is a real-Argon2 test.
fn validate_dummy_hash(encoded: &str) -> Result<(), PasswordPluginError> {
    let hash = PasswordHash::new(encoded).map_err(|_| PasswordPluginError::Hash)?;
    let engine = Argon2::default();
    let params = engine.params();
    let expected = argon2::password_hash::ParamsString::try_from(params)
        .map_err(|_| PasswordPluginError::Hash)?;
    if hash.algorithm.as_str() != argon2::Algorithm::default().as_str()
        || hash.version != Some(argon2::Version::default() as u32)
        || hash.params != expected
        || hash.salt.is_none()
        || hash.hash.as_ref().map(argon2::password_hash::Output::len)
            != Some(
                params
                    .output_len()
                    .unwrap_or(argon2::Params::DEFAULT_OUTPUT_LEN),
            )
    {
        return Err(PasswordPluginError::Hash);
    }
    Ok(())
}

fn hash_password_sync(value: &str) -> Result<String, PasswordPluginError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| PasswordPluginError::Random)?;
    let salt = SaltString::encode_b64(&bytes).map_err(|_| PasswordPluginError::Hash)?;
    Argon2::default()
        .hash_password(value.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| PasswordPluginError::Hash)
}
fn verify_password_sync(value: &str, encoded: &str) -> bool {
    PasswordHash::new(encoded).is_ok_and(|hash| {
        Argon2::default()
            .verify_password(value.as_bytes(), &hash)
            .is_ok()
    })
}
fn valid_audience(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':' | b'@'))
}

#[cfg(all(test, feature = "postgres"))]
mod tests {
    use super::*;

    #[test]
    fn password_login_configuration_accepts_capability_operation_audiences() {
        let config = PasswordAuthConfig::new(
            "password_test",
            "auth/database-url",
            vec![
                "lenso.projects@1:get_issue".into(),
                "lenso.projects@1:update_issue".into(),
            ],
            3600,
            5,
            60,
        )
        .unwrap();
        assert_eq!(config.audience[0], "lenso.projects@1:get_issue");
        for invalid in [
            "",
            "*",
            "lenso.projects@1:get issue",
            "lenso.projects@1:get_issue\n",
        ] {
            assert!(
                PasswordAuthConfig::new(
                    "password_test",
                    "auth/database-url",
                    vec![invalid.into()],
                    3600,
                    5,
                    60
                )
                .is_err()
            );
        }
    }

    #[test]
    fn password_hash_never_contains_plaintext_and_verifies() {
        let password = "correct horse battery staple";
        let hash = hash_password_sync(password).unwrap();
        assert!(!hash.contains(password));
        assert!(verify_password_sync(password, &hash));
        assert!(!verify_password_sync("wrong password", &hash));
    }

    #[test]
    fn identifiers_are_canonicalized_before_storage() {
        assert_eq!(
            normalize_identifier(" User@Example.COM "),
            Some("user@example.com".to_owned())
        );
        assert_eq!(normalize_identifier("\n"), None);
    }

    #[tokio::test]
    #[ignore = "requires LENSO_POSTGRES_TEST_URL"]
    async fn concurrent_invalid_logins_admit_exact_failure_limit() {
        use sqlx::{AssertSqlSafe, Executor};

        let database_url =
            std::env::var("LENSO_POSTGRES_TEST_URL").expect("LENSO_POSTGRES_TEST_URL is required");
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let schema = format!("password_limit_test_{}_{suffix}", std::process::id());
        PasswordAuthOperator::setup(&database_url, &schema)
            .await
            .unwrap();
        let postgres = OwnedPostgres::prepare(&database_url, schema_plan(schema.clone()).unwrap())
            .await
            .unwrap();
        let since = OffsetDateTime::now_utc() - Duration::minutes(1);
        let identifier = "concurrent@example.test";

        let outcomes = tokio::join!(
            storage::postgres::record_failure_if_allowed(&postgres, identifier, since, 2),
            storage::postgres::record_failure_if_allowed(&postgres, identifier, since, 2),
            storage::postgres::record_failure_if_allowed(&postgres, identifier, since, 2),
            storage::postgres::record_failure_if_allowed(&postgres, identifier, since, 2),
            storage::postgres::record_failure_if_allowed(&postgres, identifier, since, 2),
        );
        let recorded = [outcomes.0, outcomes.1, outcomes.2, outcomes.3, outcomes.4]
            .into_iter()
            .map(Result::unwrap)
            .filter(|outcome| *outcome == storage::FailureAdmission::Recorded)
            .count();
        assert_eq!(recorded, 2);
        assert_eq!(
            storage::postgres::current_failure_count(&postgres, identifier, since)
                .await
                .unwrap(),
            2
        );

        postgres.pool().close().await;
        let cleanup_pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        cleanup_pool
            .execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
            .await
            .unwrap();
        cleanup_pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires LENSO_POSTGRES_TEST_URL"]
    async fn stale_failure_pruning_is_bounded_and_eventually_drains() {
        use sqlx::{AssertSqlSafe, Executor};

        let database_url =
            std::env::var("LENSO_POSTGRES_TEST_URL").expect("LENSO_POSTGRES_TEST_URL is required");
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let schema = format!("password_prune_test_{}_{suffix}", std::process::id());
        PasswordAuthOperator::setup(&database_url, &schema)
            .await
            .unwrap();
        let postgres = OwnedPostgres::prepare(&database_url, schema_plan(schema.clone()).unwrap())
            .await
            .unwrap();
        let cutoff = OffsetDateTime::now_utc() - Duration::minutes(1);
        let stale_count = storage::postgres::STALE_FAILURE_PRUNE_BATCH + 5;
        sqlx::query("INSERT INTO password_login_failures(identifier,failed_at) SELECT 'stale-' || value, $1 FROM generate_series(1,$2) AS value")
            .bind(cutoff - Duration::minutes(1))
            .bind(stale_count)
            .execute(postgres.pool())
            .await
            .unwrap();
        sqlx::query("INSERT INTO password_login_failures(identifier,failed_at) VALUES('active-a',$1),('active-b',$1)")
            .bind(cutoff + Duration::seconds(1))
            .execute(postgres.pool())
            .await
            .unwrap();

        storage::postgres::failure_limit_reached(&postgres, "probe", cutoff, 10)
            .await
            .unwrap();
        let remaining_stale: i64 =
            sqlx::query_scalar("SELECT count(*) FROM password_login_failures WHERE failed_at < $1")
                .bind(cutoff)
                .fetch_one(postgres.pool())
                .await
                .unwrap();
        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM password_login_failures WHERE failed_at >= $1",
        )
        .bind(cutoff)
        .fetch_one(postgres.pool())
        .await
        .unwrap();
        assert_eq!(
            remaining_stale,
            stale_count - storage::postgres::STALE_FAILURE_PRUNE_BATCH
        );
        assert_eq!(active, 2);

        storage::postgres::failure_limit_reached(&postgres, "probe", cutoff, 10)
            .await
            .unwrap();
        let remaining_stale: i64 =
            sqlx::query_scalar("SELECT count(*) FROM password_login_failures WHERE failed_at < $1")
                .bind(cutoff)
                .fetch_one(postgres.pool())
                .await
                .unwrap();
        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM password_login_failures WHERE failed_at >= $1",
        )
        .bind(cutoff)
        .fetch_one(postgres.pool())
        .await
        .unwrap();
        assert_eq!(remaining_stale, 0);
        assert_eq!(active, 2);

        postgres.pool().close().await;
        let cleanup_pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        cleanup_pool
            .execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
            .await
            .unwrap();
        cleanup_pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires LENSO_POSTGRES_TEST_URL"]
    async fn global_prune_and_keyed_record_complete_without_deadlock() {
        use sqlx::{AssertSqlSafe, Executor};

        let database_url =
            std::env::var("LENSO_POSTGRES_TEST_URL").expect("LENSO_POSTGRES_TEST_URL is required");
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let schema = format!("password_prune_race_test_{}_{suffix}", std::process::id());
        PasswordAuthOperator::setup(&database_url, &schema)
            .await
            .unwrap();
        let postgres = OwnedPostgres::prepare(&database_url, schema_plan(schema.clone()).unwrap())
            .await
            .unwrap();
        let cutoff = OffsetDateTime::now_utc() - Duration::minutes(1);
        let identifier = "stale-target@example.test";
        sqlx::query("INSERT INTO password_login_failures(identifier,failed_at) VALUES($1,$2)")
            .bind(identifier)
            .bind(cutoff - Duration::minutes(2))
            .execute(postgres.pool())
            .await
            .unwrap();
        sqlx::query("INSERT INTO password_login_failures(identifier,failed_at) SELECT 'stale-race-' || value, $1 FROM generate_series(1,$2) AS value")
            .bind(cutoff - Duration::minutes(1))
            .bind(storage::postgres::STALE_FAILURE_PRUNE_BATCH)
            .execute(postgres.pool())
            .await
            .unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let prune_barrier = Arc::clone(&barrier);
        let record_barrier = Arc::clone(&barrier);

        let (pruned, admission) = tokio::time::timeout(StdDuration::from_secs(5), async {
            tokio::join!(
                async {
                    prune_barrier.wait().await;
                    storage::postgres::prune_stale_login_failures(&postgres, cutoff).await
                },
                async {
                    record_barrier.wait().await;
                    storage::postgres::record_failure_if_allowed(&postgres, identifier, cutoff, 2)
                        .await
                },
            )
        })
        .await
        .expect("global prune and keyed record must not deadlock");
        assert_eq!(
            pruned.unwrap(),
            storage::postgres::STALE_FAILURE_PRUNE_BATCH as u64
        );
        assert_eq!(admission.unwrap(), storage::FailureAdmission::Recorded);
        assert_eq!(
            storage::postgres::current_failure_count(&postgres, identifier, cutoff)
                .await
                .unwrap(),
            1
        );

        postgres.pool().close().await;
        let cleanup_pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        cleanup_pool
            .execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
            .await
            .unwrap();
        cleanup_pool.close().await;
    }

    #[tokio::test]
    async fn credential_hit_and_miss_each_run_one_verifier() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = Arc::new(AtomicUsize::new(0));
        let dummy_hash: Arc<str> = Arc::from("dummy-encoded-hash");
        let hit_calls = Arc::clone(&calls);
        let hit = verify_candidate_with(
            "password".to_owned(),
            Some("stored-encoded-hash".to_owned()),
            Arc::clone(&dummy_hash),
            move |_, _| async move {
                hit_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, ()>(true)
            },
        )
        .await
        .unwrap();
        let miss_calls = Arc::clone(&calls);
        let miss = verify_candidate_with(
            "password".to_owned(),
            None,
            dummy_hash,
            move |_, _| async move {
                miss_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, ()>(true)
            },
        )
        .await
        .unwrap();

        assert!(hit);
        assert!(!miss);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn password_work_rejects_overload_without_queueing() {
        let worker = PasswordWork::prepare_with_limit(1).unwrap();
        let first_worker = worker.clone();
        let release = Arc::new(std::sync::Barrier::new(2));
        let release_worker = Arc::clone(&release);
        let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
        let first = tokio::spawn(async move {
            first_worker
                .run(move || {
                    let _ = started_sender.send(());
                    release_worker.wait();
                    Ok(())
                })
                .await
        });
        started_receiver.await.unwrap();

        assert!(matches!(
            worker.run(|| Ok(())).await,
            Err(PasswordWorkError::Saturated)
        ));
        release.wait();
        first.await.unwrap().unwrap();
    }
}

/// Creates a fresh generated factory with the configured event-owned binding.
#[cfg(feature = "workers")]
pub fn workers_factory(
    binding_name: impl Into<Rc<str>>,
    batch: js_sys::Function,
) -> impl lenso_native_adapter::NativePluginFactory {
    let binding = workers::D1Binding::new(binding_name, batch);
    lenso_native_adapter::ConfiguredPluginFactory::<PasswordAuthPlugin, _>::new(move |plugin| {
        if plugin.config.d1_binding != binding.name() {
            return Err(runtime("Password Auth requires its exact D1 binding"));
        }
        plugin.d1 = Some(EventStorageBinding::D1 {
            storage_ref: None,
            binding: binding.clone(),
        });
        Ok(())
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod password_work_tests;

#[cfg(test)]
mod storage_reference_config_tests {
    use super::*;

    #[test]
    fn storage_reference_is_target_neutral_and_excludes_physical_selectors() {
        let legacy = PasswordAuthConfig::new(
            "auth_password",
            "database",
            vec!["proof.operation".into()],
            3600,
            3,
            60,
        )
        .unwrap();
        let config = legacy.clone().with_storage_ref("auth/password").unwrap();
        let mut value = serde_json::to_value(&config).unwrap();
        assert_eq!(value["storage_ref"], "auth/password");
        assert_eq!(value["database_url_secret"], "");
        assert_eq!(value["d1_binding"], "");
        value.as_object_mut().unwrap().remove("database_url_secret");
        value.as_object_mut().unwrap().remove("d1_binding");
        assert!(
            serde_json::from_value::<PasswordAuthConfig>(value.clone())
                .unwrap()
                .validate()
                .is_ok()
        );
        for key in ["database_url_secret", "d1_binding"] {
            let mut mixed = value.clone();
            mixed[key] = serde_json::json!("physical");
            assert!(
                serde_json::from_value::<PasswordAuthConfig>(mixed)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
        for bad in ["", "../escape", "/root", "a//b", "a/..", "postgres://url"] {
            assert!(legacy.clone().with_storage_ref(bad).is_err());
        }
        let mut old = serde_json::to_value(&legacy).unwrap();
        old.as_object_mut().unwrap().remove("storage_ref");
        assert_eq!(
            serde_json::from_value::<PasswordAuthConfig>(old).unwrap(),
            legacy
        );
        let mut d1 = serde_json::to_value(&legacy).unwrap();
        d1["database_url_secret"] = serde_json::json!("");
        d1["d1_binding"] = serde_json::json!("AUTH_D1");
        d1.as_object_mut().unwrap().remove("storage_ref");
        assert!(
            serde_json::from_value::<PasswordAuthConfig>(d1)
                .unwrap()
                .validate()
                .is_ok()
        );
    }
}

#[cfg(test)]
mod managed_session_config_tests {
    use super::*;

    fn legacy_config() -> PasswordAuthConfig {
        PasswordAuthConfig::new(
            "auth_password",
            "database",
            vec!["proof.operation".into()],
            3600,
            3,
            60,
        )
        .unwrap()
    }

    #[test]
    fn omitted_managed_mode_retains_the_legacy_configuration_default() {
        let legacy = legacy_config();
        assert!(!legacy.managed_sessions);
        let mut old = serde_json::to_value(&legacy).unwrap();
        old.as_object_mut().unwrap().remove("managed_sessions");
        assert_eq!(
            serde_json::from_value::<PasswordAuthConfig>(old).unwrap(),
            legacy
        );
        assert!(validate_managed_binding(&legacy, 0).is_ok());
        assert!(validate_managed_binding(&legacy, 1).is_ok());
        assert!(validate_managed_binding(&legacy, 2).is_err());
    }

    #[test]
    fn explicit_managed_mode_requires_its_binding_before_storage_preparation() {
        let legacy = legacy_config();
        let managed = legacy.clone().with_managed_sessions(true);
        assert_eq!(managed.session_ttl_seconds, legacy.session_ttl_seconds);
        assert_eq!(managed.audience, legacy.audience);
        assert!(matches!(
            validate_managed_binding(&managed, 0),
            Err(RuntimeFailure::InvalidResolvedPlan { .. })
        ));
        assert!(validate_managed_binding(&managed, 1).is_ok());
        assert!(validate_managed_binding(&managed, 2).is_err());
        assert!(!managed.with_managed_sessions(false).managed_sessions);
    }

    #[test]
    fn generated_contract_keeps_managed_binding_optional_and_legacy_issuer_required() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        let requirements = descriptor["required_capabilities"].as_array().unwrap();
        let managed = requirements
            .iter()
            .find(|value| value["capability_id"] == managed::CAPABILITY_ID)
            .unwrap();
        assert_eq!(managed["cardinality"], "many");
        let issuer = requirements
            .iter()
            .find(|value| value["capability_id"] == credential_issuer::CAPABILITY_ID)
            .unwrap();
        assert_eq!(issuer["cardinality"], "one");
        assert_eq!(
            descriptor["configuration_defaults"]["managed_sessions"],
            false
        );
        assert_eq!(
            descriptor["configuration_schema"]["properties"]["managed_sessions"]["type"],
            "boolean"
        );
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod managed_session_routing_tests {
    use super::*;
    use lenso_app_plan::{
        AppComposition, CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan,
        PluginInstancePlan,
    };
    use lenso_kernel::{NativeRequestEndpoint, ShutdownOutcome};
    use lenso_native_adapter::{
        NativePluginFactory, NativePluginFactoryContext, NativePluginInstance,
    };
    use lenso_test::TestApp;
    use std::cell::Cell;

    const CALLER: &str = "password";
    const PROVIDER: &str = "session-fixture";

    #[derive(Debug, Default)]
    struct Observed {
        legacy: RefCell<Vec<(Option<String>, IssueRequest)>>,
        managed: RefCell<Vec<(Option<String>, IssueManagedRequest)>>,
        disabled: Cell<bool>,
    }

    #[derive(Clone, Debug)]
    struct Fixture(Rc<Observed>);

    impl credential_issuer::CredentialIssuerProvider for Fixture {
        fn issue(
            &self,
            context: InvocationContext,
            request: IssueRequest,
        ) -> NativeRequestFuture<credential_issuer::CredentialIssuerIssue> {
            let expires_at = request.expires_at.clone();
            self.0
                .legacy
                .borrow_mut()
                .push((context.caller_instance().map(str::to_owned), request));
            Box::pin(std::future::ready(Ok(Ok(
                credential_issuer::IssueResponse {
                    session_id: "legacy-session".into(),
                    credential: "synthetic-legacy-credential".into(),
                    expires_at,
                },
            ))))
        }

        fn revoke(
            &self,
            _: InvocationContext,
            _: credential_issuer::RevokeRequest,
        ) -> NativeRequestFuture<credential_issuer::CredentialIssuerRevoke> {
            Box::pin(std::future::ready(Ok(Err(
                credential_issuer::RevokeError::NotFound,
            ))))
        }

        fn revoke_credential(
            &self,
            _: InvocationContext,
            _: credential_issuer::RevokeCredentialRequest,
        ) -> NativeRequestFuture<credential_issuer::CredentialIssuerRevokeCredential> {
            Box::pin(std::future::ready(Ok(Err(
                credential_issuer::RevokeCredentialError::NotFound,
            ))))
        }
    }

    impl managed::ManagedSessionProvider for Fixture {
        fn issue_managed(
            &self,
            context: InvocationContext,
            request: IssueManagedRequest,
        ) -> NativeRequestFuture<managed::ManagedSessionIssueManaged> {
            self.0
                .managed
                .borrow_mut()
                .push((context.caller_instance().map(str::to_owned), request));
            let response = if self.0.disabled.get() {
                Err(IssueManagedError::Disabled)
            } else {
                Ok(managed::IssueManagedResponse {
                    session_id: "managed-session".into(),
                    credential: "synthetic-managed-credential".into(),
                    expires_at: "2030-01-01T01:00:00Z".into(),
                    absolute_expires_at: "2030-02-01T00:00:00Z".into(),
                    renew_after: "2030-01-01T00:30:00Z".into(),
                })
            };
            Box::pin(std::future::ready(Ok(response)))
        }

        fn read_managed(
            &self,
            _: InvocationContext,
            _: managed::ReadManagedRequest,
        ) -> NativeRequestFuture<managed::ManagedSessionReadManaged> {
            Box::pin(std::future::ready(Ok(Err(
                managed::ReadManagedError::Unsupported,
            ))))
        }

        fn renew(
            &self,
            _: InvocationContext,
            _: managed::RenewRequest,
        ) -> NativeRequestFuture<managed::ManagedSessionRenew> {
            Box::pin(std::future::ready(Ok(Err(
                managed::RenewError::Unsupported,
            ))))
        }
    }

    impl NativePluginFactory for Fixture {
        fn package_id(&self) -> &'static str {
            "test.password-session-provider"
        }

        fn instantiate(
            &self,
            _: NativePluginFactoryContext<'_>,
        ) -> Result<NativePluginInstance, RuntimeFailure> {
            Ok(NativePluginInstance::new(vec![
                Rc::new(credential_issuer::CredentialIssuerEndpoint::new(
                    self.clone(),
                )) as Rc<dyn NativeRequestEndpoint>,
                Rc::new(managed::ManagedSessionEndpoint::new(self.clone()))
                    as Rc<dyn NativeRequestEndpoint>,
            ]))
        }
    }

    #[derive(Debug)]
    struct Caller;

    impl NativePluginFactory for Caller {
        fn package_id(&self) -> &'static str {
            "test.password-session-caller"
        }

        fn instantiate(
            &self,
            _: NativePluginFactoryContext<'_>,
        ) -> Result<NativePluginInstance, RuntimeFailure> {
            Ok(NativePluginInstance::default())
        }
    }

    fn app(observed: &Rc<Observed>) -> TestApp {
        let mut caller = PluginInstancePlan::new(CALLER, "test.password-session-caller");
        let mut provider = PluginInstancePlan::new(PROVIDER, "test.password-session-provider");
        let mut bindings = Vec::new();
        for (id, version, operations) in [
            (
                credential_issuer::CAPABILITY_ID,
                credential_issuer::DESCRIPTOR_VERSION,
                vec!["issue", "revoke", "revoke_credential"],
            ),
            (
                managed::CAPABILITY_ID,
                managed::DESCRIPTOR_VERSION,
                vec![
                    managed::ISSUE_MANAGED_OPERATION,
                    managed::READ_MANAGED_OPERATION,
                    managed::RENEW_OPERATION,
                ],
            ),
        ] {
            caller = caller.with_requirement(CapabilityRequirementPlan::one(id, version));
            provider = provider.with_capability(
                CapabilityEndpointPlan::new(id, version, operations).with_cross_lane_transfer(),
            );
            bindings.push(CapabilityBinding::new(CALLER, id, version, PROVIDER));
        }
        TestApp::builder(
            AppComposition::new(vec![caller, provider], bindings)
                .resolve()
                .unwrap(),
        )
        .with_factory(Caller)
        .with_factory(Fixture(Rc::clone(observed)))
        .start()
        .unwrap()
    }

    #[test]
    fn shared_issue_helper_routes_real_generated_clients_without_ttl_or_authority_widening() {
        let observed = Rc::new(Observed::default());
        let app = app(&observed);
        let issuer = app.client::<CredentialIssuerClient>(CALLER).unwrap();
        let managed = app.client::<ManagedSessionClient>(CALLER).unwrap();
        let legacy = PasswordAuthConfig::new(
            "password_routing",
            "synthetic/database",
            vec!["proof.operation".into()],
            3600,
            3,
            60,
        )
        .unwrap();
        let invoke = |config: &PasswordAuthConfig, bound| {
            app.run(issue(
                config,
                &issuer,
                bound,
                InvocationContext::new(42, None, lenso_kernel::CancellationToken::new()),
                "verified-password-subject",
            ))
        };
        let before = OffsetDateTime::now_utc();
        let response =
            invoke(&legacy, Some(&managed)).unwrap_or_else(|_| panic!("legacy issuance failed"));
        let after = OffsetDateTime::now_utc();
        assert_eq!(response.session_id, "legacy-session");
        assert_eq!(observed.legacy.borrow().len(), 1);
        assert!(observed.managed.borrow().is_empty());
        let recorded = observed.legacy.borrow();
        let (caller, request) = &recorded[0];
        assert_eq!(caller.as_deref(), Some(CALLER));
        assert_eq!(request.subject, "verified-password-subject");
        assert_eq!(request.actor_kind, "user");
        assert_eq!(request.assurance, "password");
        assert_eq!(request.audience, legacy.audience);
        assert!(request.claims.is_empty());
        let expires = OffsetDateTime::parse(&request.expires_at, &Rfc3339).unwrap();
        assert!((before + Duration::hours(1)..=after + Duration::hours(1)).contains(&expires));
        drop(recorded);

        let managed_config = legacy.with_managed_sessions(true);
        let response = invoke(&managed_config, Some(&managed))
            .unwrap_or_else(|_| panic!("managed issuance failed"));
        assert_eq!(response.session_id, "managed-session");
        assert_eq!(response.credential, "synthetic-managed-credential");
        assert_eq!(response.expires_at, "2030-01-01T01:00:00Z");
        assert_eq!(observed.legacy.borrow().len(), 1);
        let recorded = observed.managed.borrow();
        let (caller, request) = &recorded[0];
        assert_eq!(caller.as_deref(), Some(CALLER));
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            serde_json::json!({
                "subject": "verified-password-subject",
                "actor_kind": "user", "assurance": "password",
                "audience": ["proof.operation"], "claims": {}
            })
        );
        drop(recorded);

        assert!(matches!(
            invoke(&managed_config, None),
            Err(IssueCallError::Runtime(
                RuntimeFailure::InvalidResolvedPlan { .. }
            ))
        ));
        assert_eq!(observed.managed.borrow().len(), 1);
        observed.disabled.set(true);
        assert!(matches!(
            invoke(&managed_config, Some(&managed)),
            Err(IssueCallError::Disabled)
        ));
        assert_eq!(observed.managed.borrow().len(), 2);
        assert_eq!(
            observed.legacy.borrow().len(),
            1,
            "managed rejection must not fall back to legacy issuance"
        );
        assert_eq!(
            app.shutdown(std::time::Duration::from_secs(1)),
            ShutdownOutcome::Clean
        );
    }
}

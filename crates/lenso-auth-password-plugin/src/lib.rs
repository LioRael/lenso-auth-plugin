//! Password authentication as a removable Plugin over Directory and Credential Issuer contracts.

mod operator;
mod schema;
mod storage;

use std::{
    cell::RefCell, collections::BTreeMap, fmt, future::Future, rc::Rc, sync::Arc,
    time::Duration as StdDuration,
};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use lenso::{ActivateContext, DeactivateContext, Lifecycle, Port, provides};
use lenso_capability_credential_issuer as credential_issuer;
use lenso_capability_credential_issuer::{
    CredentialIssuerClient, CredentialIssuerIssueInvocationError, IssueError, IssueRequest,
};
use lenso_capability_identity_directory as directory;
use lenso_capability_identity_directory::{
    DirectoryEnsureIdentityInvocationError, EnsureIdentityError, EnsureIdentityRequest,
};
use lenso_capability_password_auth as password;
use lenso_capability_password_auth::{
    LoginError, LoginRequest, LoginResponse, PasswordLogin, PasswordProvider, PasswordRegister,
    RegisterError, RegisterRequest, RegisterResponse,
};
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsInvocationError};
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::schema::schema_plan;

pub use operator::{PasswordAuthOperator, PasswordOperatorError};

const DEPENDENCY_TIMEOUT: StdDuration = StdDuration::from_secs(10);
const MAX_PASSWORD_WORK_JOBS: usize = 4;
const DUMMY_PASSWORD_INPUT: &str = "lenso-auth-password-dummy-input";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, lenso::PluginConfig)]
#[serde(deny_unknown_fields)]
pub struct PasswordAuthConfig {
    schema: String,
    database_url_secret: String,
    audience: Vec<String>,
    session_ttl_seconds: u64,
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
            audience,
            session_ttl_seconds,
            max_failures,
            failure_window_seconds,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), PasswordConfigError> {
        schema_plan(self.schema.clone()).map_err(|_| PasswordConfigError::InvalidSchema)?;
        if self.database_url_secret.is_empty() || self.database_url_secret.len() > 256 {
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
    postgres: OwnedPostgres,
    config: PasswordAuthConfig,
    password_work: PasswordWork,
}
impl fmt::Debug for ActivePassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActivePassword")
            .field("schema", &self.postgres.schema())
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
    async fn prepare() -> Result<Self, PasswordWorkError> {
        Self::prepare_with_limit(MAX_PASSWORD_WORK_JOBS).await
    }

    async fn prepare_with_limit(limit: usize) -> Result<Self, PasswordWorkError> {
        let permits = Arc::new(Semaphore::new(limit));
        let dummy_hash = run_password_job(Arc::clone(&permits), || {
            hash_password_sync(DUMMY_PASSWORD_INPUT)
        })
        .await?;
        Ok(Self {
            permits,
            dummy_hash: Arc::from(dummy_hash),
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
    #[error("password worker terminated")]
    Join,
    #[error(transparent)]
    Password(#[from] PasswordPluginError),
}

async fn run_password_job<T, F>(permits: Arc<Semaphore>, job: F) -> Result<T, PasswordWorkError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, PasswordPluginError> + Send + 'static,
{
    let permit = permits
        .try_acquire_owned()
        .map_err(|_| PasswordWorkError::Saturated)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        job()
    })
    .await
    .map_err(|_| PasswordWorkError::Join)?
    .map_err(PasswordWorkError::from)
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
    postgres: Rc<RefCell<Option<OwnedPostgres>>>,
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
            if !storage::insert_credential(&active.postgres, &identifier, &identity.subject, &hash)
                .await
                .map_err(runtime)?
            {
                return Ok(Err(RegisterError::IdentifierTaken));
            }
            let credential = issue(&active, &issuer, context, &identity.subject).await;
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
                &active.postgres,
                &identifier,
                since,
                active.config.max_failures,
            )
            .await
            .map_err(runtime)?
            {
                return Ok(Err(LoginError::RateLimited));
            }
            let credential = storage::load_credential(&active.postgres, &identifier)
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
                    &active.postgres,
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
            storage::clear_failures(&active.postgres, &identifier)
                .await
                .map_err(runtime)?;
            let subject = subject.expect("verified credential has a subject");
            match issue(&active, &issuer, context, &subject).await {
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
    active: &ActivePassword,
    issuer: &CredentialIssuerClient,
    context: InvocationContext,
    subject: &str,
) -> Result<lenso_capability_credential_issuer::IssueResponse, IssueCallError> {
    let expires_at = (OffsetDateTime::now_utc()
        + Duration::seconds(i64::try_from(active.config.session_ttl_seconds).expect("validated")))
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
                audience: active.config.audience.clone(),
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

impl Lifecycle for PasswordAuthPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let config = self.config.clone();
        let state = self.postgres.clone();
        let dependencies = context.dependencies().clone();
        let cancellation = context.cancellation();
        let invocation = dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation)?;
        let database_url = self
            .secrets
            .resolve_with_context(
                invocation,
                ResolveRequest {
                    reference: config.database_url_secret.clone(),
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
        let password_work = PasswordWork::prepare().await.map_err(runtime)?;
        state.replace(Some(postgres.clone()));
        let active = self.active.clone();
        active.replace(Some(Rc::new(ActivePassword {
            postgres,
            config,
            password_work,
        })));
        Ok(())
    }

    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        self.active.borrow_mut().take();
        let postgres = self.postgres.borrow_mut().take();
        if let Some(postgres) = postgres {
            postgres.pool().close().await;
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
enum PasswordPluginError {
    #[error("PostgreSQL operation `{operation}` failed")]
    Database {
        operation: &'static str,
        #[source]
        source: lenso_postgres_kit::sqlx::Error,
    },
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

#[cfg(test)]
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
        use lenso_postgres_kit::sqlx::{AssertSqlSafe, Executor};

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
            storage::record_failure_if_allowed(&postgres, identifier, since, 2),
            storage::record_failure_if_allowed(&postgres, identifier, since, 2),
            storage::record_failure_if_allowed(&postgres, identifier, since, 2),
            storage::record_failure_if_allowed(&postgres, identifier, since, 2),
            storage::record_failure_if_allowed(&postgres, identifier, since, 2),
        );
        let recorded = [outcomes.0, outcomes.1, outcomes.2, outcomes.3, outcomes.4]
            .into_iter()
            .map(Result::unwrap)
            .filter(|outcome| *outcome == storage::FailureAdmission::Recorded)
            .count();
        assert_eq!(recorded, 2);
        assert_eq!(
            storage::current_failure_count(&postgres, identifier, since)
                .await
                .unwrap(),
            2
        );

        postgres.pool().close().await;
        let cleanup_pool = lenso_postgres_kit::sqlx::PgPool::connect(&database_url)
            .await
            .unwrap();
        cleanup_pool
            .execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
            .await
            .unwrap();
        cleanup_pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires LENSO_POSTGRES_TEST_URL"]
    async fn stale_failure_pruning_is_bounded_and_eventually_drains() {
        use lenso_postgres_kit::sqlx::{AssertSqlSafe, Executor};

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
        let stale_count = storage::STALE_FAILURE_PRUNE_BATCH + 5;
        lenso_postgres_kit::sqlx::query("INSERT INTO password_login_failures(identifier,failed_at) SELECT 'stale-' || value, $1 FROM generate_series(1,$2) AS value")
            .bind(cutoff - Duration::minutes(1))
            .bind(stale_count)
            .execute(postgres.pool())
            .await
            .unwrap();
        lenso_postgres_kit::sqlx::query("INSERT INTO password_login_failures(identifier,failed_at) VALUES('active-a',$1),('active-b',$1)")
            .bind(cutoff + Duration::seconds(1))
            .execute(postgres.pool())
            .await
            .unwrap();

        storage::failure_limit_reached(&postgres, "probe", cutoff, 10)
            .await
            .unwrap();
        let remaining_stale: i64 = lenso_postgres_kit::sqlx::query_scalar(
            "SELECT count(*) FROM password_login_failures WHERE failed_at < $1",
        )
        .bind(cutoff)
        .fetch_one(postgres.pool())
        .await
        .unwrap();
        let active: i64 = lenso_postgres_kit::sqlx::query_scalar(
            "SELECT count(*) FROM password_login_failures WHERE failed_at >= $1",
        )
        .bind(cutoff)
        .fetch_one(postgres.pool())
        .await
        .unwrap();
        assert_eq!(
            remaining_stale,
            stale_count - storage::STALE_FAILURE_PRUNE_BATCH
        );
        assert_eq!(active, 2);

        storage::failure_limit_reached(&postgres, "probe", cutoff, 10)
            .await
            .unwrap();
        let remaining_stale: i64 = lenso_postgres_kit::sqlx::query_scalar(
            "SELECT count(*) FROM password_login_failures WHERE failed_at < $1",
        )
        .bind(cutoff)
        .fetch_one(postgres.pool())
        .await
        .unwrap();
        let active: i64 = lenso_postgres_kit::sqlx::query_scalar(
            "SELECT count(*) FROM password_login_failures WHERE failed_at >= $1",
        )
        .bind(cutoff)
        .fetch_one(postgres.pool())
        .await
        .unwrap();
        assert_eq!(remaining_stale, 0);
        assert_eq!(active, 2);

        postgres.pool().close().await;
        let cleanup_pool = lenso_postgres_kit::sqlx::PgPool::connect(&database_url)
            .await
            .unwrap();
        cleanup_pool
            .execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
            .await
            .unwrap();
        cleanup_pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires LENSO_POSTGRES_TEST_URL"]
    async fn global_prune_and_keyed_record_complete_without_deadlock() {
        use lenso_postgres_kit::sqlx::{AssertSqlSafe, Executor};

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
        lenso_postgres_kit::sqlx::query(
            "INSERT INTO password_login_failures(identifier,failed_at) VALUES($1,$2)",
        )
        .bind(identifier)
        .bind(cutoff - Duration::minutes(2))
        .execute(postgres.pool())
        .await
        .unwrap();
        lenso_postgres_kit::sqlx::query("INSERT INTO password_login_failures(identifier,failed_at) SELECT 'stale-race-' || value, $1 FROM generate_series(1,$2) AS value")
            .bind(cutoff - Duration::minutes(1))
            .bind(storage::STALE_FAILURE_PRUNE_BATCH)
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
                    storage::prune_stale_login_failures(&postgres, cutoff).await
                },
                async {
                    record_barrier.wait().await;
                    storage::record_failure_if_allowed(&postgres, identifier, cutoff, 2).await
                },
            )
        })
        .await
        .expect("global prune and keyed record must not deadlock");
        assert_eq!(pruned.unwrap(), storage::STALE_FAILURE_PRUNE_BATCH as u64);
        assert_eq!(admission.unwrap(), storage::FailureAdmission::Recorded);
        assert_eq!(
            storage::current_failure_count(&postgres, identifier, cutoff)
                .await
                .unwrap(),
            1
        );

        postgres.pool().close().await;
        let cleanup_pool = lenso_postgres_kit::sqlx::PgPool::connect(&database_url)
            .await
            .unwrap();
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
        let worker = PasswordWork::prepare_with_limit(1).await.unwrap();
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

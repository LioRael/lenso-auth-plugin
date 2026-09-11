//! Phone OTP and phone-password authentication with private durable state.
mod operator;
mod schema;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use lenso::{ActivateContext, DeactivateContext, Lifecycle, Port, provides};
use lenso_capability_credential_issuer as credential_issuer;
use lenso_capability_credential_issuer::{
    CredentialIssuerClient, CredentialIssuerIssueInvocationError, IssueError, IssueRequest,
    IssueResponse,
};
use lenso_capability_identity_directory as directory;
use lenso_capability_identity_directory::{
    DirectoryEnsureIdentityInvocationError, DirectoryReadStatusInvocationError,
    EnsureIdentityError, EnsureIdentityRequest, ReadStatusError, ReadStatusRequest,
    ReadStatusResponseStatus,
};
use lenso_capability_phone_auth as phone;
use lenso_capability_phone_auth::{
    PasswordLoginError, PasswordLoginRequest, PhonePasswordLogin, PhoneProvider, PhoneSetPassword,
    PhoneStartOtp, PhoneVerifyOtp, SessionResponse, SetPasswordError, SetPasswordRequest,
    SetPasswordResponse, StartOtpError, StartOtpRequest, StartOtpRequestPurpose, StartOtpResponse,
    VerifyOtpError, VerifyOtpRequest,
};
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsClient, SecretsInvocationError};
use lenso_capability_sms_delivery as sms;
use lenso_capability_sms_delivery::{SendRequest, SmsInvocationError};
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
use lenso_postgres_kit::OwnedPostgres;
use lenso_postgres_kit::sqlx::Row;
pub use operator::{PhoneOperator, PhoneOperatorError};
use schema::schema_plan;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    cell::RefCell, collections::BTreeMap, fmt, future::Future, rc::Rc, sync::Arc,
    time::Duration as StdDuration,
};
use thiserror::Error;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;
const TIMEOUT: StdDuration = StdDuration::from_secs(10);
const MAX_PASSWORD_WORK_JOBS: usize = 4;
const DUMMY_PASSWORD_INPUT: &str = "lenso-auth-phone-password-dummy-input";
const STALE_FAILURE_PRUNE_BATCH: i64 = 256;
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Environment {
    Development,
    Production,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhoneConfig {
    schema: String,
    database_url_secret: String,
    otp_secret_ref: String,
    environment: Environment,
    return_debug_code: bool,
    set_password_callers: Vec<String>,
    audience: Vec<String>,
    otp_code_length: usize,
    otp_ttl_seconds: u64,
    resend_cooldown_seconds: u64,
    otp_max_attempts: i32,
    start_window_seconds: u64,
    max_starts_per_ip: i64,
    max_password_failures: i64,
    password_failure_window_seconds: u64,
    session_ttl_seconds: u64,
}
impl PhoneConfig {
    fn validate(&self) -> Result<(), RuntimeFailure> {
        schema_plan(self.schema.clone()).map_err(|e| invalid(&e.to_string()))?;
        if self.database_url_secret.is_empty()
            || self.otp_secret_ref.is_empty()
            || self.database_url_secret == self.otp_secret_ref
            || self.set_password_callers.is_empty()
            || self.set_password_callers.iter().any(|v| !valid_name(v))
            || self.audience.is_empty()
            || !(4..=10).contains(&self.otp_code_length)
            || !(60..=3600).contains(&self.otp_ttl_seconds)
            || self.resend_cooldown_seconds > 3600
            || !(1..=20).contains(&self.otp_max_attempts)
            || !(60..=3600).contains(&self.start_window_seconds)
            || !(1..=100).contains(&self.max_starts_per_ip)
            || !(1..=100).contains(&self.max_password_failures)
            || !(60..=86400).contains(&self.password_failure_window_seconds)
            || !(1..=2_592_000).contains(&self.session_ttl_seconds)
            || self.return_debug_code && self.environment != Environment::Development
        {
            return Err(invalid("invalid Phone Auth configuration"));
        }
        Ok(())
    }
}
fn validate_config(config: &PhoneConfig) -> Result<(), RuntimeFailure> {
    config.validate()
}
#[derive(Clone)]
struct Prepared {
    postgres: OwnedPostgres,
    otp_secret: Zeroizing<Vec<u8>>,
    password_work: PasswordWork,
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
    config: PhoneConfig,
}

#[derive(Clone)]
struct PasswordWork {
    permits: Arc<Semaphore>,
    dummy_hash: Arc<str>,
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
        F: FnOnce() -> Result<T, PhonePasswordError> + Send + 'static,
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
    Password(#[from] PhonePasswordError),
}

#[derive(Debug, Error)]
enum PhonePasswordError {
    #[error("password hashing failed")]
    Hash,
    #[error("random source unavailable")]
    Random,
}

async fn run_password_job<T, F>(permits: Arc<Semaphore>, job: F) -> Result<T, PasswordWorkError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, PhonePasswordError> + Send + 'static,
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
impl fmt::Debug for Active {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Active").finish_non_exhaustive()
    }
}
#[lenso::plugin(
    lifecycle,
    validate = validate_config,
    configuration_schema = "configuration.schema.json"
)]
#[derive(Clone)]
struct PhoneAuthPlugin {
    #[config]
    config: PhoneConfig,
    secrets: Port<secrets::SecretsClient>,
    directory: Port<directory::DirectoryClient>,
    issuer: Port<credential_issuer::CredentialIssuerClient>,
    sms: Port<sms::SmsClient>,
    prepared: Rc<RefCell<Option<Prepared>>>,
    active: Rc<RefCell<Option<Rc<Active>>>>,
}
#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for PhoneAuthPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhoneProvider")
            .field("active", &self.active.borrow().is_some())
            .finish()
    }
}
impl PhoneAuthPlugin {
    fn active(&self) -> Result<Rc<Active>, RuntimeFailure> {
        self.active
            .borrow()
            .clone()
            .ok_or_else(|| failure("Phone Auth is not active"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OtpReservationOutcome {
    Inserted,
    RateLimited,
    ResendTooSoon,
}

struct OtpReservation<'a> {
    challenge_id: &'a str,
    phone: &'a str,
    purpose: &'a str,
    code_digest: &'a [u8],
    client_ip: Option<&'a str>,
    expires_at: OffsetDateTime,
    resend_after: OffsetDateTime,
    now: OffsetDateTime,
    start_window: Duration,
    max_starts: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailureAdmission {
    Recorded,
    RateLimited,
}
#[provides(phone::Phone)]
impl PhoneProvider for PhoneAuthPlugin {
    fn start_otp(
        &self,
        context: InvocationContext,
        r: StartOtpRequest,
    ) -> NativeRequestFuture<PhoneStartOtp> {
        let active = self.active();
        let sms = self.sms.clone();
        Box::pin(async move {
            let a = active?;
            let Some(phone) = normalize_phone(&r.phone) else {
                return Ok(Err(StartOtpError::InvalidPhone));
            };
            let purpose = match r.purpose {
                StartOtpRequestPurpose::Login => "login",
                StartOtpRequestPurpose::Register => "register",
            };
            let now = OffsetDateTime::now_utc();
            if let Some(ip) = r.client_ip.as_ref()
                && ip.len() > 128
            {
                return Ok(Err(StartOtpError::RateLimited));
            }
            let code = random_digits(a.config.otp_code_length)?;
            let challenge_id = random_id("otp_")?;
            let digest = otp_digest(&a.prepared.otp_secret, &challenge_id, &code)?;
            let expires = now
                + Duration::seconds(i64::try_from(a.config.otp_ttl_seconds).expect("validated"));
            let resend_after = now
                + Duration::seconds(
                    i64::try_from(a.config.resend_cooldown_seconds).expect("validated"),
                );
            let reservation = OtpReservation {
                challenge_id: &challenge_id,
                phone: &phone,
                purpose,
                code_digest: &digest,
                client_ip: r.client_ip.as_deref(),
                expires_at: expires,
                resend_after,
                now,
                start_window: Duration::seconds(
                    i64::try_from(a.config.start_window_seconds).expect("validated"),
                ),
                max_starts: a.config.max_starts_per_ip,
            };
            match reserve_otp_challenge(&a.prepared.postgres, &reservation).await? {
                OtpReservationOutcome::Inserted => {}
                OtpReservationOutcome::RateLimited => {
                    return Ok(Err(StartOtpError::RateLimited));
                }
                OtpReservationOutcome::ResendTooSoon => {
                    return Ok(Err(StartOtpError::ResendTooSoon));
                }
            }
            let delivery = sms
                .send_with_context(
                    context,
                    SendRequest {
                        destination: phone.clone(),
                        body: format!("Your Lenso verification code is {code}"),
                    },
                )
                .await;
            if !matches!(delivery,Ok(ref v)if v.accepted) {
                lenso_postgres_kit::sqlx::query(
                    "DELETE FROM phone_otp_challenges WHERE challenge_id=$1",
                )
                .bind(&challenge_id)
                .execute(a.prepared.postgres.pool())
                .await
                .map_err(db)?;
                return match delivery {
                    Err(SmsInvocationError::Runtime(e)) => Err(e),
                    _ => Ok(Err(StartOtpError::DeliveryRejected)),
                };
            }
            Ok(Ok(StartOtpResponse {
                challenge_id,
                expires_at: format_time(expires)?,
                resend_after: format_time(resend_after)?,
                debug_code: a.config.return_debug_code.then_some(code),
            }))
        })
    }
    fn verify_otp(
        &self,
        context: InvocationContext,
        r: VerifyOtpRequest,
    ) -> NativeRequestFuture<PhoneVerifyOtp> {
        let active = self.active();
        let directory = self.directory.clone();
        let issuer = self.issuer.clone();
        Box::pin(async move {
            let a = active?;
            if !valid_name(&r.challenge_id)
                || r.code.len() != a.config.otp_code_length
                || !r.code.bytes().all(|b| b.is_ascii_digit())
            {
                return Ok(Err(VerifyOtpError::InvalidChallenge));
            }
            let mut tx = a.prepared.postgres.pool().begin().await.map_err(db)?;
            let row=lenso_postgres_kit::sqlx::query("SELECT phone,code_digest,attempts,expires_at,consumed_at IS NOT NULL AS consumed FROM phone_otp_challenges WHERE challenge_id=$1 FOR UPDATE").bind(&r.challenge_id).fetch_optional(&mut*tx).await.map_err(db)?;
            let Some(row) = row else {
                return Ok(Err(VerifyOtpError::InvalidChallenge));
            };
            if row.try_get::<bool, _>("consumed").map_err(db)? {
                return Ok(Err(VerifyOtpError::InvalidChallenge));
            }
            let attempts: i32 = row.try_get("attempts").map_err(db)?;
            if attempts >= a.config.otp_max_attempts {
                return Ok(Err(VerifyOtpError::TooManyAttempts));
            }
            let expires: OffsetDateTime = row.try_get("expires_at").map_err(db)?;
            if expires <= OffsetDateTime::now_utc() {
                return Ok(Err(VerifyOtpError::Expired));
            }
            let stored: Vec<u8> = row.try_get("code_digest").map_err(db)?;
            if !otp_matches(&a.prepared.otp_secret, &r.challenge_id, &r.code, &stored)? {
                lenso_postgres_kit::sqlx::query(
                    "UPDATE phone_otp_challenges SET attempts=attempts+1 WHERE challenge_id=$1",
                )
                .bind(&r.challenge_id)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
                tx.commit().await.map_err(db)?;
                return Ok(Err(if attempts + 1 >= a.config.otp_max_attempts {
                    VerifyOtpError::TooManyAttempts
                } else {
                    VerifyOtpError::InvalidCode
                }));
            }
            lenso_postgres_kit::sqlx::query("UPDATE phone_otp_challenges SET consumed_at=transaction_timestamp() WHERE challenge_id=$1").bind(&r.challenge_id).execute(&mut*tx).await.map_err(db)?;
            tx.commit().await.map_err(db)?;
            let phone: String = row.try_get("phone").map_err(db)?;
            let identity = directory
                .ensure_identity_with_context(
                    context.clone(),
                    EnsureIdentityRequest {
                        provider: "phone".to_owned(),
                        external_subject: phone.clone(),
                    },
                )
                .await;
            let identity = match identity {
                Ok(v) => v,
                Err(DirectoryEnsureIdentityInvocationError::Domain(
                    EnsureIdentityError::Disabled,
                )) => return Ok(Err(VerifyOtpError::Disabled)),
                Err(DirectoryEnsureIdentityInvocationError::Domain(_)) => {
                    return Ok(Err(VerifyOtpError::InvalidChallenge));
                }
                Err(DirectoryEnsureIdentityInvocationError::Runtime(e)) => return Err(e),
            };
            lenso_postgres_kit::sqlx::query("INSERT INTO phone_identities(phone,subject_id)VALUES($1,$2)ON CONFLICT(phone)DO UPDATE SET subject_id=EXCLUDED.subject_id").bind(&phone).bind(&identity.subject).execute(a.prepared.postgres.pool()).await.map_err(db)?;
            let credential = match issue(
                &a,
                &issuer,
                context,
                &identity.subject,
                "phone-otp",
                r.device_id,
            )
            .await
            {
                Ok(value) => value,
                Err(IssueCall::Disabled) => return Ok(Err(VerifyOtpError::Disabled)),
                Err(IssueCall::Runtime(error)) => return Err(error),
            };
            Ok(Ok(SessionResponse {
                subject: identity.subject,
                session_id: credential.session_id,
                credential: credential.credential,
                expires_at: credential.expires_at,
                masked_phone: mask_phone(&phone),
            }))
        })
    }
    fn set_password(
        &self,
        context: InvocationContext,
        r: SetPasswordRequest,
    ) -> NativeRequestFuture<PhoneSetPassword> {
        let active = self.active();
        let directory = self.directory.clone();
        Box::pin(async move {
            let a = active?;
            if !context
                .caller_instance()
                .is_some_and(|c| a.config.set_password_callers.iter().any(|v| v == c))
            {
                return Ok(Err(SetPasswordError::Forbidden));
            }
            if !valid_name(&r.subject) {
                return Ok(Err(SetPasswordError::InvalidSubject));
            }
            if !valid_password(&r.password) {
                return Ok(Err(SetPasswordError::WeakPassword));
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
                Ok(_) => return Ok(Err(SetPasswordError::Disabled)),
                Err(DirectoryReadStatusInvocationError::Domain(ReadStatusError::NotFound)) => {
                    return Ok(Err(SetPasswordError::NotFound));
                }
                Err(DirectoryReadStatusInvocationError::Domain(_)) => {
                    return Ok(Err(SetPasswordError::InvalidSubject));
                }
                Err(DirectoryReadStatusInvocationError::Runtime(e)) => return Err(e),
            }
            let phone: Option<String> = lenso_postgres_kit::sqlx::query_scalar(
                "SELECT phone FROM phone_identities WHERE subject_id=$1",
            )
            .bind(&r.subject)
            .fetch_optional(a.prepared.postgres.pool())
            .await
            .map_err(db)?;
            let Some(phone) = phone else {
                return Ok(Err(SetPasswordError::NotFound));
            };
            let hash = a
                .prepared
                .password_work
                .hash(r.password)
                .await
                .map_err(|error| password_work_failure(&error))?;
            lenso_postgres_kit::sqlx::query("INSERT INTO phone_passwords(subject_id,phone,password_hash)VALUES($1,$2,$3)ON CONFLICT(subject_id)DO UPDATE SET password_hash=EXCLUDED.password_hash,updated_at=transaction_timestamp()").bind(&r.subject).bind(phone).bind(hash).execute(a.prepared.postgres.pool()).await.map_err(db)?;
            Ok(Ok(SetPasswordResponse { updated: true }))
        })
    }
    fn password_login(
        &self,
        context: InvocationContext,
        r: PasswordLoginRequest,
    ) -> NativeRequestFuture<PhonePasswordLogin> {
        let active = self.active();
        let issuer = self.issuer.clone();
        Box::pin(async move {
            let a = active?;
            let Some(phone) = normalize_phone(&r.phone) else {
                return Ok(Err(PasswordLoginError::InvalidPhone));
            };
            let since = OffsetDateTime::now_utc()
                - Duration::seconds(
                    i64::try_from(a.config.password_failure_window_seconds).expect("validated"),
                );
            if phone_failure_limit_reached(
                &a.prepared.postgres,
                &phone,
                since,
                a.config.max_password_failures,
            )
            .await?
            {
                return Ok(Err(PasswordLoginError::RateLimited));
            }
            let row = lenso_postgres_kit::sqlx::query(
                "SELECT subject_id,password_hash FROM phone_passwords WHERE phone=$1",
            )
            .bind(&phone)
            .fetch_optional(a.prepared.postgres.pool())
            .await
            .map_err(db)?;
            let (subject, stored_hash) = match row {
                Some(row) => (
                    Some(row.try_get::<String, _>("subject_id").map_err(db)?),
                    Some(row.try_get::<String, _>("password_hash").map_err(db)?),
                ),
                None => (None, None),
            };
            let valid = match a
                .prepared
                .password_work
                .verify(r.password, stored_hash)
                .await
            {
                Ok(valid) => valid,
                Err(PasswordWorkError::Saturated) => {
                    return Ok(Err(PasswordLoginError::RateLimited));
                }
                Err(error) => return Err(password_work_failure(&error)),
            };
            if !valid {
                return match record_phone_failure_if_allowed(
                    &a.prepared.postgres,
                    &phone,
                    since,
                    a.config.max_password_failures,
                )
                .await?
                {
                    FailureAdmission::Recorded => Ok(Err(PasswordLoginError::InvalidCredentials)),
                    FailureAdmission::RateLimited => Ok(Err(PasswordLoginError::RateLimited)),
                };
            }
            clear_phone_failures(&a.prepared.postgres, &phone).await?;
            let subject = subject.expect("verified credential has a subject");
            let credential = match issue(
                &a,
                &issuer,
                context,
                &subject,
                "phone-password",
                r.device_id,
            )
            .await
            {
                Ok(v) => v,
                Err(IssueCall::Disabled) => return Ok(Err(PasswordLoginError::Disabled)),
                Err(IssueCall::Runtime(e)) => return Err(e),
            };
            Ok(Ok(SessionResponse {
                subject,
                session_id: credential.session_id,
                credential: credential.credential,
                expires_at: credential.expires_at,
                masked_phone: mask_phone(&phone),
            }))
        })
    }
}
enum IssueCall {
    Disabled,
    Runtime(RuntimeFailure),
}
async fn issue(
    a: &Active,
    issuer: &CredentialIssuerClient,
    context: InvocationContext,
    subject: &str,
    assurance: &str,
    device: Option<String>,
) -> Result<IssueResponse, IssueCall> {
    let expires = OffsetDateTime::now_utc()
        + Duration::seconds(i64::try_from(a.config.session_ttl_seconds).expect("validated"));
    let mut claims = BTreeMap::new();
    if let Some(device) = device {
        claims.insert("device_id".to_owned(), serde_json::Value::String(device));
    }
    issuer
        .issue_with_context(
            context,
            IssueRequest {
                subject: subject.to_owned(),
                actor_kind: "user".to_owned(),
                assurance: assurance.to_owned(),
                audience: a.config.audience.clone(),
                claims,
                expires_at: format_time(expires).map_err(IssueCall::Runtime)?,
            },
        )
        .await
        .map_err(|e| match e {
            CredentialIssuerIssueInvocationError::Domain(IssueError::Disabled) => {
                IssueCall::Disabled
            }
            CredentialIssuerIssueInvocationError::Domain(e) => IssueCall::Runtime(failure(
                &format!("credential issuer rejected phone session: {e:?}"),
            )),
            CredentialIssuerIssueInvocationError::Runtime(e) => IssueCall::Runtime(e),
        })
}
impl Lifecycle for PhoneAuthPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let c = self.config.clone();
        let deps = context.dependencies().clone();
        let cancel = context.cancellation();
        let state = self.prepared.clone();
        let dbs = resolve(&self.secrets, &deps, cancel.clone(), &c.database_url_secret).await?;
        let otp = resolve(&self.secrets, &deps, cancel, &c.otp_secret_ref).await?;
        if otp.len() < 32 {
            return Err(failure("OTP secret must contain at least 32 bytes"));
        }
        let postgres = OwnedPostgres::prepare(
            &dbs,
            schema_plan(c.schema.clone()).map_err(|e| invalid(&e.to_string()))?,
        )
        .await
        .map_err(|e| failure(&e.to_string()))?;
        let password_work = PasswordWork::prepare()
            .await
            .map_err(|error| password_work_failure(&error))?;
        let prepared = Prepared {
            postgres,
            otp_secret: Zeroizing::new(otp.as_bytes().to_vec()),
            password_work,
        };
        state.replace(Some(prepared.clone()));
        let active = self.active.clone();
        active.replace(Some(Rc::new(Active {
            prepared,
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
            SecretsInvocationError::Domain(_) => failure("Phone Auth secret was rejected"),
            SecretsInvocationError::Runtime(e) => e,
        })
}

async fn reserve_otp_challenge(
    postgres: &OwnedPostgres,
    reservation: &OtpReservation<'_>,
) -> Result<OtpReservationOutcome, RuntimeFailure> {
    let mut transaction = postgres.pool().begin().await.map_err(db)?;
    let phone_key = format!("lenso-auth-phone-otp-phone:{}", reservation.phone);
    advisory_lock(&mut transaction, &phone_key).await?;
    let source_key = reservation.client_ip.unwrap_or("<missing>");
    let source_key = format!("lenso-auth-phone-otp-source:{source_key}");
    advisory_lock(&mut transaction, &source_key).await?;
    let starts: i64 = lenso_postgres_kit::sqlx::query_scalar(
        "SELECT count(*) FROM phone_otp_challenges WHERE client_ip IS NOT DISTINCT FROM $1 AND created_at >= $2",
    )
    .bind(reservation.client_ip)
    .bind(reservation.now - reservation.start_window)
    .fetch_one(&mut *transaction)
    .await
    .map_err(db)?;
    if starts >= reservation.max_starts {
        transaction.commit().await.map_err(db)?;
        return Ok(OtpReservationOutcome::RateLimited);
    }
    let resend: Option<OffsetDateTime> = lenso_postgres_kit::sqlx::query_scalar(
        "SELECT resend_after FROM phone_otp_challenges WHERE phone=$1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(reservation.phone)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(db)?;
    if resend.is_some_and(|value| value > reservation.now) {
        transaction.commit().await.map_err(db)?;
        return Ok(OtpReservationOutcome::ResendTooSoon);
    }
    lenso_postgres_kit::sqlx::query("INSERT INTO phone_otp_challenges(challenge_id,phone,purpose,code_digest,client_ip,expires_at,resend_after)VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(reservation.challenge_id)
        .bind(reservation.phone)
        .bind(reservation.purpose)
        .bind(reservation.code_digest)
        .bind(reservation.client_ip)
        .bind(reservation.expires_at)
        .bind(reservation.resend_after)
        .execute(&mut *transaction)
        .await
        .map_err(db)?;
    transaction.commit().await.map_err(db)?;
    Ok(OtpReservationOutcome::Inserted)
}

async fn phone_failure_limit_reached(
    postgres: &OwnedPostgres,
    phone: &str,
    since: OffsetDateTime,
    max_failures: i64,
) -> Result<bool, RuntimeFailure> {
    prune_stale_phone_failures(postgres, since).await?;
    let mut transaction = postgres.pool().begin().await.map_err(db)?;
    lock_phone_failures(&mut transaction, phone).await?;
    prune_phone_failures(&mut transaction, phone, since).await?;
    let count: i64 = lenso_postgres_kit::sqlx::query_scalar(
        "SELECT count(*) FROM phone_login_failures WHERE phone=$1 AND failed_at >= $2",
    )
    .bind(phone)
    .bind(since)
    .fetch_one(&mut *transaction)
    .await
    .map_err(db)?;
    transaction.commit().await.map_err(db)?;
    Ok(count >= max_failures)
}

async fn record_phone_failure_if_allowed(
    postgres: &OwnedPostgres,
    phone: &str,
    since: OffsetDateTime,
    max_failures: i64,
) -> Result<FailureAdmission, RuntimeFailure> {
    let mut transaction = postgres.pool().begin().await.map_err(db)?;
    lock_phone_failures(&mut transaction, phone).await?;
    prune_phone_failures(&mut transaction, phone, since).await?;
    let inserted = lenso_postgres_kit::sqlx::query_scalar::<_, i32>(
        "INSERT INTO phone_login_failures(phone) SELECT $1 WHERE (SELECT count(*) FROM phone_login_failures WHERE phone=$1 AND failed_at >= $2) < $3 RETURNING 1",
    )
    .bind(phone)
    .bind(since)
    .bind(max_failures)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(db)?;
    transaction.commit().await.map_err(db)?;
    Ok(if inserted.is_some() {
        FailureAdmission::Recorded
    } else {
        FailureAdmission::RateLimited
    })
}

async fn clear_phone_failures(postgres: &OwnedPostgres, phone: &str) -> Result<(), RuntimeFailure> {
    let mut transaction = postgres.pool().begin().await.map_err(db)?;
    lock_phone_failures(&mut transaction, phone).await?;
    lenso_postgres_kit::sqlx::query("DELETE FROM phone_login_failures WHERE phone=$1")
        .bind(phone)
        .execute(&mut *transaction)
        .await
        .map_err(db)?;
    transaction.commit().await.map_err(db)?;
    Ok(())
}

#[cfg(test)]
async fn current_phone_failure_count(
    postgres: &OwnedPostgres,
    phone: &str,
    since: OffsetDateTime,
) -> Result<i64, RuntimeFailure> {
    lenso_postgres_kit::sqlx::query_scalar(
        "SELECT count(*) FROM phone_login_failures WHERE phone=$1 AND failed_at >= $2",
    )
    .bind(phone)
    .bind(since)
    .fetch_one(postgres.pool())
    .await
    .map_err(db)
}

async fn lock_phone_failures(
    transaction: &mut lenso_postgres_kit::sqlx::Transaction<'_, lenso_postgres_kit::sqlx::Postgres>,
    phone: &str,
) -> Result<(), RuntimeFailure> {
    let key = format!("lenso-auth-phone-password:{phone}");
    advisory_lock(transaction, &key).await
}

async fn prune_phone_failures(
    transaction: &mut lenso_postgres_kit::sqlx::Transaction<'_, lenso_postgres_kit::sqlx::Postgres>,
    phone: &str,
    since: OffsetDateTime,
) -> Result<(), RuntimeFailure> {
    lenso_postgres_kit::sqlx::query(
        "DELETE FROM phone_login_failures WHERE phone=$1 AND failed_at < $2",
    )
    .bind(phone)
    .bind(since)
    .execute(&mut **transaction)
    .await
    .map_err(db)?;
    Ok(())
}

async fn prune_stale_phone_failures(
    postgres: &OwnedPostgres,
    before: OffsetDateTime,
) -> Result<u64, RuntimeFailure> {
    let result = lenso_postgres_kit::sqlx::query(
        "WITH stale AS (SELECT ctid FROM phone_login_failures WHERE failed_at < $1 ORDER BY failed_at, ctid FOR UPDATE SKIP LOCKED LIMIT $2) DELETE FROM phone_login_failures AS failures USING stale WHERE failures.ctid = stale.ctid",
    )
    .bind(before)
    .bind(STALE_FAILURE_PRUNE_BATCH)
    .execute(postgres.pool())
    .await
    .map_err(db)?;
    Ok(result.rows_affected())
}

async fn advisory_lock(
    transaction: &mut lenso_postgres_kit::sqlx::Transaction<'_, lenso_postgres_kit::sqlx::Postgres>,
    key: &str,
) -> Result<(), RuntimeFailure> {
    lenso_postgres_kit::sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(key)
        .execute(&mut **transaction)
        .await
        .map_err(db)?;
    Ok(())
}
fn normalize_phone(v: &str) -> Option<String> {
    let mut out = String::new();
    for (c, i) in v.trim().chars().zip(0..) {
        if (c == '+' && i == 0) || c.is_ascii_digit() {
            out.push(c);
        } else if !matches!(c, ' ' | '-' | '(' | ')') {
            return None;
        }
    }
    let digits = out.trim_start_matches('+');
    ((8..=15).contains(&digits.len())).then(|| format!("+{digits}"))
}
fn mask_phone(v: &str) -> String {
    let d = v.trim_start_matches('+');
    let keep = d.len().min(4);
    format!("+{}{}", "*".repeat(d.len() - keep), &d[d.len() - keep..])
}
fn random_digits(n: usize) -> Result<String, RuntimeFailure> {
    let mut out = String::with_capacity(n);
    while out.len() < n {
        let mut b = [0u8; 1];
        getrandom::fill(&mut b).map_err(|_| failure("random source unavailable"))?;
        if b[0] < 250 {
            out.push(char::from(b'0' + b[0] % 10));
        }
    }
    Ok(out)
}
fn random_id(prefix: &str) -> Result<String, RuntimeFailure> {
    let mut b = [0u8; 18];
    getrandom::fill(&mut b).map_err(|_| failure("random source unavailable"))?;
    Ok(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(b)))
}
fn otp_digest(key: &[u8], id: &str, code: &str) -> Result<Vec<u8>, RuntimeFailure> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| failure("invalid OTP secret"))?;
    mac.update(id.as_bytes());
    mac.update(b":");
    mac.update(code.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}
fn otp_matches(key: &[u8], id: &str, code: &str, expected: &[u8]) -> Result<bool, RuntimeFailure> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| failure("invalid OTP secret"))?;
    mac.update(id.as_bytes());
    mac.update(b":");
    mac.update(code.as_bytes());
    Ok(mac.verify_slice(expected).is_ok())
}
fn valid_name(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 256
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}
fn valid_password(v: &str) -> bool {
    (8..=1024).contains(&v.len())
}
fn hash_password_sync(v: &str) -> Result<String, PhonePasswordError> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|_| PhonePasswordError::Random)?;
    let salt = SaltString::encode_b64(&b).map_err(|_| PhonePasswordError::Hash)?;
    Argon2::default()
        .hash_password(v.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| PhonePasswordError::Hash)
}
fn verify_password_sync(v: &str, h: &str) -> bool {
    PasswordHash::new(h).is_ok_and(|p| Argon2::default().verify_password(v.as_bytes(), &p).is_ok())
}
fn password_work_failure(error: &PasswordWorkError) -> RuntimeFailure {
    failure(&error.to_string())
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
    failure(&format!("Phone Auth storage operation failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_postgres(label: &str) -> (String, String, OwnedPostgres) {
        let database_url =
            std::env::var("LENSO_POSTGRES_TEST_URL").expect("LENSO_POSTGRES_TEST_URL is required");
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let schema = format!("phone_{label}_test_{}_{suffix}", std::process::id());
        PhoneOperator::setup(&database_url, &schema).await.unwrap();
        let postgres = OwnedPostgres::prepare(&database_url, schema_plan(schema.clone()).unwrap())
            .await
            .unwrap();
        (database_url, schema, postgres)
    }

    async fn cleanup_test_postgres(database_url: &str, schema: &str, postgres: OwnedPostgres) {
        use lenso_postgres_kit::sqlx::{AssertSqlSafe, Executor};

        postgres.pool().close().await;
        let cleanup_pool = lenso_postgres_kit::sqlx::PgPool::connect(database_url)
            .await
            .unwrap();
        cleanup_pool
            .execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
            .await
            .unwrap();
        cleanup_pool.close().await;
    }

    #[test]
    fn phone_normalization_is_canonical_and_rejects_invalid_input() {
        assert_eq!(
            normalize_phone("+86 138-0013-8000"),
            Some("+8613800138000".into())
        );
        assert_eq!(normalize_phone("13800138000"), Some("+13800138000".into()));
        assert_eq!(normalize_phone("+12.ext"), None);
        assert_eq!(normalize_phone("123"), None);
        assert_eq!(mask_phone("+8613800138000"), "+*********8000");
    }

    #[test]
    fn otp_digest_binds_code_to_challenge() {
        let key = [7_u8; 32];
        let first = otp_digest(&key, "otp_a", "123456").unwrap();
        assert_eq!(first, otp_digest(&key, "otp_a", "123456").unwrap());
        assert_ne!(first, otp_digest(&key, "otp_b", "123456").unwrap());
        assert_ne!(first, otp_digest(&key, "otp_a", "654321").unwrap());
        assert!(otp_matches(&key, "otp_a", "123456", &first).unwrap());
        assert!(!otp_matches(&key, "otp_a", "654321", &first).unwrap());
    }

    #[test]
    fn password_hash_round_trip_does_not_store_plaintext() {
        let hash = hash_password_sync("correct horse battery staple").unwrap();
        assert!(!hash.contains("correct horse battery staple"));
        assert!(verify_password_sync("correct horse battery staple", &hash));
        assert!(!verify_password_sync("wrong", &hash));
    }

    #[tokio::test]
    #[ignore = "requires LENSO_POSTGRES_TEST_URL"]
    async fn missing_ip_otp_starts_share_one_atomic_fallback_limit() {
        let (database_url, schema, postgres) = test_postgres("otp_limit").await;
        let now = OffsetDateTime::now_utc();
        let digest = [0_u8; 32];
        let reservation = |challenge_id, phone| OtpReservation {
            challenge_id,
            phone,
            purpose: "login",
            code_digest: &digest,
            client_ip: None,
            expires_at: now + Duration::minutes(5),
            resend_after: now,
            now,
            start_window: Duration::minutes(1),
            max_starts: 2,
        };
        let first = reservation("otp_concurrent_1", "+12025550101");
        let second = reservation("otp_concurrent_2", "+12025550102");
        let third = reservation("otp_concurrent_3", "+12025550103");
        let fourth = reservation("otp_concurrent_4", "+12025550104");
        let fifth = reservation("otp_concurrent_5", "+12025550105");

        let outcomes = tokio::join!(
            reserve_otp_challenge(&postgres, &first),
            reserve_otp_challenge(&postgres, &second),
            reserve_otp_challenge(&postgres, &third),
            reserve_otp_challenge(&postgres, &fourth),
            reserve_otp_challenge(&postgres, &fifth),
        );
        let inserted = [outcomes.0, outcomes.1, outcomes.2, outcomes.3, outcomes.4]
            .into_iter()
            .map(Result::unwrap)
            .filter(|outcome| *outcome == OtpReservationOutcome::Inserted)
            .count();
        assert_eq!(inserted, 2);

        cleanup_test_postgres(&database_url, &schema, postgres).await;
    }

    #[tokio::test]
    #[ignore = "requires LENSO_POSTGRES_TEST_URL"]
    async fn concurrent_phone_password_failures_admit_exact_limit() {
        let (database_url, schema, postgres) = test_postgres("password_limit").await;
        let since = OffsetDateTime::now_utc() - Duration::minutes(1);
        let phone = "+12025550123";

        let outcomes = tokio::join!(
            record_phone_failure_if_allowed(&postgres, phone, since, 2),
            record_phone_failure_if_allowed(&postgres, phone, since, 2),
            record_phone_failure_if_allowed(&postgres, phone, since, 2),
            record_phone_failure_if_allowed(&postgres, phone, since, 2),
            record_phone_failure_if_allowed(&postgres, phone, since, 2),
        );
        let recorded = [outcomes.0, outcomes.1, outcomes.2, outcomes.3, outcomes.4]
            .into_iter()
            .map(Result::unwrap)
            .filter(|outcome| *outcome == FailureAdmission::Recorded)
            .count();
        assert_eq!(recorded, 2);
        assert_eq!(
            current_phone_failure_count(&postgres, phone, since)
                .await
                .unwrap(),
            2
        );

        cleanup_test_postgres(&database_url, &schema, postgres).await;
    }

    #[tokio::test]
    #[ignore = "requires LENSO_POSTGRES_TEST_URL"]
    async fn stale_phone_failure_pruning_is_bounded_and_eventually_drains() {
        let (database_url, schema, postgres) = test_postgres("password_prune").await;
        let cutoff = OffsetDateTime::now_utc() - Duration::minutes(1);
        let stale_count = STALE_FAILURE_PRUNE_BATCH + 5;
        lenso_postgres_kit::sqlx::query("INSERT INTO phone_login_failures(phone,failed_at) SELECT '+1202555' || lpad(value::text, 4, '0'), $1 FROM generate_series(1,$2) AS value")
            .bind(cutoff - Duration::minutes(1))
            .bind(stale_count)
            .execute(postgres.pool())
            .await
            .unwrap();
        lenso_postgres_kit::sqlx::query("INSERT INTO phone_login_failures(phone,failed_at) VALUES('+12025559998',$1),('+12025559999',$1)")
            .bind(cutoff + Duration::seconds(1))
            .execute(postgres.pool())
            .await
            .unwrap();

        phone_failure_limit_reached(&postgres, "+12025550000", cutoff, 10)
            .await
            .unwrap();
        let remaining_stale: i64 = lenso_postgres_kit::sqlx::query_scalar(
            "SELECT count(*) FROM phone_login_failures WHERE failed_at < $1",
        )
        .bind(cutoff)
        .fetch_one(postgres.pool())
        .await
        .unwrap();
        let active: i64 = lenso_postgres_kit::sqlx::query_scalar(
            "SELECT count(*) FROM phone_login_failures WHERE failed_at >= $1",
        )
        .bind(cutoff)
        .fetch_one(postgres.pool())
        .await
        .unwrap();
        assert_eq!(remaining_stale, stale_count - STALE_FAILURE_PRUNE_BATCH);
        assert_eq!(active, 2);

        phone_failure_limit_reached(&postgres, "+12025550000", cutoff, 10)
            .await
            .unwrap();
        let remaining_stale: i64 = lenso_postgres_kit::sqlx::query_scalar(
            "SELECT count(*) FROM phone_login_failures WHERE failed_at < $1",
        )
        .bind(cutoff)
        .fetch_one(postgres.pool())
        .await
        .unwrap();
        let active: i64 = lenso_postgres_kit::sqlx::query_scalar(
            "SELECT count(*) FROM phone_login_failures WHERE failed_at >= $1",
        )
        .bind(cutoff)
        .fetch_one(postgres.pool())
        .await
        .unwrap();
        assert_eq!(remaining_stale, 0);
        assert_eq!(active, 2);

        cleanup_test_postgres(&database_url, &schema, postgres).await;
    }

    #[tokio::test]
    #[ignore = "requires LENSO_POSTGRES_TEST_URL"]
    async fn global_phone_prune_and_keyed_record_complete_without_deadlock() {
        let (database_url, schema, postgres) = test_postgres("password_prune_race").await;
        let cutoff = OffsetDateTime::now_utc() - Duration::minutes(1);
        let phone = "+12025550000";
        lenso_postgres_kit::sqlx::query(
            "INSERT INTO phone_login_failures(phone,failed_at) VALUES($1,$2)",
        )
        .bind(phone)
        .bind(cutoff - Duration::minutes(2))
        .execute(postgres.pool())
        .await
        .unwrap();
        lenso_postgres_kit::sqlx::query("INSERT INTO phone_login_failures(phone,failed_at) SELECT '+1202666' || lpad(value::text, 4, '0'), $1 FROM generate_series(1,$2) AS value")
            .bind(cutoff - Duration::minutes(1))
            .bind(STALE_FAILURE_PRUNE_BATCH)
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
                    prune_stale_phone_failures(&postgres, cutoff).await
                },
                async {
                    record_barrier.wait().await;
                    record_phone_failure_if_allowed(&postgres, phone, cutoff, 2).await
                },
            )
        })
        .await
        .expect("global prune and keyed record must not deadlock");
        assert_eq!(pruned.unwrap(), STALE_FAILURE_PRUNE_BATCH as u64);
        assert_eq!(admission.unwrap(), FailureAdmission::Recorded);
        assert_eq!(
            current_phone_failure_count(&postgres, phone, cutoff)
                .await
                .unwrap(),
            1
        );

        cleanup_test_postgres(&database_url, &schema, postgres).await;
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

//! Plugin-owned identity directory and opaque session credentials.

mod delegation;
#[cfg(feature = "postgres")]
mod operator;
#[cfg(feature = "postgres")]
mod schema;
mod storage;

use std::{cell::RefCell, fmt, rc::Rc, time::Duration as StdDuration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use lenso::{ActivateContext, DeactivateContext, Lifecycle, Port, provides};
use lenso_auth_sdk::{ActorAssertionIssuer, Validity, absent_response, authenticated_response};
use lenso_capability_account_admin as account_admin;
use lenso_capability_account_admin::{
    AccountAdminListSessions, AccountAdminListSubjects, AccountAdminSetSubjectStatus,
    ListSessionsError, ListSessionsRequest, ListSessionsResponse, ListSessionsResponseSessionsItem,
    ListSubjectsError, ListSubjectsRequest, ListSubjectsResponse, ListSubjectsResponseSubjectsItem,
    ListSubjectsResponseSubjectsItemStatus, SetSubjectStatusError, SetSubjectStatusRequest,
    SetSubjectStatusRequestStatus, SetSubjectStatusResponse,
};
use lenso_capability_auth as auth;
use lenso_capability_auth::{Auth, AuthRequest, AuthenticateError};
use lenso_capability_auth_delegation as auth_delegation;
use lenso_capability_credential_issuer as credential_issuer;
use lenso_capability_credential_issuer::{
    CredentialIssuerIssue, CredentialIssuerRevoke, CredentialIssuerRevokeCredential, IssueError,
    IssueRequest, IssueResponse, RevokeCredentialError, RevokeCredentialRequest,
    RevokeCredentialResponse, RevokeError, RevokeRequest, RevokeResponse,
};
use lenso_capability_identity_directory as directory;
use lenso_capability_identity_directory::{
    DirectoryEnsureIdentity, DirectoryReadStatus, EnsureIdentityError, EnsureIdentityRequest,
    EnsureIdentityResponse, ReadStatusError, ReadStatusRequest, ReadStatusResponse,
    ReadStatusResponseStatus,
};
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsClient, SecretsInvocationError};
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
#[cfg(feature = "postgres")]
use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize};

use thiserror::Error;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

#[cfg(feature = "postgres")]
use crate::schema::schema_plan;

#[cfg(feature = "postgres")]
pub use operator::{AccountAuthOperator, AccountOperatorError};

const DEPENDENCY_TIMEOUT: StdDuration = StdDuration::from_secs(10);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, lenso::PluginConfig)]
#[serde(deny_unknown_fields)]
pub struct AccountAuthConfig {
    schema: String,
    issuer: String,
    assertion_public_key: String,
    #[serde(default)]
    #[lenso(default = "")]
    database_url_secret: String,
    #[serde(default)]
    #[lenso(default = "")]
    d1_binding: String,
    assertion_signing_key_secret: String,
    token_pepper_secret: String,
    assertion_ttl_seconds: u64,
    #[serde(default)]
    #[lenso(default = [])]
    admin_callers: Vec<String>,
    #[serde(default)]
    #[lenso(default = [])]
    delegation_callers: Vec<String>,
}

impl AccountAuthConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        schema: impl Into<String>,
        issuer: impl Into<String>,
        assertion_public_key: impl Into<String>,
        database_url_secret: impl Into<String>,
        assertion_signing_key_secret: impl Into<String>,
        token_pepper_secret: impl Into<String>,
        assertion_ttl_seconds: u64,
    ) -> Result<Self, AccountConfigError> {
        let value = Self {
            schema: schema.into(),
            issuer: issuer.into(),
            assertion_public_key: assertion_public_key.into(),
            database_url_secret: database_url_secret.into(),
            d1_binding: String::new(),
            assertion_signing_key_secret: assertion_signing_key_secret.into(),
            token_pepper_secret: token_pepper_secret.into(),
            assertion_ttl_seconds,
            admin_callers: Vec::new(),
            delegation_callers: Vec::new(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn with_admin_callers(mut self, callers: Vec<String>) -> Result<Self, AccountConfigError> {
        self.admin_callers = callers;
        self.validate()?;
        Ok(self)
    }

    pub fn with_delegation_callers(
        mut self,
        callers: Vec<String>,
    ) -> Result<Self, AccountConfigError> {
        self.delegation_callers = callers;
        self.validate()?;
        Ok(self)
    }

    /// Select an explicit D1 binding for the Workers implementation.
    pub fn with_d1_binding(
        mut self,
        binding: impl Into<String>,
    ) -> Result<Self, AccountConfigError> {
        self.database_url_secret.clear();
        self.d1_binding = binding.into();
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> Result<(), AccountConfigError> {
        if self.schema.is_empty()
            || !self
                .schema
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(AccountConfigError::InvalidSchema);
        }
        #[cfg(feature = "postgres")]
        schema_plan(self.schema.clone()).map_err(|_| AccountConfigError::InvalidSchema)?;
        if !valid_name(&self.issuer) {
            return Err(AccountConfigError::InvalidIssuer);
        }
        lenso_auth_sdk::ActorAssertionVerifier::from_public_key_base64(
            self.issuer.clone(),
            &self.assertion_public_key,
        )
        .map_err(|_| AccountConfigError::InvalidPublicKey)?;
        if self.assertion_ttl_seconds == 0 || self.assertion_ttl_seconds > 3600 {
            return Err(AccountConfigError::InvalidTtl);
        }
        let references = [
            &self.database_url_secret,
            &self.assertion_signing_key_secret,
            &self.token_pepper_secret,
        ];
        if !self.d1_binding.is_empty()
            && (!valid_name(&self.d1_binding) || !self.database_url_secret.is_empty())
        {
            return Err(AccountConfigError::InvalidSecretReference);
        }
        for (index, reference) in references.into_iter().enumerate() {
            if reference.is_empty() && !self.d1_binding.is_empty() && index == 0 {
                continue;
            }
            if !valid_secret_reference(reference) {
                return Err(AccountConfigError::InvalidSecretReference);
            }
        }
        if self.database_url_secret == self.assertion_signing_key_secret
            || self.database_url_secret == self.token_pepper_secret
            || self.assertion_signing_key_secret == self.token_pepper_secret
        {
            return Err(AccountConfigError::DuplicateSecretReference);
        }
        if self.admin_callers.iter().any(|value| !valid_caller(value)) {
            return Err(AccountConfigError::InvalidAdminCaller);
        }
        if self
            .delegation_callers
            .iter()
            .any(|value| !valid_caller(value))
        {
            return Err(AccountConfigError::InvalidDelegationCaller);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AccountConfigError {
    #[error("invalid owned PostgreSQL schema")]
    InvalidSchema,
    #[error("invalid assertion issuer")]
    InvalidIssuer,
    #[error("invalid assertion public key")]
    InvalidPublicKey,
    #[error("invalid secret reference")]
    InvalidSecretReference,
    #[error("database, signing key, and token pepper require distinct secret references")]
    DuplicateSecretReference,
    #[error("assertion TTL must be between 1 and 3600 seconds")]
    InvalidTtl,
    #[error("invalid Account Admin caller instance")]
    InvalidAdminCaller,
    #[error("invalid delegation caller instance")]
    InvalidDelegationCaller,
}

pub fn assertion_public_key(signing_secret: impl AsRef<[u8]>) -> String {
    ActorAssertionIssuer::new("key-derivation", signing_secret).public_key_base64()
}

fn validate_config(config: &AccountAuthConfig) -> Result<(), RuntimeFailure> {
    config
        .validate()
        .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: error.to_string(),
        })
}

#[lenso::plugin(
    lifecycle,
    validate = validate_config
)]
#[derive(Clone)]
struct AccountAuthPlugin {
    #[config]
    config: AccountAuthConfig,
    secrets: Port<secrets::SecretsClient>,
    state: Rc<RefCell<Option<PreparedAccount>>>,
    #[cfg_attr(not(feature = "workers"), allow(dead_code))]
    d1: EventStorageBinding,
}

#[derive(Clone)]
struct PreparedAccount {
    store: storage::AccountStore,
    issuer: ActorAssertionIssuer,
    pepper: Zeroizing<Vec<u8>>,
    assertion_ttl: Duration,
}
impl fmt::Debug for PreparedAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedAccount")
            .field("storage", &self.store)
            .finish_non_exhaustive()
    }
}

#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for AccountAuthPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountAuthPlugin")
            .field("prepared", &self.state.borrow().is_some())
            .field("admin_caller_count", &self.config.admin_callers.len())
            .finish()
    }
}

#[provides(
    auth::Auth,
    directory::Directory,
    credential_issuer::CredentialIssuer,
    account_admin::AccountAdmin,
    auth_delegation::Delegation
)]
impl AccountAuthPlugin {}

impl AccountAuthPlugin {
    fn prepared(&self) -> Result<PreparedAccount, RuntimeFailure> {
        self.state
            .borrow()
            .clone()
            .ok_or(RuntimeFailure::PluginFailure {
                detail: "Account Auth is not prepared".to_owned(),
            })
    }

    fn admin_authorized(&self, context: &InvocationContext) -> bool {
        context.caller_instance().is_some_and(|caller| {
            self.config
                .admin_callers
                .iter()
                .any(|allowed| allowed == caller)
        })
    }
}

impl AccountAuthPlugin {
    fn ensure_identity(
        &self,
        _context: InvocationContext,
        request: EnsureIdentityRequest,
    ) -> NativeRequestFuture<DirectoryEnsureIdentity> {
        let prepared = self.prepared();
        Box::pin(async move {
            let prepared = prepared?;
            if !valid_name(&request.provider)
                || request.external_subject.trim().is_empty()
                || request.external_subject.len() > 512
            {
                return Ok(Err(EnsureIdentityError::InvalidIdentity));
            }
            let subject = random_id("usr_").map_err(runtime)?;
            let (subject, status, created) = storage::ensure_identity(
                &prepared.store,
                &request.provider,
                &request.external_subject,
                &subject,
            )
            .await
            .map_err(runtime)?;
            if status == "disabled" {
                return Ok(Err(EnsureIdentityError::Disabled));
            }
            Ok(Ok(EnsureIdentityResponse { subject, created }))
        })
    }

    fn read_status(
        &self,
        _context: InvocationContext,
        request: ReadStatusRequest,
    ) -> NativeRequestFuture<DirectoryReadStatus> {
        let prepared = self.prepared();
        Box::pin(async move {
            let prepared = prepared?;
            if !valid_name(&request.subject) {
                return Ok(Err(ReadStatusError::InvalidSubject));
            }
            let Some(status) = storage::subject_status(&prepared.store, &request.subject)
                .await
                .map_err(runtime)?
            else {
                return Ok(Err(ReadStatusError::NotFound));
            };
            let status = if status == "disabled" {
                ReadStatusResponseStatus::Disabled
            } else {
                ReadStatusResponseStatus::Active
            };
            Ok(Ok(ReadStatusResponse {
                subject: request.subject,
                status,
            }))
        })
    }
}

impl AccountAuthPlugin {
    fn issue(
        &self,
        _context: InvocationContext,
        request: IssueRequest,
    ) -> NativeRequestFuture<CredentialIssuerIssue> {
        let prepared = self.prepared();
        Box::pin(async move {
            let prepared = prepared?;
            if !valid_name(&request.subject) {
                return Ok(Err(IssueError::InvalidSubject));
            }
            if !valid_name(&request.actor_kind)
                || !valid_name(&request.assurance)
                || request.audience.is_empty()
                || request.audience.len() > 64
                || request.audience.iter().any(|v| !valid_audience(v))
                || serde_json::to_vec(&request.claims).map_or(true, |value| value.len() > 16_384)
            {
                return Ok(Err(IssueError::InvalidAuthority));
            }
            let expires_at =
                OffsetDateTime::parse(&request.expires_at, &Rfc3339).map_err(|_| {
                    RuntimeFailure::ProtocolViolation {
                        capability: lenso_capability_credential_issuer::CAPABILITY_ID,
                    }
                })?;
            if expires_at <= OffsetDateTime::now_utc() {
                return Ok(Err(IssueError::Expired));
            }
            let token = random_token().map_err(runtime)?;
            let digest = storage::token_digest(&prepared.pepper, &token).map_err(runtime)?;
            let session_id = random_id("ses_").map_err(runtime)?;
            let session = storage::NewSession {
                session_id: session_id.clone(),
                digest,
                subject: request.subject,
                actor_kind: request.actor_kind,
                assurance: request.assurance,
                audience: request.audience,
                claims: request.claims,
                expires_at,
            };
            match storage::issue_session(&prepared.store, &session)
                .await
                .map_err(runtime)?
            {
                storage::IssueSessionOutcome::Inserted => {}
                storage::IssueSessionOutcome::Disabled => return Ok(Err(IssueError::Disabled)),
                storage::IssueSessionOutcome::InvalidSubject => {
                    return Ok(Err(IssueError::InvalidSubject));
                }
            }
            Ok(Ok(IssueResponse {
                credential: token,
                expires_at: request.expires_at,
                session_id,
            }))
        })
    }

    fn revoke(
        &self,
        _context: InvocationContext,
        request: RevokeRequest,
    ) -> NativeRequestFuture<CredentialIssuerRevoke> {
        let prepared = self.prepared();
        Box::pin(async move {
            let prepared = prepared?;
            if !valid_name(&request.session_id) {
                return Ok(Err(RevokeError::InvalidSession));
            }
            match storage::revoke_session(&prepared.store, &request.session_id)
                .await
                .map_err(runtime)?
            {
                Some(changed) => Ok(Ok(RevokeResponse { changed })),
                None => Ok(Err(RevokeError::NotFound)),
            }
        })
    }

    fn revoke_credential(
        &self,
        _context: InvocationContext,
        request: RevokeCredentialRequest,
    ) -> NativeRequestFuture<CredentialIssuerRevokeCredential> {
        let prepared = self.prepared();
        Box::pin(async move {
            let prepared = prepared?;
            if request.scheme != "session" {
                return Ok(Err(RevokeCredentialError::Unsupported));
            }
            if !valid_session_token(&request.credential) {
                return Ok(Err(RevokeCredentialError::InvalidCredential));
            }
            let digest =
                storage::token_digest(&prepared.pepper, &request.credential).map_err(runtime)?;
            match storage::revoke_credential(&prepared.store, &digest)
                .await
                .map_err(runtime)?
            {
                Some(changed) => Ok(Ok(RevokeCredentialResponse { changed })),
                None => Ok(Err(RevokeCredentialError::NotFound)),
            }
        })
    }
}

impl AccountAuthPlugin {
    #[allow(clippy::needless_pass_by_value)]
    fn list_subjects(
        &self,
        context: InvocationContext,
        request: ListSubjectsRequest,
    ) -> NativeRequestFuture<AccountAdminListSubjects> {
        let prepared = self.prepared();
        let authorized = self.admin_authorized(&context);
        Box::pin(async move {
            if !authorized {
                return Ok(Err(ListSubjectsError::Forbidden));
            }
            let prepared = prepared?;
            if !(1..=200).contains(&request.limit)
                || request
                    .cursor
                    .as_ref()
                    .is_some_and(|value| !valid_name(value))
            {
                return Ok(Err(ListSubjectsError::InvalidPage));
            }
            let subjects = storage::list_subjects(&prepared.store, &request).await?;
            let next_cursor = (subjects.len()
                == usize::try_from(request.limit).expect("positive limit"))
            .then(|| {
                subjects
                    .last()
                    .expect("non-empty full page")
                    .subject
                    .clone()
            });
            Ok(Ok(ListSubjectsResponse {
                subjects,
                next_cursor,
            }))
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    fn set_subject_status(
        &self,
        context: InvocationContext,
        request: SetSubjectStatusRequest,
    ) -> NativeRequestFuture<AccountAdminSetSubjectStatus> {
        let prepared = self.prepared();
        let authorized = self.admin_authorized(&context);
        Box::pin(async move {
            if !authorized {
                return Ok(Err(SetSubjectStatusError::Forbidden));
            }
            let prepared = prepared?;
            if !valid_name(&request.subject) {
                return Ok(Err(SetSubjectStatusError::InvalidSubject));
            }
            let disabled_until = request
                .disabled_until
                .as_deref()
                .map(|value| OffsetDateTime::parse(value, &Rfc3339))
                .transpose()
                .map_err(|_| RuntimeFailure::ProtocolViolation {
                    capability: lenso_capability_account_admin::CAPABILITY_ID,
                })?;
            if request
                .reason
                .as_ref()
                .is_some_and(|value| value.trim().is_empty() || value.len() > 512)
            {
                return Ok(Err(SetSubjectStatusError::InvalidStatus));
            }
            let (status, reason, until) = match request.status {
                SetSubjectStatusRequestStatus::Active => ("active", None, None),
                SetSubjectStatusRequestStatus::Disabled => {
                    ("disabled", request.reason, disabled_until)
                }
            };
            match storage::set_subject_status(
                &prepared.store,
                &request.subject,
                status,
                reason,
                until,
            )
            .await?
            {
                None => Ok(Err(SetSubjectStatusError::NotFound)),
                Some(changed) => Ok(Ok(SetSubjectStatusResponse { changed })),
            }
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    fn list_sessions(
        &self,
        context: InvocationContext,
        request: ListSessionsRequest,
    ) -> NativeRequestFuture<AccountAdminListSessions> {
        let prepared = self.prepared();
        let authorized = self.admin_authorized(&context);
        Box::pin(async move {
            if !authorized {
                return Ok(Err(ListSessionsError::Forbidden));
            }
            let prepared = prepared?;
            if !(1..=200).contains(&request.limit)
                || request
                    .cursor
                    .as_ref()
                    .is_some_and(|value| !valid_name(value))
            {
                return Ok(Err(ListSessionsError::InvalidPage));
            }
            if request
                .subject
                .as_ref()
                .is_some_and(|value| !valid_name(value))
            {
                return Ok(Err(ListSessionsError::InvalidSubject));
            }
            let sessions = storage::list_sessions(&prepared.store, &request).await?;
            let next_cursor = (sessions.len()
                == usize::try_from(request.limit).expect("positive limit"))
            .then(|| {
                sessions
                    .last()
                    .expect("non-empty full page")
                    .session_id
                    .clone()
            });
            Ok(Ok(ListSessionsResponse {
                sessions,
                next_cursor,
            }))
        })
    }
}

impl AccountAuthPlugin {
    fn authenticate(
        &self,
        _context: InvocationContext,
        request: AuthRequest,
    ) -> NativeRequestFuture<Auth> {
        let prepared = self.prepared();
        Box::pin(async move {
            let prepared = prepared?;
            let Some(credential) = request.credential else {
                return Ok(Ok(absent_response()));
            };
            if credential.scheme != "session" {
                return Ok(Err(AuthenticateError::Unsupported));
            }
            if !valid_session_token(&credential.value) {
                return Ok(Err(AuthenticateError::Invalid));
            }
            let digest =
                storage::token_digest(&prepared.pepper, &credential.value).map_err(runtime)?;
            let Some(session) = storage::load_session(&prepared.store, &digest)
                .await
                .map_err(runtime)?
            else {
                return Ok(Err(AuthenticateError::Invalid));
            };
            if session.status == "disabled" || session.revoked {
                return Ok(Err(AuthenticateError::Revoked));
            }
            let now = OffsetDateTime::now_utc();
            if session.expires_at <= now {
                return Ok(Err(AuthenticateError::Expired));
            }
            let validity = Validity::new(
                now,
                std::cmp::min(session.expires_at, now + prepared.assertion_ttl),
            )
            .map_err(|_| RuntimeFailure::PluginFailure {
                detail: "invalid session validity".to_owned(),
            })?;
            let assertion = prepared.issuer.issue(
                session.subject,
                session.actor_kind,
                session.assurance,
                session.audience,
                validity,
                session.claims,
            );
            Ok(Ok(authenticated_response(&assertion)))
        })
    }
}

impl Lifecycle for AccountAuthPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let config = self.config.clone();
        let state = self.state.clone();
        let dependencies = context.dependencies().clone();
        let cancellation = context.cancellation();
        let signing = resolve(
            &self.secrets,
            &dependencies,
            cancellation.clone(),
            &config.assertion_signing_key_secret,
        )
        .await?;
        let pepper = resolve(
            &self.secrets,
            &dependencies,
            cancellation,
            &config.token_pepper_secret,
        )
        .await?;
        if signing.len() < 32 || pepper.len() < 32 {
            return Err(RuntimeFailure::PluginFailure {
                detail: "signing key and token pepper must contain at least 32 bytes".to_owned(),
            });
        }
        let issuer = ActorAssertionIssuer::new(&config.issuer, signing.as_bytes());
        if issuer.public_key_base64() != config.assertion_public_key {
            return Err(RuntimeFailure::PluginFailure {
                detail: "signing key does not match public key".to_owned(),
            });
        }
        let store = if config.d1_binding.is_empty() {
            #[cfg(feature = "postgres")]
            {
                let database_url = resolve(
                    &self.secrets,
                    &dependencies,
                    context.cancellation(),
                    &config.database_url_secret,
                )
                .await?;
                let postgres = OwnedPostgres::prepare(
                    &database_url,
                    schema_plan(config.schema).map_err(runtime)?,
                )
                .await
                .map_err(runtime)?;
                storage::AccountStore::Postgres(postgres)
            }
            #[cfg(not(feature = "postgres"))]
            {
                return Err(runtime("Account PostgreSQL implementation is not enabled"));
            }
        } else {
            let binding_name = &config.d1_binding;
            #[cfg(feature = "workers")]
            {
                let binding = self
                    .d1
                    .as_ref()
                    .filter(|b| b.name() == binding_name)
                    .ok_or_else(|| runtime("configured Account D1 binding is unavailable"))?
                    .clone();
                migration::verify(&binding)
                    .await
                    .map_err(|_| runtime("Account D1 migration verification failed"))?;
                storage::AccountStore::D1(binding)
            }
            #[cfg(not(feature = "workers"))]
            {
                let _ = binding_name;
                return Err(runtime("Account D1 implementation is not enabled"));
            }
        };
        state.replace(Some(PreparedAccount {
            store,
            issuer,
            pepper: Zeroizing::new(pepper.as_bytes().to_vec()),
            assertion_ttl: Duration::seconds(
                i64::try_from(config.assertion_ttl_seconds).expect("validated"),
            ),
        }));
        Ok(())
    }

    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        let prepared = self.state.borrow_mut().take();
        if let Some(prepared) = prepared {
            prepared.store.close().await;
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
enum AccountError {
    #[error("invalid secret material")]
    InvalidSecretMaterial,
    #[cfg(feature = "postgres")]
    #[error("PostgreSQL operation `{operation}` failed")]
    Database {
        operation: &'static str,
        #[source]
        source: sqlx::Error,
    },
    #[cfg(feature = "workers")]
    #[error("Auth storage operation failed")]
    Storage,
    #[error("random source unavailable")]
    Random,
}
fn runtime(error: impl fmt::Display) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: error.to_string(),
    }
}

fn random_id(prefix: &str) -> Result<String, AccountError> {
    let mut bytes = [0_u8; 18];
    getrandom::fill(&mut bytes).map_err(|_| AccountError::Random)?;
    Ok(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes)))
}
fn random_token() -> Result<String, AccountError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| AccountError::Random)?;
    Ok(format!("lenso_st_{}", URL_SAFE_NO_PAD.encode(bytes)))
}
fn format_time(value: OffsetDateTime) -> Result<String, RuntimeFailure> {
    value
        .format(&Rfc3339)
        .map_err(|error| RuntimeFailure::PluginFailure {
            detail: error.to_string(),
        })
}
fn valid_caller(value: &str) -> bool {
    value.split_once('/').map_or_else(
        || valid_name(value),
        |(plugin, instance)| valid_name(plugin) && valid_name(instance),
    )
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

fn valid_audience(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'@')
        })
}

fn valid_secret_reference(reference: &str) -> bool {
    !reference.is_empty()
        && reference.len() <= 256
        && !reference.starts_with('/')
        && !reference.ends_with('/')
        && !reference.contains("//")
        && reference
            .split('/')
            .all(|segment| segment != "." && segment != "..")
        && reference
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
}

fn valid_session_token(value: &str) -> bool {
    value.strip_prefix("lenso_st_").is_some_and(|encoded| {
        encoded.len() == 43
            && encoded
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    })
}

async fn resolve(
    secrets: &SecretsClient,
    dependencies: &lenso_kernel::PluginDependencies,
    cancellation: lenso_kernel::CancellationToken,
    reference: &str,
) -> Result<Zeroizing<String>, RuntimeFailure> {
    let context = dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation)?;
    secrets
        .resolve_with_context(
            context,
            ResolveRequest {
                reference: reference.to_owned(),
            },
        )
        .await
        .map(|value| Zeroizing::new(value.value))
        .map_err(|error| match error {
            SecretsInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                detail: format!("secret `{reference}` was rejected"),
            },
            SecretsInvocationError::Runtime(error) => error,
        })
}

#[cfg(feature = "workers")]
pub mod migration;
#[cfg(feature = "workers")]
pub mod workers;

/// Build the selected Auth implementation with a request-owned D1 binding.
/// The caller must create a fresh registry/factory for each Workers event.
#[cfg(feature = "workers")]
pub fn workers_factory(
    binding_name: impl Into<Rc<str>>,
    batch: js_sys::Function,
) -> impl lenso_native_adapter::NativePluginFactory {
    let binding = workers::D1Binding::new(binding_name, batch);
    lenso_native_adapter::ConfiguredPluginFactory::<AccountAuthPlugin, _>::new(move |value| {
        if value.config.d1_binding != binding.name() {
            return Err(RuntimeFailure::InvalidResolvedPlan {
                detail: "Auth factory requires its exact configured D1 binding".to_owned(),
            });
        }
        value.d1 = Some(binding.clone());
        Ok(())
    })
}

#[cfg(feature = "workers")]
type EventStorageBinding = Option<workers::D1Binding>;
#[cfg(not(feature = "workers"))]
type EventStorageBinding = ();

#[cfg(all(test, feature = "postgres"))]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn caller_configuration_accepts_normal_plugin_root_keys_only() {
        assert!(valid_caller("proof.caller/caller"));
        assert!(valid_caller("legacy-caller"));
        for invalid in [
            "/caller",
            "plugin/",
            "plugin/instance/extra",
            "plugin/../caller",
        ] {
            assert!(!valid_caller(invalid));
        }
    }

    pub(super) async fn test_postgres(label: &str) -> (String, String, OwnedPostgres) {
        let database_url =
            std::env::var("LENSO_POSTGRES_TEST_URL").expect("LENSO_POSTGRES_TEST_URL is required");
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let schema = format!("auth_{label}_test_{}_{suffix}", std::process::id());
        AccountAuthOperator::setup(&database_url, &schema)
            .await
            .unwrap();
        let postgres = OwnedPostgres::prepare(&database_url, schema_plan(schema.clone()).unwrap())
            .await
            .unwrap();
        (database_url, schema, postgres)
    }

    pub(super) async fn cleanup_test_postgres(
        database_url: &str,
        schema: &str,
        postgres: OwnedPostgres,
    ) {
        use sqlx::{AssertSqlSafe, Executor};

        postgres.pool().close().await;
        let cleanup_pool = sqlx::PgPool::connect(database_url).await.unwrap();
        cleanup_pool
            .execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
            .await
            .unwrap();
        cleanup_pool.close().await;
    }

    pub(super) fn test_session(
        session_id: &str,
        digest: &[u8],
        subject: &str,
    ) -> storage::NewSession {
        storage::NewSession {
            session_id: session_id.to_owned(),
            digest: digest.to_vec(),
            subject: subject.to_owned(),
            actor_kind: "user".to_owned(),
            assurance: "test".to_owned(),
            audience: vec!["test.app@1".to_owned()],
            claims: BTreeMap::new(),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
        }
    }

    #[test]
    fn session_secrets_are_random_and_redaction_safe() {
        let first = random_token().unwrap();
        let second = random_token().unwrap();
        assert!(first.starts_with("lenso_st_"));
        assert_ne!(first, second);
    }

    #[test]
    fn configuration_rejects_unbounded_assertion_lifetime() {
        let secret = "a sufficiently long signing secret value";
        let result = AccountAuthConfig::new(
            "auth_account",
            "auth.account",
            assertion_public_key(secret),
            "auth/database",
            "auth/signing",
            "auth/pepper",
            3_601,
        );
        assert_eq!(result.unwrap_err(), AccountConfigError::InvalidTtl);
    }

    #[test]
    fn credential_issuer_accepts_versioned_capability_audience() {
        assert!(valid_audience("lenso.http.endpoint@1:handle"));
    }

    #[tokio::test]
    #[ignore = "requires LENSO_POSTGRES_TEST_URL"]
    async fn credential_digest_revocation_is_atomic_and_idempotent() {
        let (database_url, schema, postgres) = test_postgres("revoke").await;
        let subject = "usr_revoke_test";
        storage::postgres::ensure_identity(
            &postgres,
            "test-provider",
            "external-revoke-test",
            subject,
        )
        .await
        .unwrap();
        let pepper = b"test-only-pepper";
        let token = "lenso_st_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let digest = storage::token_digest(pepper, token).unwrap();
        let session = test_session("ses_revoke_test", &digest, subject);
        assert_eq!(
            storage::postgres::issue_session(&postgres, &session)
                .await
                .unwrap(),
            storage::IssueSessionOutcome::Inserted
        );

        assert_eq!(
            storage::postgres::revoke_credential(&postgres, &digest)
                .await
                .unwrap(),
            Some(true)
        );
        assert_eq!(
            storage::postgres::revoke_credential(&postgres, &digest)
                .await
                .unwrap(),
            Some(false)
        );
        let unknown = storage::token_digest(
            pepper,
            "lenso_st_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        )
        .unwrap();
        assert_eq!(
            storage::postgres::revoke_credential(&postgres, &unknown)
                .await
                .unwrap(),
            None
        );

        cleanup_test_postgres(&database_url, &schema, postgres).await;
    }

    #[tokio::test]
    #[ignore = "requires LENSO_POSTGRES_TEST_URL"]
    async fn expired_temporary_disable_allows_usable_session() {
        let (database_url, schema, postgres) = test_postgres("expired_disable").await;
        let subject = "usr_expired_disable";
        storage::postgres::ensure_identity(&postgres, "test-provider", "expired-disable", subject)
            .await
            .unwrap();
        sqlx::query("UPDATE identity_subjects SET status='disabled', disabled_until=transaction_timestamp() - interval '1 second' WHERE subject_id=$1")
            .bind(subject)
            .execute(postgres.pool())
            .await
            .unwrap();
        let digest = storage::token_digest(b"test-only-pepper", "expired-disable-token").unwrap();
        let session = test_session("ses_expired_disable", &digest, subject);

        assert_eq!(
            storage::postgres::issue_session(&postgres, &session)
                .await
                .unwrap(),
            storage::IssueSessionOutcome::Inserted
        );
        assert_eq!(
            storage::postgres::load_session(&postgres, &digest)
                .await
                .unwrap()
                .unwrap()
                .status,
            "active"
        );

        cleanup_test_postgres(&database_url, &schema, postgres).await;
    }

    #[tokio::test]
    #[ignore = "requires LENSO_POSTGRES_TEST_URL"]
    async fn disable_serializes_with_concurrent_session_issue() {
        let (database_url, schema, postgres) = test_postgres("issue_disable").await;
        let subject = "usr_issue_disable";
        storage::postgres::ensure_identity(&postgres, "test-provider", "issue-disable", subject)
            .await
            .unwrap();
        let mut disable = postgres.pool().begin().await.unwrap();
        sqlx::query("UPDATE identity_subjects SET status='disabled' WHERE subject_id=$1")
            .bind(subject)
            .execute(&mut *disable)
            .await
            .unwrap();
        sqlx::query("UPDATE auth_sessions SET revoked_at=transaction_timestamp() WHERE subject_id=$1 AND revoked_at IS NULL")
            .bind(subject)
            .execute(&mut *disable)
            .await
            .unwrap();
        let digest = storage::token_digest(b"test-only-pepper", "concurrent-token").unwrap();
        let session = test_session("ses_concurrent", &digest, subject);

        let (issue, commit) = tokio::join!(
            storage::postgres::issue_session(&postgres, &session),
            disable.commit()
        );
        commit.unwrap();
        assert_eq!(issue.unwrap(), storage::IssueSessionOutcome::Disabled);
        let session_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM auth_sessions WHERE subject_id=$1")
                .bind(subject)
                .fetch_one(postgres.pool())
                .await
                .unwrap();
        assert_eq!(session_count, 0);

        cleanup_test_postgres(&database_url, &schema, postgres).await;
    }

    #[tokio::test]
    #[ignore = "requires LENSO_POSTGRES_TEST_URL"]
    async fn reactivated_subject_can_receive_new_session() {
        let (database_url, schema, postgres) = test_postgres("reactivate").await;
        let subject = "usr_reactivate";
        storage::postgres::ensure_identity(&postgres, "test-provider", "reactivate", subject)
            .await
            .unwrap();
        sqlx::query("UPDATE identity_subjects SET status='disabled' WHERE subject_id=$1")
            .bind(subject)
            .execute(postgres.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE identity_subjects SET status='active', disabled_reason=NULL, disabled_until=NULL WHERE subject_id=$1")
            .bind(subject)
            .execute(postgres.pool())
            .await
            .unwrap();
        let digest = storage::token_digest(b"test-only-pepper", "reactivated-token").unwrap();
        let session = test_session("ses_reactivated", &digest, subject);

        assert_eq!(
            storage::postgres::issue_session(&postgres, &session)
                .await
                .unwrap(),
            storage::IssueSessionOutcome::Inserted
        );

        cleanup_test_postgres(&database_url, &schema, postgres).await;
    }
}

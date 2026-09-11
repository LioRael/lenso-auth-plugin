//! Plugin-owned identity directory and opaque session credentials.

mod delegation;
mod operator;
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
use lenso_postgres_kit::OwnedPostgres;
use lenso_postgres_kit::sqlx::Row;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

use crate::schema::schema_plan;

pub use operator::{AccountAuthOperator, AccountOperatorError};

const DEPENDENCY_TIMEOUT: StdDuration = StdDuration::from_secs(10);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountAuthConfig {
    schema: String,
    issuer: String,
    assertion_public_key: String,
    database_url_secret: String,
    assertion_signing_key_secret: String,
    token_pepper_secret: String,
    assertion_ttl_seconds: u64,
    #[serde(default)]
    admin_callers: Vec<String>,
    #[serde(default)]
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

    fn validate(&self) -> Result<(), AccountConfigError> {
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
        for reference in references {
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
        if self.admin_callers.iter().any(|value| !valid_name(value)) {
            return Err(AccountConfigError::InvalidAdminCaller);
        }
        if self
            .delegation_callers
            .iter()
            .any(|value| !valid_name(value))
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
    configuration_schema = "configuration.schema.json",
    validate = validate_config
)]
#[derive(Clone)]
struct AccountAuthPlugin {
    #[config]
    config: AccountAuthConfig,
    secrets: Port<secrets::SecretsClient>,
    state: Rc<RefCell<Option<PreparedAccount>>>,
}

#[derive(Clone)]
struct PreparedAccount {
    postgres: OwnedPostgres,
    issuer: ActorAssertionIssuer,
    pepper: Zeroizing<Vec<u8>>,
    assertion_ttl: Duration,
}
impl fmt::Debug for PreparedAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedAccount")
            .field("schema", &self.postgres.schema())
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
                &prepared.postgres,
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
            let Some(status) = storage::subject_status(&prepared.postgres, &request.subject)
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
            match storage::issue_session(&prepared.postgres, &session)
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
            match storage::revoke_session(&prepared.postgres, &request.session_id)
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
            match storage::revoke_credential(&prepared.postgres, &digest)
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
            let rows = lenso_postgres_kit::sqlx::query("SELECT subject_id, CASE WHEN status='disabled' AND (disabled_until IS NULL OR disabled_until > transaction_timestamp()) THEN 'disabled' ELSE 'active' END AS effective_status, disabled_reason, disabled_until, created_at FROM identity_subjects WHERE ($1::text IS NULL OR subject_id > $1) ORDER BY subject_id LIMIT $2")
                .bind(&request.cursor).bind(request.limit).fetch_all(prepared.postgres.pool()).await.map_err(|error| runtime(AccountError::Database { operation: "list subjects", source: error }))?;
            let mut subjects = Vec::with_capacity(rows.len());
            for row in rows {
                let created_at: OffsetDateTime = row.try_get("created_at").map_err(|error| {
                    runtime(AccountError::Database {
                        operation: "decode subject creation",
                        source: error,
                    })
                })?;
                let disabled_until: Option<OffsetDateTime> =
                    row.try_get("disabled_until").map_err(|error| {
                        runtime(AccountError::Database {
                            operation: "decode subject disable expiry",
                            source: error,
                        })
                    })?;
                let status: String = row.try_get("effective_status").map_err(|error| {
                    runtime(AccountError::Database {
                        operation: "decode subject status",
                        source: error,
                    })
                })?;
                subjects.push(ListSubjectsResponseSubjectsItem {
                    subject: row.try_get("subject_id").map_err(|error| {
                        runtime(AccountError::Database {
                            operation: "decode subject",
                            source: error,
                        })
                    })?,
                    status: if status == "disabled" {
                        ListSubjectsResponseSubjectsItemStatus::Disabled
                    } else {
                        ListSubjectsResponseSubjectsItemStatus::Active
                    },
                    disabled_reason: row.try_get("disabled_reason").map_err(|error| {
                        runtime(AccountError::Database {
                            operation: "decode subject disable reason",
                            source: error,
                        })
                    })?,
                    disabled_until: disabled_until.map(format_time).transpose()?,
                    created_at: format_time(created_at)?,
                });
            }
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
            let mut transaction = prepared.postgres.pool().begin().await.map_err(|source| {
                runtime(AccountError::Database {
                    operation: "begin subject status",
                    source,
                })
            })?;
            let result = lenso_postgres_kit::sqlx::query("UPDATE identity_subjects SET status=$2,disabled_reason=$3,disabled_until=$4 WHERE subject_id=$1 AND (status,disabled_reason,disabled_until) IS DISTINCT FROM ($2,$3,$4)").bind(&request.subject).bind(status).bind(reason).bind(until).execute(&mut *transaction).await.map_err(|source| runtime(AccountError::Database { operation: "set subject status", source }))?;
            let exists: bool = lenso_postgres_kit::sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM identity_subjects WHERE subject_id=$1)",
            )
            .bind(&request.subject)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|source| {
                runtime(AccountError::Database {
                    operation: "check subject",
                    source,
                })
            })?;
            if status == "disabled" {
                lenso_postgres_kit::sqlx::query("UPDATE auth_sessions SET revoked_at=transaction_timestamp() WHERE subject_id=$1 AND revoked_at IS NULL").bind(&request.subject).execute(&mut *transaction).await.map_err(|source| runtime(AccountError::Database { operation: "revoke disabled subject sessions", source }))?;
            }
            transaction.commit().await.map_err(|source| {
                runtime(AccountError::Database {
                    operation: "commit subject status",
                    source,
                })
            })?;
            if !exists {
                return Ok(Err(SetSubjectStatusError::NotFound));
            }
            Ok(Ok(SetSubjectStatusResponse {
                changed: result.rows_affected() == 1,
            }))
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
            let rows = lenso_postgres_kit::sqlx::query("SELECT session_id,subject_id,actor_kind,assurance,expires_at,revoked_at IS NOT NULL AS revoked,created_at FROM auth_sessions WHERE ($1::text IS NULL OR subject_id=$1) AND ($2::text IS NULL OR session_id>$2) ORDER BY session_id LIMIT $3").bind(&request.subject).bind(&request.cursor).bind(request.limit).fetch_all(prepared.postgres.pool()).await.map_err(|source| runtime(AccountError::Database { operation: "list sessions", source }))?;
            let mut sessions = Vec::with_capacity(rows.len());
            for row in rows {
                let expires_at: OffsetDateTime = row.try_get("expires_at").map_err(|source| {
                    runtime(AccountError::Database {
                        operation: "decode session expiry",
                        source,
                    })
                })?;
                let created_at: OffsetDateTime = row.try_get("created_at").map_err(|source| {
                    runtime(AccountError::Database {
                        operation: "decode session creation",
                        source,
                    })
                })?;
                sessions.push(ListSessionsResponseSessionsItem {
                    session_id: row.try_get("session_id").map_err(|source| {
                        runtime(AccountError::Database {
                            operation: "decode session id",
                            source,
                        })
                    })?,
                    subject: row.try_get("subject_id").map_err(|source| {
                        runtime(AccountError::Database {
                            operation: "decode session subject",
                            source,
                        })
                    })?,
                    actor_kind: row.try_get("actor_kind").map_err(|source| {
                        runtime(AccountError::Database {
                            operation: "decode actor kind",
                            source,
                        })
                    })?,
                    assurance: row.try_get("assurance").map_err(|source| {
                        runtime(AccountError::Database {
                            operation: "decode assurance",
                            source,
                        })
                    })?,
                    expires_at: format_time(expires_at)?,
                    revoked: row.try_get("revoked").map_err(|source| {
                        runtime(AccountError::Database {
                            operation: "decode revocation",
                            source,
                        })
                    })?,
                    created_at: format_time(created_at)?,
                });
            }
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
            let Some(session) = storage::load_session(&prepared.postgres, &digest)
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
        let database_url = resolve(
            &self.secrets,
            &dependencies,
            cancellation.clone(),
            &config.database_url_secret,
        )
        .await?;
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
        let postgres = OwnedPostgres::prepare(
            &database_url,
            schema_plan(config.schema).map_err(|error| RuntimeFailure::InvalidResolvedPlan {
                detail: error.to_string(),
            })?,
        )
        .await
        .map_err(|error| RuntimeFailure::PluginFailure {
            detail: error.to_string(),
        })?;
        state.replace(Some(PreparedAccount {
            postgres,
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
            prepared.postgres.pool().close().await;
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
enum AccountError {
    #[error("invalid secret material")]
    InvalidSecretMaterial,
    #[error("PostgreSQL operation `{operation}` failed")]
    Database {
        operation: &'static str,
        #[source]
        source: lenso_postgres_kit::sqlx::Error,
    },
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

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
        storage::ensure_identity(&postgres, "test-provider", "external-revoke-test", subject)
            .await
            .unwrap();
        let pepper = b"test-only-pepper";
        let token = "lenso_st_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let digest = storage::token_digest(pepper, token).unwrap();
        let session = test_session("ses_revoke_test", &digest, subject);
        assert_eq!(
            storage::issue_session(&postgres, &session).await.unwrap(),
            storage::IssueSessionOutcome::Inserted
        );

        assert_eq!(
            storage::revoke_credential(&postgres, &digest)
                .await
                .unwrap(),
            Some(true)
        );
        assert_eq!(
            storage::revoke_credential(&postgres, &digest)
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
            storage::revoke_credential(&postgres, &unknown)
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
        storage::ensure_identity(&postgres, "test-provider", "expired-disable", subject)
            .await
            .unwrap();
        lenso_postgres_kit::sqlx::query("UPDATE identity_subjects SET status='disabled', disabled_until=transaction_timestamp() - interval '1 second' WHERE subject_id=$1")
            .bind(subject)
            .execute(postgres.pool())
            .await
            .unwrap();
        let digest = storage::token_digest(b"test-only-pepper", "expired-disable-token").unwrap();
        let session = test_session("ses_expired_disable", &digest, subject);

        assert_eq!(
            storage::issue_session(&postgres, &session).await.unwrap(),
            storage::IssueSessionOutcome::Inserted
        );
        assert_eq!(
            storage::load_session(&postgres, &digest)
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
        storage::ensure_identity(&postgres, "test-provider", "issue-disable", subject)
            .await
            .unwrap();
        let mut disable = postgres.pool().begin().await.unwrap();
        lenso_postgres_kit::sqlx::query(
            "UPDATE identity_subjects SET status='disabled' WHERE subject_id=$1",
        )
        .bind(subject)
        .execute(&mut *disable)
        .await
        .unwrap();
        lenso_postgres_kit::sqlx::query("UPDATE auth_sessions SET revoked_at=transaction_timestamp() WHERE subject_id=$1 AND revoked_at IS NULL")
            .bind(subject)
            .execute(&mut *disable)
            .await
            .unwrap();
        let digest = storage::token_digest(b"test-only-pepper", "concurrent-token").unwrap();
        let session = test_session("ses_concurrent", &digest, subject);

        let (issue, commit) = tokio::join!(
            storage::issue_session(&postgres, &session),
            disable.commit()
        );
        commit.unwrap();
        assert_eq!(issue.unwrap(), storage::IssueSessionOutcome::Disabled);
        let session_count: i64 = lenso_postgres_kit::sqlx::query_scalar(
            "SELECT count(*) FROM auth_sessions WHERE subject_id=$1",
        )
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
        storage::ensure_identity(&postgres, "test-provider", "reactivate", subject)
            .await
            .unwrap();
        lenso_postgres_kit::sqlx::query(
            "UPDATE identity_subjects SET status='disabled' WHERE subject_id=$1",
        )
        .bind(subject)
        .execute(postgres.pool())
        .await
        .unwrap();
        lenso_postgres_kit::sqlx::query("UPDATE identity_subjects SET status='active', disabled_reason=NULL, disabled_until=NULL WHERE subject_id=$1")
            .bind(subject)
            .execute(postgres.pool())
            .await
            .unwrap();
        let digest = storage::token_digest(b"test-only-pepper", "reactivated-token").unwrap();
        let session = test_session("ses_reactivated", &digest, subject);

        assert_eq!(
            storage::issue_session(&postgres, &session).await.unwrap(),
            storage::IssueSessionOutcome::Inserted
        );

        cleanup_test_postgres(&database_url, &schema, postgres).await;
    }
}

//! Account-owned, protocol-neutral managed session continuation.
//!
//! Policy is fixed by the provider Instance, never chosen by the client.
use lenso_contract_authoring as lenso;

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct IssueManagedRequest {
    pub subject: String,
    pub actor_kind: String,
    pub assurance: String,
    pub audience: Vec<String>,
    pub claims: std::collections::BTreeMap<String, serde_json::Value>,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct SessionResponse {
    pub session_id: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub credential: String,
    /// RFC3339 effective idle deadline, bounded by `absolute_expires_at`.
    pub expires_at: String,
    /// RFC3339 immutable upper bound established at managed issuance.
    pub absolute_expires_at: String,
    /// RFC3339 earliest time the current credential may be renewed.
    pub renew_after: String,
}

#[derive(lenso::DomainError)]
pub enum IssueManagedError {
    InvalidSubject,
    Disabled,
    InvalidAuthority,
    PermissionDenied,
    NotEnabled,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct RenewRequest {
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub credential: String,
}

#[derive(lenso::DomainError)]
pub enum RenewError {
    InvalidCredential,
    StaleCredential,
    Expired,
    Revoked,
    TooEarly,
    PermissionDenied,
    NotEnabled,
    Unsupported,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ReadManagedRequest {
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub credential: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ReadManagedResponse {
    pub session_id: String,
    pub expires_at: String,
    pub absolute_expires_at: String,
    pub renew_after: String,
}

#[derive(lenso::DomainError)]
pub enum ReadManagedError {
    InvalidCredential,
    StaleCredential,
    Expired,
    Revoked,
    PermissionDenied,
    NotEnabled,
    Unsupported,
}

#[lenso::capability(
    id = "lenso.auth.managed-session",
    major = 1,
    version = "1.0.0",
    portable = true,
    cross_lane_transfer = true
)]
pub trait ManagedSession {
    async fn issue_managed(
        &self,
        context: lenso::Ctx<'_>,
        request: IssueManagedRequest,
    ) -> Result<SessionResponse, IssueManagedError>;
    async fn renew(
        &self,
        context: lenso::Ctx<'_>,
        request: RenewRequest,
    ) -> Result<SessionResponse, RenewError>;
    async fn read_managed(
        &self,
        context: lenso::Ctx<'_>,
        request: ReadManagedRequest,
    ) -> Result<ReadManagedResponse, ReadManagedError>;
}

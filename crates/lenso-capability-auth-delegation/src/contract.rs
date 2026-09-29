//! Narrowed credentials derived from an authenticated root session.
use lenso_contract_authoring as lenso;

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct GrantRequest {
    #[schemars(length(min = 1, max = 512), extend("x-lenso-sensitive" = true))]
    pub parent_credential: String,
    #[schemars(length(min = 1, max = 64))]
    pub audience: Vec<String>,
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct GrantResponse {
    pub session_id: String,
    pub subject: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub credential: String,
    pub audience: Vec<String>,
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
}

#[derive(lenso::DomainError)]
pub enum GrantError {
    PermissionDenied,
    InvalidCredential,
    Expired,
    Revoked,
    InvalidScope,
    NestedDelegation,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ResourceScope {
    pub kind: String,
    pub id: String,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct GrantScopedRequest {
    #[schemars(length(min = 1, max = 128))]
    pub idempotency_key: String,
    #[schemars(length(min = 1, max = 128))]
    pub task_id: String,
    #[schemars(length(min = 1, max = 128))]
    pub agent_session_id: String,
    pub delegate_caller: String,
    pub deployment: String,
    pub permissions: Vec<String>,
    pub resource_scopes: Vec<ResourceScope>,
    pub audience: Vec<String>,
    #[schemars(extend("format"="date-time"))]
    pub expires_at: String,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ScopedDelegationMetadata {
    pub session_id: String,
    pub subject: String,
    pub task_id: String,
    pub agent_session_id: String,
    pub delegate_caller: String,
    pub deployment: String,
    pub permissions: Vec<String>,
    pub resource_scopes: Vec<ResourceScope>,
    pub audience: Vec<String>,
    #[schemars(extend("format"="date-time"))]
    pub expires_at: String,
    pub active: bool,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct GrantScopedResponse {
    pub delegation: ScopedDelegationMetadata,
    #[schemars(extend("x-lenso-sensitive"=true))]
    pub credential: Option<String>,
    pub replayed: bool,
}
#[derive(lenso::DomainError)]
pub enum GrantScopedError {
    PermissionDenied,
    InvalidRequest,
    Conflict,
    UnsupportedProfile,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ScopedReceiptRequest {
    pub idempotency_key: String,
    pub task_id: String,
    pub agent_session_id: String,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ScopedReceiptResponse {
    pub found: bool,
    pub delegation: Option<ScopedDelegationMetadata>,
}
#[derive(lenso::DomainError)]
pub enum ScopedReceiptError {
    PermissionDenied,
    InvalidRequest,
    UnsupportedProfile,
}

#[lenso::capability(
    id = "lenso.auth.delegation",
    major = 1,
    version = "1.1.0",
    portable = true,
    cross_lane_transfer = false
)]
pub trait Delegation {
    async fn grant_scoped(
        &self,
        context: lenso::Ctx<'_>,
        request: GrantScopedRequest,
    ) -> Result<GrantScopedResponse, GrantScopedError>;
    async fn scoped_receipt(
        &self,
        context: lenso::Ctx<'_>,
        request: ScopedReceiptRequest,
    ) -> Result<ScopedReceiptResponse, ScopedReceiptError>;
    async fn grant(
        &self,
        context: lenso::Ctx<'_>,
        request: GrantRequest,
    ) -> Result<GrantResponse, GrantError>;
}

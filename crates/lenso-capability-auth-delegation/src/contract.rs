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

#[lenso::capability(
    id = "lenso.auth.delegation",
    major = 1,
    version = "1.0.0",
    portable = true,
    cross_lane_transfer = false
)]
pub trait Delegation {
    async fn grant(
        &self,
        context: lenso::Ctx<'_>,
        request: GrantRequest,
    ) -> Result<GrantResponse, GrantError>;
}

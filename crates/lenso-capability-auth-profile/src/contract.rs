//! Stale-allowed display projection, separate from current Auth authority.
use lenso_contract_authoring as lenso;
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ReadRequest {
    pub subject: String,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ReadResponse {
    pub found: bool,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub revision: Option<i64>,
    pub cached: bool,
}
#[derive(lenso::DomainError)]
pub enum ReadError {
    PermissionDenied,
    InvalidRequest,
    UnsupportedProfile,
}
#[lenso::capability(
    id = "lenso.auth.profile",
    major = 1,
    version = "1.0.0",
    portable = true,
    cross_lane_transfer = false
)]
pub trait Profile {
    async fn read(
        &self,
        context: lenso::Ctx<'_>,
        request: ReadRequest,
    ) -> Result<ReadResponse, ReadError>;
}

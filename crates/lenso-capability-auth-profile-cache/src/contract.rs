//! Display-only stale cache. No identity, session or authorization facts.
use lenso_contract_authoring as lenso;
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct GetRequest {
    pub namespace: String,
    pub subject: String,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct GetResponse {
    pub found: bool,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub revision: Option<i64>,
}
#[derive(lenso::DomainError)]
pub enum GetError {
    PermissionDenied,
    InvalidRequest,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PutRequest {
    pub namespace: String,
    pub subject: String,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub revision: i64,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PutResponse {
    pub stored: bool,
}
#[derive(lenso::DomainError)]
pub enum PutError {
    PermissionDenied,
    InvalidRequest,
}
#[lenso::capability(
    id = "lenso.auth.profile-cache",
    major = 1,
    version = "1.0.0",
    portable = true,
    cross_lane_transfer = false
)]
pub trait ProfileCache {
    async fn get(
        &self,
        context: lenso::Ctx<'_>,
        request: GetRequest,
    ) -> Result<GetResponse, GetError>;
    async fn put(
        &self,
        context: lenso::Ctx<'_>,
        request: PutRequest,
    ) -> Result<PutResponse, PutError>;
}

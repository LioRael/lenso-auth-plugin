use lenso_contract_authoring as lenso;
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
pub struct CredentialMetadata {
    pub credential_id: String,
    pub name: String,
    pub deployment: String,
    pub permissions: Vec<String>,
    pub resource_scopes: Vec<ResourceScope>,
    #[schemars(extend("format"="date-time"))]
    pub expires_at: String,
    pub active: bool,
    #[schemars(extend("format"="date-time"))]
    pub created_at: Option<String>,
    #[schemars(extend("format"="date-time"))]
    pub last_used_at: Option<String>,
    #[schemars(extend("format"="date-time"))]
    pub revoked_at: Option<String>,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct IssueRequest {
    #[schemars(length(min = 1, max = 128))]
    pub idempotency_key: String,
    #[schemars(length(min = 1, max = 128))]
    pub name: String,
    pub deployment: String,
    pub permissions: Vec<String>,
    pub resource_scopes: Vec<ResourceScope>,

    #[schemars(extend("format"="date-time"))]
    pub expires_at: String,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct IssueResponse {
    pub credential: CredentialMetadata,
    #[schemars(extend("x-lenso-sensitive"=true))]
    pub token: Option<String>,
    pub replayed: bool,
}
#[derive(lenso::DomainError)]
pub enum IssueError {
    PermissionDenied,
    InvalidRequest,
    Conflict,
    UnsupportedProfile,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ListRequest {
    pub deployment: String,
    #[schemars(range(min = 1, max = 100))]
    pub limit: u32,
    pub after_credential_id: Option<String>,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ListResponse {
    pub credentials: Vec<CredentialMetadata>,
}
#[derive(lenso::DomainError)]
pub enum ListError {
    PermissionDenied,
    InvalidRequest,
    UnsupportedProfile,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ReceiptRequest {
    pub deployment: String,
    #[schemars(length(min = 1, max = 128))]
    pub idempotency_key: String,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ReceiptResponse {
    pub found: bool,
    pub credential: Option<CredentialMetadata>,
}
#[derive(lenso::DomainError)]
pub enum ReceiptError {
    PermissionDenied,
    InvalidRequest,
    UnsupportedProfile,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct RevokeRequest {
    pub deployment: String,
    pub credential_id: String,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct RevokeResponse {
    pub revoked: bool,
}
#[derive(lenso::DomainError)]
pub enum RevokeError {
    PermissionDenied,
    InvalidRequest,
    NotFound,
    UnsupportedProfile,
}
#[lenso::capability(
    id = "lenso.auth.human-api-token",
    major = 1,
    version = "1.1.0",
    portable = true,
    cross_lane_transfer = false
)]
pub trait HumanApiToken {
    async fn issue(
        &self,
        context: lenso::Ctx<'_>,
        request: IssueRequest,
    ) -> Result<IssueResponse, IssueError>;
    async fn list(
        &self,
        context: lenso::Ctx<'_>,
        request: ListRequest,
    ) -> Result<ListResponse, ListError>;
    async fn receipt(
        &self,
        context: lenso::Ctx<'_>,
        request: ReceiptRequest,
    ) -> Result<ReceiptResponse, ReceiptError>;
    async fn revoke(
        &self,
        context: lenso::Ctx<'_>,
        request: RevokeRequest,
    ) -> Result<RevokeResponse, RevokeError>;
}

//! Authoritative current-state contract; raw credentials are never accepted.
use lenso_contract_authoring as lenso;

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct InspectRequest {
    #[schemars(length(min = 1, max = 256))]
    pub credential_id: String,
    #[schemars(length(min = 1, max = 256))]
    pub session_id: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct InspectResponse {
    pub credential_id: String,
    pub session_id: String,
    pub subject: String,
    pub actor_kind: String,
    pub assurance: String,
    pub audience: Vec<String>,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub claims: std::collections::BTreeMap<String, serde_json::Value>,
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
    pub active: bool,
}

#[derive(lenso::DomainError)]
pub enum InspectError {
    PermissionDenied,
    InvalidReference,
    NotFound,
}

#[lenso::capability(
    id = "lenso.auth.credential-state",
    major = 1,
    version = "1.0.0",
    portable = true,
    cross_lane_transfer = false
)]
pub trait CredentialState {
    async fn inspect(
        &self,
        context: lenso::Ctx<'_>,
        request: InspectRequest,
    ) -> Result<InspectResponse, InspectError>;
}

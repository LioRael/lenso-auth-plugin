use lenso_contract_authoring as lenso;
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct EmptyRequest {}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct Binding {
    pub source_issuer: String,
    pub deployment: String,
    pub scope_kind: String,
    pub scope_id: String,
    pub binding_id: String,
    pub source_subject: String,
    pub operator_subject: String,
    pub revision: String,
    pub active: bool,
    pub revoked: bool,
    pub revocation_pending: bool,
    pub revocation_audit_event_id: String,
    pub revoked_by: String,
    pub revoked_at: String,
    pub audit_event_id: String,
    pub policy_revision: String,
}
#[derive(lenso::DomainError)]
pub enum BindingError {
    Unauthenticated,
    PermissionDenied,
    NotEnabled,
    NotFound,
    NotActive,
    BootstrapExpired,
    BootstrapConsumed,
    InvalidRequest,
    AuditUnavailable,
    AccessUnavailable,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct RevokeBindingRequest {
    pub binding_id: String,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct SessionResponse {
    pub session_id: String,
    #[schemars(extend("x-lenso-sensitive"=true))]
    pub credential: String,
    pub expires_at: String,
}
#[lenso::capability(
    id = "lenso.auth.operator-session",
    major = 1,
    version = "1.0.0",
    portable = true,
    cross_lane_transfer = true
)]
pub trait OperatorSession {
    async fn recover_revocation(
        &self,
        context: lenso::Ctx<'_>,
        request: RevokeBindingRequest,
    ) -> Result<Binding, BindingError>;

    async fn bootstrap_binding(
        &self,
        context: lenso::Ctx<'_>,
        request: EmptyRequest,
    ) -> Result<Binding, BindingError>;
    async fn read_binding(
        &self,
        context: lenso::Ctx<'_>,
        request: EmptyRequest,
    ) -> Result<Binding, BindingError>;
    async fn exchange_session(
        &self,
        context: lenso::Ctx<'_>,
        request: EmptyRequest,
    ) -> Result<SessionResponse, BindingError>;
    async fn revoke_binding(
        &self,
        context: lenso::Ctx<'_>,
        request: RevokeBindingRequest,
    ) -> Result<Binding, BindingError>;
}

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
pub struct ReadBindingRequest {
    pub source_subject: String,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PrepareBootstrapRequest {
    pub source_subject: String,
    pub source_issuer: String,
    pub deployment: String,
    pub scope_kind: String,
    pub scope_id: String,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PrepareBootstrapResponse {
    pub binding: Binding,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub control_assertion: String,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ActivateBindingRequest {
    pub binding_id: String,
    pub revision: String,
    pub audit_event_id: String,
    pub policy_revision: String,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct RevokeBindingRequest {
    pub binding_id: String,
    pub actor_subject: String,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct CompleteRevocationRequest {
    pub binding_id: String,
    pub revision: String,
    pub audit_event_id: String,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct RecoveryRequest {
    pub binding_id: String,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrepareActivationRequestOperation {
    CreateRole,
    SetRolePermissions,
    AssignRole,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PrepareActivationRequest {
    pub binding_id: String,
    pub revision: String,
    pub operation: PrepareActivationRequestOperation,
    pub permissions: Vec<String>,
    pub source_assertion_expires_at: String,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PrepareActivationResponse {
    pub binding: Binding,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub control_assertion: String,
    pub audit_occurred_at: String,
    pub audit_idempotency_key: String,
    pub permissions: Vec<String>,
}
#[lenso::capability(
    id = "lenso.auth.operator-binding",
    major = 1,
    version = "1.1.0",
    portable = true,
    cross_lane_transfer = true
)]
pub trait OperatorBinding {
    async fn prepare_activation(
        &self,
        context: lenso::Ctx<'_>,
        request: PrepareActivationRequest,
    ) -> Result<PrepareActivationResponse, BindingError>;
    async fn prepare_recovery(
        &self,
        context: lenso::Ctx<'_>,
        request: RecoveryRequest,
    ) -> Result<PrepareBootstrapResponse, BindingError>;
    async fn complete_revocation(
        &self,
        context: lenso::Ctx<'_>,
        request: CompleteRevocationRequest,
    ) -> Result<Binding, BindingError>;

    async fn prepare_bootstrap(
        &self,
        context: lenso::Ctx<'_>,
        request: PrepareBootstrapRequest,
    ) -> Result<PrepareBootstrapResponse, BindingError>;
    async fn activate_binding(
        &self,
        context: lenso::Ctx<'_>,
        request: ActivateBindingRequest,
    ) -> Result<Binding, BindingError>;
    async fn read_binding(
        &self,
        context: lenso::Ctx<'_>,
        request: ReadBindingRequest,
    ) -> Result<Binding, BindingError>;
    async fn revoke_binding(
        &self,
        context: lenso::Ctx<'_>,
        request: RevokeBindingRequest,
    ) -> Result<Binding, BindingError>;
}

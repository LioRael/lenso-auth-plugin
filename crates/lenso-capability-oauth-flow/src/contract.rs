//! Authoritative source for this Auth Capability contract.

use lenso_contract_authoring as lenso;

#[derive(serde::Deserialize)]
pub struct Nullable<T>(Option<T>);

impl<T> Default for Nullable<T> {
    fn default() -> Self {
        Self(None)
    }
}

impl<T: lenso::JsonSchema> lenso::JsonSchema for Nullable<T> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        format!("Nullable_{}", T::schema_name()).into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        format!("Nullable<{}>", T::schema_id()).into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        <Option<T> as lenso::JsonSchema>::json_schema(generator)
    }
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct CreateRequest {
    pub provider: String,
    pub return_to: String,
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct CreateResponse {
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub state: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub code_verifier: String,
    pub code_challenge: String,
    #[serde(default)]
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub nonce: Nullable<String>,
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
}

#[derive(lenso::DomainError)]
#[allow(clippy::enum_variant_names)]
pub enum CreateError {
    InvalidProvider,
    InvalidReturnTo,
    InvalidExpiry,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ConsumeRequest {
    pub provider: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub state: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ConsumeResponse {
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub code_verifier: String,
    #[serde(default)]
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub nonce: Nullable<String>,
    pub return_to: String,
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
}

#[derive(lenso::DomainError)]
pub enum ConsumeError {
    InvalidState,
    Expired,
    ProviderMismatch,
    AlreadyConsumed,
    Revoked,
}

/// Cancels an unconsumed OAuth state before the authorization callback can
/// exchange it. The state value is sensitive for the same reason as consume.
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct RevokeRequest {
    pub provider: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub state: String,
}

/// Confirmation that the durable cancellation transition completed.
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct RevokeResponse {}

#[derive(lenso::DomainError)]
pub enum RevokeError {
    InvalidState,
    Expired,
    ProviderMismatch,
    AlreadyConsumed,
    AlreadyRevoked,
}

#[lenso::capability(
    id = "lenso.auth.oauth-flow",
    major = 1,
    version = "1.2.0",
    portable = true,
    cross_lane_transfer = true
)]
pub trait OauthFlow {
    async fn create(
        &self,
        context: lenso::Ctx<'_>,
        request: CreateRequest,
    ) -> Result<CreateResponse, CreateError>;
    async fn consume(
        &self,
        context: lenso::Ctx<'_>,
        request: ConsumeRequest,
    ) -> Result<ConsumeResponse, ConsumeError>;
    async fn revoke(
        &self,
        context: lenso::Ctx<'_>,
        request: RevokeRequest,
    ) -> Result<RevokeResponse, RevokeError>;
}

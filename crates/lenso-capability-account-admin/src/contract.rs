//! Authoritative source for this Auth Capability contract.

use lenso_contract_authoring as lenso;

#[derive(serde::Deserialize)]
pub struct Nullable<T>(Option<T>);

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
pub struct ListSubjectsRequest {
    #[schemars(range(min = 1, max = 200))]
    pub limit: i64,
    pub cursor: Nullable<String>,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListSubjectsResponseSubjectsItemStatus {
    Active,
    Disabled,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ListSubjectsResponseSubjectsItem {
    pub subject: String,
    pub status: ListSubjectsResponseSubjectsItemStatus,
    pub disabled_reason: Nullable<String>,
    #[schemars(extend("format" = "date-time"))]
    pub disabled_until: Nullable<String>,
    #[schemars(extend("format" = "date-time"))]
    pub created_at: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ListSubjectsResponse {
    pub subjects: Vec<ListSubjectsResponseSubjectsItem>,
    pub next_cursor: Nullable<String>,
}

#[derive(lenso::DomainError)]
pub enum ListSubjectsError {
    InvalidPage,
    Forbidden,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetSubjectStatusRequestStatus {
    Active,
    Disabled,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct SetSubjectStatusRequest {
    pub subject: String,
    pub status: SetSubjectStatusRequestStatus,
    pub reason: Nullable<String>,
    #[schemars(extend("format" = "date-time"))]
    pub disabled_until: Nullable<String>,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct SetSubjectStatusResponse {
    pub changed: bool,
}

#[derive(lenso::DomainError)]
pub enum SetSubjectStatusError {
    InvalidSubject,
    InvalidStatus,
    NotFound,
    Forbidden,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ListSessionsRequest {
    pub subject: Nullable<String>,
    #[schemars(range(min = 1, max = 200))]
    pub limit: i64,
    pub cursor: Nullable<String>,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ListSessionsResponseSessionsItem {
    pub session_id: String,
    pub subject: String,
    pub actor_kind: String,
    pub assurance: String,
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
    pub revoked: bool,
    #[schemars(extend("format" = "date-time"))]
    pub created_at: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ListSessionsResponse {
    pub sessions: Vec<ListSessionsResponseSessionsItem>,
    pub next_cursor: Nullable<String>,
}

#[derive(lenso::DomainError)]
pub enum ListSessionsError {
    InvalidPage,
    InvalidSubject,
    Forbidden,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ReadProfileRequest {
    pub subject: String,
}
#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ReadProfileResponse {
    pub found: bool,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub revision: Option<i64>,
    pub cached: bool,
}
#[derive(lenso::DomainError)]
pub enum ReadProfileError {
    Forbidden,
    InvalidSubject,
    UnsupportedProfile,
}

#[lenso::capability(
    id = "lenso.auth.account-admin",
    major = 1,
    version = "1.1.0",
    portable = true,
    cross_lane_transfer = true
)]
pub trait AccountAdmin {
    async fn read_profile(
        &self,
        context: lenso::Ctx<'_>,
        request: ReadProfileRequest,
    ) -> Result<ReadProfileResponse, ReadProfileError>;
    async fn list_subjects(
        &self,
        context: lenso::Ctx<'_>,
        request: ListSubjectsRequest,
    ) -> Result<ListSubjectsResponse, ListSubjectsError>;
    async fn set_subject_status(
        &self,
        context: lenso::Ctx<'_>,
        request: SetSubjectStatusRequest,
    ) -> Result<SetSubjectStatusResponse, SetSubjectStatusError>;
    async fn list_sessions(
        &self,
        context: lenso::Ctx<'_>,
        request: ListSessionsRequest,
    ) -> Result<ListSessionsResponse, ListSessionsError>;
}

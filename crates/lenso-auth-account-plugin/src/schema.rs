use lenso_postgres_kit::{Migration, PlanError, SchemaPlan, sql_migrations};

const MIGRATIONS: &[Migration] = sql_migrations![
    (
        1,
        "create-identities-and-sessions",
        "migrations/001_create_identities_and_sessions.sql",
    ),
    (
        2,
        "add-subject-disable-details",
        "migrations/002_add_subject_disable_details.sql",
    ),
    (
        3,
        "add-session-delegations",
        "migrations/003_add_session_delegations.sql"
    ),
];

pub(crate) fn schema_plan(schema: impl Into<std::sync::Arc<str>>) -> Result<SchemaPlan, PlanError> {
    SchemaPlan::new(schema, MIGRATIONS)
}

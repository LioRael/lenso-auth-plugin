use lenso_postgres_kit::{Migration, PlanError, SchemaPlan, sql_migrations};

const MIGRATIONS: &[Migration] = sql_migrations![
    (
        1,
        "create-phone-auth",
        "migrations/postgres/001_create_phone_auth.sql",
    ),
    (
        2,
        "index-stale-login-failures",
        "migrations/postgres/002_index_stale_login_failures.sql",
    ),
];

pub(crate) fn schema_plan(schema: impl Into<std::sync::Arc<str>>) -> Result<SchemaPlan, PlanError> {
    SchemaPlan::new(schema, MIGRATIONS)
}

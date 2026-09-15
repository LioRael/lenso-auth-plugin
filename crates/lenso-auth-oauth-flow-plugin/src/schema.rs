use lenso_postgres_kit::{Migration, PlanError, SchemaPlan, sql_migrations};

const MIGRATIONS: &[Migration] = sql_migrations![
    (
        1,
        "create-oauth-flows",
        "migrations/postgres/001_create_oauth_flows.sql",
    ),
    (
        2,
        "add-oidc-nonce",
        "migrations/postgres/002_add_oidc_nonce.sql",
    ),
];

pub(crate) fn schema_plan(schema: impl Into<std::sync::Arc<str>>) -> Result<SchemaPlan, PlanError> {
    SchemaPlan::new(schema, MIGRATIONS)
}

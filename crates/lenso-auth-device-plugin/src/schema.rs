use lenso_postgres_kit::{Migration, PlanError, SchemaPlan, sql_migrations};

const MIGRATIONS: &[Migration] = sql_migrations![
    (
        1,
        "create-auth-devices",
        "migrations/postgres/001_create_auth_devices.sql",
    ),
    (
        2,
        "enforce-one-primary-device",
        "migrations/postgres/002_enforce_one_primary_device.sql",
    ),
];

pub(crate) fn schema_plan(schema: impl Into<std::sync::Arc<str>>) -> Result<SchemaPlan, PlanError> {
    SchemaPlan::new(schema, MIGRATIONS)
}

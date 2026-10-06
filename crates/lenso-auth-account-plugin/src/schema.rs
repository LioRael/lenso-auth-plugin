use lenso_postgres_kit::{Migration, PlanError, SchemaPlan, sql_migrations};

const MIGRATIONS: &[Migration] = sql_migrations![
    (
        1,
        "create-identities-and-sessions",
        "migrations/postgres/001_create_identities_and_sessions.sql",
    ),
    (
        2,
        "add-subject-disable-details",
        "migrations/postgres/002_add_subject_disable_details.sql",
    ),
    (
        3,
        "add-session-delegations",
        "migrations/postgres/003_add_session_delegations.sql"
    ),
    (
        4,
        "add-scoped-delegation-receipts",
        "migrations/postgres/004_add_scoped_delegation_receipts.sql"
    ),
    (
        5,
        "add-display-profile",
        "migrations/postgres/005_add_display_profile.sql"
    ),
    (
        6,
        "add-managed-sessions",
        "migrations/postgres/006_add_managed_sessions.sql"
    ),
    (
        7,
        "operator-bindings",
        "migrations/postgres/007_operator_bindings.sql"
    ),
    (
        8,
        "operator-activation-intents",
        "migrations/postgres/008_operator_activation_intents.sql"
    ),
];

pub(crate) fn schema_plan(schema: impl Into<std::sync::Arc<str>>) -> Result<SchemaPlan, PlanError> {
    SchemaPlan::new(schema, &MIGRATIONS[..5])
}

pub(crate) fn managed_schema_plan(
    schema: impl Into<std::sync::Arc<str>>,
) -> Result<SchemaPlan, PlanError> {
    SchemaPlan::new(schema, &MIGRATIONS[..6])
}

pub(crate) fn operator_schema_plan(
    schema: impl Into<std::sync::Arc<str>>,
) -> Result<SchemaPlan, PlanError> {
    SchemaPlan::new(schema, MIGRATIONS)
}
fn previous_operator_schema_plan(
    schema: impl Into<std::sync::Arc<str>>,
) -> Result<SchemaPlan, PlanError> {
    SchemaPlan::new(schema, &MIGRATIONS[..7])
}
/// Read-only compatibility wrapper preserving existing callers.
pub(crate) async fn prepare(
    database_url: &str,
    schema: &str,
    managed_required: bool,
) -> Result<lenso_postgres_kit::OwnedPostgres, lenso_postgres_kit::PostgresKitError> {
    prepare_features(database_url, schema, managed_required, false).await
}
/// Read-only exact history verification, with independent opt-ins.
pub(crate) async fn prepare_features(
    database_url: &str,
    schema: &str,
    managed_required: bool,
    operator_required: bool,
) -> Result<lenso_postgres_kit::OwnedPostgres, lenso_postgres_kit::PostgresKitError> {
    use lenso_postgres_kit::{OwnedPostgres, PostgresKitError};
    match OwnedPostgres::prepare(database_url, operator_schema_plan(schema)?).await {
        Ok(pg) => Ok(pg),
        Err(PostgresKitError::UpgradeRequired {
            current: 5..=7,
            expected: 8,
            ..
        }) if !operator_required => {
            match OwnedPostgres::prepare(database_url, previous_operator_schema_plan(schema)?).await
            {
                Ok(pg) => Ok(pg),
                Err(PostgresKitError::UpgradeRequired {
                    current: 5 | 6,
                    expected: 7,
                    ..
                }) => {
                    match OwnedPostgres::prepare(database_url, managed_schema_plan(schema)?).await {
                        Ok(pg) => Ok(pg),
                        Err(PostgresKitError::UpgradeRequired {
                            current: 5,
                            expected: 6,
                            ..
                        }) if !managed_required => {
                            OwnedPostgres::prepare(database_url, schema_plan(schema)?).await
                        }
                        Err(e) => Err(e),
                    }
                }
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

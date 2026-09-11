use lenso_postgres_kit::{
    OwnedPostgres, PostgresKitError, SchemaOperator, SetupOutcome, UpgradeOutcome,
};
use thiserror::Error;

use crate::schema::schema_plan;

/// Explicit schema and subject administration for the Account Plugin.
#[derive(Clone, Debug)]
pub struct AccountAuthOperator {
    postgres: OwnedPostgres,
}

impl AccountAuthOperator {
    pub async fn setup(
        database_url: &str,
        schema: &str,
    ) -> Result<SetupOutcome, AccountOperatorError> {
        Ok(SchemaOperator::connect(database_url, schema_plan(schema)?)
            .await?
            .setup()
            .await?)
    }
    pub async fn upgrade(
        database_url: &str,
        schema: &str,
    ) -> Result<UpgradeOutcome, AccountOperatorError> {
        Ok(SchemaOperator::connect(database_url, schema_plan(schema)?)
            .await?
            .upgrade()
            .await?)
    }
    pub async fn connect(database_url: &str, schema: &str) -> Result<Self, AccountOperatorError> {
        Ok(Self {
            postgres: OwnedPostgres::prepare(database_url, schema_plan(schema)?).await?,
        })
    }
    /// Disables an identity and revokes all of its sessions in one transaction.
    pub async fn disable_subject(&self, subject: &str) -> Result<bool, AccountOperatorError> {
        let mut transaction = self
            .postgres
            .pool()
            .begin()
            .await
            .map_err(db("begin subject disable"))?;
        let result = lenso_postgres_kit::sqlx::query("UPDATE identity_subjects SET status = 'disabled' WHERE subject_id = $1 AND status <> 'disabled'").bind(subject).execute(&mut *transaction).await.map_err(db("disable subject"))?;
        lenso_postgres_kit::sqlx::query("UPDATE auth_sessions SET revoked_at = transaction_timestamp() WHERE subject_id = $1 AND revoked_at IS NULL").bind(subject).execute(&mut *transaction).await.map_err(db("revoke subject sessions"))?;
        transaction
            .commit()
            .await
            .map_err(db("commit subject disable"))?;
        Ok(result.rows_affected() == 1)
    }
}

#[derive(Debug, Error)]
pub enum AccountOperatorError {
    #[error(transparent)]
    Plan(#[from] lenso_postgres_kit::PlanError),
    #[error(transparent)]
    Postgres(#[from] PostgresKitError),
    #[error("PostgreSQL operation `{operation}` failed")]
    Database {
        operation: &'static str,
        #[source]
        source: lenso_postgres_kit::sqlx::Error,
    },
}
fn db(
    operation: &'static str,
) -> impl FnOnce(lenso_postgres_kit::sqlx::Error) -> AccountOperatorError {
    move |source| AccountOperatorError::Database { operation, source }
}

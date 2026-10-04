use lenso_postgres_kit::{
    OwnedPostgres, PostgresKitError, SchemaOperator, SetupOutcome, UpgradeOutcome,
};
use thiserror::Error;

use crate::schema::{managed_schema_plan, operator_schema_plan, schema_plan};

/// Explicit schema and subject administration for the Account Plugin.
#[derive(Clone, Debug)]
pub struct AccountAuthOperator {
    postgres: OwnedPostgres,
}

impl AccountAuthOperator {
    /// Explicit operator binding setup. Never invoked by runtime Ready.
    pub async fn setup_operator_bound(
        database_url: &str,
        schema: &str,
    ) -> Result<SetupOutcome, AccountOperatorError> {
        Ok(
            SchemaOperator::connect(database_url, operator_schema_plan(schema)?)
                .await?
                .setup()
                .await?,
        )
    }
    /// Explicit operator binding upgrade. Original SQL histories stay immutable.
    pub async fn upgrade_operator_bound(
        database_url: &str,
        schema: &str,
    ) -> Result<UpgradeOutcome, AccountOperatorError> {
        Ok(
            SchemaOperator::connect(database_url, operator_schema_plan(schema)?)
                .await?
                .upgrade()
                .await?,
        )
    }

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
    /// Explicit opt-in setup including managed-session tables.
    pub async fn setup_managed(
        database_url: &str,
        schema: &str,
    ) -> Result<SetupOutcome, AccountOperatorError> {
        Ok(
            SchemaOperator::connect(database_url, managed_schema_plan(schema)?)
                .await?
                .setup()
                .await?,
        )
    }
    /// Explicit opt-in upgrade including managed-session tables.
    pub async fn upgrade_managed(
        database_url: &str,
        schema: &str,
    ) -> Result<UpgradeOutcome, AccountOperatorError> {
        Ok(
            SchemaOperator::connect(database_url, managed_schema_plan(schema)?)
                .await?
                .upgrade()
                .await?,
        )
    }
    pub async fn connect(database_url: &str, schema: &str) -> Result<Self, AccountOperatorError> {
        Ok(Self {
            postgres: crate::schema::prepare(database_url, schema, false).await?,
        })
    }
    /// Updates display-only subject data using an explicit revision precondition.
    pub async fn update_display_profile(
        &self,
        subject: &str,
        expected_revision: i64,
        display_name: &str,
        avatar_url: Option<&str>,
    ) -> Result<Option<i64>, AccountOperatorError> {
        if !crate::valid_name(subject)
            || expected_revision < 0
            || !crate::profile::valid_profile(display_name, avatar_url)
        {
            return Err(AccountOperatorError::InvalidProfile);
        }
        sqlx::query_scalar("UPDATE identity_subjects SET display_name=$3,avatar_url=$4,profile_revision=profile_revision+1 WHERE subject_id=$1 AND profile_revision=$2 RETURNING profile_revision").bind(subject).bind(expected_revision).bind(display_name).bind(avatar_url).fetch_optional(self.postgres.pool()).await.map_err(db("update display profile"))
    }

    /// Narrows an existing session's stored ceiling without issuing another credential.
    pub async fn attenuate_session_ceiling(
        &self,
        session_id: &str,
        ceiling: &lenso_auth_sdk::credential::ManagementCredentialCeiling,
    ) -> Result<bool, AccountOperatorError> {
        use sqlx::Row;
        let mut tx = self
            .postgres
            .pool()
            .begin()
            .await
            .map_err(db("begin session attenuation"))?;
        let row = sqlx::query("SELECT claims FROM auth_sessions WHERE session_id=$1 FOR UPDATE")
            .bind(session_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db("lock session ceiling"))?;
        let Some(row) = row else {
            return Ok(false);
        };
        let mut claims: std::collections::BTreeMap<String, serde_json::Value> = row
            .try_get::<sqlx::types::Json<_>, _>("claims")
            .map_err(db("decode session ceiling"))?
            .0;
        let Ok(parent) =
            lenso_auth_sdk::credential::ManagementCredentialCeiling::from_claims(&claims)
        else {
            return Ok(false);
        };
        if !ceiling.is_attenuation_of(&parent) {
            return Ok(false);
        }
        claims.insert(
            lenso_auth_sdk::credential::MANAGEMENT_CEILING_CLAIM.into(),
            serde_json::json!(ceiling),
        );
        sqlx::query("UPDATE auth_sessions SET claims=$2 WHERE session_id=$1")
            .bind(session_id)
            .bind(sqlx::types::Json(&claims))
            .execute(&mut *tx)
            .await
            .map_err(db("attenuate session ceiling"))?;
        tx.commit()
            .await
            .map_err(db("commit session attenuation"))?;
        Ok(true)
    }
    /// Disables an identity and revokes all of its sessions in one transaction.
    pub async fn disable_subject(&self, subject: &str) -> Result<bool, AccountOperatorError> {
        let mut transaction = self
            .postgres
            .pool()
            .begin()
            .await
            .map_err(db("begin subject disable"))?;
        let result = sqlx::query("UPDATE identity_subjects SET status = 'disabled' WHERE subject_id = $1 AND status <> 'disabled'").bind(subject).execute(&mut *transaction).await.map_err(db("disable subject"))?;
        sqlx::query("UPDATE auth_sessions SET revoked_at = transaction_timestamp() WHERE subject_id = $1 AND revoked_at IS NULL").bind(subject).execute(&mut *transaction).await.map_err(db("revoke subject sessions"))?;
        transaction
            .commit()
            .await
            .map_err(db("commit subject disable"))?;
        Ok(result.rows_affected() == 1)
    }
}

#[derive(Debug, Error)]
pub enum AccountOperatorError {
    #[error("invalid display-only profile")]
    InvalidProfile,
    #[error(transparent)]
    Plan(#[from] lenso_postgres_kit::PlanError),
    #[error(transparent)]
    Postgres(#[from] PostgresKitError),
    #[error("PostgreSQL operation `{operation}` failed")]
    Database {
        operation: &'static str,
        #[source]
        source: sqlx::Error,
    },
}
fn db(operation: &'static str) -> impl FnOnce(sqlx::Error) -> AccountOperatorError {
    move |source| AccountOperatorError::Database { operation, source }
}

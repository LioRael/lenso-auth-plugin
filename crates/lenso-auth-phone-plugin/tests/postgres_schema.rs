use std::sync::atomic::{AtomicU64, Ordering};

use lenso_auth_phone_plugin::PhoneOperator;
use lenso_postgres_kit::sqlx::{AssertSqlSafe, Executor, PgPool};

static NEXT_SCHEMA: AtomicU64 = AtomicU64::new(0);

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires LENSO_POSTGRES_TEST_URL"]
async fn external_sql_schema_setup_and_upgrade() {
    let url = std::env::var("LENSO_POSTGRES_TEST_URL").unwrap();
    let schema = unique_schema("phone");
    let pool = PgPool::connect(&url).await.unwrap();
    PhoneOperator::setup(&url, &schema).await.unwrap();
    PhoneOperator::upgrade(&url, &schema).await.unwrap();
    assert!(table_exists(&pool, &schema, "phone_otp_challenges").await);
    cleanup(&pool, &schema).await;
}

fn unique_schema(label: &str) -> String {
    format!(
        "lenso_{label}_{}_{}",
        std::process::id(),
        NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed)
    )
}

async fn table_exists(pool: &PgPool, schema: &str, table: &str) -> bool {
    lenso_postgres_kit::sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(format!("{schema}.{table}"))
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn cleanup(pool: &PgPool, schema: &str) {
    pool.execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
        .await
        .unwrap();
}

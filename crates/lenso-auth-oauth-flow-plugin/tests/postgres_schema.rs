use std::sync::atomic::{AtomicU64, Ordering};

use lenso_auth_oauth_flow_plugin::OAuthFlowOperator;
use lenso_postgres_kit::sqlx::{AssertSqlSafe, Executor, PgPool};

static NEXT_SCHEMA: AtomicU64 = AtomicU64::new(0);

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires LENSO_POSTGRES_TEST_URL"]
async fn external_sql_schema_setup_and_upgrade() {
    let url = std::env::var("LENSO_POSTGRES_TEST_URL").unwrap();
    let schema = unique_schema("oauth");
    let pool = PgPool::connect(&url).await.unwrap();
    OAuthFlowOperator::setup(&url, &schema).await.unwrap();
    OAuthFlowOperator::upgrade(&url, &schema).await.unwrap();
    assert!(table_exists(&pool, &schema, "oauth_flows").await);
    assert!(column_exists(&pool, &schema, "oauth_flows", "oidc_nonce").await);
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

async fn column_exists(pool: &PgPool, schema: &str, table: &str, column: &str) -> bool {
    lenso_postgres_kit::sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2 AND column_name = $3)",
    )
    .bind(schema)
    .bind(table)
    .bind(column)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn cleanup(pool: &PgPool, schema: &str) {
    pool.execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
        .await
        .unwrap();
}

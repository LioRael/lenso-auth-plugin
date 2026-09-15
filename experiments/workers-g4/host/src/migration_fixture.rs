//! Test-only pending-upgrade and rollback proof for the actual D1 adapter.
use lenso_migration::Migration;
use lenso_migration_d1::{Error, Plan, SqlMigration};

const INITIAL: &str = "CREATE TABLE migration_fixture(id INTEGER PRIMARY KEY);";
const NEXT: &str = "ALTER TABLE migration_fixture ADD COLUMN label TEXT;";
const BAD: &str = "CREATE TABLE rollback_marker(id INTEGER);INSERT INTO missing_table VALUES(1);";
const COMMON: &[Migration] = &[
    Migration::new(1, "create-fixture", INITIAL),
    Migration::new(2, "add-label", NEXT),
    Migration::new(3, "failed-upgrade", BAD),
];
const SQL: &[SqlMigration] = &[
    SqlMigration {
        migration: COMMON[0],
        statement_ends: &[INITIAL.len()],
    },
    SqlMigration {
        migration: COMMON[1],
        statement_ends: &[NEXT.len()],
    },
    SqlMigration {
        migration: COMMON[2],
        statement_ends: &["CREATE TABLE rollback_marker(id INTEGER);".len(), BAD.len()],
    },
];

pub fn plan(version: usize) -> Result<Plan, Error> {
    Plan::new("proof.migration", &SQL[..version], &COMMON[..version], None)
}

use crate::{ConsumeError, OffsetDateTime, RevokeError, RuntimeFailure, failure};

#[cfg(any(test, feature = "simulator-test-support"))]
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

#[cfg(test)]
use std::cell::Cell;

#[derive(Clone, Debug)]
pub(crate) enum FlowStore {
    #[cfg(feature = "postgres")]
    Postgres(lenso_postgres_kit::OwnedPostgres),
    #[cfg(feature = "workers")]
    D1(crate::workers::D1Binding),
    /// A Host-injected PostgreSQL transport. The Auth Plugin only owns the
    /// OAuth persistence protocol; a Workers Host may implement this through
    /// Hyperdrive or another target-owned PostgreSQL transport.
    #[cfg(feature = "workers")]
    PostgresTransport(crate::postgres_transport::PostgresBinding),
    #[cfg(any(test, feature = "simulator-test-support"))]
    Simulated(SimulatedFlowStore),
}
#[derive(Clone, Debug)]
pub(crate) struct EncryptedFlow {
    pub digest: Vec<u8>,
    pub provider: String,
    pub nonce: Vec<u8>,
    pub encrypted: Vec<u8>,
    pub return_to: String,
    pub expiry: OffsetDateTime,
    pub oidc_nonce: Option<String>,
}
impl FlowStore {
    #[cfg_attr(
        not(feature = "postgres"),
        allow(clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    pub(crate) async fn close(&self) {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(pg) => pg.pool().close().await,
            #[cfg(feature = "workers")]
            Self::D1(_) => (),
            #[cfg(feature = "workers")]
            Self::PostgresTransport(_) => (),
            #[cfg(any(test, feature = "simulator-test-support"))]
            Self::Simulated(_) => (),
        }
    }
}
pub(crate) async fn create(store: &FlowStore, row: EncryptedFlow) -> Result<(), RuntimeFailure> {
    match store {
        #[cfg(feature = "postgres")]
        FlowStore::Postgres(pg) => postgres::create(pg, row).await,
        #[cfg(feature = "workers")]
        FlowStore::D1(db) => d1::create(db, row).await,
        #[cfg(feature = "workers")]
        FlowStore::PostgresTransport(binding) => {
            crate::postgres_transport::postgres_create(binding, row).await
        }
        #[cfg(any(test, feature = "simulator-test-support"))]
        FlowStore::Simulated(store) => simulated::create(store, row),
    }
}
pub(crate) async fn consume(
    store: &FlowStore,
    digest: &[u8],
    provider: &str,
) -> Result<Result<EncryptedFlow, ConsumeError>, RuntimeFailure> {
    match store {
        #[cfg(feature = "postgres")]
        FlowStore::Postgres(pg) => postgres::consume(pg, digest, provider).await,
        #[cfg(feature = "workers")]
        FlowStore::D1(db) => d1::consume(db, digest, provider).await,
        #[cfg(feature = "workers")]
        FlowStore::PostgresTransport(binding) => {
            crate::postgres_transport::postgres_consume(binding, digest, provider).await
        }
        #[cfg(any(test, feature = "simulator-test-support"))]
        FlowStore::Simulated(store) => Ok(simulated::consume(store, digest, provider)),
    }
}

/// Revokes an unconsumed state in the same durable authority that performs
/// `consume`. It is deliberately not modeled as deleting a row: retaining the
/// terminal state lets a concurrent or restarted consumer receive a truthful
/// domain result rather than incorrectly treating a revoked token as unknown.
pub(crate) async fn revoke(
    store: &FlowStore,
    digest: &[u8],
    provider: &str,
) -> Result<Result<(), RevokeError>, RuntimeFailure> {
    match store {
        #[cfg(feature = "postgres")]
        FlowStore::Postgres(pg) => postgres::revoke(pg, digest, provider).await,
        #[cfg(feature = "workers")]
        FlowStore::D1(db) => d1::revoke(db, digest, provider).await,
        #[cfg(feature = "workers")]
        FlowStore::PostgresTransport(binding) => {
            crate::postgres_transport::postgres_revoke(binding, digest, provider).await
        }
        #[cfg(any(test, feature = "simulator-test-support"))]
        FlowStore::Simulated(store) => Ok(simulated::revoke(store, digest, provider)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlowTerminalState {
    Available,
    Consumed,
    Revoked,
}

fn validate_consume(
    provider: &str,
    expected: &str,
    state: FlowTerminalState,
    expiry: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<(), ConsumeError> {
    if provider != expected {
        return Err(ConsumeError::ProviderMismatch);
    }
    match state {
        FlowTerminalState::Available => {}
        FlowTerminalState::Consumed => return Err(ConsumeError::AlreadyConsumed),
        FlowTerminalState::Revoked => return Err(ConsumeError::Revoked),
    }
    if expiry <= now {
        return Err(ConsumeError::Expired);
    }
    Ok(())
}

fn validate_revoke(
    provider: &str,
    expected: &str,
    state: FlowTerminalState,
    expiry: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<(), RevokeError> {
    if provider != expected {
        return Err(RevokeError::ProviderMismatch);
    }
    match state {
        FlowTerminalState::Available => {}
        FlowTerminalState::Consumed => return Err(RevokeError::AlreadyConsumed),
        FlowTerminalState::Revoked => return Err(RevokeError::AlreadyRevoked),
    }
    if expiry <= now {
        return Err(RevokeError::Expired);
    }
    Ok(())
}

/// Test-support implementation of the same durable consume predicate used by
/// PostgreSQL and D1. A `RefCell` critical section intentionally spans lookup,
/// validation, and the consumed transition without an `await`, so a second
/// local operation cannot observe a read-before-write gap.
#[cfg(any(test, feature = "simulator-test-support"))]
#[derive(Clone)]
pub(crate) struct SimulatedFlowStore {
    rows: Rc<RefCell<BTreeMap<Vec<u8>, SimulatedFlow>>>,
    now: Rc<dyn Fn() -> OffsetDateTime>,
}

#[cfg(any(test, feature = "simulator-test-support"))]
#[derive(Clone, Debug)]
struct SimulatedFlow {
    row: EncryptedFlow,
    state: FlowTerminalState,
}

#[cfg(any(test, feature = "simulator-test-support"))]
impl std::fmt::Debug for SimulatedFlowStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SimulatedFlowStore")
            .field("record_count", &self.rows.borrow().len())
            .finish_non_exhaustive()
    }
}

#[cfg(any(test, feature = "simulator-test-support"))]
impl SimulatedFlowStore {
    pub(crate) fn new(now: impl Fn() -> OffsetDateTime + 'static) -> Self {
        Self {
            rows: Rc::new(RefCell::new(BTreeMap::new())),
            now: Rc::new(now),
        }
    }
}

#[cfg(any(test, feature = "simulator-test-support"))]
mod simulated {
    use super::{
        ConsumeError, EncryptedFlow, FlowTerminalState, RevokeError, RuntimeFailure, SimulatedFlow,
        SimulatedFlowStore, failure, validate_consume, validate_revoke,
    };

    pub(super) fn create(
        store: &SimulatedFlowStore,
        row: EncryptedFlow,
    ) -> Result<(), RuntimeFailure> {
        let mut rows = store.rows.borrow_mut();
        if rows.contains_key(&row.digest) {
            return Err(failure("OAuth storage operation failed"));
        }
        rows.insert(
            row.digest.clone(),
            SimulatedFlow {
                row,
                state: FlowTerminalState::Available,
            },
        );
        Ok(())
    }

    pub(super) fn consume(
        store: &SimulatedFlowStore,
        digest: &[u8],
        expected: &str,
    ) -> Result<EncryptedFlow, ConsumeError> {
        let mut rows = store.rows.borrow_mut();
        let Some(flow) = rows.get_mut(digest) else {
            return Err(ConsumeError::InvalidState);
        };
        validate_consume(
            &flow.row.provider,
            expected,
            flow.state,
            flow.row.expiry,
            (store.now)(),
        )?;
        flow.state = FlowTerminalState::Consumed;
        Ok(flow.row.clone())
    }

    pub(super) fn revoke(
        store: &SimulatedFlowStore,
        digest: &[u8],
        expected: &str,
    ) -> Result<(), RevokeError> {
        let mut rows = store.rows.borrow_mut();
        let Some(flow) = rows.get_mut(digest) else {
            return Err(RevokeError::InvalidState);
        };
        validate_revoke(
            &flow.row.provider,
            expected,
            flow.state,
            flow.row.expiry,
            (store.now)(),
        )?;
        flow.state = FlowTerminalState::Revoked;
        Ok(())
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::{
        ConsumeError, EncryptedFlow, FlowTerminalState, OffsetDateTime, RevokeError,
        RuntimeFailure, failure, validate_consume, validate_revoke,
    };
    use lenso_postgres_kit::OwnedPostgres;
    use sqlx::Row;

    fn db(_: sqlx::Error) -> RuntimeFailure {
        failure("OAuth storage operation failed")
    }

    fn state(consumed: bool, revoked: bool) -> FlowTerminalState {
        if consumed {
            FlowTerminalState::Consumed
        } else if revoked {
            FlowTerminalState::Revoked
        } else {
            FlowTerminalState::Available
        }
    }

    pub(super) async fn create(pg: &OwnedPostgres, r: EncryptedFlow) -> Result<(), RuntimeFailure> {
        sqlx::query("INSERT INTO oauth_flows(state_digest,provider,verifier_nonce,encrypted_verifier,return_to,expires_at,oidc_nonce) VALUES($1,$2,$3,$4,$5,$6,$7)").bind(r.digest).bind(r.provider).bind(r.nonce).bind(r.encrypted).bind(r.return_to).bind(r.expiry).bind(r.oidc_nonce).execute(pg.pool()).await.map_err(db)?;
        Ok(())
    }
    pub(super) async fn consume(
        pg: &OwnedPostgres,
        digest: &[u8],
        expected: &str,
    ) -> Result<Result<EncryptedFlow, ConsumeError>, RuntimeFailure> {
        let mut tx = pg.pool().begin().await.map_err(db)?;
        let row=sqlx::query("SELECT provider,verifier_nonce,encrypted_verifier,oidc_nonce,return_to,expires_at,consumed_at IS NOT NULL AS consumed,revoked_at IS NOT NULL AS revoked FROM oauth_flows WHERE state_digest=$1 FOR UPDATE").bind(digest).fetch_optional(&mut *tx).await.map_err(db)?;
        let Some(row) = row else {
            return Ok(Err(ConsumeError::InvalidState));
        };
        let provider: String = row.try_get("provider").map_err(db)?;
        let expiry: OffsetDateTime = row.try_get("expires_at").map_err(db)?;
        if let Err(e) = validate_consume(
            &provider,
            expected,
            state(
                row.try_get("consumed").map_err(db)?,
                row.try_get("revoked").map_err(db)?,
            ),
            expiry,
            OffsetDateTime::now_utc(),
        ) {
            return Ok(Err(e));
        }
        sqlx::query(
            "UPDATE oauth_flows SET consumed_at=transaction_timestamp() WHERE state_digest=$1",
        )
        .bind(digest)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(Ok(EncryptedFlow {
            digest: digest.to_vec(),
            provider,
            nonce: row.try_get("verifier_nonce").map_err(db)?,
            encrypted: row.try_get("encrypted_verifier").map_err(db)?,
            return_to: row.try_get("return_to").map_err(db)?,
            expiry,
            oidc_nonce: row.try_get("oidc_nonce").map_err(db)?,
        }))
    }

    pub(super) async fn revoke(
        pg: &OwnedPostgres,
        digest: &[u8],
        expected: &str,
    ) -> Result<Result<(), RevokeError>, RuntimeFailure> {
        let mut tx = pg.pool().begin().await.map_err(db)?;
        let row = sqlx::query(
            "SELECT provider,expires_at,consumed_at IS NOT NULL AS consumed,revoked_at IS NOT NULL AS revoked FROM oauth_flows WHERE state_digest=$1 FOR UPDATE",
        )
        .bind(digest)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        let Some(row) = row else {
            return Ok(Err(RevokeError::InvalidState));
        };
        let provider: String = row.try_get("provider").map_err(db)?;
        let expiry: OffsetDateTime = row.try_get("expires_at").map_err(db)?;
        if let Err(error) = validate_revoke(
            &provider,
            expected,
            state(
                row.try_get("consumed").map_err(db)?,
                row.try_get("revoked").map_err(db)?,
            ),
            expiry,
            OffsetDateTime::now_utc(),
        ) {
            return Ok(Err(error));
        }
        sqlx::query(
            "UPDATE oauth_flows SET revoked_at=transaction_timestamp() WHERE state_digest=$1",
        )
        .bind(digest)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(digest: u8, provider: &str, expiry: OffsetDateTime) -> EncryptedFlow {
        EncryptedFlow {
            digest: vec![digest; 32],
            provider: provider.to_owned(),
            nonce: vec![7; 12],
            encrypted: vec![8; 32],
            return_to: "/settings/security".to_owned(),
            expiry,
            oidc_nonce: Some("nonce".to_owned()),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn simulated_store_consumes_a_state_exactly_once() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let store = FlowStore::Simulated(SimulatedFlowStore::new(move || now));
        let digest = vec![1; 32];
        create(&store, flow(1, "github", now + time::Duration::minutes(5)))
            .await
            .unwrap();

        let (first, second) = tokio::join!(
            consume(&store, &digest, "github"),
            consume(&store, &digest, "github"),
        );

        let first = first.unwrap();
        let second = second.unwrap();
        assert!(first.is_ok());
        assert!(matches!(second, Err(ConsumeError::AlreadyConsumed)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn provider_mismatch_does_not_consume_simulated_state() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let store = FlowStore::Simulated(SimulatedFlowStore::new(move || now));
        let digest = vec![2; 32];
        create(&store, flow(2, "github", now + time::Duration::minutes(5)))
            .await
            .unwrap();

        assert!(matches!(
            consume(&store, &digest, "google").await.unwrap(),
            Err(ConsumeError::ProviderMismatch)
        ));
        assert!(consume(&store, &digest, "github").await.unwrap().is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn explicit_simulated_clock_rejects_expired_state() {
        let initial = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let now = Rc::new(Cell::new(initial));
        let store = FlowStore::Simulated(SimulatedFlowStore::new({
            let now = now.clone();
            move || now.get()
        }));
        let digest = vec![3; 32];
        create(
            &store,
            flow(3, "github", initial + time::Duration::seconds(1)),
        )
        .await
        .unwrap();

        now.set(initial + time::Duration::seconds(1));
        assert!(matches!(
            consume(&store, &digest, "github").await.unwrap(),
            Err(ConsumeError::Expired)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn simulated_revocation_is_durable_and_prevents_consumption() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let store = FlowStore::Simulated(SimulatedFlowStore::new(move || now));
        let digest = vec![4; 32];
        create(&store, flow(4, "github", now + time::Duration::minutes(5)))
            .await
            .unwrap();

        assert!(matches!(
            revoke(&store, &digest, "github").await.unwrap(),
            Ok(())
        ));
        assert!(matches!(
            consume(&store, &digest, "github").await.unwrap(),
            Err(ConsumeError::Revoked)
        ));
        assert!(matches!(
            revoke(&store, &digest, "github").await.unwrap(),
            Err(RevokeError::AlreadyRevoked)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn simulated_consume_and_revoke_have_one_atomic_winner() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let store = FlowStore::Simulated(SimulatedFlowStore::new(move || now));
        let digest = vec![5; 32];
        create(&store, flow(5, "github", now + time::Duration::minutes(5)))
            .await
            .unwrap();

        let (consume_result, revoke_result) = tokio::join!(
            consume(&store, &digest, "github"),
            revoke(&store, &digest, "github"),
        );
        let consume_result = consume_result.unwrap();
        let revoke_result = revoke_result.unwrap();
        let success_count =
            usize::from(consume_result.is_ok()) + usize::from(revoke_result.is_ok());
        assert_eq!(success_count, 1);
        assert!(consume_result.is_ok() || matches!(consume_result, Err(ConsumeError::Revoked)));
        assert!(
            revoke_result.is_ok() || matches!(revoke_result, Err(RevokeError::AlreadyConsumed))
        );
    }
}
#[cfg(feature = "workers")]
mod d1 {
    use super::{
        ConsumeError, EncryptedFlow, FlowTerminalState, OffsetDateTime, RevokeError,
        RuntimeFailure, failure, validate_consume, validate_revoke,
    };
    use crate::workers::{D1Binding, decode_time, field, statement, timestamp};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::json;
    fn fail(_: ()) -> RuntimeFailure {
        failure("OAuth storage operation failed")
    }

    fn state(consumed: bool, revoked: bool) -> FlowTerminalState {
        if consumed {
            FlowTerminalState::Consumed
        } else if revoked {
            FlowTerminalState::Revoked
        } else {
            FlowTerminalState::Available
        }
    }

    pub(super) async fn create(db: &D1Binding, r: EncryptedFlow) -> Result<(), RuntimeFailure> {
        db.run(vec![statement("INSERT INTO oauth_flows(state_digest,provider,verifier_nonce,encrypted_verifier,return_to,expires_at,oidc_nonce) VALUES(?1,?2,?3,?4,?5,?6,?7)",vec![json!(URL_SAFE_NO_PAD.encode(r.digest)),json!(r.provider),json!(URL_SAFE_NO_PAD.encode(r.nonce)),json!(URL_SAFE_NO_PAD.encode(r.encrypted)),json!(r.return_to),timestamp(r.expiry),json!(r.oidc_nonce)])]).await.map_err(fail)?;
        Ok(())
    }
    pub(super) async fn consume(
        db: &D1Binding,
        digest: &[u8],
        expected: &str,
    ) -> Result<Result<EncryptedFlow, ConsumeError>, RuntimeFailure> {
        let now = OffsetDateTime::now_utc();
        let key = json!(URL_SAFE_NO_PAD.encode(digest));
        let r=db.run(vec![
            statement("SELECT provider,verifier_nonce,encrypted_verifier,oidc_nonce,return_to,expires_at,consumed_at IS NOT NULL AS consumed,revoked_at IS NOT NULL AS revoked,strftime('%Y-%m-%dT%H:%M:%f000000Z','now') AS observed_now FROM oauth_flows WHERE state_digest=?1",vec![key.clone()]),
            statement("UPDATE oauth_flows SET consumed_at=strftime('%Y-%m-%dT%H:%M:%f000000Z','now') WHERE state_digest=?1 AND provider=?2 AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>?3 AND expires_at>strftime('%Y-%m-%dT%H:%M:%f000000Z','now')",vec![key,json!(expected),timestamp(now)])
        ]).await.map_err(fail)?;
        let Some(row) = r[0].results.first() else {
            return Ok(Err(ConsumeError::InvalidState));
        };
        let provider: String = field(row, "provider").map_err(fail)?;
        let expiry = decode_time(row, "expires_at").map_err(fail)?;
        let now = now.max(decode_time(row, "observed_now").map_err(fail)?);
        if let Err(e) = validate_consume(
            &provider,
            expected,
            state(
                field::<i64>(row, "consumed").map_err(fail)? != 0,
                field::<i64>(row, "revoked").map_err(fail)? != 0,
            ),
            expiry,
            now,
        ) {
            if r[1].meta.changes != 0 {
                return Err(fail(()));
            }
            return Ok(Err(e));
        }
        if r[1].meta.changes != 1 {
            return Err(fail(()));
        }
        Ok(Ok(EncryptedFlow {
            digest: digest.to_vec(),
            provider,
            nonce: URL_SAFE_NO_PAD
                .decode(field::<String>(row, "verifier_nonce").map_err(fail)?)
                .map_err(|_| fail(()))?,
            encrypted: URL_SAFE_NO_PAD
                .decode(field::<String>(row, "encrypted_verifier").map_err(fail)?)
                .map_err(|_| fail(()))?,
            return_to: field(row, "return_to").map_err(fail)?,
            expiry,
            oidc_nonce: field(row, "oidc_nonce").map_err(fail)?,
        }))
    }

    pub(super) async fn revoke(
        db: &D1Binding,
        digest: &[u8],
        expected: &str,
    ) -> Result<Result<(), RevokeError>, RuntimeFailure> {
        let now = OffsetDateTime::now_utc();
        let key = json!(URL_SAFE_NO_PAD.encode(digest));
        let results = db
            .run(vec![
                statement(
                    "SELECT provider,expires_at,consumed_at IS NOT NULL AS consumed,revoked_at IS NOT NULL AS revoked,strftime('%Y-%m-%dT%H:%M:%f000000Z','now') AS observed_now FROM oauth_flows WHERE state_digest=?1",
                    vec![key.clone()],
                ),
                statement(
                    "UPDATE oauth_flows SET revoked_at=strftime('%Y-%m-%dT%H:%M:%f000000Z','now') WHERE state_digest=?1 AND provider=?2 AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>?3 AND expires_at>strftime('%Y-%m-%dT%H:%M:%f000000Z','now')",
                    vec![key, json!(expected), timestamp(now)],
                ),
            ])
            .await
            .map_err(fail)?;
        let Some(row) = results[0].results.first() else {
            return Ok(Err(RevokeError::InvalidState));
        };
        let provider: String = field(row, "provider").map_err(fail)?;
        let expiry = decode_time(row, "expires_at").map_err(fail)?;
        let now = now.max(decode_time(row, "observed_now").map_err(fail)?);
        if let Err(error) = validate_revoke(
            &provider,
            expected,
            state(
                field::<i64>(row, "consumed").map_err(fail)? != 0,
                field::<i64>(row, "revoked").map_err(fail)? != 0,
            ),
            expiry,
            now,
        ) {
            if results[1].meta.changes != 0 {
                return Err(fail(()));
            }
            return Ok(Err(error));
        }
        if results[1].meta.changes != 1 {
            return Err(fail(()));
        }
        Ok(Ok(()))
    }
}

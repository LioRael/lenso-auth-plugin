//! Explicit sources for deterministic OAuth Flow test compositions.
//!
//! This module exists only behind `simulator-test-support`. It has no default
//! implementation and cannot become a production entropy or wall-clock
//! fallback: a test Host must supply the clock, entropy stream, and encryption
//! key for every simulated Plugin generation.

use std::{fmt, rc::Rc};

use time::OffsetDateTime;

use crate::storage::SimulatedFlowStore;

/// Stable private operation boundaries exposed by the OAuth simulator seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthSimulationBoundary {
    /// Before validating and creating a new state record.
    BeforeCreate,
    /// After the state record became durable.
    AfterCreateDurableCommit,
    /// Before returning a create response.
    BeforeCreateResponse,
    /// Before validating and consuming an existing state record.
    BeforeConsume,
    /// After the consumed transition became durable.
    AfterConsumeDurableCommit,
    /// Before returning a consume response.
    BeforeConsumeResponse,
    /// Before validating and revoking an existing state record.
    BeforeRevoke,
    /// After the revoked transition became durable.
    AfterRevokeDurableCommit,
    /// Before returning a revoke response.
    BeforeRevokeResponse,
}

/// A bounded simulated failure class.
///
/// It deliberately carries no transport implementation, request payload, or
/// credential content. The Host maps it to its own test fault vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthSimulationFault {
    /// The configured operation deadline elapsed.
    Timeout,
    /// Cooperative cancellation was requested.
    Cancellation,
    /// The caller disconnected after a durable effect.
    DroppedConnection,
    /// Generation-owned cleanup failed.
    CleanupFailure,
    /// A private resource was unavailable.
    ResourceUnavailable,
}

type Clock = Rc<dyn Fn() -> OffsetDateTime>;
type Entropy = Rc<dyn Fn(&mut [u8])>;
type FaultHook = Rc<dyn Fn(OAuthSimulationBoundary) -> Option<OAuthSimulationFault>>;

/// The complete set of test-owned sources for one simulated Auth generation.
#[derive(Clone)]
pub struct OAuthSimulation {
    clock: Clock,
    entropy: Entropy,
    encryption_key: [u8; 32],
    store: SimulatedFlowStore,
    fault_hook: Option<FaultHook>,
}

impl fmt::Debug for OAuthSimulation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthSimulation")
            .field("clock", &"explicit")
            .field("entropy", &"explicit")
            .field("encryption_key", &"<redacted>")
            .field("store", &self.store)
            .field("fault_hook", &self.fault_hook.is_some())
            .finish()
    }
}

impl OAuthSimulation {
    /// Creates an explicit simulated world for a single Auth generation.
    pub fn new(
        clock: impl Fn() -> OffsetDateTime + 'static,
        entropy: impl Fn(&mut [u8]) + 'static,
        encryption_key: [u8; 32],
    ) -> Self {
        let clock: Clock = Rc::new(clock);
        let store = SimulatedFlowStore::new({
            let clock = Rc::clone(&clock);
            move || clock()
        });
        Self {
            clock,
            entropy: Rc::new(entropy),
            encryption_key,
            store,
            fault_hook: None,
        }
    }

    /// Adds an explicit, test-owned hook for bounded fault boundaries.
    #[must_use]
    pub fn with_fault_hook(
        mut self,
        fault_hook: impl Fn(OAuthSimulationBoundary) -> Option<OAuthSimulationFault> + 'static,
    ) -> Self {
        self.fault_hook = Some(Rc::new(fault_hook));
        self
    }

    pub(crate) fn now(&self) -> OffsetDateTime {
        (self.clock)()
    }

    pub(crate) fn fill(&self, output: &mut [u8]) {
        (self.entropy)(output);
    }

    pub(crate) const fn encryption_key(&self) -> &[u8; 32] {
        &self.encryption_key
    }

    /// Returns the deterministic persistence authority for this simulated
    /// world. It is intentionally shared across fresh Plugin generations so a
    /// test can prove restart semantics without sharing Plugin-owned state.
    pub(crate) fn store(&self) -> SimulatedFlowStore {
        self.store.clone()
    }

    pub(crate) fn fault(&self, boundary: OAuthSimulationBoundary) -> Option<OAuthSimulationFault> {
        self.fault_hook.as_ref().and_then(|hook| hook(boundary))
    }
}

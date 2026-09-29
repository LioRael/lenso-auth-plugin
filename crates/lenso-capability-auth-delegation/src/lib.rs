#[allow(dead_code)]
mod contract;

include!("generated.rs");

/// Original grant operation marker retained for existing typed callers.
pub type Delegation = DelegationGrant;

/// Invocation error for the original grant operation.
pub type DelegationInvocationError = DelegationGrantInvocationError;

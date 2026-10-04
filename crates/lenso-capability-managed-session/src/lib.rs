//! Versioned managed session role. Policy and state belong to the provider.

#[allow(dead_code)]
mod contract;

mod generated {
    include!("generated.rs");
}

pub use generated::*;

/// Managed issuance and renewal have the same immutable response shape.
pub type IssueManagedResponse = SessionResponse;
pub type RenewResponse = SessionResponse;

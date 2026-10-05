# Packaged Auth D1 resource adapters

The independent formal-main/contract699 compatibility slice supplies a normal
Cargo-package asset in both `lenso-auth-account-plugin` and
`lenso-auth-password-plugin`:

`src/host_facilities/state-resource.mjs`

This self-contained module exports `create` and `createD1Binding`. `create`
requires the existing Relay resource identifier `implementation = "relay.auth-d1"`.
Missing, inherited or different identifiers fail with `incompatible_target_resource`.
Only that field is removed before the original Auth factory validates `profile`,
`binding`, optional `storage_ref` and the exact field set. Primary D1 batching,
event scope, immutability and transport errors retain their original semantics.

The selected consumer Slot metadata uses Core's existing selector, for example:

```toml
workers-adapter-package = "lenso-auth-account-plugin"
workers-adapter = "src/host_facilities/state-resource.mjs"
```

Password selects `lenso-auth-password-plugin` at the same relative path. The
consumer's Rust factory selection remains separate. Core selects the reachable
Cargo owner and stages the module bytes unchanged; no bundler, application-owned
copy, runtime import, public DB Capability or new package is needed. Operators
may import `createD1Binding` from the same module for their explicit workflows.

The original `state.mjs` and its two/three-field facility contract remain
unchanged. The new asset is generated inside Auth from that package's canonical
module by `node workers/generate-resource-adapters.mjs`; the existing
`node workers/generate-bridges.mjs --check` also checks resource adapter drift.
Run `node --test workers/resource-adapter.test.mjs` for isolated staging and
failure evidence. Generation is an owner build step; consumers only use the
committed package asset.

This branch retains formal main's full renewal/operator functionality while
normalizing existing SDK/Role dependencies to Git699. It does not replace main
or establish full root workspace CI,
browser multiRealm Ingress, App assembly or deployment qualification. Relay owns
the frozen consumer graph and Native/Workers App checks at the final source SHA.

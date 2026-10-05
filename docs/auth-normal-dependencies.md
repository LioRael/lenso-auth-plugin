# Normal Git consumption with one identity per Auth package

This compatibility branch starts at formal main `4e4da9e9` and retains its
complete Account, Password, managed-session, renewal and operator behavior.
No business Rust, Role contract, schema, permission, Store or migration changes.

Three implementation manifests normalize fourteen existing SDK/Role edges to
exact Git699 (`699bd9621bc2e7f8581f6c0ff0bcbfcb6e3c2167`), preserving versions:
Account seven, Password three and Operator Session four. The eight distinct
shared SDK/Role packages are byte-identical between Git699 and formal main.
Cargo.lock adds those exact Git identities; existing package versions remain.

Consumers select one final immutable successor revision for all four
implementations and three new Roles: Account, Password, Session Renewal,
Operator Session, Managed Session, Operator Session Role and Operator Binding.
The new Roles have no dependency on an existing Auth SDK/Role, so their original
main source and same-repository package dependencies remain unchanged.

Existing SDK, Auth, Account Admin, Auth Delegation, Credential Issuer,
Credential State, Identity Directory and Password Auth dependencies remain
Git699. Console's existing shared Auth dependencies therefore need no new
contract version. A consumer's Operator Session Role dependency must move from
Git4e to the same new successor as its implementation. Replace old Account and
Password Git82 implementations everywhere in that selected graph. Each package
must resolve to one Cargo source identity; equal bytes do not merge identities.

Access Roles remain Git94b6d06 and Audit Role Git83b4e52. Core Kernel, facade,
authoring, adapters and HTTP Role identities must match the consumer's existing
Core cohort; its crates.io patches are a separate consumer responsibility.
Console requires its independently reviewed compatible successor.

Renewal alone accepts HTTP Endpoint `0.3.7` with Cargo's compatible `0.3.x`
range, so the consumer's Core25 patch can supply `0.3.8` rather than resolving
an additional exact-registry `0.3.7` identity. The workspace baseline remains
locked at `0.3.7`; no HTTP contract or endpoint implementation changes.

Both storage owners carry the self-contained resource entry documented in
[resource adapters](auth-resource-adapters.md). It preserves the exact existing
`relay.auth-d1` resource contract and both exports; no application source copies
or Core bundler are needed.

Core25/CLI029 exposes Many-Slot selection, not the historical per-instance
`--host-binding` One selection. This branch does not rename Auth requirements
or change the Plugin Descriptor to hide that prerequisite. Core and Relay must
qualify the actual selected per-instance One edges and browser realm routing.

Narrow owner and normal local-Git consumer checks establish only their recorded
source tuple. They are not full root workspace CI, generated common App, real
D1, deployment, production grant or publication qualification. Main is not
replaced; a remote push or landing needs separate approval.

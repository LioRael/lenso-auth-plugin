# D01: local G4 Auth characterization

## Result: passed locally

The complete 14-scenario G4 matrix ran on 2026-09-15 with **370 serial samples** against the real release Wasm bundle in Miniflare/workerd. The strict receipt checker passed. This is a local characterization of the Worker adaptation path; it is not a cloud capacity or SLA result.

- [Compressed machine-readable receipt](workers-g4-d01.raw.json.gz)
- [Validation receipt](workers-g4-d01-validation.json)
- Base commit: `a5bc01a2120ec46cd3ad5e0ebe31df7fc5ba90b8`
- Node v26.8.2; workerd 1.20260701.1; Miniflare 4.20260701.0
- Sample policy: 5 cold starts per composition, 30 warm/operation samples, concurrency 1

## Measured results

Wall time is measured outside the Worker around local HTTP request and full response consumption. Wasm memory is allocated linear memory observed at instrumented boundaries; it is not RSS or live heap.

| Scenario | n | p50 ms | p95 ms | p99 ms | Max Wasm MiB | Generation changes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Cold Ready, 1 owner | 5 | 85.74 | 89.63 | 89.63 | 1.62 | 0 |
| Cold Ready, 7 owners | 5 | 141.93 | 147.72 | 147.72 | 1.81 | 0 |
| Warm Ready, 1 owner | 30 | 3.49 | 4.28 | 4.81 | 2.00 | 0 |
| Warm Ready, 7 owners | 30 | 16.16 | 18.63 | 19.56 | 4.56 | 0 |
| Password login, valid | 30 | 37.30 | 40.23 | 41.08 | 42.81 | 0 |
| Password login, wrong password | 30 | 36.61 | 39.90 | 47.15 | 42.81 | 1 |
| Password login, absent identity | 30 | 36.13 | 38.93 | 43.42 | 39.94 | 1 |
| API token issue | 30 | 15.60 | 17.46 | 21.31 | 39.94 | 0 |
| API token verify | 30 | 15.41 | 18.58 | 20.03 | 39.94 | 1 |
| OIDC activation and metadata | 30 | 14.72 | 17.00 | 31.33 | 7.69 | 1 |
| Injected D1 failure | 30 | 3.59 | 6.31 | 13.24 | 3.38 | 30 |
| Recovery after D1 failure | 30 | 15.45 | 18.74 | 19.39 | 1.81 | 0 |
| Controlled abandonment | 30 | 2.13 | 2.69 | 6.19 | 1.81 | 30 |
| Recovery after abandonment | 30 | 15.26 | 17.29 | 18.66 | 1.81 | 0 |

The seven-owner Ready path increased from a 3.49 ms one-owner warm median to 16.16 ms. Password verification dominated this local profile at about 36–37 ms median and expanded observed Wasm linear memory to 42.81 MiB. Injected storage failure and abandonment replaced every affected generation, and all 60 following recovery samples succeeded.

Expected failures stayed fail closed: wrong and absent passwords returned domain errors; injected D1 failure and controlled abandonment returned runtime errors. No unexpected sample failed. Generation changes on a few later scenarios reflect normal retirement inherited from preceding operations and are retained in the raw receipt.

## Scope and method

Each sample creates, resolves, activates and shuts down a fresh normal App. The one-owner composition contains Account and Secrets. The seven-owner composition contains Account, OAuth Flow, Password, Phone, Device, API Token and OIDC Provider, plus Router, caller, Secrets and the controlled SMS fixture. Schema setup and warmups happen outside measurement.

Cold samples start before a new Miniflare/workerd process and reuse initialized D1 files and the same artifact; OS caches are not flushed. Warm samples reuse a workerd process but create a fresh App and event scope. Password registration, token setup, JWKS control probes and login resets are outside measured samples. Requests are never retried.

D1 evidence records exact owner batch attempts and statement counts, with returned rows and local `meta.rows_read`/`rows_written` when available. Oversized or uncertain metadata remains null. Evidence includes observations only; it contains no request bodies, Auth responses, passwords, tokens, Argon2 hashes, private keys or signing material.

## Reproduce

From a clean checkout with Node 26.8.2, pnpm 11.5.0, Rust 1.94.0 plus `wasm32-unknown-unknown`, wasm-bindgen 0.2.127 and Python 3.9 or later:

```sh
bash experiments/workers-g4/profile.sh
```

The command installs from the frozen lockfile, builds the release Wasm through the workspace Cargo wrapper, runs focused JS/Python checks, executes the full local matrix, and applies the strict receipt validator. Temporary D1 databases, generated credentials, bundle output and processes are task owned and removed after execution.

## Interpretation limits

The p99 value is the maximum for these small 5- and 30-sample sets. The results provide no confidence interval or stable tail guarantee. They do not measure CPU time, production capacity, concurrent throughput, cloud latency/cost, RSS, JS heap, external IdP behavior or constant-time properties. See [native password measurements](password-performance.md) and [storage migration ownership](storage-migrations.md) for their separate scopes.

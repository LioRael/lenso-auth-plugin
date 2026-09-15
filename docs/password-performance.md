# Password preparation and verification cost

Password and Phone preparation reuse a public precomputed dummy PHC hash. They
validate the fixture's algorithm, version, all parameters and output length
against the same current `Argon2::default()` policy used for real credentials.
A mismatch fails preparation, and a real-Argon2 test regenerates each fixture.
There is no global App, secret, credential, or event-I/O cache. Admission remains
per App; native hash and verification retain `spawn_blocking` and their permits.

Both owners retain Argon2id v19 with 19,456 KiB memory, two iterations, one lane,
and a 32-byte output. New real credentials retain fresh 16-byte random salts.
Absent identities still run a full dummy verification and always reject, even
if the supplied password matches the public dummy input. Removing the setup hash
does not reduce hash or verification cost or establish equal end-to-end latency
for every invalid-login path.

## Reproduce the native microbenchmark

From the repository root:

```sh
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo +1.94.0 test \
  --locked --release -p lenso-auth-password-plugin -p lenso-auth-phone-plugin \
  --lib password_work_benchmark -- --ignored --nocapture --test-threads=1
```

Outside the shared Lenso workspace, use the normal `cargo +1.94.0` executable.
The benchmark is only compiled in release tests, so CI's debug
`--include-ignored` run does not execute performance work. It invokes each
owner's actual private `PasswordWork` methods. Each operation has 12 samples;
preparation averages 1,000 fresh workers per sample to reduce timer noise. The
`previous_prepare` case reconstructs the previous implementation: fresh semaphore,
a random-salted dummy hash dispatched to the native executor, and the stored
immutable hash. The first real hash warms the executor before sampling.
Output contains timings only and uses fixed public benchmark inputs.

These are local password-work timings, excluding database preparation, D1,
network, full App startup, binding resolution and assertion/session issuance.
They are descriptive samples, not a statistical constant-time proof or a service
latency budget.

## Local result (2026-09-15)

Apple M2 Pro, aarch64 macOS, Rust/Cargo 1.94.0, locked argon2 0.5.3, release
profile. The recorded run followed compilation and all task-owned concurrent
builds. Median times from that run:

| Operation | Password | Phone |
| --- | ---: | ---: |
| Previous preparation (reconstructed) | 14.850 ms | 14.789 ms |
| Current preparation | 0.515 us | 0.513 us |
| New random-salted hash | 14.572 ms | 14.456 ms |
| Correct credential verification | 15.222 ms | 15.040 ms |
| Wrong-password verification | 14.465 ms | 14.514 ms |
| Absent-identity verification | 14.090 ms | 14.853 ms |

The measured saving is approximately one 14.8 ms hash per owner preparation on
this machine. This does not establish a whole-App speedup; verification remains
about 14-15 ms in this native sample. Raw sample summaries, including min/max,
are retained in [`password-performance-native.txt`](password-performance-native.txt).

## Wasm execution limit

Wasm continues to execute Argon2 synchronously in `run_password_job`; the permit
bounds admission but does not yield during hashing. The source change removes
one setup Argon2 operation from each fresh event App for each enabled owner.
Hashing and verification still consume the isolate's execution thread.

Workers-only compilation and linting are checked for `wasm32-unknown-unknown`.
No Wasm runtime timing is claimed by this native benchmark. A meaningful Workers
CPU measurement needs a separately controlled Workers runtime experiment with
its CPU policy and event composition recorded; native numbers must not be used
as Workers capacity or throughput predictions.

## Generated D1 bridge maintenance

Edit only `workers/d1.rs`, then run:

```sh
node workers/generate-bridges.mjs
node workers/generate-bridges.mjs --check
```

Generation writes the same canonical transport with a generated header into all
seven owners' `src/workers.rs`. Check mode rejects missing or drifted artifacts
without writing. Each package contains its own Rust source; building or consuming
an archive does not invoke the generator or include source outside the package.
This is build tooling for Auth's private transport, with no new shared SQL,
migration, or public Capability contract. `workers/check-packages.py` runs the
generation check, then compiles actual extracted archives with workers enabled
and verifies every non-registry dependency is also an extracted archive.

use super::*;

#[test]
fn public_dummy_matches_current_policy_and_rejects_policy_drift() {
    validate_dummy_hash(DUMMY_PASSWORD_HASH).unwrap();
    let salt = SaltString::encode_b64(b"lenso-dummy-salt").unwrap();
    let generated = Argon2::default()
        .hash_password(DUMMY_PASSWORD_INPUT.as_bytes(), &salt)
        .unwrap()
        .to_string();
    assert_eq!(generated, DUMMY_PASSWORD_HASH);
    for (from, to) in [
        ("argon2id", "argon2i"),
        ("v=19", "v=16"),
        ("m=19456", "m=8192"),
        ("t=2", "t=1"),
        ("p=1", "p=2"),
    ] {
        assert!(validate_dummy_hash(&DUMMY_PASSWORD_HASH.replace(from, to)).is_err());
    }
    let (prefix, _) = DUMMY_PASSWORD_HASH.rsplit_once('$').unwrap();
    assert!(validate_dummy_hash(&format!("{prefix}$AAAAAAAAAAAAAAAAAAAAAA")).is_err());
    assert!(validate_dummy_hash("invalid").is_err());
}

#[tokio::test]
async fn real_password_and_absent_identity_keep_verification_semantics() {
    let worker = PasswordWork::prepare().unwrap();
    let password = "a-valid-test-password".to_owned();
    let hash = worker.hash(password.clone()).await.unwrap();
    let second_hash = worker.hash(password.clone()).await.unwrap();
    assert_ne!(
        hash, second_hash,
        "real credentials retain fresh random salts"
    );
    assert!(worker.verify(password, Some(hash.clone())).await.unwrap());
    assert!(
        !worker
            .verify("wrong-password".to_owned(), Some(hash))
            .await
            .unwrap()
    );
    assert!(
        !worker
            .verify("wrong-password".to_owned(), None)
            .await
            .unwrap()
    );
    // Even the public dummy's correct input cannot authenticate a missing user.
    assert!(
        !worker
            .verify(DUMMY_PASSWORD_INPUT.to_owned(), None)
            .await
            .unwrap()
    );
}

#[test]
fn app_preparation_keeps_admission_event_local() {
    let first = PasswordWork::prepare_with_limit(1).unwrap();
    let _permit = first.permits.try_acquire().unwrap();
    let second = PasswordWork::prepare_with_limit(1).unwrap();
    assert_eq!(first.permits.available_permits(), 0);
    assert_eq!(second.permits.available_permits(), 1);
}

/// Reproducible native microbenchmark; no database, network, or credential output.
/// Run with `--release --ignored password_work_benchmark --nocapture`.
#[cfg(not(debug_assertions))]
#[tokio::test]
#[ignore = "explicit performance measurement; not a correctness gate"]
async fn password_work_benchmark() {
    use std::{hint::black_box, time::Instant};
    const SAMPLES: usize = 12;
    fn report(name: &str, mut samples: Vec<std::time::Duration>) {
        samples.sort_unstable();
        println!(
            "{} {name}: n={} median_ns={} min_ns={} max_ns={}",
            env!("CARGO_PKG_NAME"),
            samples.len(),
            samples[samples.len() / 2].as_nanos(),
            samples[0].as_nanos(),
            samples[samples.len() - 1].as_nanos(),
        );
    }
    let worker = PasswordWork::prepare().unwrap();
    let encoded = worker.hash("benchmark-password".to_owned()).await.unwrap();
    for operation in [
        "prepare",
        "previous_prepare",
        "hash",
        "verify_hit",
        "verify_wrong",
        "verify_absent",
    ] {
        let mut samples = Vec::new();
        for _ in 0..SAMPLES {
            let start = Instant::now();
            match operation {
                "prepare" => {
                    // Amortize timer resolution; each iteration makes a fresh App worker.
                    for _ in 0..1000 {
                        black_box(PasswordWork::prepare().unwrap());
                    }
                }
                "previous_prepare" => {
                    let permits = Arc::new(Semaphore::new(MAX_PASSWORD_WORK_JOBS));
                    let hash = run_password_job(Arc::clone(&permits), || {
                        hash_password_sync(DUMMY_PASSWORD_INPUT)
                    })
                    .await
                    .unwrap();
                    black_box(PasswordWork {
                        permits,
                        dummy_hash: Arc::from(hash),
                    });
                }
                "hash" => {
                    black_box(worker.hash("benchmark-password".to_owned()).await.unwrap());
                }
                "verify_hit" => {
                    assert!(
                        worker
                            .verify("benchmark-password".to_owned(), Some(encoded.clone()))
                            .await
                            .unwrap()
                    );
                }
                "verify_wrong" => {
                    assert!(
                        !worker
                            .verify("wrong-password".to_owned(), Some(encoded.clone()))
                            .await
                            .unwrap()
                    );
                }
                "verify_absent" => {
                    assert!(
                        !worker
                            .verify("wrong-password".to_owned(), None)
                            .await
                            .unwrap()
                    );
                }
                _ => unreachable!(),
            }
            samples.push(start.elapsed() / if operation == "prepare" { 1000 } else { 1 });
        }
        report(operation, samples);
    }
}

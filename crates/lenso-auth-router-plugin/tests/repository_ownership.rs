use std::{collections::BTreeSet, fs, path::PathBuf};

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn repository_owns_the_expected_auth_crates() {
    let crates = fs::read_dir(repository_root().join("crates"))
        .expect("read repository crates")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().join("Cargo.toml").is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<BTreeSet<_>>();
    let expected = [
        "lenso-auth-account-admin-agent-tools-plugin",
        "lenso-auth-account-plugin",
        "lenso-auth-anonymous-plugin",
        "lenso-auth-api-token-plugin",
        "lenso-auth-device-plugin",
        "lenso-auth-federated-plugin",
        "lenso-auth-oauth-flow-plugin",
        "lenso-auth-oidc-client-plugin",
        "lenso-auth-oidc-plugin",
        "lenso-auth-password-plugin",
        "lenso-auth-phone-plugin",
        "lenso-auth-router-plugin",
        "lenso-auth-sdk",
        "lenso-auth-web-session-plugin",
        "lenso-capability-account-admin",
        "lenso-capability-anonymous-auth",
        "lenso-capability-auth",
        "lenso-capability-auth-delegation",
        "lenso-capability-credential-issuer",
        "lenso-capability-device-auth",
        "lenso-capability-federated-auth",
        "lenso-capability-identity-directory",
        "lenso-capability-oauth-flow",
        "lenso-capability-oidc-provider",
        "lenso-capability-password-auth",
        "lenso-capability-phone-auth",
        "lenso-capability-sms-delivery",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();

    assert_eq!(crates, expected);
}

#[test]
fn portable_auth_crates_do_not_own_concrete_adapters() {
    let root = repository_root();
    let manifests = [
        root.join("crates/lenso-auth-sdk/Cargo.toml"),
        root.join("crates/lenso-capability-auth/Cargo.toml"),
    ];
    let forbidden = [
        "sqlx",
        "postgres",
        "lenso-postgres-kit",
        "lenso-native-adapter",
        "lenso-capability-secrets",
    ];

    for manifest in manifests {
        let contents = fs::read_to_string(&manifest).expect("read portable Auth manifest");
        for dependency in forbidden {
            assert!(
                !contents.contains(dependency),
                "{} contains concrete dependency {dependency}",
                manifest.display()
            );
        }
    }
}

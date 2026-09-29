#![allow(clippy::too_many_lines)]

use lenso_access_control_postgres_plugin::{AccessControlConfig, AccessControlOperator};
use lenso_app_plan::{
    AppComposition, CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan,
    PluginInstancePlan, ResolvedAppPlan,
};
use lenso_auth_account_plugin::{AccountAuthConfig, AccountAuthOperator};
use lenso_auth_api_token_plugin::{ApiTokenAuthConfig, ApiTokenAuthOperator};
use lenso_auth_human_api_token_plugin::HumanApiTokenConfig;
use lenso_auth_sdk::credential::{
    CredentialBinding, MANAGEMENT_CEILING_CLAIM, ManagementCredentialCeiling,
    ManagementResourceScope,
};
use lenso_auth_sdk::{
    ActorAssertion, AuthOutcome, CredentialEvidence, audience, authenticate_request,
    decode_auth_response,
};
use lenso_capability_access_control as access;
use lenso_capability_access_control_admin as access_admin;
use lenso_capability_access_control_directory as access_directory;
use lenso_capability_account_admin as account_admin;
use lenso_capability_api_token_admin as token_admin;
use lenso_capability_auth as auth;
use lenso_capability_auth_delegation as delegation;
use lenso_capability_credential_issuer as issuer;
use lenso_capability_credential_state as state;
use lenso_capability_human_api_token as human;
use lenso_capability_identity_directory as directory;
use lenso_capability_secrets::{
    self as secrets, ResolveError, ResolveRequest, ResolveResponse, Secrets, SecretsEndpoint,
    SecretsProvider,
};
use lenso_kernel::{
    CancellationToken, InvocationContext, Kernel, NativeApp, NativeRequestEndpoint,
    NativeRequestFuture, RuntimeFailure, ShutdownOutcome,
};
use lenso_native_adapter::{
    NativePluginFactory, NativePluginFactoryContext, NativePluginInstance, NativePluginRegistry,
};
use lenso_runner::TokioDriver;
use std::{collections::BTreeMap, rc::Rc, time::Duration as StdDuration};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
const CALLER_PACKAGE_ID: &str = "test.human";
const SECRETS_PACKAGE_ID: &str = "test.static-secrets";
const ACCOUNT_KEY: &str = "account-test-operator-key-with-high-entropy";
const API_KEY: &str = "api-test-operator-key-with-high-entropy";
const TOKEN_PEPPER: &str = "human-test-pepper-with-high-entropy";
const DEPLOYMENT: &str = "deployment-a";
const HUMAN: &str = "lenso.auth.human-api-token/human";
#[derive(Debug)]
struct CallerFactory;

impl NativePluginFactory for CallerFactory {
    fn package_id(&self) -> &'static str {
        CALLER_PACKAGE_ID
    }

    fn instantiate(
        &self,
        _context: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        Ok(NativePluginInstance::default())
    }
}

#[derive(Clone)]
struct StaticSecretsFactory {
    values: BTreeMap<String, String>,
}

impl std::fmt::Debug for StaticSecretsFactory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StaticSecretsFactory")
            .field("references", &self.values.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl NativePluginFactory for StaticSecretsFactory {
    fn package_id(&self) -> &'static str {
        SECRETS_PACKAGE_ID
    }

    fn instantiate(
        &self,
        _context: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        let endpoint = Rc::new(SecretsEndpoint::new(StaticSecretsProvider {
            values: self.values.clone(),
        })) as Rc<dyn NativeRequestEndpoint>;
        Ok(NativePluginInstance::new(vec![endpoint]))
    }
}

#[derive(Clone)]
struct StaticSecretsProvider {
    values: BTreeMap<String, String>,
}

impl std::fmt::Debug for StaticSecretsProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StaticSecretsProvider")
            .field("references", &self.values.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl SecretsProvider for StaticSecretsProvider {
    fn resolve(
        &self,
        _context: InvocationContext,
        request: ResolveRequest,
    ) -> NativeRequestFuture<Secrets> {
        let result = self
            .values
            .get(&request.reference)
            .cloned()
            .map(|value| ResolveResponse { value })
            .ok_or(ResolveError::UnknownReference);
        Box::pin(futures::future::ready(Ok(result)))
    }
}

fn ceiling() -> ManagementCredentialCeiling {
    ManagementCredentialCeiling {
        deployment: DEPLOYMENT.into(),
        permissions: vec![
            "auth.pat.issue".into(),
            "auth.pat.list".into(),
            "auth.pat.revoke".into(),
            "notes.write".into(),
        ],
        resource_scopes: vec![ManagementResourceScope {
            kind: "deployment".into(),
            id: DEPLOYMENT.into(),
        }],
    }
}
fn public_key(key: &str) -> String {
    lenso_auth_account_plugin::assertion_public_key(key)
}
fn requirement(instance: PluginInstancePlan, cap: &str, version: &str) -> PluginInstancePlan {
    instance.with_requirement(CapabilityRequirementPlan::one(cap, version))
}
fn endpoint(
    instance: PluginInstancePlan,
    cap: &str,
    version: &str,
    ops: &[&str],
) -> PluginInstancePlan {
    instance.with_capability(CapabilityEndpointPlan::new(
        cap,
        version,
        ops.iter().copied(),
    ))
}
fn plan(schemas: &[String; 3], current: ManagementCredentialCeiling) -> ResolvedAppPlan {
    let mut bindings = Vec::new();
    let account_config = AccountAuthConfig::new(
        &schemas[0],
        "operators.account",
        public_key(ACCOUNT_KEY),
        "database",
        "account-key",
        "pepper",
        60,
    )
    .unwrap()
    .with_management_session_ceiling(current)
    .unwrap()
    .with_credential_state_callers(vec![HUMAN.into(), "test.human/browser".into()])
    .unwrap();
    let token_config = ApiTokenAuthConfig::new(
        &schemas[1],
        "operators.pat",
        public_key(API_KEY),
        "database",
        "api-key",
        "pepper",
        60,
    )
    .unwrap()
    .with_management_callers(vec![HUMAN.into()])
    .unwrap()
    .with_credential_state_callers(vec!["test.human/pat".into()])
    .unwrap();
    let acl_config = AccessControlConfig::new(
        &schemas[2],
        "database",
        "operators.account",
        public_key(ACCOUNT_KEY),
        vec!["test.human/bootstrap".into()],
    )
    .unwrap();
    let human_config = HumanApiTokenConfig::new(
        "operators",
        "operators.account",
        public_key(ACCOUNT_KEY),
        60,
        86400,
        DEPLOYMENT,
        "deployment",
        DEPLOYMENT,
        vec![
            audience("lenso.management@1", "catalog"),
            audience("lenso.management@1", "invoke"),
            audience("lenso.management@1", "status"),
        ],
    )
    .unwrap();
    let owner = |key: &str, package: &str, config: String| {
        requirement(
            PluginInstancePlan::new(key, package).with_configuration(config),
            secrets::CAPABILITY_ID,
            secrets::DESCRIPTOR_VERSION,
        )
    };
    let mut account = owner(
        "account",
        lenso_auth_account_plugin::PACKAGE_ID,
        serde_json::to_string(&account_config).unwrap(),
    );
    for (cap, version, ops) in [
        (
            auth::CAPABILITY_ID,
            auth::DESCRIPTOR_VERSION,
            vec!["authenticate"],
        ),
        (
            directory::CAPABILITY_ID,
            directory::DESCRIPTOR_VERSION,
            vec!["ensure_identity", "read_status"],
        ),
        (
            issuer::CAPABILITY_ID,
            issuer::DESCRIPTOR_VERSION,
            vec!["issue", "revoke", "revoke_credential"],
        ),
        (
            account_admin::CAPABILITY_ID,
            account_admin::DESCRIPTOR_VERSION,
            vec!["list_sessions", "list_subjects", "set_subject_status"],
        ),
        (
            delegation::CAPABILITY_ID,
            delegation::DESCRIPTOR_VERSION,
            vec!["grant"],
        ),
        (
            state::CAPABILITY_ID,
            state::DESCRIPTOR_VERSION,
            vec!["inspect"],
        ),
    ] {
        account = endpoint(account, cap, version, &ops);
    }
    let mut tokens = owner(
        "tokens",
        lenso_auth_api_token_plugin::PACKAGE_ID,
        serde_json::to_string(&token_config).unwrap(),
    );
    for (cap, version, ops) in [
        (
            auth::CAPABILITY_ID,
            auth::DESCRIPTOR_VERSION,
            vec!["authenticate"],
        ),
        (
            state::CAPABILITY_ID,
            state::DESCRIPTOR_VERSION,
            vec!["inspect"],
        ),
        (
            token_admin::CAPABILITY_ID,
            token_admin::DESCRIPTOR_VERSION,
            vec!["issue", "list", "revoke"],
        ),
    ] {
        tokens = endpoint(tokens, cap, version, &ops);
    }
    let mut acl = owner(
        "access",
        lenso_access_control_postgres_plugin::PACKAGE_ID,
        serde_json::to_string(&acl_config).unwrap(),
    );
    for (cap, version, ops) in [
        (
            access::CAPABILITY_ID,
            access::DESCRIPTOR_VERSION,
            vec!["check_permission"],
        ),
        (
            access_admin::CAPABILITY_ID,
            access_admin::DESCRIPTOR_VERSION,
            vec![
                "assign_role",
                "bootstrap_scope",
                "create_role",
                "delete_role",
                "revoke_role",
                "set_role_permissions",
            ],
        ),
        (
            access_directory::CAPABILITY_ID,
            access_directory::DESCRIPTOR_VERSION,
            vec!["get_role", "list_roles", "list_subject_roles"],
        ),
    ] {
        acl = endpoint(acl, cap, version, &ops);
    }
    let mut facade = endpoint(
        PluginInstancePlan::new(
            "lenso.auth.human-api-token/human",
            lenso_auth_human_api_token_plugin::PACKAGE_ID,
        )
        .with_configuration(serde_json::to_string(&human_config).unwrap()),
        human::CAPABILITY_ID,
        human::DESCRIPTOR_VERSION,
        &["issue", "list", "revoke"],
    );
    for (cap, version, target) in [
        (state::CAPABILITY_ID, state::DESCRIPTOR_VERSION, "account"),
        (
            token_admin::CAPABILITY_ID,
            token_admin::DESCRIPTOR_VERSION,
            "tokens",
        ),
        (access::CAPABILITY_ID, access::DESCRIPTOR_VERSION, "access"),
    ] {
        facade = requirement(facade, cap, version);
        bindings.push(CapabilityBinding::new(
            "lenso.auth.human-api-token/human",
            cap,
            version,
            target,
        ));
    }
    let mut browser = PluginInstancePlan::new("test.human/browser", CALLER_PACKAGE_ID);
    for (cap, version, target) in [
        (
            human::CAPABILITY_ID,
            human::DESCRIPTOR_VERSION,
            "lenso.auth.human-api-token/human",
        ),
        (auth::CAPABILITY_ID, auth::DESCRIPTOR_VERSION, "account"),
        (state::CAPABILITY_ID, state::DESCRIPTOR_VERSION, "account"),
        (
            token_admin::CAPABILITY_ID,
            token_admin::DESCRIPTOR_VERSION,
            "tokens",
        ),
    ] {
        browser = requirement(browser, cap, version);
        bindings.push(CapabilityBinding::new(
            "test.human/browser",
            cap,
            version,
            target,
        ));
    }
    let mut bootstrap = PluginInstancePlan::new("test.human/bootstrap", CALLER_PACKAGE_ID);
    for (cap, version, target) in [
        (auth::CAPABILITY_ID, auth::DESCRIPTOR_VERSION, "account"),
        (
            directory::CAPABILITY_ID,
            directory::DESCRIPTOR_VERSION,
            "account",
        ),
        (issuer::CAPABILITY_ID, issuer::DESCRIPTOR_VERSION, "account"),
        (
            access_admin::CAPABILITY_ID,
            access_admin::DESCRIPTOR_VERSION,
            "access",
        ),
    ] {
        bootstrap = requirement(bootstrap, cap, version);
        bindings.push(CapabilityBinding::new(
            "test.human/bootstrap",
            cap,
            version,
            target,
        ));
    }
    let mut pat = PluginInstancePlan::new("test.human/pat", CALLER_PACKAGE_ID);
    for (cap, version) in [
        (auth::CAPABILITY_ID, auth::DESCRIPTOR_VERSION),
        (state::CAPABILITY_ID, state::DESCRIPTOR_VERSION),
    ] {
        pat = requirement(pat, cap, version);
        bindings.push(CapabilityBinding::new(
            "test.human/pat",
            cap,
            version,
            "tokens",
        ));
    }
    let observer = requirement(
        PluginInstancePlan::new("test.human/observer", CALLER_PACKAGE_ID),
        state::CAPABILITY_ID,
        state::DESCRIPTOR_VERSION,
    );
    bindings.push(CapabilityBinding::new(
        "test.human/observer",
        state::CAPABILITY_ID,
        state::DESCRIPTOR_VERSION,
        "account",
    ));
    let secrets = endpoint(
        PluginInstancePlan::new("secrets", SECRETS_PACKAGE_ID),
        secrets::CAPABILITY_ID,
        secrets::DESCRIPTOR_VERSION,
        &[secrets::RESOLVE_OPERATION],
    );
    for key in ["account", "tokens", "access"] {
        bindings.push(CapabilityBinding::new(
            key,
            secrets::CAPABILITY_ID,
            secrets::DESCRIPTOR_VERSION,
            "secrets",
        ));
    }
    AppComposition::new(
        vec![
            account, tokens, acl, facade, browser, bootstrap, pat, observer, secrets,
        ],
        bindings,
    )
    .resolve()
    .unwrap()
}
async fn start(
    database: &str,
    schemas: &[String; 3],
    current: ManagementCredentialCeiling,
) -> NativeApp {
    Kernel::start_native(
        plan(schemas, current),
        TokioDriver::new(),
        NativePluginRegistry::new()
            .with_linked_factories()
            .with_factory(CallerFactory)
            .with_factory(StaticSecretsFactory {
                values: BTreeMap::from([
                    ("database".into(), database.into()),
                    ("account-key".into(), ACCOUNT_KEY.into()),
                    ("api-key".into(), API_KEY.into()),
                    ("pepper".into(), TOKEN_PEPPER.into()),
                ]),
            }),
    )
    .await
    .unwrap()
}
fn context(app: &NativeApp, assertion: &ActorAssertion) -> InvocationContext {
    assertion
        .attach(app.invocation_context(None, CancellationToken::new()))
        .unwrap()
}
async fn authenticate(
    app: &NativeApp,
    caller: &str,
    scheme: &str,
    credential: &str,
) -> ActorAssertion {
    let response = app
        .invoke::<auth::Auth>(
            caller,
            "authenticate",
            authenticate_request(Some(CredentialEvidence::new(scheme, credential))),
        )
        .await
        .unwrap()
        .unwrap();
    let AuthOutcome::Authenticated(assertion) = decode_auth_response(response).unwrap() else {
        panic!("expected actual owner authentication")
    };
    assertion
}
fn audiences() -> Vec<String> {
    [
        audience(human::CAPABILITY_ID, "issue"),
        audience(human::CAPABILITY_ID, "list"),
        audience(human::CAPABILITY_ID, "revoke"),
        audience(access_admin::CAPABILITY_ID, "assign_role"),
        audience(access_admin::CAPABILITY_ID, "create_role"),
        audience(access_admin::CAPABILITY_ID, "revoke_role"),
        audience(access_admin::CAPABILITY_ID, "set_role_permissions"),
    ]
    .to_vec()
}
async fn session(
    app: &NativeApp,
    label: &str,
    actor_kind: &str,
) -> (String, issuer::IssueResponse) {
    let directory = directory::DirectoryClient::from_dependencies(
        &app.dependencies("test.human/bootstrap").unwrap(),
    )
    .unwrap();
    let subject = directory
        .ensure_identity(directory::EnsureIdentityRequest {
            provider: "password".into(),
            external_subject: label.into(),
        })
        .await
        .unwrap()
        .subject;
    let session_issuer = issuer::CredentialIssuerClient::from_dependencies(
        &app.dependencies("test.human/bootstrap").unwrap(),
    )
    .unwrap();
    let credential = session_issuer
        .issue(issuer::IssueRequest {
            subject: subject.clone(),
            actor_kind: actor_kind.into(),
            assurance: "password".into(),
            audience: audiences(),
            claims: BTreeMap::new(),
            expires_at: (OffsetDateTime::now_utc() + Duration::hours(1))
                .format(&Rfc3339)
                .unwrap(),
        })
        .await
        .unwrap();
    (subject, credential)
}
fn issue_request(key: &str) -> human::IssueRequest {
    human::IssueRequest {
        idempotency_key: key.into(),
        name: "CLI credential".into(),
        deployment: DEPLOYMENT.into(),
        permissions: vec!["notes.write".into()],
        resource_scopes: vec![human::ResourceScope {
            kind: "deployment".into(),
            id: DEPLOYMENT.into(),
        }],
        expires_at: (OffsetDateTime::now_utc() + Duration::hours(2))
            .replace_nanosecond(0)
            .unwrap()
            .format(&Rfc3339)
            .unwrap(),
    }
}
async fn list(
    app: &NativeApp,
    assertion: &ActorAssertion,
) -> Result<human::ListResponse, human::HumanApiTokenListInvocationError> {
    human::HumanApiTokenClient::from_dependencies(&app.dependencies("test.human/browser").unwrap())
        .unwrap()
        .list_with_context(
            context(app, assertion),
            human::ListRequest {
                deployment: DEPLOYMENT.into(),
                limit: 100,
                after_credential_id: None,
            },
        )
        .await
}
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires disposable LENSO_POSTGRES_TEST_URL"]
async fn real_account_session_owns_live_human_pat_lifecycle() {
    let database = std::env::var("LENSO_POSTGRES_TEST_URL").expect("explicit disposable database");
    let schemas = [
        format!("human_account_{}", std::process::id()),
        format!("human_tokens_{}", std::process::id()),
        format!("human_access_{}", std::process::id()),
    ];
    AccountAuthOperator::setup(&database, &schemas[0])
        .await
        .unwrap();
    ApiTokenAuthOperator::setup(&database, &schemas[1])
        .await
        .unwrap();
    AccessControlOperator::setup(&database, &schemas[2])
        .await
        .unwrap();
    let account_operator = AccountAuthOperator::connect(&database, &schemas[0])
        .await
        .unwrap();
    let local = tokio::task::LocalSet::new();
    local
        .run_until(Box::pin(async {
            let app = start(&database, &schemas, ceiling()).await;
            let (root, root_session) = session(&app, "root", "user").await;
            let (alice, alice_session) = session(&app, "alice", "user").await;
            let (bob, bob_session) = session(&app, "bob", "user").await;
            let (_, machine_session) = session(&app, "machine", "service-account").await;
            let root_assertion = authenticate(
                &app,
                "test.human/bootstrap",
                "session",
                &root_session.credential,
            )
            .await;
            let alice_assertion = authenticate(
                &app,
                "test.human/browser",
                "session",
                &alice_session.credential,
            )
            .await;
            let bob_assertion = authenticate(
                &app,
                "test.human/browser",
                "session",
                &bob_session.credential,
            )
            .await;
            let binding = CredentialBinding::from_assertion(&alice_assertion).unwrap();
            assert_eq!(binding.session_id, alice_session.session_id);
            assert_eq!(binding.credential_id, binding.session_id);
            assert_ne!(binding.credential_id, alice_session.credential);
            let state = state::CredentialStateClient::from_dependencies(
                &app.dependencies("test.human/browser").unwrap(),
            )
            .unwrap();
            let current = state
                .inspect(state::InspectRequest {
                    credential_id: binding.credential_id.clone(),
                    session_id: binding.session_id.clone(),
                })
                .await
                .unwrap();
            assert!(current.active);
            assert_eq!(current.subject, alice);
            assert!(!format!("{current:?}").contains(&alice_session.credential));
            let observer = state::CredentialStateClient::from_dependencies(
                &app.dependencies("test.human/observer").unwrap(),
            )
            .unwrap();
            assert!(matches!(
                observer
                    .inspect(state::InspectRequest {
                        credential_id: binding.credential_id.clone(),
                        session_id: binding.session_id.clone()
                    })
                    .await,
                Err(state::CredentialStateInvocationError::Domain(
                    state::InspectError::PermissionDenied
                ))
            ));
            assert!(matches!(
                state
                    .inspect(state::InspectRequest {
                        credential_id: "ses_other".into(),
                        session_id: binding.session_id.clone()
                    })
                    .await,
                Err(state::CredentialStateInvocationError::Domain(
                    state::InspectError::NotFound
                ))
            ));
            let acl = access_admin::AccessControlAdminClient::from_dependencies(
                &app.dependencies("test.human/bootstrap").unwrap(),
            )
            .unwrap();
            acl.bootstrap_scope(access_admin::BootstrapScopeRequest {
                subject: root,
                scope: access_admin::BootstrapScopeRequestScope {
                    kind: "deployment".into(),
                    id: DEPLOYMENT.into(),
                },
            })
            .await
            .unwrap();
            acl.create_role_with_context(
                context(&app, &root_assertion),
                access_admin::CreateRoleRequest {
                    role_id: "operators".into(),
                    name: "Operators".into(),
                    scope: access_admin::CreateRoleRequestScope {
                        kind: "deployment".into(),
                        id: DEPLOYMENT.into(),
                    },
                },
            )
            .await
            .unwrap();
            acl.set_role_permissions_with_context(
                context(&app, &root_assertion),
                access_admin::SetRolePermissionsRequest {
                    role_id: "operators".into(),
                    permissions: ceiling().permissions,
                    scope: access_admin::SetRolePermissionsRequestScope {
                        kind: "deployment".into(),
                        id: DEPLOYMENT.into(),
                    },
                },
            )
            .await
            .unwrap();
            for subject in [&alice, &bob] {
                acl.assign_role_with_context(
                    context(&app, &root_assertion),
                    access_admin::AssignRoleRequest {
                        role_id: "operators".into(),
                        subject: subject.clone(),
                        scope: access_admin::AssignRoleRequestScope {
                            kind: "deployment".into(),
                            id: DEPLOYMENT.into(),
                        },
                    },
                )
                .await
                .unwrap();
            }
            let human = human::HumanApiTokenClient::from_dependencies(
                &app.dependencies("test.human/browser").unwrap(),
            )
            .unwrap();
            let request = issue_request("one-time");
            let issued = human
                .issue_with_context(context(&app, &alice_assertion), request.clone())
                .await
                .unwrap();
            let token = issued
                .token
                .clone()
                .flatten()
                .expect("secret only first time");
            assert!(!format!("{issued:?}").contains(&token));
            let replay = human
                .issue_with_context(context(&app, &alice_assertion), request.clone())
                .await
                .unwrap();
            assert!(replay.replayed);
            assert!(replay.token.is_none());
            assert_eq!(replay.credential, issued.credential);
            let mut changed = request.clone();
            changed.name = "Different intent".into();
            assert!(matches!(
                human
                    .issue_with_context(context(&app, &alice_assertion), changed)
                    .await,
                Err(human::HumanApiTokenIssueInvocationError::Domain(
                    human::IssueError::Conflict
                ))
            ));
            let mut expanded = issue_request("expanded");
            expanded.permissions.push("ungranted.permission".into());
            assert!(
                human
                    .issue_with_context(context(&app, &alice_assertion), expanded)
                    .await
                    .is_err()
            );
            let machine = authenticate(
                &app,
                "test.human/browser",
                "session",
                &machine_session.credential,
            )
            .await;
            assert!(matches!(
                list(&app, &machine).await,
                Err(human::HumanApiTokenListInvocationError::Domain(
                    human::ListError::PermissionDenied
                ))
            ));
            let alice_list = list(&app, &alice_assertion).await.unwrap();
            assert_eq!(alice_list.credentials.len(), 1);
            assert!(!format!("{alice_list:?}").contains(&token));
            assert!(
                list(&app, &bob_assertion)
                    .await
                    .unwrap()
                    .credentials
                    .is_empty()
            );
            assert!(matches!(
                human
                    .revoke_with_context(
                        context(&app, &bob_assertion),
                        human::RevokeRequest {
                            deployment: DEPLOYMENT.into(),
                            credential_id: issued.credential.credential_id.clone()
                        }
                    )
                    .await,
                Err(human::HumanApiTokenRevokeInvocationError::Domain(
                    human::RevokeError::NotFound
                ))
            ));
            let pat_assertion = authenticate(&app, "test.human/pat", "bearer", &token).await;
            assert_eq!(pat_assertion.subject(), alice);
            assert_eq!(
                ManagementCredentialCeiling::from_assertion(&pat_assertion)
                    .unwrap()
                    .permissions,
                vec!["notes.write"]
            );
            assert!(matches!(
                list(&app, &pat_assertion).await,
                Err(human::HumanApiTokenListInvocationError::Domain(
                    human::ListError::PermissionDenied
                ))
            ));
            let admin = token_admin::ApiTokenAdminClient::from_dependencies(
                &app.dependencies("test.human/browser").unwrap(),
            )
            .unwrap();
            assert!(matches!(
                admin
                    .list(token_admin::ListRequest {
                        subject: alice.clone(),
                        deployment: DEPLOYMENT.into(),
                        limit: 100,
                        after_credential_id: None
                    })
                    .await,
                Err(token_admin::ApiTokenAdminListInvocationError::Domain(
                    token_admin::ListError::PermissionDenied
                ))
            ));
            human
                .revoke_with_context(
                    context(&app, &alice_assertion),
                    human::RevokeRequest {
                        deployment: DEPLOYMENT.into(),
                        credential_id: issued.credential.credential_id,
                    },
                )
                .await
                .unwrap();
            assert!(
                app.invoke::<auth::Auth>(
                    "test.human/pat",
                    "authenticate",
                    authenticate_request(Some(CredentialEvidence::new("bearer", &token)))
                )
                .await
                .unwrap()
                .is_err()
            );
            let mut expiring = issue_request("expired-receipt");
            expiring.expires_at = (OffsetDateTime::now_utc() + Duration::seconds(2))
                .format(&Rfc3339)
                .unwrap();
            let first = human
                .issue_with_context(context(&app, &alice_assertion), expiring.clone())
                .await
                .unwrap();
            assert!(first.token.flatten().is_some());
            tokio::time::sleep(StdDuration::from_millis(2100)).await;
            let expired = human
                .issue_with_context(context(&app, &alice_assertion), expiring)
                .await
                .unwrap();
            assert!(expired.replayed);
            assert!(expired.token.is_none());
            assert!(!expired.credential.active);
            let session_issuer = issuer::CredentialIssuerClient::from_dependencies(
                &app.dependencies("test.human/bootstrap").unwrap(),
            )
            .unwrap();
            let mut forged = issuer::IssueRequest {
                subject: alice.clone(),
                actor_kind: "user".into(),
                assurance: "password".into(),
                audience: audiences(),
                claims: BTreeMap::from([(
                    MANAGEMENT_CEILING_CLAIM.into(),
                    serde_json::json!(ceiling()),
                )]),
                expires_at: (OffsetDateTime::now_utc() + Duration::hours(1))
                    .format(&Rfc3339)
                    .unwrap(),
            };
            assert!(matches!(
                session_issuer.issue(forged.clone()).await,
                Err(issuer::CredentialIssuerIssueInvocationError::Domain(
                    issuer::IssueError::InvalidAuthority
                ))
            ));
            forged.claims = BTreeMap::from([(
                lenso_auth_sdk::credential::CREDENTIAL_BINDING_CLAIM.into(),
                serde_json::json!({"credential_id":"fake","session_id":"fake"}),
            )]);
            assert!(session_issuer.issue(forged).await.is_err());
            session_issuer
                .revoke(issuer::RevokeRequest {
                    session_id: bob_session.session_id,
                })
                .await
                .unwrap();
            assert!(list(&app, &bob_assertion).await.is_err());
            drop(session_issuer);
            drop(acl);
            drop(state);
            drop(human);
            drop(admin);
            drop(observer);
            assert_eq!(
                app.shutdown(StdDuration::from_secs(2)).await,
                ShutdownOutcome::Clean
            );
            let mut narrowed = ceiling();
            narrowed
                .permissions
                .retain(|permission| permission != "auth.pat.issue");
            let app = start(&database, &schemas, narrowed).await;
            let human = human::HumanApiTokenClient::from_dependencies(
                &app.dependencies("test.human/browser").unwrap(),
            )
            .unwrap();
            assert!(matches!(
                human
                    .issue_with_context(
                        context(&app, &alice_assertion),
                        issue_request("after-config-narrow")
                    )
                    .await,
                Err(human::HumanApiTokenIssueInvocationError::Domain(
                    human::IssueError::PermissionDenied
                ))
            ));
            account_operator.disable_subject(&alice).await.unwrap();
            assert!(list(&app, &alice_assertion).await.is_err());
            drop(human);
            assert_eq!(
                app.shutdown(StdDuration::from_secs(2)).await,
                ShutdownOutcome::Clean
            );
        }))
        .await;
}

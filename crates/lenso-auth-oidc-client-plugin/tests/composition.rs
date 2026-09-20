use std::{cell::Cell, collections::BTreeMap, rc::Rc, time::Duration as StdDuration};

use jsonwebtoken::jwk::{Jwk, JwkSet, KeyOperations, PublicKeyUse};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use lenso_app_plan::{
    AppComposition, CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan,
    PluginInstancePlan, ResolvedAppPlan,
};
use lenso_auth_oidc_client_plugin::PACKAGE_ID;
use lenso_capability_credential_issuer as credential;
use lenso_capability_credential_issuer::{
    CredentialIssuerEndpoint, CredentialIssuerIssue, CredentialIssuerProvider,
    CredentialIssuerRevoke, CredentialIssuerRevokeCredential, IssueRequest, IssueResponse,
    RevokeCredentialError, RevokeCredentialRequest, RevokeError, RevokeRequest,
};
use lenso_capability_federated_auth as federated;
use lenso_capability_federated_auth::{
    CompleteError, CompleteRequest, FederatedComplete, StartRequest,
};
use lenso_capability_http_client as http;
use lenso_capability_http_client::{
    Client, ClientEndpoint, ClientProvider, SendError, SendRequest, SendResponse,
};
use lenso_capability_identity_directory as directory;
use lenso_capability_identity_directory::{
    DirectoryEndpoint, DirectoryEnsureIdentity, DirectoryProvider, DirectoryReadStatus,
    EnsureIdentityRequest, EnsureIdentityResponse, ReadStatusError, ReadStatusRequest,
};
use lenso_capability_oauth_flow as flow;
use lenso_capability_oauth_flow::{
    ConsumeError, ConsumeRequest, ConsumeResponse, CreateRequest, CreateResponse, OauthFlowConsume,
    OauthFlowCreate, OauthFlowEndpoint, OauthFlowProvider, OauthFlowRevoke,
    RevokeError as OAuthFlowRevokeError, RevokeRequest as OAuthFlowRevokeRequest,
    RevokeResponse as OAuthFlowRevokeResponse,
};
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{
    ResolveRequest, ResolveResponse, Secrets, SecretsEndpoint, SecretsProvider,
};
use lenso_kernel::{
    InvocationContext, Kernel, NativeRequestEndpoint, NativeRequestFuture, RuntimeFailure,
    ShutdownOutcome,
};
use lenso_native_adapter::{
    NativePluginFactory, NativePluginFactoryContext, NativePluginInstance, NativePluginRegistry,
};
use lenso_runner::TokioDriver;
use rand::rngs::OsRng;
use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePrivateKey, LineEnding},
};
use serde::Serialize;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

const CALLER_PACKAGE: &str = "test.oidc-client-caller";
const DEPENDENCIES_PACKAGE: &str = "test.oidc-client-dependencies";
const PROVIDER: &str = "work-sso";
const ISSUER: &str = "https://issuer.example/tenant";
const CLIENT_ID: &str = "lenso-console";
const NONCE: &str = "nonce-1";
const STATE: &str = "state-1";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
const CHALLENGE: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG";
#[derive(Clone, Copy, Debug)]
struct EmptyFactory;

impl NativePluginFactory for EmptyFactory {
    fn package_id(&self) -> &'static str {
        CALLER_PACKAGE
    }

    fn instantiate(
        &self,
        _: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        Ok(NativePluginInstance::default())
    }
}

#[derive(Clone, Debug)]
struct DependenciesFactory {
    token_nonce: &'static str,
    signing_key: Rc<String>,
}

impl NativePluginFactory for DependenciesFactory {
    fn package_id(&self) -> &'static str {
        DEPENDENCIES_PACKAGE
    }

    fn instantiate(
        &self,
        _: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        let dependencies = FakeDependencies {
            consumed: Rc::new(Cell::new(false)),
            revoked: Rc::new(Cell::new(false)),
            token_nonce: self.token_nonce,
            signing_key: Rc::clone(&self.signing_key),
        };
        Ok(NativePluginInstance::new(vec![
            Rc::new(SecretsEndpoint::new(dependencies.clone())) as Rc<dyn NativeRequestEndpoint>,
            Rc::new(OauthFlowEndpoint::new(dependencies.clone())) as Rc<dyn NativeRequestEndpoint>,
            Rc::new(ClientEndpoint::new(dependencies.clone())) as Rc<dyn NativeRequestEndpoint>,
            Rc::new(DirectoryEndpoint::new(dependencies.clone())) as Rc<dyn NativeRequestEndpoint>,
            Rc::new(CredentialIssuerEndpoint::new(dependencies)) as Rc<dyn NativeRequestEndpoint>,
        ]))
    }
}

#[derive(Clone, Debug)]
struct FakeDependencies {
    consumed: Rc<Cell<bool>>,
    revoked: Rc<Cell<bool>>,
    token_nonce: &'static str,
    signing_key: Rc<String>,
}

impl SecretsProvider for FakeDependencies {
    fn resolve(
        &self,
        _: InvocationContext,
        request: ResolveRequest,
    ) -> NativeRequestFuture<Secrets> {
        assert_eq!(request.reference, "oidc/client-secret");
        Box::pin(std::future::ready(Ok(Ok(ResolveResponse {
            value: "test-client-secret".to_owned(),
        }))))
    }
}

impl OauthFlowProvider for FakeDependencies {
    fn create(
        &self,
        _: InvocationContext,
        request: CreateRequest,
    ) -> NativeRequestFuture<OauthFlowCreate> {
        assert_eq!(request.provider, PROVIDER);
        assert_eq!(request.return_to, "/after-login");
        let response = CreateResponse {
            state: STATE.to_owned(),
            code_verifier: VERIFIER.to_owned(),
            code_challenge: CHALLENGE.to_owned(),
            nonce: Some(Some(NONCE.to_owned())),
            expires_at: request.expires_at,
        };
        Box::pin(std::future::ready(Ok(Ok(response))))
    }

    fn consume(
        &self,
        _: InvocationContext,
        request: ConsumeRequest,
    ) -> NativeRequestFuture<OauthFlowConsume> {
        if request.provider != PROVIDER || request.state != STATE {
            return Box::pin(std::future::ready(Ok(Err(ConsumeError::InvalidState))));
        }
        if self.consumed.replace(true) {
            return Box::pin(std::future::ready(Ok(Err(ConsumeError::AlreadyConsumed))));
        }
        Box::pin(std::future::ready(Ok(Ok(ConsumeResponse {
            code_verifier: VERIFIER.to_owned(),
            nonce: Some(Some(NONCE.to_owned())),
            return_to: "/after-login".to_owned(),
            expires_at: future_time(300),
        }))))
    }

    fn revoke(
        &self,
        _: InvocationContext,
        request: OAuthFlowRevokeRequest,
    ) -> NativeRequestFuture<OauthFlowRevoke> {
        if request.provider != PROVIDER || request.state != STATE {
            return Box::pin(std::future::ready(Ok(Err(
                OAuthFlowRevokeError::InvalidState,
            ))));
        }
        if self.consumed.get() {
            return Box::pin(std::future::ready(Ok(Err(
                OAuthFlowRevokeError::AlreadyConsumed,
            ))));
        }
        if self.revoked.replace(true) {
            return Box::pin(std::future::ready(Ok(Err(
                OAuthFlowRevokeError::AlreadyRevoked,
            ))));
        }
        Box::pin(std::future::ready(Ok(Ok(OAuthFlowRevokeResponse {}))))
    }
}

impl ClientProvider for FakeDependencies {
    fn send(&self, _: InvocationContext, request: SendRequest) -> NativeRequestFuture<Client> {
        let response = match (request.method.as_str(), request.url.as_str()) {
            ("POST", "https://issuer.example/token") => {
                let body = String::from_utf8(request.body.into_vec()).unwrap();
                let form = url::form_urlencoded::parse(body.as_bytes())
                    .into_owned()
                    .collect::<BTreeMap<_, _>>();
                assert_eq!(
                    form.get("grant_type").map(String::as_str),
                    Some("authorization_code")
                );
                assert_eq!(
                    form.get("code").map(String::as_str),
                    Some("authorization-code")
                );
                assert_eq!(form.get("client_id").map(String::as_str), Some(CLIENT_ID));
                assert_eq!(
                    form.get("client_secret").map(String::as_str),
                    Some("test-client-secret")
                );
                assert_eq!(
                    form.get("code_verifier").map(String::as_str),
                    Some(VERIFIER)
                );
                SendResponse {
                    status: 200,
                    headers: vec![],
                    body: serde_json::to_vec(
                        &serde_json::json!({"id_token": id_token(self.token_nonce, &self.signing_key)}),
                    )
                    .unwrap()
                    .into(),
                }
            }
            ("GET", "https://issuer.example/jwks") => SendResponse {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&jwks(&self.signing_key)).unwrap().into(),
            },
            _ => {
                return Box::pin(std::future::ready(Ok(Err(
                    SendError::DestinationNotAllowed,
                ))));
            }
        };
        Box::pin(std::future::ready(Ok(Ok(response))))
    }
}

impl DirectoryProvider for FakeDependencies {
    fn ensure_identity(
        &self,
        _: InvocationContext,
        request: EnsureIdentityRequest,
    ) -> NativeRequestFuture<DirectoryEnsureIdentity> {
        assert_eq!(request.provider, PROVIDER);
        assert_eq!(request.external_subject, "external-user-1");
        Box::pin(std::future::ready(Ok(Ok(EnsureIdentityResponse {
            subject: "usr_1".to_owned(),
            created: true,
        }))))
    }

    fn read_status(
        &self,
        _: InvocationContext,
        _: ReadStatusRequest,
    ) -> NativeRequestFuture<DirectoryReadStatus> {
        Box::pin(std::future::ready(Ok(Err(ReadStatusError::NotFound))))
    }
}

impl CredentialIssuerProvider for FakeDependencies {
    fn issue(
        &self,
        _: InvocationContext,
        request: IssueRequest,
    ) -> NativeRequestFuture<CredentialIssuerIssue> {
        assert_eq!(request.subject, "usr_1");
        assert_eq!(request.actor_kind, "user");
        assert_eq!(request.assurance, "oidc");
        assert_eq!(request.audience, ["console.app@1"]);
        assert_eq!(
            request
                .claims
                .get("oidc_issuer")
                .and_then(serde_json::Value::as_str),
            Some(ISSUER)
        );
        Box::pin(std::future::ready(Ok(Ok(IssueResponse {
            session_id: "ses_1".to_owned(),
            credential: "session-credential".to_owned(),
            expires_at: request.expires_at,
        }))))
    }

    fn revoke(
        &self,
        _: InvocationContext,
        _: RevokeRequest,
    ) -> NativeRequestFuture<CredentialIssuerRevoke> {
        Box::pin(std::future::ready(Ok(Err(RevokeError::NotFound))))
    }

    fn revoke_credential(
        &self,
        _: InvocationContext,
        _: RevokeCredentialRequest,
    ) -> NativeRequestFuture<CredentialIssuerRevokeCredential> {
        Box::pin(std::future::ready(Ok(Err(RevokeCredentialError::NotFound))))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn bound_providers_complete_a_strict_oidc_login_once() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let app = Kernel::start_native(plan(), TokioDriver::new(), registry(NONCE))
                .await
                .unwrap();

            let started = app
                .invoke::<federated::FederatedStart>(
                    "caller",
                    federated::START_OPERATION,
                    StartRequest {
                        return_to: "/after-login".to_owned(),
                    },
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(started.provider, PROVIDER);
            let authorization_url = Url::parse(&started.authorization_url).unwrap();
            let query = authorization_url
                .query_pairs()
                .into_owned()
                .collect::<BTreeMap<_, _>>();
            assert_eq!(query.get("state").map(String::as_str), Some(STATE));
            assert_eq!(query.get("nonce").map(String::as_str), Some(NONCE));
            assert_eq!(
                query.get("code_challenge").map(String::as_str),
                Some(CHALLENGE)
            );
            assert_eq!(
                query.get("code_challenge_method").map(String::as_str),
                Some("S256")
            );

            let completed = complete(&app).await.unwrap();
            assert_eq!(completed.provider, PROVIDER);
            assert_eq!(completed.subject, "usr_1");
            assert_eq!(completed.session_id, "ses_1");
            assert_eq!(completed.credential, "session-credential");
            assert_eq!(completed.return_to, "/after-login");

            assert_eq!(
                complete(&app).await.unwrap_err(),
                CompleteError::InvalidState
            );
            assert_eq!(
                app.shutdown(StdDuration::from_secs(2)).await,
                ShutdownOutcome::Clean
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn bound_provider_nonce_mismatch_is_rejected_after_single_use_consume() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let app = Kernel::start_native(plan(), TokioDriver::new(), registry("different-nonce"))
                .await
                .unwrap();
            app.invoke::<federated::FederatedStart>(
                "caller",
                federated::START_OPERATION,
                StartRequest {
                    return_to: "/after-login".to_owned(),
                },
            )
            .await
            .unwrap()
            .unwrap();

            assert_eq!(
                complete(&app).await.unwrap_err(),
                CompleteError::ProviderRejected
            );
            assert_eq!(
                complete(&app).await.unwrap_err(),
                CompleteError::InvalidState
            );
            assert_eq!(
                app.shutdown(StdDuration::from_secs(2)).await,
                ShutdownOutcome::Clean
            );
        })
        .await;
}

async fn complete(
    app: &lenso_kernel::NativeApp,
) -> Result<federated::CompleteResponse, CompleteError> {
    app.invoke::<FederatedComplete>(
        "caller",
        federated::COMPLETE_OPERATION,
        CompleteRequest {
            code: "authorization-code".to_owned(),
            state: STATE.to_owned(),
        },
    )
    .await
    .unwrap()
}

fn registry(token_nonce: &'static str) -> NativePluginRegistry {
    NativePluginRegistry::new()
        .with_linked_factories()
        .with_factory(EmptyFactory)
        .with_factory(DependenciesFactory {
            token_nonce,
            signing_key: Rc::new(test_rsa_key()),
        })
}

#[allow(clippy::too_many_lines)]
fn plan() -> ResolvedAppPlan {
    let caller = PluginInstancePlan::new("caller", CALLER_PACKAGE).with_requirement(
        CapabilityRequirementPlan::one(federated::CAPABILITY_ID, federated::DESCRIPTOR_VERSION),
    );
    let client = PluginInstancePlan::new("oidc-client", PACKAGE_ID)
        .with_configuration(
            serde_json::json!({
                "provider": PROVIDER,
                "issuer": ISSUER,
                "authorization_endpoint": "https://issuer.example/authorize",
                "token_endpoint": "https://issuer.example/token",
                "jwks_uri": "https://issuer.example/jwks",
                "client_id": CLIENT_ID,
                "client_secret_ref": "oidc/client-secret",
                "redirect_uri": "https://console.example/auth/oidc/callback",
                "scopes": ["openid", "profile"],
                "audience": ["console.app@1"],
                "flow_ttl_seconds": 300,
                "session_ttl_seconds": 3600
            })
            .to_string(),
        )
        .with_requirement(CapabilityRequirementPlan::one(
            secrets::CAPABILITY_ID,
            secrets::DESCRIPTOR_VERSION,
        ))
        .with_requirement(CapabilityRequirementPlan::one(
            flow::CAPABILITY_ID,
            flow::DESCRIPTOR_VERSION,
        ))
        .with_requirement(CapabilityRequirementPlan::one(
            http::CAPABILITY_ID,
            http::DESCRIPTOR_VERSION,
        ))
        .with_requirement(CapabilityRequirementPlan::one(
            directory::CAPABILITY_ID,
            directory::DESCRIPTOR_VERSION,
        ))
        .with_requirement(CapabilityRequirementPlan::one(
            credential::CAPABILITY_ID,
            credential::DESCRIPTOR_VERSION,
        ))
        .with_capability(CapabilityEndpointPlan::new(
            federated::CAPABILITY_ID,
            federated::DESCRIPTOR_VERSION,
            [federated::COMPLETE_OPERATION, federated::START_OPERATION],
        ));
    let dependencies = PluginInstancePlan::new("dependencies", DEPENDENCIES_PACKAGE)
        .with_capability(CapabilityEndpointPlan::new(
            secrets::CAPABILITY_ID,
            secrets::DESCRIPTOR_VERSION,
            [secrets::RESOLVE_OPERATION],
        ))
        .with_capability(CapabilityEndpointPlan::new(
            flow::CAPABILITY_ID,
            flow::DESCRIPTOR_VERSION,
            [
                flow::CONSUME_OPERATION,
                flow::CREATE_OPERATION,
                flow::REVOKE_OPERATION,
            ],
        ))
        .with_capability(CapabilityEndpointPlan::new(
            http::CAPABILITY_ID,
            http::DESCRIPTOR_VERSION,
            [http::SEND_OPERATION],
        ))
        .with_capability(CapabilityEndpointPlan::new(
            directory::CAPABILITY_ID,
            directory::DESCRIPTOR_VERSION,
            [
                directory::ENSURE_IDENTITY_OPERATION,
                directory::READ_STATUS_OPERATION,
            ],
        ))
        .with_capability(CapabilityEndpointPlan::new(
            credential::CAPABILITY_ID,
            credential::DESCRIPTOR_VERSION,
            [
                credential::ISSUE_OPERATION,
                credential::REVOKE_OPERATION,
                credential::REVOKE_CREDENTIAL_OPERATION,
            ],
        ));
    let mut bindings = vec![CapabilityBinding::new(
        "caller",
        federated::CAPABILITY_ID,
        federated::DESCRIPTOR_VERSION,
        "oidc-client",
    )];
    for (capability, version) in [
        (secrets::CAPABILITY_ID, secrets::DESCRIPTOR_VERSION),
        (flow::CAPABILITY_ID, flow::DESCRIPTOR_VERSION),
        (http::CAPABILITY_ID, http::DESCRIPTOR_VERSION),
        (directory::CAPABILITY_ID, directory::DESCRIPTOR_VERSION),
        (credential::CAPABILITY_ID, credential::DESCRIPTOR_VERSION),
    ] {
        bindings.push(CapabilityBinding::new(
            "oidc-client",
            capability,
            version,
            "dependencies",
        ));
    }
    AppComposition::new(vec![caller, client, dependencies], bindings)
        .resolve()
        .unwrap()
}

#[derive(Serialize)]
struct TestClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: u64,
    iat: u64,
    nonce: &'a str,
}

fn id_token(nonce: &str, signing_key: &str) -> String {
    let now = u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".to_owned());
    header.typ = Some("JWT".to_owned());
    encode(
        &header,
        &TestClaims {
            iss: ISSUER,
            sub: "external-user-1",
            aud: CLIENT_ID,
            exp: now + 300,
            iat: now,
            nonce,
        },
        &EncodingKey::from_rsa_pem(signing_key.as_bytes()).unwrap(),
    )
    .unwrap()
}

fn jwks(signing_key: &str) -> JwkSet {
    let encoding_key = EncodingKey::from_rsa_pem(signing_key.as_bytes()).unwrap();
    let mut key = Jwk::from_encoding_key(&encoding_key, Algorithm::RS256).unwrap();
    key.common.key_id = Some("test-key".to_owned());
    key.common.public_key_use = Some(PublicKeyUse::Signature);
    key.common.key_operations = Some(vec![KeyOperations::Verify]);
    JwkSet { keys: vec![key] }
}

fn test_rsa_key() -> String {
    RsaPrivateKey::new(&mut OsRng, 2_048)
        .unwrap()
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap()
        .to_string()
}

fn future_time(seconds: i64) -> String {
    (OffsetDateTime::now_utc() + Duration::seconds(seconds))
        .format(&Rfc3339)
        .unwrap()
}

//! A small, generated App business Plugin used only by the local G4 composition
//! cohort. It deliberately owns no Auth state: the real Router-selected Auth
//! capability remains the source of truth for its session decision.

use lenso::Port;
use lenso_auth_sdk::{AuthOutcome, decode_auth_response};
use lenso_capability_auth as auth;
use lenso_capability_http_endpoint::{
    self as http_endpoint_contract, EndpointHandleInvocationError, HandleRequest, HandleResponse,
    endpoint,
    response::{self, StatusCode},
};
use lenso_kernel::InvocationContext;
use serde_json::json;

#[lenso::plugin]
#[derive(Clone, Debug)]
struct SessionBusinessPlugin {
    auth: Port<auth::AuthClient>,
}

#[endpoint]
impl SessionBusinessPlugin {
    /// A bounded business read whose success proves Web Ingress selected this
    /// Plugin and its Auth Port accepted the App-owned session credential.
    #[get("proof.business.session", "/auth/proof/business/session")]
    async fn read_session(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let Some(credential) = request
            .credential
            .filter(|credential| credential.scheme == "session")
        else {
            return Ok(response::problem(
                StatusCode::UNAUTHORIZED,
                "session_required",
                "A valid App session is required for this business read.",
            ));
        };
        let outcome = self
            .auth
            .authenticate_with_context(
                context,
                auth::AuthRequest {
                    credential: Some(auth::AuthenticateRequestCredential {
                        scheme: "session".into(),
                        value: credential.value,
                    }),
                },
            )
            .await;
        match outcome {
            Ok(value) => match decode_auth_response(value) {
                Ok(AuthOutcome::Authenticated(_)) => Ok(response::json(
                    StatusCode::OK,
                    &json!({"business":"session-read","authenticated":true}),
                )?),
                Ok(_) | Err(_) => Ok(response::problem(
                    StatusCode::UNAUTHORIZED,
                    "session_rejected",
                    "The App session was not accepted.",
                )),
            },
            Err(auth::AuthInvocationError::Domain(_)) => Ok(response::problem(
                StatusCode::UNAUTHORIZED,
                "session_rejected",
                "The App session was not accepted.",
            )),
            Err(auth::AuthInvocationError::Runtime(error)) => {
                Err(EndpointHandleInvocationError::Runtime(error))
            }
        }
    }
}

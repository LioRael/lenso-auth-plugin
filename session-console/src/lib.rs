//! Optional global UI consumer of Auth's existing managed-session transport.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use lenso::prelude::*;
use lenso_capability_ui_global_contribution as global;
use serde::Deserialize;

const MODULE: &str = include_str!("../dist/session.mjs");

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionConsoleConfig {
    session_cookie_name: String,
    csrf_cookie_name: String,
}

fn validate(config: &SessionConsoleConfig) -> Result<(), lenso_kernel::RuntimeFailure> {
    let name = |name: &str| {
        name.starts_with("__Host-")
            && name.len() > 7
            && name.len() <= 128
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    };
    if !name(&config.session_cookie_name)
        || !name(&config.csrf_cookie_name)
        || config.session_cookie_name == config.csrf_cookie_name
    {
        return Err(lenso_kernel::RuntimeFailure::InvalidResolvedPlan {
            detail: "Auth session surface requires distinct __Host- session/CSRF Cookie names"
                .into(),
        });
    }
    Ok(())
}

#[lenso::plugin(configuration_schema = "config.schema.json", validate = validate)]
#[derive(Clone, Debug)]
struct SessionConsole {
    #[config]
    config: SessionConsoleConfig,
}

#[lenso::provides(global::GlobalContribution)]
impl SessionConsole {
    async fn describe_contribution(
        &self,
        _context: Ctx,
        _request: global::DescribeContributionRequest,
    ) -> Result<global::DescribeContributionResponse, PluginError<global::DescribeContributionError>>
    {
        let config = serde_json::json!({"csrfCookieName": self.config.csrf_cookie_name, "csrfHeaderName": "x-csrf-token"});
        let module = format!(
            "const LENSO_SESSION_CONFIG = {};\n{}",
            serde_json::to_string(&config).expect("public JSON configuration"),
            MODULE
        );
        serde_json::from_value(serde_json::json!({
            "workspace_id": "session", "subject": {"kind":"console","app_id":null},
            "title": "Session", "revision": "1", "module": "session.mjs", "styles": [],
            "navigation": {"label":"Session","items":[]}, "requirements": [],
            "assets": [{"path":"session.mjs","media_type":"text/javascript; charset=utf-8","content_base64":STANDARD.encode(module)}],
        })).map_err(|_| PluginError::runtime(lenso_kernel::RuntimeFailure::PluginFailure { detail: "Auth session contribution encoding failed".into() }))
    }
}

pub fn link() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_names_match_existing_renewal_transport() {
        let mut config = SessionConsoleConfig {
            session_cookie_name: "__Host-session".into(),
            csrf_cookie_name: "__Host-csrf".into(),
        };
        assert!(validate(&config).is_ok());
        config.csrf_cookie_name = "__Host-custom.csrf".into();
        assert!(validate(&config).is_err());
        config.csrf_cookie_name = format!("__Host-{}", "a".repeat(121));
        assert!(validate(&config).is_ok());
        config.csrf_cookie_name.push('a');
        assert!(validate(&config).is_err());
        config.csrf_cookie_name = "__Host-csrf".into();
        config.session_cookie_name = "__Host-custom.session".into();
        assert!(validate(&config).is_err());
    }
}

use std::{collections::BTreeMap, env, error::Error};

use lenso_auth_api_token_plugin::{ApiTokenAuthOperator, IssueApiToken, assertion_public_key};
use serde_json::json;
use time::{Duration, OffsetDateTime};

const DATABASE_URL_ENV: &str = "LENSO_AUTH_DATABASE_URL";
const SIGNING_SECRET_ENV: &str = "LENSO_AUTH_SIGNING_SECRET";
const TOKEN_PEPPER_ENV: &str = "LENSO_AUTH_TOKEN_PEPPER";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);
    let command = arguments.next().ok_or("missing command")?;
    match command.as_str() {
        "public-key" => {
            reject_extra(arguments)?;
            println!(
                "{}",
                assertion_public_key(required_env(SIGNING_SECRET_ENV)?)
            );
        }
        "setup" | "upgrade" => {
            let schema = arguments.next().ok_or("missing schema")?;
            reject_extra(arguments)?;
            let database_url = required_env(DATABASE_URL_ENV)?;
            if command == "setup" {
                ApiTokenAuthOperator::setup(&database_url, &schema).await?;
            } else {
                ApiTokenAuthOperator::upgrade(&database_url, &schema).await?;
            }
        }
        "issue" => {
            let schema = arguments.next().ok_or("missing schema")?;
            let subject = arguments.next().ok_or("missing subject")?;
            let audience = arguments.collect::<Vec<_>>();
            if audience.is_empty() {
                return Err("at least one audience is required".into());
            }
            let database_url = required_env(DATABASE_URL_ENV)?;
            let token_pepper = required_env(TOKEN_PEPPER_ENV)?;
            let operator = ApiTokenAuthOperator::connect(&database_url, &schema).await?;
            let issued = operator
                .issue(
                    token_pepper.as_bytes(),
                    IssueApiToken {
                        subject,
                        actor_kind: "user".to_owned(),
                        assurance: "api-token".to_owned(),
                        audience,
                        claims: BTreeMap::new(),
                        expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
                    },
                )
                .await?;
            println!(
                "{}",
                json!({
                    "session_id": issued.session_id(),
                    "token": issued.expose_secret(),
                    "token_id": issued.token_id(),
                })
            );
        }
        _ => return Err(format!("unknown command `{command}`").into()),
    }
    Ok(())
}

fn required_env(name: &str) -> Result<String, Box<dyn Error>> {
    env::var(name).map_err(|_| {
        format!("{name} must be set; secret values are never accepted as arguments").into()
    })
}

fn reject_extra(mut arguments: impl Iterator<Item = String>) -> Result<(), Box<dyn Error>> {
    if arguments.next().is_some() {
        return Err("unexpected extra argument".into());
    }
    Ok(())
}

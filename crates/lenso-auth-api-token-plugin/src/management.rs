use crate::ApiTokenAuthPlugin;
#[cfg(feature = "postgres")]
use crate::{PreparedAuth, operator::random_identifier, storage::ApiTokenStore};
#[cfg(feature = "postgres")]
use lenso_auth_sdk::credential::{
    MANAGEMENT_CEILING_CLAIM, ManagementCredentialCeiling, ManagementResourceScope,
};
use lenso_capability_api_token_admin as admin;
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
#[cfg(feature = "postgres")]
use sha2::{Digest, Sha256};
#[cfg(feature = "postgres")]
use sqlx::{Row, types::Json};
#[cfg(feature = "postgres")]
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

impl ApiTokenAuthPlugin {
    fn management_permitted(&self, context: &InvocationContext) -> bool {
        context.caller_instance().is_some_and(|caller| {
            self.config
                .management_callers
                .iter()
                .any(|allowed| allowed == caller)
        })
    }
    #[cfg_attr(not(feature = "postgres"), allow(clippy::needless_pass_by_value))]
    pub(crate) fn issue(
        &self,
        context: InvocationContext,
        request: admin::IssueRequest,
    ) -> NativeRequestFuture<admin::ApiTokenAdminIssue> {
        let allowed = self.management_permitted(&context);
        let prepared = self.state.borrow().clone();
        Box::pin(async move {
            if !allowed {
                return Ok(Err(admin::IssueError::PermissionDenied));
            }
            let prepared = prepared.ok_or_else(unprepared)?;
            #[cfg(feature = "postgres")]
            #[allow(irrefutable_let_patterns)]
            if let ApiTokenStore::Postgres(postgres) = &prepared.store {
                return issue(
                    postgres,
                    &prepared,
                    context.caller_instance().expect("permitted exact caller"),
                    request,
                )
                .await;
            }
            let _ = (prepared, request);
            Ok(Err(admin::IssueError::UnsupportedProfile))
        })
    }
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn list(
        &self,
        context: InvocationContext,
        request: admin::ListRequest,
    ) -> NativeRequestFuture<admin::ApiTokenAdminList> {
        let allowed = self.management_permitted(&context);
        let prepared = self.state.borrow().clone();
        Box::pin(async move {
            if !allowed {
                return Ok(Err(admin::ListError::PermissionDenied));
            }
            let prepared = prepared.ok_or_else(unprepared)?;
            #[cfg(feature = "postgres")]
            #[allow(irrefutable_let_patterns)]
            if let ApiTokenStore::Postgres(postgres) = &prepared.store {
                if !crate::valid_identity(&request.subject)
                    || !crate::valid_identity(&request.deployment)
                    || !(1..=100).contains(&request.limit)
                    || request
                        .after_credential_id
                        .as_ref()
                        .and_then(Option::as_ref)
                        .is_some_and(|id| !crate::valid_identity(id))
                {
                    return Ok(Err(admin::ListError::InvalidRequest));
                }
                let rows = sqlx::query("SELECT t.token_id,COALESCE(i.name,'Operator-issued token') AS name,s.claims,LEAST(s.expires_at,t.expires_at) AS expires_at,(s.revoked_at IS NOT NULL OR t.revoked_at IS NOT NULL) AS revoked FROM api_tokens t JOIN auth_sessions s ON s.session_id=t.session_id LEFT JOIN management_token_issuances i ON i.token_id=t.token_id WHERE s.subject=$1 AND s.actor_kind='user' AND s.claims->'lenso.auth.management-ceiling'->>'deployment'=$2 AND ($3::text IS NULL OR t.token_id>$3) ORDER BY t.token_id LIMIT $4")
                    .bind(&request.subject).bind(&request.deployment).bind(request.after_credential_id.flatten()).bind(request.limit).fetch_all(postgres.pool()).await.map_err(database)?;
                return Ok(Ok(admin::ListResponse {
                    credentials: rows.iter().map(metadata).collect::<Result<_, _>>()?,
                }));
            }
            let _ = (prepared, request);
            Ok(Err(admin::ListError::UnsupportedProfile))
        })
    }
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn revoke(
        &self,
        context: InvocationContext,
        request: admin::RevokeRequest,
    ) -> NativeRequestFuture<admin::ApiTokenAdminRevoke> {
        let allowed = self.management_permitted(&context);
        let prepared = self.state.borrow().clone();
        Box::pin(async move {
            if !allowed {
                return Ok(Err(admin::RevokeError::PermissionDenied));
            }
            let prepared = prepared.ok_or_else(unprepared)?;
            #[cfg(feature = "postgres")]
            #[allow(irrefutable_let_patterns)]
            if let ApiTokenStore::Postgres(postgres) = &prepared.store {
                if !crate::valid_identity(&request.subject)
                    || !crate::valid_identity(&request.deployment)
                    || !crate::valid_identity(&request.credential_id)
                {
                    return Ok(Err(admin::RevokeError::InvalidRequest));
                }
                let result = sqlx::query("UPDATE api_tokens t SET revoked_at=COALESCE(t.revoked_at,transaction_timestamp()) FROM auth_sessions s WHERE t.session_id=s.session_id AND t.token_id=$1 AND s.subject=$2 AND s.actor_kind='user' AND s.claims->'lenso.auth.management-ceiling'->>'deployment'=$3")
                    .bind(&request.credential_id).bind(&request.subject).bind(&request.deployment).execute(postgres.pool()).await.map_err(database)?;
                return if result.rows_affected() == 1 {
                    Ok(Ok(admin::RevokeResponse { revoked: true }))
                } else {
                    Ok(Err(admin::RevokeError::NotFound))
                };
            }
            let _ = (prepared, request);
            Ok(Err(admin::RevokeError::UnsupportedProfile))
        })
    }
}
fn unprepared() -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: "API Token Auth is not prepared".into(),
    }
}
#[cfg(feature = "postgres")]
fn database(_source: sqlx::Error) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail:
            "API Token management storage is unavailable; reconcile by the same idempotency key"
                .into(),
    }
}

#[cfg(feature = "postgres")]
#[derive(Debug)]
struct NormalizedIssue {
    ceiling: ManagementCredentialCeiling,
    expires_at: OffsetDateTime,
    expiry: String,
    digest: String,
}
#[cfg(feature = "postgres")]
fn normalize_issue(request: &mut admin::IssueRequest) -> Option<NormalizedIssue> {
    let mut ceiling = ManagementCredentialCeiling {
        deployment: request.deployment.clone(),
        permissions: request.permissions.clone(),
        resource_scopes: request
            .resource_scopes
            .iter()
            .map(|scope| ManagementResourceScope {
                kind: scope.kind.clone(),
                id: scope.id.clone(),
            })
            .collect(),
    };
    let expires_at = OffsetDateTime::parse(&request.expires_at, &Rfc3339).ok()?;
    if !crate::valid_identity(&request.subject)
        || !crate::valid_identity(&request.idempotency_key)
        || request.idempotency_key.len() > 128
        || request.name.trim().is_empty()
        || request.name.chars().count() > 128
        || request.name.chars().any(char::is_control)
        || ceiling.validate().is_err()
        || request.audience.is_empty()
        || request.audience.len() > 64
        || request
            .audience
            .iter()
            .any(|aud| aud.is_empty() || aud.len() > 256)
        || request
            .audience
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != request.audience.len()
    {
        return None;
    }
    ceiling.permissions.sort();
    ceiling.resource_scopes.sort();
    request.audience.sort();
    let expires_at = expires_at
        .replace_nanosecond(expires_at.nanosecond() / 1000 * 1000)
        .expect("valid microsecond precision");
    let expiry = expires_at.format(&Rfc3339).ok()?;
    let intent = serde_json::json!({"subject":request.subject,"name":request.name,"ceiling":ceiling,"audience":request.audience,"expires_at":expiry});
    let digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&intent).expect("intent serializes"))
    );
    Some(NormalizedIssue {
        ceiling,
        expires_at,
        expiry,
        digest,
    })
}

#[cfg(feature = "postgres")]
async fn issue(
    postgres: &lenso_postgres_kit::OwnedPostgres,
    prepared: &PreparedAuth,
    caller: &str,
    mut request: admin::IssueRequest,
) -> Result<Result<admin::IssueResponse, admin::IssueError>, RuntimeFailure> {
    let Some(NormalizedIssue {
        ceiling,
        expires_at,
        expiry,
        digest,
    }) = normalize_issue(&mut request)
    else {
        return Ok(Err(admin::IssueError::InvalidRequest));
    };
    let lock_key = serde_json::to_string(&(caller, &request.subject, &request.idempotency_key))
        .expect("key serializes");
    let mut tx = postgres.pool().begin().await.map_err(database)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(lock_key)
        .execute(&mut *tx)
        .await
        .map_err(database)?;
    let previous=sqlx::query("SELECT i.intent_digest,t.token_id,i.name,s.claims,LEAST(s.expires_at,t.expires_at) AS expires_at,(s.revoked_at IS NOT NULL OR t.revoked_at IS NOT NULL) AS revoked FROM management_token_issuances i JOIN api_tokens t ON t.token_id=i.token_id JOIN auth_sessions s ON s.session_id=t.session_id WHERE i.caller_instance=$1 AND i.subject=$2 AND i.idempotency_key=$3")
        .bind(caller).bind(&request.subject).bind(&request.idempotency_key).fetch_optional(&mut *tx).await.map_err(database)?;
    if let Some(row) = previous {
        let old: String = row.try_get("intent_digest").map_err(database)?;
        return if old == digest {
            Ok(Ok(admin::IssueResponse {
                credential: metadata(&row)?,
                token: None,
                replayed: true,
            }))
        } else {
            Ok(Err(admin::IssueError::Conflict))
        };
    }
    let now = OffsetDateTime::now_utc();
    if expires_at <= now || expires_at > now + time::Duration::days(365) {
        return Ok(Err(admin::IssueError::InvalidRequest));
    }
    let secret = random_identifier("lenso_at_", 32).map_err(|_| unprepared())?;
    let token_id = random_identifier("tok_", 16).map_err(|_| unprepared())?;
    let session_id = random_identifier("ses_", 16).map_err(|_| unprepared())?;
    let token_digest =
        crate::storage::token_digest(&prepared.token_pepper, &secret).map_err(|_| unprepared())?;
    let claims = serde_json::json!({MANAGEMENT_CEILING_CLAIM:ceiling});
    sqlx::query("INSERT INTO auth_sessions(session_id,subject,actor_kind,assurance,audience,claims,expires_at) VALUES($1,$2,'user','personal-api-token',$3,$4,$5)")
        .bind(&session_id).bind(&request.subject).bind(&request.audience).bind(Json(&claims)).bind(expires_at).execute(&mut *tx).await.map_err(database)?;
    sqlx::query(
        "INSERT INTO api_tokens(token_id,token_digest,session_id,expires_at) VALUES($1,$2,$3,$4)",
    )
    .bind(&token_id)
    .bind(token_digest)
    .bind(&session_id)
    .bind(expires_at)
    .execute(&mut *tx)
    .await
    .map_err(database)?;
    sqlx::query("INSERT INTO management_token_issuances(caller_instance,subject,idempotency_key,intent_digest,token_id,name) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(caller).bind(&request.subject).bind(&request.idempotency_key).bind(digest).bind(&token_id).bind(&request.name).execute(&mut *tx).await.map_err(database)?;
    tx.commit().await.map_err(database)?;
    Ok(Ok(admin::IssueResponse {
        credential: admin::CredentialMetadata {
            credential_id: token_id,
            name: request.name,
            deployment: ceiling.deployment,
            permissions: ceiling.permissions,
            resource_scopes: ceiling
                .resource_scopes
                .into_iter()
                .map(|scope| admin::ResourceScope {
                    kind: scope.kind,
                    id: scope.id,
                })
                .collect(),
            expires_at: expiry,
            active: true,
        },
        token: Some(Some(secret)),
        replayed: false,
    }))
}
#[cfg(feature = "postgres")]
fn metadata(row: &sqlx::postgres::PgRow) -> Result<admin::CredentialMetadata, RuntimeFailure> {
    let claims: Json<std::collections::BTreeMap<String, serde_json::Value>> =
        row.try_get("claims").map_err(database)?;
    let ceiling = ManagementCredentialCeiling::from_claims(&claims.0).map_err(|_| unprepared())?;
    let expiry: OffsetDateTime = row.try_get("expires_at").map_err(database)?;
    let revoked: bool = row.try_get("revoked").map_err(database)?;
    Ok(admin::CredentialMetadata {
        credential_id: row.try_get("token_id").map_err(database)?,
        name: row.try_get("name").map_err(database)?,
        deployment: ceiling.deployment,
        permissions: ceiling.permissions,
        resource_scopes: ceiling
            .resource_scopes
            .into_iter()
            .map(|scope| admin::ResourceScope {
                kind: scope.kind,
                id: scope.id,
            })
            .collect(),
        expires_at: expiry.format(&Rfc3339).map_err(|_| unprepared())?,
        active: !revoked && expiry > OffsetDateTime::now_utc(),
    })
}

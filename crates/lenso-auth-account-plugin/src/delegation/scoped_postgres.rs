use super::{
    Duration, InvocationContext, ManagementCredentialCeiling, OffsetDateTime, RuntimeFailure,
    SCOPED_DELEGATION_CLAIM, ScopedDelegationBinding, ScopedParent, random_id, random_token,
    requested_ceiling, runtime, scoped, storage,
};
use lenso_auth_sdk::credential::MANAGEMENT_CEILING_CLAIM;
use lenso_postgres_kit::OwnedPostgres;
use sqlx::Row;

fn db(_: sqlx::Error) -> RuntimeFailure {
    runtime("scoped delegation storage failed")
}
fn metadata(
    row: &sqlx::postgres::PgRow,
) -> Result<scoped::ScopedDelegationMetadata, RuntimeFailure> {
    let mut metadata: scoped::ScopedDelegationMetadata =
        serde_json::from_value(row.try_get("metadata").map_err(db)?).map_err(runtime)?;
    metadata.active = row.try_get("active").map_err(db)?;
    Ok(metadata)
}
const RECEIPT_QUERY: &str = "SELECT r.intent,r.metadata,r.parent_session_id,((i.status <> 'disabled' OR (i.disabled_until IS NOT NULL AND i.disabled_until<=transaction_timestamp())) AND s.revoked_at IS NULL AND p.revoked_at IS NULL AND s.expires_at>transaction_timestamp() AND p.expires_at>transaction_timestamp()) AS active FROM scoped_delegation_receipts r JOIN auth_sessions s ON s.session_id=r.session_id JOIN auth_sessions p ON p.session_id=r.parent_session_id JOIN identity_subjects i ON i.subject_id=r.subject_id WHERE r.issuer_caller=$1 AND r.subject_id=$2 AND r.idempotency_key=$3";

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) async fn grant(
    pg: &OwnedPostgres,
    pepper: &[u8],
    context: &InvocationContext,
    parent: &ScopedParent,
    request: &scoped::GrantScopedRequest,
    configured: Option<&ManagementCredentialCeiling>,
    expiry: OffsetDateTime,
) -> Result<Result<scoped::GrantScopedResponse, scoped::GrantScopedError>, RuntimeFailure> {
    let caller = context.caller_instance().unwrap_or_default();
    let mut tx = pg.pool().begin().await.map_err(db)?;
    let lock = serde_json::to_string(&(caller, &parent.subject, &request.idempotency_key))
        .map_err(runtime)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(lock)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    let intent = serde_json::to_string(&(
        parent.session_id.clone(),
        serde_json::to_value(request).map_err(runtime)?,
    ))
    .map_err(runtime)?;
    let current=sqlx::query("SELECT s.subject_id,s.actor_kind,s.assurance,s.audience,s.claims,s.expires_at,s.revoked_at IS NOT NULL AS revoked,(i.status='disabled' AND (i.disabled_until IS NULL OR i.disabled_until>transaction_timestamp())) AS disabled,EXISTS(SELECT 1 FROM auth_session_delegations d WHERE d.session_id=s.session_id) AS nested FROM auth_sessions s JOIN identity_subjects i ON i.subject_id=s.subject_id WHERE s.session_id=$1 FOR SHARE OF s,i").bind(&parent.session_id).fetch_optional(&mut *tx).await.map_err(db)?;
    let Some(current) = current else {
        return Ok(Err(scoped::GrantScopedError::PermissionDenied));
    };
    let now = OffsetDateTime::now_utc();
    let audience: Vec<String> = current.try_get("audience").map_err(db)?;
    if current.try_get::<String, _>("subject_id").map_err(db)? != parent.subject
        || current.try_get::<String, _>("actor_kind").map_err(db)? != "user"
        || current.try_get::<bool, _>("revoked").map_err(db)?
        || current.try_get::<bool, _>("disabled").map_err(db)?
        || current.try_get::<bool, _>("nested").map_err(db)?
        || current
            .try_get::<OffsetDateTime, _>("expires_at")
            .map_err(db)?
            <= now
        || !audience.contains(&lenso_auth_sdk::audience(
            scoped::CAPABILITY_ID,
            scoped::GRANT_SCOPED_OPERATION,
        ))
    {
        return Ok(Err(scoped::GrantScopedError::PermissionDenied));
    }
    let mut claims: std::collections::BTreeMap<String, serde_json::Value> = current
        .try_get::<sqlx::types::Json<_>, _>("claims")
        .map_err(db)?
        .0;
    super::super::constrain_management_claim(&mut claims, configured);
    let ceiling = requested_ceiling(request);
    let Ok(current_ceiling) = ManagementCredentialCeiling::from_claims(&claims) else {
        return Ok(Err(scoped::GrantScopedError::PermissionDenied));
    };
    if !ceiling.is_attenuation_of(&current_ceiling)
        || request
            .audience
            .iter()
            .any(|entry| !audience.contains(entry))
    {
        return Ok(Err(scoped::GrantScopedError::PermissionDenied));
    }
    let old = sqlx::query(RECEIPT_QUERY)
        .bind(caller)
        .bind(&parent.subject)
        .bind(&request.idempotency_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
    if let Some(old) = old {
        if old.try_get::<String, _>("intent").map_err(db)? != intent {
            return Ok(Err(scoped::GrantScopedError::Conflict));
        }
        let delegation = metadata(&old)?;
        tx.commit().await.map_err(db)?;
        return Ok(Ok(scoped::GrantScopedResponse {
            delegation,
            credential: None,
            replayed: true,
        }));
    }
    if expiry <= now
        || expiry > now + Duration::minutes(15)
        || expiry
            > current
                .try_get::<OffsetDateTime, _>("expires_at")
                .map_err(db)?
    {
        return Ok(Err(scoped::GrantScopedError::InvalidRequest));
    }
    let token = random_token().map_err(runtime)?;
    let digest = storage::token_digest(pepper, &token).map_err(runtime)?;
    let session_id = random_id("ses_").map_err(runtime)?;
    let binding = ScopedDelegationBinding {
        task_id: request.task_id.clone(),
        agent_session_id: request.agent_session_id.clone(),
        delegate_caller: request.delegate_caller.clone(),
    };
    claims.remove(lenso_auth_sdk::credential::CREDENTIAL_BINDING_CLAIM);
    claims.insert(MANAGEMENT_CEILING_CLAIM.into(), serde_json::json!(ceiling));
    claims.insert(SCOPED_DELEGATION_CLAIM.into(), serde_json::json!(binding));
    sqlx::query("INSERT INTO auth_sessions(session_id,token_digest,subject_id,actor_kind,assurance,audience,claims,expires_at) VALUES($1,$2,$3,'user',$4,$5,$6,$7)").bind(&session_id).bind(digest).bind(&parent.subject).bind(current.try_get::<String,_>("assurance").map_err(db)?).bind(&request.audience).bind(sqlx::types::Json(&claims)).bind(expiry).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("INSERT INTO auth_session_delegations(session_id,parent_session_id) VALUES($1,$2)")
        .bind(&session_id)
        .bind(&parent.session_id)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    let delegation = scoped::ScopedDelegationMetadata {
        session_id: session_id.clone(),
        subject: parent.subject.clone(),
        task_id: binding.task_id,
        agent_session_id: binding.agent_session_id,
        delegate_caller: binding.delegate_caller,
        deployment: request.deployment.clone(),
        permissions: request.permissions.clone(),
        resource_scopes: request.resource_scopes.clone(),
        audience: request.audience.clone(),
        expires_at: request.expires_at.clone(),
        active: true,
    };
    sqlx::query("INSERT INTO scoped_delegation_receipts(issuer_caller,subject_id,idempotency_key,parent_session_id,session_id,intent,metadata) VALUES($1,$2,$3,$4,$5,$6,$7)").bind(caller).bind(&parent.subject).bind(&request.idempotency_key).bind(&parent.session_id).bind(&session_id).bind(intent).bind(sqlx::types::Json(&delegation)).execute(&mut *tx).await.map_err(db)?;
    tx.commit().await.map_err(db)?;
    Ok(Ok(scoped::GrantScopedResponse {
        delegation,
        credential: Some(Some(token)),
        replayed: false,
    }))
}
pub(super) async fn receipt(
    pg: &OwnedPostgres,
    caller: &str,
    parent: &ScopedParent,
    request: &scoped::ScopedReceiptRequest,
) -> Result<Result<scoped::ScopedReceiptResponse, scoped::ScopedReceiptError>, RuntimeFailure> {
    let row = sqlx::query(RECEIPT_QUERY)
        .bind(caller)
        .bind(&parent.subject)
        .bind(&request.idempotency_key)
        .fetch_optional(pg.pool())
        .await
        .map_err(db)?;
    let Some(row) = row else {
        return Ok(Ok(scoped::ScopedReceiptResponse {
            found: false,
            delegation: None,
        }));
    };
    let delegation = metadata(&row)?;
    if row.try_get::<String, _>("parent_session_id").map_err(db)? != parent.session_id
        || delegation.task_id != request.task_id
        || delegation.agent_session_id != request.agent_session_id
    {
        return Ok(Err(scoped::ScopedReceiptError::PermissionDenied));
    }
    Ok(Ok(scoped::ScopedReceiptResponse {
        found: true,
        delegation: Some(Some(delegation)),
    }))
}

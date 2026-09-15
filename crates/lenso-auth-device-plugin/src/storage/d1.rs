use super::{
    ListResponseDevicesItem, ObserveRequest, ObserveResponse, OffsetDateTime, Rfc3339,
    RuntimeFailure, SetTrustOutcome, SetTrustRequest, failure,
};
use crate::workers::{D1Binding, decode_time, field, statement, timestamp};
use serde_json::json;

fn fail(_: ()) -> RuntimeFailure {
    failure()
}

pub(super) async fn observe(
    binding: &D1Binding,
    request: ObserveRequest,
) -> Result<ObserveResponse, RuntimeFailure> {
    let now = timestamp(OffsetDateTime::now_utc());
    let params = vec![
        json!(request.subject),
        json!(request.device_id),
        json!(request.client_ip),
        json!(request.user_agent),
        now,
    ];
    // INSERT and UPDATE share one primary batch. Changes from INSERT distinguish
    // a new device even when two observations have the same timestamp.
    let results = binding.run(vec![
        statement("INSERT INTO auth_devices(subject_id,device_id,last_seen_ip,last_seen_user_agent,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?5) ON CONFLICT(subject_id,device_id) DO NOTHING", params.clone()),
        statement("UPDATE auth_devices SET last_seen_ip=?3,last_seen_user_agent=?4,updated_at=?5 WHERE subject_id=?1 AND device_id=?2 RETURNING trusted_at IS NOT NULL AS trusted", params),
    ]).await.map_err(fail)?;
    let row = results[1].results.first().ok_or_else(failure)?;
    Ok(ObserveResponse {
        device_id: request.device_id,
        created: results[0].meta.changes == 1,
        trusted: field::<i64>(row, "trusted").map_err(fail)? != 0,
    })
}

pub(super) async fn list(
    binding: &D1Binding,
    subject: &str,
) -> Result<Vec<ListResponseDevicesItem>, RuntimeFailure> {
    let results = binding.run(vec![statement("SELECT device_id,trusted_at IS NOT NULL AS trusted,primary_at IS NOT NULL AS is_primary,last_seen_ip,last_seen_user_agent,updated_at FROM auth_devices WHERE subject_id=?1 ORDER BY updated_at DESC LIMIT 200", vec![json!(subject)])]).await.map_err(fail)?;
    results[0]
        .results
        .iter()
        .map(|row| {
            Ok(ListResponseDevicesItem {
                device_id: field(row, "device_id").map_err(fail)?,
                trusted: field::<i64>(row, "trusted").map_err(fail)? != 0,
                primary: field::<i64>(row, "is_primary").map_err(fail)? != 0,
                last_seen_ip: field(row, "last_seen_ip").map_err(fail)?,
                last_seen_user_agent: field(row, "last_seen_user_agent").map_err(fail)?,
                updated_at: decode_time(row, "updated_at")
                    .map_err(fail)?
                    .format(&Rfc3339)
                    .map_err(|_| failure())?,
            })
        })
        .collect()
}

pub(super) async fn set_trust(
    binding: &D1Binding,
    request: &SetTrustRequest,
) -> Result<SetTrustOutcome, RuntimeFailure> {
    let mut statements = Vec::new();
    if request.primary {
        // A missing target cannot clear the old primary. Serial D1 batches plus
        // the unique partial index preserve one primary under competing writes.
        statements.push(statement("UPDATE auth_devices SET primary_at=NULL WHERE subject_id=?1 AND primary_at IS NOT NULL AND EXISTS(SELECT 1 FROM auth_devices WHERE subject_id=?1 AND device_id=?2)",vec![json!(request.subject),json!(request.device_id)]));
    }
    statements.push(statement("UPDATE auth_devices SET trusted_at=CASE WHEN ?3 THEN ?5 ELSE NULL END,primary_at=CASE WHEN ?4 THEN ?5 ELSE NULL END,updated_at=?5 WHERE subject_id=?1 AND device_id=?2 RETURNING device_id", vec![json!(request.subject),json!(request.device_id),json!(i32::from(request.trusted)),json!(i32::from(request.primary)),timestamp(OffsetDateTime::now_utc())]));
    let results = binding.run(statements).await.map_err(fail)?;
    Ok(if results.last().ok_or_else(failure)?.results.is_empty() {
        SetTrustOutcome::NotFound
    } else {
        SetTrustOutcome::Updated
    })
}

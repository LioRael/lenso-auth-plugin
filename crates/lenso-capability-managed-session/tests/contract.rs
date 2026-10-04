use lenso_capability_managed_session::{
    CAPABILITY_ID, DESCRIPTOR_VERSION, IssueManagedRequest, ReadManagedRequest, RenewRequest,
    RenewResponse,
};
use serde_json::{Value, json};

#[test]
fn locked_contract_has_no_client_selected_lifetime_or_profile() {
    let descriptor: Value = serde_json::from_str(include_str!("../capability.json")).unwrap();
    assert_eq!(descriptor["id"], CAPABILITY_ID);
    assert_eq!(descriptor["version"], DESCRIPTOR_VERSION);
    assert_eq!(CAPABILITY_ID, "lenso.auth.managed-session@1");
    assert_eq!(DESCRIPTOR_VERSION, "1.0.0");
    let issue: Value =
        serde_json::from_str(include_str!("../schemas/issue-managed-request.schema.json")).unwrap();
    let fields = issue["properties"].as_object().unwrap();
    assert_eq!(fields.len(), 5);
    assert!(!fields.contains_key("expires_at"));
    assert!(!fields.contains_key("profile"));
    assert!(!fields.contains_key("ttl_seconds"));
    assert_eq!(issue["additionalProperties"], false);
    let renew: Value =
        serde_json::from_str(include_str!("../schemas/renew-request.schema.json")).unwrap();
    assert_eq!(renew["properties"].as_object().unwrap().len(), 1);
    assert_eq!(renew["properties"]["credential"]["x-lenso-sensitive"], true);
    let state: Value =
        serde_json::from_str(include_str!("../schemas/read-managed-response.schema.json")).unwrap();
    assert_eq!(state["properties"].as_object().unwrap().len(), 4);
    assert!(state["properties"].get("credential").is_none());
}

#[test]
fn generated_sensitive_debug_does_not_disclose_credentials() {
    let request = RenewRequest {
        credential: "synthetic-sensitive-proof".into(),
    };
    let response = RenewResponse {
        session_id: "ses_synthetic".into(),
        credential: request.credential.clone(),
        expires_at: "2026-10-04T02:00:00Z".into(),
        absolute_expires_at: "2026-10-05T01:00:00Z".into(),
        renew_after: "2026-10-04T01:30:00Z".into(),
    };
    assert!(!format!("{request:?} {response:?}").contains("synthetic-sensitive-proof"));
    let state = ReadManagedRequest {
        credential: request.credential.clone(),
    };
    assert!(!format!("{state:?}").contains("synthetic-sensitive-proof"));
    assert_eq!(
        serde_json::to_value(&request).unwrap(),
        json!({"credential":"synthetic-sensitive-proof"})
    );
    let issued = IssueManagedRequest {
        subject: "usr_synthetic".into(),
        actor_kind: "user".into(),
        assurance: "password".into(),
        audience: vec!["example.operation@1".into()],
        claims: std::collections::BTreeMap::default(),
    };
    assert_eq!(
        serde_json::to_value(issued)
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        5
    );
}

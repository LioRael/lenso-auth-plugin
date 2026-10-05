use super::*;
use lenso_capability_http_endpoint::{HandleRequestCredential, HandleRequestHeadersItem};

fn config() -> Config {
    Config {
        allowed_origin: "https://app.example".into(),
        session_cookie_name: "__Host-test-session".into(),
        csrf_cookie_name: "__Host-test-csrf".into(),
    }
}
fn request(body: &[u8]) -> HandleRequest {
    HandleRequest {
        body: body.into(),
        credential: None,
        headers: vec![
            HandleRequestHeadersItem {
                name: "origin".into(),
                value: "https://app.example".into(),
            },
            HandleRequestHeadersItem {
                name: "content-type".into(),
                value: "application/json".into(),
            },
        ],
        method: "POST".into(),
        path: "/auth/password/login".into(),
        path_parameters: vec![],
        query: None,
        request_id: "login-test".into(),
        route_id: "auth.password-web-session.login".into(),
    }
}

#[test]
fn exact_https_origin_distinct_host_cookies_and_closed_login_are_required() {
    let mut config = config();
    assert!(validate_config(&config).is_ok());
    for origin in [
        "http://app.example",
        "https://app.example/",
        "https://app.example/path",
        "https://user@app.example",
        "https://app.example?query",
    ] {
        config.allowed_origin = origin.into();
        assert!(validate_config(&config).is_err());
    }
    config.allowed_origin = "https://app.example".into();
    config.csrf_cookie_name = config.session_cookie_name.clone();
    assert!(validate_config(&config).is_err());
    config.csrf_cookie_name = "csrf".into();
    assert!(validate_config(&config).is_err());
    let config = super::tests::config();
    let valid = br#"{"identifier":"reader","password":"example-password"}"#;
    assert!(login_input(&request(valid), &config).is_ok());
    for body in [
        br#"{"identifier":"reader","password":"password","subject":"admin"}"#.as_slice(),
        br#"{"identifier":"reader","password":"password","credential":"session"}"#,
        br#"{"identifier":"reader","password":""}"#,
    ] {
        assert!(login_input(&request(body), &config).is_err());
    }
    assert!(matches!(
        login_input(&request(&vec![b'a'; MAX_LOGIN_BYTES + 1]), &config),
        Err((StatusCode::PAYLOAD_TOO_LARGE, _))
    ));
}

#[test]
fn duplicate_origin_form_content_and_selected_identity_do_not_reach_password() {
    let config = config();
    let body = br#"{"identifier":"reader","password":"example-password"}"#;
    let mut req = request(body);
    req.headers.push(HandleRequestHeadersItem {
        name: "Origin".into(),
        value: "https://app.example".into(),
    });
    assert!(matches!(
        login_input(&req, &config),
        Err((StatusCode::FORBIDDEN, _))
    ));
    req = request(body);
    req.headers[0].value = "https://other.example".into();
    assert!(matches!(
        login_input(&req, &config),
        Err((StatusCode::FORBIDDEN, _))
    ));
    req = request(body);
    req.headers[1].value = "application/x-www-form-urlencoded".into();
    assert!(matches!(
        login_input(&req, &config),
        Err((StatusCode::UNSUPPORTED_MEDIA_TYPE, _))
    ));
    req = request(body);
    req.credential = Some(HandleRequestCredential {
        scheme: "session".into(),
        value: "selected-session".into(),
    });
    assert!(matches!(
        login_input(&req, &config),
        Err((StatusCode::CONFLICT, "logout_required"))
    ));
    req = request(body);
    req.query = Some("password=forbidden".into());
    assert!(matches!(
        login_input(&req, &config),
        Err((StatusCode::BAD_REQUEST, _))
    ));
}

#[test]
fn login_installs_only_valid_future_credentials_without_json_disclosure() {
    let config = config();
    let mut session = LoginResponse {
        subject: "user-1".into(),
        session_id: "session-1".into(),
        credential: "test_opaque_session".into(),
        expires_at: (OffsetDateTime::now_utc() + time::Duration::minutes(10))
            .format(&Rfc3339)
            .unwrap(),
    };
    let response = login_response(&config, &session, "csrf_token").unwrap();
    assert_eq!(response.status, 200);
    let json: serde_json::Value = serde_json::from_slice(response.body.as_ref()).unwrap();
    assert_eq!(json["authenticated"], true);
    assert!(json.get("credential").is_none());
    let cookies = response
        .headers
        .iter()
        .filter(|h| h.name == "set-cookie")
        .collect::<Vec<_>>();
    assert_eq!(cookies.len(), 2);
    assert!(cookies[0].value.contains("; Secure; HttpOnly;"));
    assert!(cookies[1].value.contains("; Secure;"));
    assert!(!cookies[1].value.contains("HttpOnly"));
    assert!(
        response
            .headers
            .iter()
            .any(|h| h.name == "cache-control" && h.value == "no-store")
    );
    for credential in ["bad;cookie", "bad\nheader", ""] {
        session.credential = credential.into();
        let failed = login_response(&config, &session, "csrf_token").unwrap();
        assert_eq!(failed.status, 502);
        assert!(!failed.headers.iter().any(|h| h.name == "set-cookie"));
    }
    session.credential = "test_opaque_session".into();
    session.expires_at = "invalid".into();
    assert_eq!(
        login_response(&config, &session, "csrf_token")
            .unwrap()
            .status,
        502
    );
    let cleared = clear_cookies(&config).unwrap();
    assert_eq!(cleared.status, 204);
    assert_eq!(
        cleared
            .headers
            .iter()
            .filter(|h| h.name == "set-cookie" && h.value.contains("Max-Age=0; Secure"))
            .count(),
        2
    );
}

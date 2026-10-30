use super::*;

/// Basic authentication protects both protected and API routes.
#[tokio::test]
async fn basic_auth_protects_routes_and_api() {
    let auth = Auth::new(AuthConfig {
        origin: "https://app.example".into(),
        mode: AuthMode::Basic {
            username: "admin".into(),
            password: "secret".into(),
            realm: "my \"realm\"".into(),
        },
    })
    .await
    .unwrap();
    let app = auth.protect(
        Router::new()
            .route("/", get(|| async { "application" }))
            .route("/api/observability", get(|| async { "logs" })),
    );
    for path in ["/", "/api/observability"] {
        let request = Request::builder()
            .uri(path)
            .header(header::HOST, "app.example")
            .body(Body::empty());
        let response = app.clone().oneshot(request.unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            "Basic realm=\"my \\\"realm\\\"\", charset=\"UTF-8\""
        );

        let request = Request::builder()
            .uri(path)
            .header(header::HOST, "app.example")
            .header(header::AUTHORIZATION, "Basic YWRtaW46d3Jvbmc=")
            .body(Body::empty());
        assert_eq!(
            app.clone()
                .oneshot(request.unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );

        let request = Request::builder()
            .uri(path)
            .header(header::HOST, "app.example")
            .header(header::AUTHORIZATION, "Basic YWRtaW46c2VjcmV0")
            .body(Body::empty());
        assert_eq!(
            app.clone()
                .oneshot(request.unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
}

/// HTTPS and loopback HTTP select the last matching authentication cookie.
#[tokio::test]
async fn oidc_cookie_names_and_duplicate_precedence() {
    for (secure, origin, host, session_name, state_name) in [
        (
            true,
            "https://app.example",
            "app.example",
            "__Host-axum_auth_gate_session",
            "__Host-axum_auth_gate_oidc_state",
        ),
        (
            false,
            "http://127.0.0.1:8080",
            "127.0.0.1:8080",
            "axum_auth_gate_session",
            "axum_auth_gate_oidc_state",
        ),
    ] {
        let mut store = Store::default();
        store.sessions.insert(
            "valid".into(),
            Instant::now().checked_add(SESSION_TTL).unwrap(),
        );
        store.pending.insert(
            "valid".into(),
            Pending {
                verifier: "verifier".into(),
                nonce: "nonce".into(),
                return_to: "/".into(),
                created: Instant::now(),
            },
        );
        let mut oidc = test_oidc(store);
        oidc.secure = secure;
        let auth = Auth(
            Arc::new(Mode::Oidc(Box::new(oidc))),
            Arc::new(reqwest::Url::parse(origin).unwrap()),
        );
        let app = auth.protect(Router::new().route("/api/settings", get(|| async { "ok" })));

        for (first, last, expected) in [
            ("wrong", "valid", StatusCode::OK),
            ("valid", "wrong", StatusCode::UNAUTHORIZED),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/settings")
                        .header(header::HOST, host)
                        .header(
                            header::COOKIE,
                            format!("{session_name}={first}; unrelated=1"),
                        )
                        .header(header::COOKIE, format!("{session_name}={last}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/auth/callback?state=valid&error=access_denied")
                    .header(header::HOST, host)
                    .header(
                        header::COOKIE,
                        format!("{state_name}=wrong; {state_name}=valid"),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let cleared = response.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(cleared.starts_with(&format!("{state_name}=")));
        assert_eq!(cleared.contains("; Secure"), secure);

        let start = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, host)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let issued = start.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(issued.starts_with(&format!("{state_name}=")));
        assert_eq!(issued.contains("; Secure"), secure);
        assert!(issued.contains("Path=/") && issued.contains("HttpOnly"));
        assert!(!issued.contains("Domain="));
    }
}

/// Callback state must match the browser and be fresh and single-use.
#[tokio::test]
async fn oidc_callback_requires_matching_unexpired_single_use_state() {
    let mut store = Store::default();
    store.pending.insert(
        "valid".into(),
        Pending {
            verifier: "verifier".into(),
            nonce: "nonce".into(),
            return_to: "/".into(),
            created: Instant::now(),
        },
    );
    store.pending.insert(
        "expired".into(),
        Pending {
            verifier: "verifier".into(),
            nonce: "nonce".into(),
            return_to: "/".into(),
            created: Instant::now().checked_sub(LOGIN_TTL).unwrap(),
        },
    );
    let auth = Auth(
        Arc::new(Mode::Oidc(Box::new(test_oidc(store)))),
        Arc::new(reqwest::Url::parse("https://app.example").unwrap()),
    );
    let app = auth.protect(Router::new().route("/", get(|| async { "application" })));
    for (uri, cookie_value, expected) in [
        ("/auth/callback?state=valid", None, StatusCode::BAD_REQUEST),
        (
            "/auth/callback?state=valid",
            Some("__Host-axum_auth_gate_oidc_state=wrong"),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/auth/callback?state=expired",
            Some("__Host-axum_auth_gate_oidc_state=expired"),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/auth/callback?state=valid&error=access_denied",
            Some("__Host-axum_auth_gate_oidc_state=valid"),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/auth/callback?state=valid&error=access_denied",
            Some("__Host-axum_auth_gate_oidc_state=valid"),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let mut request = Request::builder()
            .uri(uri)
            .header(header::HOST, "app.example");
        if let Some(value) = cookie_value {
            request = request.header(header::COOKIE, value);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cookie.contains("Max-Age=0") && cookie.contains("Secure"));
    }
}

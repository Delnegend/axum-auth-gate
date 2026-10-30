use super::*;
use axum::{body::Body, http::Request};
use tower::ServiceExt;

#[tokio::test]
async fn configuration_errors_are_typed() {
    assert!(matches!(safe_url("not a URL"), Err(Error::InvalidUrl(_))));
    assert!(matches!(
        safe_url("http://example.com"),
        Err(Error::UnsafeUrl)
    ));
    let result = Auth::new(AuthConfig {
        origin: "https://app.example/path".into(),
        mode: AuthMode::Basic {
            username: "user".into(),
            password: "password".into(),
            realm: "private".into(),
        },
    })
    .await;
    assert!(matches!(result, Err(Error::InvalidOrigin)));
}

#[tokio::test]
async fn rejects_invalid_public_configuration() {
    let basic = || AuthMode::Basic {
        username: "user".into(),
        password: "password".into(),
        realm: "private".into(),
    };
    for origin in [
        "",
        "http://example.com",
        "https://example.com/path",
        "https://example.com/?x=1",
    ] {
        assert!(
            Auth::new(AuthConfig {
                origin: origin.into(),
                mode: basic()
            })
            .await
            .is_err()
        );
    }
    for (username, password, realm) in [
        ("", "pass", "realm"),
        ("user", " ", "realm"),
        ("user", "pass", ""),
        ("a:b", "pass", "realm"),
        ("user", "pass", "bad\r\nrealm"),
    ] {
        assert!(
            Auth::new(AuthConfig {
                origin: "https://example.com".into(),
                mode: AuthMode::Basic {
                    username: username.into(),
                    password: password.into(),
                    realm: realm.into()
                },
            })
            .await
            .is_err()
        );
    }
    for (issuer, client_id, client_secret, redirect_url, emails, groups) in [
        (
            "",
            "client",
            "secret",
            "https://example.com/auth/callback",
            vec!["a"],
            vec![],
        ),
        (
            "https://issuer.example",
            "",
            "secret",
            "https://example.com/auth/callback",
            vec!["a"],
            vec![],
        ),
        (
            "https://issuer.example",
            "client",
            "",
            "https://example.com/auth/callback",
            vec!["a"],
            vec![],
        ),
        (
            "https://issuer.example",
            "client",
            "secret",
            "https://example.com/auth/callback",
            vec![" "],
            vec![],
        ),
        (
            "https://issuer.example",
            "client",
            "secret",
            "https://other.example/auth/callback",
            vec!["a"],
            vec![],
        ),
        (
            "https://issuer.example",
            "client",
            "secret",
            "https://example.com/auth/callback?x=1",
            vec!["a"],
            vec![],
        ),
    ] {
        assert!(
            Auth::new(AuthConfig {
                origin: "https://example.com".into(),
                mode: AuthMode::Oidc {
                    issuer: issuer.into(),
                    client_id: client_id.into(),
                    client_secret: client_secret.into(),
                    redirect_url: redirect_url.into(),
                    allowed_emails: emails.into_iter().map(str::to_owned).collect(),
                    allowed_groups: groups.into_iter().map(str::to_owned).collect(),
                },
            })
            .await
            .is_err()
        );
    }
}

/// Builds a test OIDC configuration with supplied in-memory state.
pub(super) fn test_oidc(store: Store) -> Oidc {
    let metadata: CoreProviderMetadata = serde_json::from_value(serde_json::json!({
        "issuer": "https://issuer.example",
        "authorization_endpoint": "https://issuer.example/authorize",
        "token_endpoint": "https://issuer.example/token",
        "jwks_uri": "https://issuer.example/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
    }))
    .unwrap();
    let issuer = metadata.issuer().clone();
    let jwks_uri = metadata.jwks_uri().clone();
    let signing_algorithms = metadata.id_token_signing_alg_values_supported().clone();
    let client = OidcClient::from_provider_metadata(
        metadata,
        ClientId::new("client".into()),
        Some(ClientSecret::new("secret".into())),
    )
    .set_redirect_uri(RedirectUrl::new("https://app.example/auth/callback".into()).unwrap());
    Oidc {
        http_client: SafeHttp(reqwest::Client::new()),
        client,
        issuer,
        jwks_uri,
        signing_algorithms,
        allowed_emails: vec!["admin@example.com".into()],
        allowed_groups: vec![],
        secure: true,
        state: Mutex::new(store),
    }
}

/// Authenticated HTML cannot be cached even if its handler asks for public caching.
#[tokio::test]
async fn protected_pages_are_not_cacheable() {
    let auth = Auth::new(AuthConfig {
        origin: "https://app.example".into(),
        mode: AuthMode::Basic {
            username: "admin".into(),
            password: "secret".into(),
            realm: "test".into(),
        },
    })
    .await
    .unwrap();
    let app = auth.protect(Router::new().route(
        "/",
        get(|| async { ([(header::CACHE_CONTROL, "public, max-age=3600")], "private") }),
    ));
    for (authorization, status) in [
        (Some("Basic YWRtaW46c2VjcmV0"), StatusCode::OK),
        (None, StatusCode::UNAUTHORIZED),
    ] {
        let mut request = Request::builder()
            .uri("/")
            .header(header::HOST, "app.example");
        if let Some(value) = authorization {
            request = request.header(header::AUTHORIZATION, value);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
}

/// Expired login slots are reclaimed, but live pending attempts remain bounded.
#[tokio::test]
async fn oidc_limits_pending_logins_without_blocking_existing_sessions() {
    let now = Instant::now();
    let mut store = Store::default();
    for n in 0..MAX_PENDING_LOGINS {
        store.pending.insert(
            n.to_string(),
            Pending {
                verifier: "verifier".into(),
                nonce: "nonce".into(),
                return_to: "/".into(),
                created: if n == 0 {
                    now.checked_sub(LOGIN_TTL).unwrap()
                } else {
                    now
                },
            },
        );
    }
    store
        .sessions
        .insert("valid".into(), now.checked_add(SESSION_TTL).unwrap());
    let auth = Auth(
        Arc::new(Mode::Oidc(Box::new(test_oidc(store)))),
        Arc::new(reqwest::Url::parse("https://app.example").unwrap()),
    );
    let app = auth.protect(Router::new().route("/", get(|| async { "ok" })));
    for status in [StatusCode::SEE_OTHER, StatusCode::SERVICE_UNAVAILABLE] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "app.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
    let response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::HOST, "app.example")
                .header(header::COOKIE, "__Host-axum_auth_gate_session=valid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// Verified email or exact group membership grants access.
#[test]
fn oidc_allows_verified_emails_or_exact_group_membership() {
    let emails = vec!["admin@example.com".to_owned()];
    let groups = vec!["admins".to_owned()];
    assert!(!authorized(None, false, &[], &emails, &groups));
    assert!(!authorized(
        Some("admin@example.com"),
        false,
        &[],
        &emails,
        &groups
    ));
    assert!(authorized(
        Some("admin@example.com"),
        true,
        &[],
        &emails,
        &groups
    ));
    assert!(!authorized(
        None,
        false,
        &["admin".into()],
        &emails,
        &groups
    ));
    assert!(authorized(
        None,
        false,
        &["admins".into()],
        &emails,
        &groups
    ));
    assert!(!authorized(None, false, &["admins".into()], &[], &[]));
}

/// Both authentication modes enforce host and origin rules for writes.
#[tokio::test]
async fn writes_require_trusted_origin_and_host_in_both_modes() {
    let mut store = Store::default();
    store.sessions.insert(
        "session".into(),
        Instant::now().checked_add(SESSION_TTL).unwrap(),
    );
    let oidc = Mode::Oidc(Box::new(test_oidc(store)));
    for mode in [
        Mode::Basic {
            username: "admin".into(),
            password: "secret".into(),
            realm: "test".into(),
        },
        oidc,
    ] {
        let auth = Auth(
            Arc::new(mode),
            Arc::new(reqwest::Url::parse("https://app.example").unwrap()),
        );
        let app = auth
            .protect(Router::new().route("/api/settings", axum::routing::post(|| async { "ok" })));
        for (host, origin, fetch, expected) in [
            (
                "app.example",
                Some("https://app.example"),
                Some("same-origin"),
                StatusCode::OK,
            ),
            ("app.example", None, None, StatusCode::OK),
            (
                "app.example",
                Some("https://evil.example"),
                Some("cross-site"),
                StatusCode::FORBIDDEN,
            ),
            (
                "app.example",
                None,
                Some("cross-site"),
                StatusCode::FORBIDDEN,
            ),
            (
                "evil.example",
                Some("https://evil.example"),
                Some("same-origin"),
                StatusCode::FORBIDDEN,
            ),
        ] {
            let mut request = Request::builder()
                .method(Method::POST)
                .uri("/api/settings")
                .header(header::HOST, host)
                .header(header::AUTHORIZATION, "Basic YWRtaW46c2VjcmV0")
                .header(header::COOKIE, "__Host-axum_auth_gate_session=session");
            if let Some(value) = origin {
                request = request.header(header::ORIGIN, value);
            }
            if let Some(value) = fetch {
                request = request.header("sec-fetch-site", value);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL).unwrap(),
                "no-store"
            );
        }
    }
}

mod flows;
mod signed;

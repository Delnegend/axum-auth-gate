use super::*;

#[allow(clippy::too_many_lines)]
/// Signed OIDC login validates nonce and group before creating a session.
#[tokio::test]
async fn oidc_signed_login_checks_nonce_group_and_session() {
    use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
    use serde_json::{Value, json};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let fixture: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/oidc-test-key.json")).unwrap();
    let signing_key = Arc::new(
        RsaKeyPair::from_pkcs8(
            &STANDARD
                .decode(fixture["privateKey"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap(),
    );
    let public_key = fixture["publicKey"].clone();
    let publish_key = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let provider_key = publish_key.clone();
    let scenario = Arc::new(Mutex::new((String::new(), true, true, true)));
    let challenge = Arc::new(Mutex::new(String::new()));
    let token_challenge = challenge.clone();
    let discovery_issuer = issuer.clone();
    let keys = public_key.clone();
    let token_issuer = issuer.clone();
    let token_scenario = scenario.clone();
    let provider = Router::new()
        .route("/.well-known/openid-configuration", get(move || {
            let base = discovery_issuer.clone();
            async move { axum::Json(json!({"issuer":base,"authorization_endpoint":format!("{base}/authorize"),"token_endpoint":format!("{base}/token"),"jwks_uri":format!("{base}/keys"),"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]})) }
        }))
        .route("/keys", get(move || {
            let mut key = keys.clone();
            let published = provider_key.load(std::sync::atomic::Ordering::Relaxed);
            async move {
                key["kid"] = json!("test-key");
                key["alg"] = json!("RS256");
                key["use"] = json!("sig");
                axum::Json(json!({"keys": if published { vec![key] } else { vec![] }}))
            }
        }))
        .route("/token", axum::routing::post(move |axum::Form(form): axum::Form<std::collections::HashMap<String, String>>| {
            let base = token_issuer.clone();
            let scenario = token_scenario.clone();
            let challenge = token_challenge.clone();
            let key = signing_key.clone();
            async move {
                let digest = ring::digest::digest(&ring::digest::SHA256, form["code_verifier"].as_bytes());
                assert_eq!(URL_SAFE_NO_PAD.encode(digest.as_ref()), *challenge.lock().await);
                let (nonce, matching_nonce, allowed_group, valid_signature) = scenario.lock().await.clone();
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"test-key","typ":"JWT"}"#);
                let claims = json!({"iss":base,"aud":"client","sub":"subject","iat":now,"exp":now.saturating_add(300),"nonce":if matching_nonce {nonce} else {"wrong".into()},"groups":if allowed_group {vec!["admins"]} else {vec!["users"]}});
                let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
                let message = format!("{header}.{payload}");
                let mut signature = vec![0; key.public().modulus_len()];
                key.sign(&RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), message.as_bytes(), &mut signature).unwrap();
                if !valid_signature { signature[0] ^= 1; }
                axum::Json(json!({"access_token":"test-access","token_type":"Bearer","id_token":format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature))}))
            }
        }));
    let task = tokio::spawn(async move {
        axum::serve(listener, provider).await.unwrap();
    });
    let auth = Auth::new(AuthConfig {
        origin: "https://app.example".into(),
        mode: AuthMode::Oidc {
            issuer,
            client_id: "client".into(),
            client_secret: "secret".into(),
            redirect_url: "https://app.example/auth/callback".into(),
            allowed_emails: vec![],
            allowed_groups: vec!["admins".into()],
        },
    })
    .await
    .unwrap();
    publish_key.store(true, std::sync::atomic::Ordering::Relaxed);
    let app = auth.protect(
        Router::new()
            .route("/", get(|| async { "application" }))
            .route("/api/settings", get(|| async { "settings" })),
    );
    for (valid_nonce, allowed_group, valid_signature, expected) in [
        (true, true, true, StatusCode::SEE_OTHER),
        (false, true, true, StatusCode::UNAUTHORIZED),
        (true, false, true, StatusCode::UNAUTHORIZED),
        (true, true, false, StatusCode::UNAUTHORIZED),
    ] {
        let start = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/llm-logs?search=test")
                    .header(header::HOST, "app.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let url = reqwest::Url::parse(
            start
                .headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap();
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query["code_challenge_method"], "S256");
        *challenge.lock().await = query["code_challenge"].clone();
        assert!(
            query["scope"]
                .split_whitespace()
                .any(|scope| scope == "groups")
        );
        *scenario.lock().await = (
            query["nonce"].clone(),
            valid_nonce,
            allowed_group,
            valid_signature,
        );
        let state_cookie = start
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(state_cookie.starts_with("__Host-axum_auth_gate_oidc_state="));
        assert!(state_cookie.contains("Path=/") && state_cookie.contains("Secure"));
        assert!(!state_cookie.contains("Domain="));
        let cookie = state_cookie.split(';').next().unwrap();
        let callback = format!("/auth/callback?code=test-code&state={}", query["state"]);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(callback)
                    .header(header::HOST, "app.example")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        if expected == StatusCode::SEE_OTHER {
            assert_eq!(
                response.headers()[header::LOCATION],
                "/llm-logs?search=test"
            );
            let session = response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .find(|v| v.starts_with("__Host-axum_auth_gate_session="))
                .unwrap()
                .split(';')
                .next()
                .unwrap();
            let result = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/settings")
                        .header(header::HOST, "app.example")
                        .header(header::COOKIE, session)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(result.status(), StatusCode::OK);
        }
    }
    task.abort();
}

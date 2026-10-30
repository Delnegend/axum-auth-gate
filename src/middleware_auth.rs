use super::*;

/// Checks request origin and authentication, disabling caching for protected responses.
pub(super) async fn authenticate(State(auth): State<Auth>, req: Request, next: Next) -> Response {
    let mut response = if valid_request_origin(&auth.1, &req) {
        authenticate_inner(auth, req, next).await
    } else {
        (StatusCode::FORBIDDEN, "Invalid request origin").into_response()
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Enforces the configured host and same-origin rules for protected requests.
fn valid_request_origin(origin: &reqwest::Url, req: &Request) -> bool {
    let headers = req.headers();
    let mut hosts = headers.get_all(header::HOST).iter();
    let Some(host) = hosts.next().and_then(|v| v.to_str().ok()) else {
        return false;
    };
    if hosts.next().is_some() || host.contains(['/', '?', '#', '@', '\\']) {
        return false;
    }
    let Ok(host_url) = reqwest::Url::parse(&format!("{}://{host}/", origin.scheme())) else {
        return false;
    };
    if host_url.origin() != origin.origin() {
        return false;
    }
    if req.uri().path() == CALLBACK && req.method() == Method::GET {
        return true;
    }

    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    let mut origins = headers.get_all(header::ORIGIN).iter();
    let request_origin = origins.next();
    if origins.next().is_some() {
        return false;
    }
    if let Some(value) = request_origin {
        if value.to_str().ok() != Some(origin.origin().ascii_serialization().as_str()) {
            return false;
        }
    } else if !safe
        && headers
            .keys()
            .any(|name| name.as_str().starts_with("sec-fetch-"))
    {
        return false;
    }
    if !safe {
        let mut sites = headers.get_all("sec-fetch-site").iter();
        if let Some(site) = sites.next()
            && (sites.next().is_some() || site.to_str().ok() != Some("same-origin"))
        {
            return false;
        }
    }
    true
}

/// Validates Basic credentials or an OIDC session, starting login when needed.
async fn authenticate_inner(auth: Auth, req: Request, next: Next) -> Response {
    match auth.0.as_ref() {
        Mode::Basic {
            username,
            password,
            realm,
        } => {
            let valid = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split_once(' '))
                .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
                .and_then(|(_, value)| STANDARD.decode(value).ok())
                .is_some_and(|decoded| {
                    let expected = format!("{username}:{password}");
                    equal(&decoded, expected.as_bytes())
                });
            if valid {
                return next.run(req).await;
            }
            (
                StatusCode::UNAUTHORIZED,
                [(
                    header::WWW_AUTHENTICATE,
                    format!(
                        "Basic realm=\"{}\", charset=\"UTF-8\"",
                        realm.replace('\\', "\\\\").replace('"', "\\\"")
                    ),
                )],
                "Authentication required",
            )
                .into_response()
        }
        Mode::Oidc(oidc) => {
            if req.uri().path() == CALLBACK {
                return next.run(req).await;
            }
            let session = cookie(req.headers(), oidc.session_cookie());
            let now = Instant::now();
            let mut store = oidc.state.lock().await;
            store.sessions.retain(|_, expiry| *expiry > now);
            store
                .pending
                .retain(|_, pending| now.duration_since(pending.created) < LOGIN_TTL);
            if session
                .as_ref()
                .is_some_and(|s| store.sessions.contains_key(s))
            {
                drop(store);
                return next.run(req).await;
            }
            if req.method() != Method::GET
                || req.uri().path().starts_with("/api/")
                || req.uri().path() == "/api"
            {
                return (StatusCode::UNAUTHORIZED, "Authentication required").into_response();
            }
            if store.pending.len() >= MAX_PENDING_LOGINS {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Too many pending login attempts",
                )
                    .into_response();
            }
            let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
            let mut request = oidc
                .client
                .authorize_url(
                    CoreAuthenticationFlow::AuthorizationCode,
                    CsrfToken::new_random,
                    Nonce::new_random,
                )
                .add_scope(Scope::new("profile".into()))
                .add_scope(Scope::new("email".into()))
                .set_pkce_challenge(challenge);
            if !oidc.allowed_groups.is_empty() {
                request = request.add_scope(Scope::new("groups".into()));
            }
            let (url, csrf, nonce) = request.url();
            let state = csrf.secret().to_owned();
            store.pending.insert(
                state.clone(),
                Pending {
                    verifier: verifier.secret().to_owned(),
                    nonce: nonce.secret().to_owned(),
                    return_to: req
                        .uri()
                        .path_and_query()
                        .map(axum::http::uri::PathAndQuery::as_str)
                        .filter(|value| {
                            value.starts_with('/')
                                && !value.starts_with("//")
                                && !value.contains('\\')
                        })
                        .unwrap_or("/")
                        .to_owned(),
                    created: now,
                },
            );
            drop(store);
            with_cookie(
                Redirect::to(url.as_str()).into_response(),
                &set_cookie(
                    oidc.state_cookie(),
                    &state,
                    LOGIN_TTL.as_secs(),
                    oidc.secure,
                ),
            )
        }
    }
}

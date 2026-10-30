//! Authentication middleware for selected Axum routes. Configure a trusted public
//! origin and either Basic credentials or an OIDC provider with an allowlist.
//! `protect` adds `/auth/callback`; unauthenticated requests to `/api` and
//! `/api/*` receive 401 rather than an OIDC redirect. Protect only intended routes.
//! Browser writes require a matching Origin; non-browser clients may omit it.
//! Sessions and pending logins are process-local.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use openidconnect::{
    AdditionalClaims, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IdTokenFields, IssuerUrl, JsonWebKeySetUrl, Nonce,
    PkceCodeChallenge, RedirectUrl, Scope, StandardErrorResponse, StandardTokenResponse,
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreErrorResponseType,
        CoreGenderClaim, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreRevocableToken,
        CoreRevocationErrorResponse, CoreTokenIntrospectionResponse, CoreTokenType,
    },
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// OIDC authorization callback and identity verification.
mod callback;

#[cfg(feature = "openapi")]
use callback::__path_callback;
use callback::callback;

/// OIDC HTTP client that validates every requested endpoint before sending.
struct SafeHttp(reqwest::Client);

impl<'a> openidconnect::AsyncHttpClient<'a> for SafeHttp {
    type Error = std::io::Error;
    type Future = std::pin::Pin<
        Box<
            dyn Future<Output = Result<openidconnect::HttpResponse, Self::Error>>
                + Send
                + Sync
                + 'a,
        >,
    >;

    fn call(&'a self, request: openidconnect::HttpRequest) -> Self::Future {
        Box::pin(async move {
            safe_url(&request.uri().to_string()).map_err(std::io::Error::other)?;
            openidconnect::AsyncHttpClient::call(&self.0, request)
                .await
                .map_err(std::io::Error::other)
        })
    }
}

/// OIDC client configured with the provider's discovered endpoints and group claims.
type OidcClient = openidconnect::Client<
    ExtraClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    StandardTokenResponse<
        IdTokenFields<
            ExtraClaims,
            EmptyExtraTokenFields,
            CoreGenderClaim,
            CoreJweContentEncryptionAlgorithm,
            CoreJwsSigningAlgorithm,
        >,
        CoreTokenType,
    >,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// Additional identity-token claims used for group authorization.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct ExtraClaims {
    /// Group memberships asserted by the identity provider.
    #[serde(default)]
    groups: Vec<String>,
}
impl AdditionalClaims for ExtraClaims {}

/// Path receiving the identity provider's authorization response.
const CALLBACK: &str = "/auth/callback";
/// Host-bound session cookie used on HTTPS.
const SESSION_COOKIE_HTTPS: &str = "__Host-axum_auth_gate_session";
/// Host-bound login-state cookie used on HTTPS.
const STATE_COOKIE_HTTPS: &str = "__Host-axum_auth_gate_oidc_state";
/// Session cookie used for loopback HTTP.
const SESSION_COOKIE_HTTP: &str = "axum_auth_gate_session";
/// Login-state cookie used for loopback HTTP.
const STATE_COOKIE_HTTP: &str = "axum_auth_gate_oidc_state";
/// Maximum age of a pending authorization flow.
const LOGIN_TTL: Duration = Duration::from_secs(600);
/// Maximum simultaneous unfinished OIDC login attempts.
const MAX_PENDING_LOGINS: usize = 1_024;
/// Lifetime of an authenticated dashboard session.
const SESSION_TTL: Duration = Duration::from_secs(28_800);

/// Shared authentication configuration and trusted public origin.
#[derive(Clone)]
pub struct Auth(Arc<Mode>, Arc<reqwest::Url>);

/// Dashboard authentication mechanism selected at startup.
enum Mode {
    /// HTTP Basic credentials configured for the dashboard.
    Basic {
        /// Expected Basic username.
        username: String,
        /// Expected Basic password.
        password: String,
        realm: String,
    },
    /// OIDC authorization-code flow and session state.
    Oidc(Box<Oidc>),
}

/// Discovered OIDC provider configuration and local login state.
struct Oidc {
    /// Validating HTTP client for discovery and token requests.
    http_client: SafeHttp,
    /// Configured authorization and token endpoint client.
    client: OidcClient,
    /// Expected issuer of identity tokens.
    issuer: IssuerUrl,
    /// Endpoint supplying identity-token verification keys.
    jwks_uri: JsonWebKeySetUrl,
    /// Provider-advertised signing algorithms accepted for identity tokens.
    signing_algorithms: Vec<CoreJwsSigningAlgorithm>,
    /// Email addresses permitted when verified by the provider.
    allowed_emails: Vec<String>,
    /// Group memberships permitted to access the dashboard.
    allowed_groups: Vec<String>,
    /// Whether authentication cookies require HTTPS.
    secure: bool,
    /// Pending login flows and active sessions protected by a mutex.
    state: Mutex<Store>,
}

impl Oidc {
    /// Selects the host-bound session cookie on HTTPS.
    const fn session_cookie(&self) -> &'static str {
        match self.secure {
            true => SESSION_COOKIE_HTTPS,
            false => SESSION_COOKIE_HTTP,
        }
    }

    /// Selects the host-bound login-state cookie on HTTPS.
    const fn state_cookie(&self) -> &'static str {
        match self.secure {
            true => STATE_COOKIE_HTTPS,
            false => STATE_COOKIE_HTTP,
        }
    }
}

/// In-memory login and session records.
#[derive(Default)]
struct Store {
    /// Authorization state tokens mapped to their pending flow.
    pending: HashMap<String, Pending>,
    /// Session tokens mapped to their expiration instants.
    sessions: HashMap<String, Instant>,
}

/// Data retained between authorization redirect and callback.
struct Pending {
    /// PKCE verifier used when exchanging the authorization code.
    verifier: String,
    /// Nonce expected in the identity token.
    nonce: String,
    /// Local path to visit after successful login.
    return_to: String,
    /// Instant at which the login flow began.
    created: Instant,
}

/// OpenAPI description of the OIDC callback.
#[cfg(feature = "openapi")]
#[derive(utoipa::OpenApi)]
#[openapi(paths(callback))]
pub struct Api;

/// Authentication settings and the trusted public origin.
#[derive(Clone)]
pub struct AuthConfig {
    /// Public scheme and authority, with no path or query.
    pub origin: String,
    /// Authentication mechanism.
    pub mode: AuthMode,
}

/// Authentication mechanism and its credentials.
#[derive(Clone)]
pub enum AuthMode {
    /// HTTP Basic authentication.
    Basic {
        username: String,
        password: String,
        realm: String,
    },
    /// OIDC authorization-code authentication.
    Oidc {
        issuer: String,
        client_id: String,
        client_secret: String,
        redirect_url: String,
        allowed_emails: Vec<String>,
        allowed_groups: Vec<String>,
    },
}

/// Authorizes a verified allowlisted email or an allowlisted group membership.
fn authorized(
    email: Option<&str>,
    verified: bool,
    membership: &[String],
    emails: &[String],
    groups: &[String],
) -> bool {
    (verified && email.is_some_and(|value| emails.iter().any(|entry| entry == value)))
        || membership.iter().any(|group| groups.contains(group))
}

/// Validates an endpoint URL, allowing plaintext HTTP only on loopback.
// Only explicitly configured loopback HTTP is permitted. All other endpoints
// must use TLS; never derive the public callback URL from request headers.
fn safe_url(value: &str) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(value).map_err(|e| format!("invalid URL: {e}"))?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "URL must use HTTPS (or HTTP on loopback), without credentials or fragment".into(),
        );
    }
    Ok(url)
}

impl Auth {
    /// Validates configuration and discovers the OIDC provider before serving.
    pub async fn new(config: AuthConfig) -> Result<Self, String> {
        let origin = safe_url(&config.origin)?;
        if origin.path() != "/" || origin.query().is_some() {
            return Err("origin must contain only scheme and authority".into());
        }
        let mode = match config.mode {
            AuthMode::Basic {
                username,
                password,
                realm,
            } => {
                if username.trim().is_empty()
                    || password.trim().is_empty()
                    || realm.trim().is_empty()
                {
                    return Err("Basic username, password and realm must not be blank".into());
                }
                if username.contains(':') {
                    return Err("Basic username must not contain ':'".into());
                }
                if realm.chars().any(char::is_control) {
                    return Err("Basic realm must not contain control characters".into());
                }
                Mode::Basic {
                    username,
                    password,
                    realm,
                }
            }
            AuthMode::Oidc {
                issuer,
                client_id,
                client_secret,
                redirect_url,
                allowed_emails,
                allowed_groups,
            } => {
                if issuer.trim().is_empty()
                    || client_id.trim().is_empty()
                    || client_secret.trim().is_empty()
                    || redirect_url.trim().is_empty()
                {
                    return Err(
                        "OIDC issuer, client ID, client secret and redirect URL must not be blank"
                            .into(),
                    );
                }
                let issuer_url = safe_url(&issuer)?;
                if issuer_url.query().is_some() {
                    return Err("OIDC issuer must not contain a query".into());
                }
                let allowed_emails: Vec<_> = allowed_emails
                    .into_iter()
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty())
                    .collect();
                let allowed_groups: Vec<_> = allowed_groups
                    .into_iter()
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty())
                    .collect();
                if allowed_emails.is_empty() && allowed_groups.is_empty() {
                    return Err("Configure at least one OIDC allowed email or group".into());
                }
                let redirect = safe_url(&redirect_url)?;
                if redirect.origin() != origin.origin() {
                    return Err("OIDC redirect URL must match origin".into());
                }
                if redirect.path() != CALLBACK || redirect.query().is_some() {
                    return Err(format!(
                        "OIDC redirect URL must end in {CALLBACK} without a query"
                    ));
                }
                let http_client = SafeHttp(
                    reqwest::Client::builder()
                        .redirect(reqwest::redirect::Policy::none())
                        .timeout(Duration::from_secs(10))
                        .build()
                        .map_err(|e| format!("creating OIDC client: {e}"))?,
                );
                let metadata = CoreProviderMetadata::discover_async(
                    IssuerUrl::new(issuer).map_err(|e| format!("invalid OIDC issuer: {e}"))?,
                    &http_client,
                )
                .await
                .map_err(|e| format!("OIDC discovery: {e}"))?;
                safe_url(metadata.authorization_endpoint().url().as_str())?;
                if let Some(endpoint) = metadata.token_endpoint() {
                    safe_url(endpoint.url().as_str())?;
                }
                let issuer = metadata.issuer().clone();
                let jwks_uri = metadata.jwks_uri().clone();
                let signing_algorithms = metadata.id_token_signing_alg_values_supported().clone();
                let client = OidcClient::from_provider_metadata(
                    metadata,
                    ClientId::new(client_id),
                    Some(ClientSecret::new(client_secret)),
                )
                .set_redirect_uri(RedirectUrl::new(redirect_url).map_err(|e| e.to_string())?);
                Mode::Oidc(Box::new(Oidc {
                    http_client,
                    client,
                    issuer,
                    jwks_uri,
                    signing_algorithms,
                    allowed_emails,
                    allowed_groups,
                    secure: redirect.scheme() == "https",
                    state: Mutex::new(Store::default()),
                }))
            }
        };
        Ok(Self(Arc::new(mode), Arc::new(origin)))
    }

    /// Protects the supplied routes and adds the OIDC callback endpoint.
    /// Merge routes that should remain public after calling this method.
    pub fn protect(&self, router: Router) -> Router {
        router
            .merge(
                Router::new()
                    .route(CALLBACK, get(callback))
                    .with_state(self.clone()),
            )
            .layer(middleware::from_fn_with_state(self.clone(), authenticate))
    }
}

/// Generates a random URL-safe token for an authenticated session.
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Finds the last named cookie across the request's Cookie headers.
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .filter_map(|(key, value)| (key == name).then_some(value))
        .next_back()
        .map(str::to_owned)
}

/// Builds an HTTP-only, same-site cookie with an optional Secure attribute.
fn set_cookie(name: &str, value: &str, max_age: u64, secure: bool) -> String {
    format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    )
}

/// Appends a cookie and prevents caching of the response.
fn with_cookie(mut response: Response, value: &str) -> Response {
    if let Ok(value) = HeaderValue::from_str(value) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Compares byte slices without early exit on differing bytes.
// Avoid early exit on differing bytes for credentials and state values.
fn equal(a: &[u8], b: &[u8]) -> bool {
    let mut difference = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        difference |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    difference == 0
}

/// Checks request origin and authentication, disabling caching for protected responses.
async fn authenticate(State(auth): State<Auth>, req: Request, next: Next) -> Response {
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

/// Enforces the configured host and same-origin rules for dashboard requests.
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

#[cfg(test)]
/// Exercises dashboard authentication, origin checks, and OIDC login.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

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
    fn test_oidc(store: Store) -> Oidc {
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
        .set_redirect_uri(
            RedirectUrl::new("https://dashboard.example/auth/callback".into()).unwrap(),
        );
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
            origin: "https://dashboard.example".into(),
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
                .header(header::HOST, "dashboard.example");
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
            Arc::new(reqwest::Url::parse("https://dashboard.example").unwrap()),
        );
        let app = auth.protect(Router::new().route("/", get(|| async { "ok" })));
        for status in [StatusCode::SEE_OTHER, StatusCode::SERVICE_UNAVAILABLE] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/")
                        .header(header::HOST, "dashboard.example")
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
                    .header(header::HOST, "dashboard.example")
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
                Arc::new(reqwest::Url::parse("https://dashboard.example").unwrap()),
            );
            let app = auth.protect(
                Router::new().route("/api/settings", axum::routing::post(|| async { "ok" })),
            );
            for (host, origin, fetch, expected) in [
                (
                    "dashboard.example",
                    Some("https://dashboard.example"),
                    Some("same-origin"),
                    StatusCode::OK,
                ),
                ("dashboard.example", None, None, StatusCode::OK),
                (
                    "dashboard.example",
                    Some("https://evil.example"),
                    Some("cross-site"),
                    StatusCode::FORBIDDEN,
                ),
                (
                    "dashboard.example",
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

    /// Basic authentication protects both dashboard and management API routes.
    #[tokio::test]
    async fn basic_auth_protects_dashboard_and_api() {
        let auth = Auth::new(AuthConfig {
            origin: "https://dashboard.example".into(),
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
                .route("/", get(|| async { "dashboard" }))
                .route("/api/observability", get(|| async { "logs" })),
        );
        for path in ["/", "/api/observability"] {
            let request = Request::builder()
                .uri(path)
                .header(header::HOST, "dashboard.example")
                .body(Body::empty());
            let response = app.clone().oneshot(request.unwrap()).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                response.headers()[header::WWW_AUTHENTICATE],
                "Basic realm=\"my \\\"realm\\\"\", charset=\"UTF-8\""
            );

            let request = Request::builder()
                .uri(path)
                .header(header::HOST, "dashboard.example")
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
                .header(header::HOST, "dashboard.example")
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
                "https://dashboard.example",
                "dashboard.example",
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
            Arc::new(reqwest::Url::parse("https://dashboard.example").unwrap()),
        );
        let app = auth.protect(Router::new().route("/", get(|| async { "dashboard" })));
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
                .header(header::HOST, "dashboard.example");
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
            serde_json::from_str(include_str!("../tests/fixtures/oidc-test-key.json")).unwrap();
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
            origin: "https://dashboard.example".into(),
            mode: AuthMode::Oidc {
                issuer,
                client_id: "client".into(),
                client_secret: "secret".into(),
                redirect_url: "https://dashboard.example/auth/callback".into(),
                allowed_emails: vec![],
                allowed_groups: vec!["admins".into()],
            },
        })
        .await
        .unwrap();
        publish_key.store(true, std::sync::atomic::Ordering::Relaxed);
        let app = auth.protect(
            Router::new()
                .route("/", get(|| async { "dashboard" }))
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
                        .header(header::HOST, "dashboard.example")
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
                        .header(header::HOST, "dashboard.example")
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
                            .header(header::HOST, "dashboard.example")
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
}

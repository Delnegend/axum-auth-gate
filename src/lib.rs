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
mod error;
pub use error::Error;

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
/// Lifetime of an authenticated session.
const SESSION_TTL: Duration = Duration::from_secs(28_800);

/// Shared authentication configuration and trusted public origin.
#[derive(Clone)]
pub struct Auth(Arc<Mode>, Arc<reqwest::Url>);

/// Authentication mechanism selected at startup.
enum Mode {
    /// HTTP Basic credentials configured for protected routes.
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
    /// Group memberships permitted to access protected routes.
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
fn safe_url(value: &str) -> Result<reqwest::Url, Error> {
    let url = reqwest::Url::parse(value).map_err(|e| Error::InvalidUrl(Box::new(e)))?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::UnsafeUrl);
    }
    Ok(url)
}

impl Auth {
    /// Validates configuration and discovers the OIDC provider before serving.
    pub async fn new(config: AuthConfig) -> Result<Self, Error> {
        let origin = safe_url(&config.origin)?;
        if origin.path() != "/" || origin.query().is_some() {
            return Err(Error::InvalidOrigin);
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
                    return Err(Error::BlankBasicCredentials);
                }
                if username.contains(':') {
                    return Err(Error::InvalidBasicUsername);
                }
                if realm.chars().any(char::is_control) {
                    return Err(Error::InvalidBasicRealm);
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
                    return Err(Error::BlankOidcConfig);
                }
                let issuer_url = safe_url(&issuer)?;
                if issuer_url.query().is_some() {
                    return Err(Error::InvalidIssuerQuery);
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
                    return Err(Error::EmptyAllowlist);
                }
                let redirect = safe_url(&redirect_url)?;
                if redirect.origin() != origin.origin() {
                    return Err(Error::RedirectOriginMismatch);
                }
                if redirect.path() != CALLBACK || redirect.query().is_some() {
                    return Err(Error::InvalidRedirect);
                }
                let http_client = SafeHttp(
                    reqwest::Client::builder()
                        .redirect(reqwest::redirect::Policy::none())
                        .timeout(Duration::from_secs(10))
                        .build()
                        .map_err(Error::HttpClient)?,
                );
                let metadata = CoreProviderMetadata::discover_async(
                    IssuerUrl::new(issuer).map_err(|e| Error::InvalidIssuer(Box::new(e)))?,
                    &http_client,
                )
                .await
                .map_err(Error::Discovery)?;
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
                .set_redirect_uri(
                    RedirectUrl::new(redirect_url).map_err(|e| Error::InvalidUrl(Box::new(e)))?,
                );
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

mod middleware_auth;
use middleware_auth::authenticate;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

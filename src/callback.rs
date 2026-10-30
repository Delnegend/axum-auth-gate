use std::time::Instant;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use openidconnect::{
    AuthorizationCode, Nonce, OAuth2TokenResponse, PkceCodeVerifier, TokenResponse,
    core::{CoreIdTokenVerifier, CoreJsonWebKeySet, CoreJwsSigningAlgorithm},
};
use serde::Deserialize;

use super::{
    Auth, LOGIN_TTL, Mode, Oidc, Pending, SESSION_TTL, authorized, cookie, equal, random_token,
    set_cookie, with_cookie,
};

/// Query parameters returned by the OIDC authorization endpoint.
#[derive(Deserialize)]
pub(super) struct Callback {
    /// CSRF state returned by the provider.
    state: Option<String>,
    /// Authorization code to exchange for tokens.
    code: Option<String>,
    /// Provider-reported authorization error, if any.
    error: Option<String>,
}

/// Consumes OIDC callback state and creates a session after successful verification.
#[cfg_attr(feature = "openapi", utoipa::path(get, path = "/auth/callback", operation_id = "dashboardOidcCallback",
    params(("state" = Option<String>, Query, description = "OIDC state"),
        ("code" = Option<String>, Query, description = "Authorization code"),
        ("error" = Option<String>, Query, description = "Identity provider error")),
    responses((status = 303, description = "Signed in; redirects to the dashboard"),
        (status = 400, description = "Invalid or expired login state"),
        (status = 401, description = "Authentication rejected"),
        (status = 404, description = "OIDC is not enabled"),
        (status = 500, description = "Session could not be created"))))]
pub(super) async fn callback(
    State(auth): State<Auth>,
    headers: HeaderMap,
    Query(params): Query<Callback>,
) -> Response {
    let Mode::Oidc(oidc) = auth.0.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let clear = set_cookie(oidc.state_cookie(), "", 0, oidc.secure);
    let Some(state) = params.state else {
        return with_cookie(StatusCode::BAD_REQUEST.into_response(), &clear);
    };
    let Some(browser_state) = cookie(&headers, oidc.state_cookie()) else {
        return with_cookie(StatusCode::BAD_REQUEST.into_response(), &clear);
    };
    if !equal(state.as_bytes(), browser_state.as_bytes()) {
        return with_cookie(StatusCode::BAD_REQUEST.into_response(), &clear);
    }
    let pending = oidc.state.lock().await.pending.remove(&state);
    let Some(pending) = pending.filter(|p| p.created.elapsed() < LOGIN_TTL) else {
        return with_cookie(StatusCode::BAD_REQUEST.into_response(), &clear);
    };
    let Some(code) = params.code.filter(|_| params.error.is_none()) else {
        return with_cookie(StatusCode::UNAUTHORIZED.into_response(), &clear);
    };
    if verify_login(oidc, &code, &pending).await.is_err() {
        return with_cookie(StatusCode::UNAUTHORIZED.into_response(), &clear);
    }
    let Some(expires) = Instant::now().checked_add(SESSION_TTL) else {
        return with_cookie(StatusCode::INTERNAL_SERVER_ERROR.into_response(), &clear);
    };
    let session = random_token();
    oidc.state
        .lock()
        .await
        .sessions
        .insert(session.clone(), expires);
    let response = with_cookie(Redirect::to(&pending.return_to).into_response(), &clear);
    with_cookie(
        response,
        &set_cookie(
            oidc.session_cookie(),
            &session,
            SESSION_TTL.as_secs(),
            oidc.secure,
        ),
    )
}

/// Exchanges a code and verifies the identity token and authorization claims.
async fn verify_login(oidc: &Oidc, code: &str, pending: &Pending) -> Result<(), String> {
    let tokens = oidc
        .client
        .exchange_code(AuthorizationCode::new(code.to_owned()))
        .map_err(|e| e.to_string())?
        .set_pkce_verifier(PkceCodeVerifier::new(pending.verifier.clone()))
        .request_async(&oidc.http_client)
        .await
        .map_err(|e| e.to_string())?;
    let id_token = tokens.id_token().ok_or("OIDC response missing ID token")?;
    if !matches!(
        id_token.signing_alg().map_err(|e| e.to_string())?,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256
            | CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384
            | CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512
            | CoreJwsSigningAlgorithm::RsaSsaPssSha256
            | CoreJwsSigningAlgorithm::RsaSsaPssSha384
            | CoreJwsSigningAlgorithm::RsaSsaPssSha512
            | CoreJwsSigningAlgorithm::EcdsaP256Sha256
            | CoreJwsSigningAlgorithm::EcdsaP384Sha384
            | CoreJwsSigningAlgorithm::EdDsa
    ) {
        return Err("unsupported ID token algorithm".into());
    }
    let keys = CoreJsonWebKeySet::fetch_async(&oidc.jwks_uri, &oidc.http_client)
        .await
        .map_err(|e| e.to_string())?;
    let verifier = CoreIdTokenVerifier::new_public_client(
        oidc.client.client_id().clone(),
        oidc.issuer.clone(),
        keys,
    )
    .set_allowed_algs(oidc.signing_algorithms.clone());
    let claims = id_token
        .claims(&verifier, &Nonce::new(pending.nonce.clone()))
        .map_err(|e| e.to_string())?;
    if claims.subject().as_str().is_empty() {
        return Err("invalid ID token subject".into());
    }
    if let Some(expected) = claims.access_token_hash() {
        let actual = openidconnect::AccessTokenHash::from_token(
            tokens.access_token(),
            id_token.signing_alg().map_err(|e| e.to_string())?,
            id_token.signing_key(&verifier).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        if actual != *expected {
            return Err("invalid access token hash".into());
        }
    }
    if !authorized(
        claims.email().map(|email| email.as_str()),
        claims.email_verified().unwrap_or(false),
        &claims.additional_claims().groups,
        &oidc.allowed_emails,
        &oidc.allowed_groups,
    ) {
        return Err("OIDC identity is not authorized".into());
    }
    Ok(())
}

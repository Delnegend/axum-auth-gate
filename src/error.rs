/// Errors configuring authentication or verifying an OIDC identity.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A URL could not be parsed.
    #[error("invalid URL: {0}")]
    InvalidUrl(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// A URL violates the transport or authority requirements.
    #[error("URL must use HTTPS (or HTTP on loopback), without credentials or fragment")]
    UnsafeUrl,
    /// The configured origin contains a path or query.
    #[error("origin must contain only scheme and authority")]
    InvalidOrigin,
    /// A Basic authentication field is blank.
    #[error("Basic username, password and realm must not be blank")]
    BlankBasicCredentials,
    /// A Basic username contains a colon.
    #[error("Basic username must not contain ':'")]
    InvalidBasicUsername,
    /// A Basic realm contains control characters.
    #[error("Basic realm must not contain control characters")]
    InvalidBasicRealm,
    /// An OIDC configuration field is blank.
    #[error("OIDC issuer, client ID, client secret and redirect URL must not be blank")]
    BlankOidcConfig,
    /// The issuer contains a query.
    #[error("OIDC issuer must not contain a query")]
    InvalidIssuerQuery,
    /// No identities are allowed to sign in.
    #[error("Configure at least one OIDC allowed email or group")]
    EmptyAllowlist,
    /// The redirect URL does not match the configured origin.
    #[error("OIDC redirect URL must match origin")]
    RedirectOriginMismatch,
    /// The redirect URL does not identify the callback endpoint.
    #[error("OIDC redirect URL must end in /auth/callback without a query")]
    InvalidRedirect,
    /// The OIDC HTTP client could not be constructed.
    #[error("creating OIDC client: {0}")]
    HttpClient(#[source] reqwest::Error),
    /// The OIDC issuer URL could not be parsed.
    #[error("invalid OIDC issuer: {0}")]
    InvalidIssuer(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// OIDC provider discovery failed.
    #[error("OIDC discovery: {0}")]
    Discovery(#[source] openidconnect::DiscoveryError<std::io::Error>),
    /// An OIDC response could not be verified.
    #[error("OIDC verification: {0}")]
    OidcVerification(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The token response did not include an identity token.
    #[error("OIDC response missing ID token")]
    MissingIdToken,
    /// The identity token uses an unsupported signature algorithm.
    #[error("unsupported ID token algorithm")]
    UnsupportedIdTokenAlgorithm,
    /// The identity token has an empty subject.
    #[error("invalid ID token subject")]
    InvalidSubject,
    /// The access token does not match the identity token.
    #[error("invalid access token hash")]
    InvalidAccessTokenHash,
    /// The identity does not match the configured allowlist.
    #[error("OIDC identity is not authorized")]
    UnauthorizedIdentity,
}

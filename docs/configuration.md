# Configuration

Construct `AuthConfig` in your application; the library does not read environment variables. `origin` is the public scheme and authority only, such as `https://app.example.com`. Use HTTPS except for explicitly configured loopback HTTP (`localhost`, `127.0.0.1`, or `[::1]`) during local development. Behind a reverse proxy, preserve the public `Host` header and configure the external origin, not the upstream address. The gate does not derive its trusted origin from forwarded headers. Browser writes require a matching `Origin`; authenticated non-browser clients may omit it.

## Authentication modes

`AuthMode::Basic` takes a `username`, `password`, and challenge `realm`. Supply secrets from your application's configuration, not source code. Basic credentials are only protected in transit when HTTPS is used.

`AuthMode::Oidc` takes `issuer`, `client_id`, `client_secret`, `redirect_url`, `allowed_emails`, and `allowed_groups`. Register an OIDC confidential client with the provider and register the exact public redirect URL `https://app.example.com/auth/callback`. The redirect must share the configured origin and have no query. Configure at least one allowed email or group; the provider must return the corresponding verified email or group claims. The gate requests the `groups` scope when a group allowlist is configured.

### OIDC example

To use an identity provider with the [Quick Start](../README.md#quick-start), register a confidential client with redirect URL `http://127.0.0.1:3000/auth/callback`. Replace the `AuthConfig` passed to `Auth::new` with:

```rust
AuthConfig {
    origin: "http://127.0.0.1:3000".into(),
    mode: AuthMode::Oidc {
        issuer: std::env::var("OIDC_ISSUER")?,
        client_id: std::env::var("OIDC_CLIENT_ID")?,
        client_secret: std::env::var("OIDC_CLIENT_SECRET")?,
        redirect_url: "http://127.0.0.1:3000/auth/callback".into(),
        allowed_emails: vec![],
        allowed_groups: vec![std::env::var("OIDC_ALLOWED_GROUP")?],
    },
}
```

Set `OIDC_ISSUER` to the provider's HTTPS issuer URL, `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` to the registered client's credentials, and `OIDC_ALLOWED_GROUP` to an exact group name returned by the provider. Run `cargo run`, open `http://127.0.0.1:3000/` in a browser, and sign in with an account in that group. For production, configure an HTTPS origin and matching callback instead of the loopback URLs.

## Routing and sessions

Call `protect` on the router containing only the routes to secure; it adds `/auth/callback`. Do not merge another callback at that path. Protected `/api` and `/api/*` requests receive API-specific handling; place unrelated public endpoints outside the protected router. The optional `openapi` feature exports `Api` implementing `utoipa::OpenApi` for the callback.

OIDC login and session cookies are HTTP-only, `SameSite=Lax`, and scoped to `/`. HTTPS uses `__Host-` prefixed, Secure, host-only cookies; loopback HTTP uses unprefixed names. If multiple matching cookies occur across Cookie headers, the last matching value wins. Sessions and pending logins are process-local and are lost on restart; multiple replicas do not share them. Plan routing accordingly.

Protected responses use `Cache-Control: no-store`, including HTML, assets and authentication errors. OIDC permits up to 1,024 unfinished login attempts at once; further attempts receive HTTP 503 until a pending attempt completes or expires after ten minutes. Existing authenticated sessions continue to work when that limit is reached.

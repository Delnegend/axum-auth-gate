# axum-auth-gate

An authentication gate for Axum applications that protects selected routes with HTTP Basic or OpenID Connect.

## Quick start

Add the crate to your application:

```sh
cargo add axum-auth-gate
```

Protect the routes that need authentication, supplying credentials from your application's configuration:

```rust
use axum::{routing::get, Router};
use axum_auth_gate::{Auth, AuthConfig, AuthMode};

async fn protected_app(username: String, password: String) -> Result<Router, String> {
    let auth = Auth::new(AuthConfig {
        origin: "https://dashboard.example.com".into(),
        mode: AuthMode::Basic {
            username,
            password,
            realm: "Dashboard".into(),
        },
    }).await?;
    Ok(auth.protect(Router::new().route("/", get(|| async { "Hello" }))))
}
```

Serve the returned router with Axum, then open it at the configured origin and authenticate. Keep public routes outside the protected router.

## Highlights

- Protect a selected router with Basic authentication or an OIDC login.
- Restrict OIDC access to allowed email addresses or groups.
- Use a configured public origin instead of trusting forwarded headers.
- Optionally include the callback in your OpenAPI document with the `openapi` feature.

See [configuration](docs/configuration.md) for OIDC and proxy requirements and [development](docs/development.md) for the checks and release prerequisites.

## License

MIT OR Apache-2.0.

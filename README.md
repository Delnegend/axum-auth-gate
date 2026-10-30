<div align="center">

# axum-auth-gate

**Protect selected Axum routes with a password or an identity provider, without building sign-in yourself.**

[![CI](https://img.shields.io/github/actions/workflow/status/Delnegend/axum-auth-gate/ci.yml?branch=main&style=flat-square)](https://github.com/Delnegend/axum-auth-gate/actions) [![Crates.io](https://img.shields.io/crates/v/axum-auth-gate?style=flat-square)](https://crates.io/crates/axum-auth-gate) [![License](https://img.shields.io/crates/l/axum-auth-gate?style=flat-square)](#license)

</div>

## Quick Start

Create an example Rust application and add the library:

```sh
cargo new auth-example && cd auth-example
cargo add axum axum-auth-gate
cargo add tokio --features macros,rt-multi-thread,net
```

Replace `src/main.rs` with:

```rust
use axum::{routing::get, Router};
use axum_auth_gate::{Auth, AuthConfig, AuthMode};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let auth = Auth::new(AuthConfig {
        origin: "http://127.0.0.1:3000".into(),
        mode: AuthMode::Basic {
            username: std::env::var("AUTH_USER")?,
            password: std::env::var("AUTH_PASSWORD")?,
            realm: "Example".into(),
        },
    }).await?;
    let app = auth.protect(Router::new().route("/", get(|| async { "Hello" })));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

Run the example, then verify it in another terminal:

```sh
AUTH_USER=demo AUTH_PASSWORD=example cargo run
# In another terminal:
curl -u demo:example http://127.0.0.1:3000/
```

The response is `Hello`. These credentials and plain HTTP are for local development only. Use HTTPS and securely supplied credentials for a real deployment.

## Highlights

- Protect only the routes you choose, leaving public routes outside the gate.
- Accept a password or sign in through an OpenID Connect identity provider.
- Limit identity-provider access to allowed email addresses or groups.
- Avoid trusting forwarded headers for the public origin.
- Include the sign-in callback in an OpenAPI document when needed.

## Documentation

- [Configuration](docs/configuration.md) — identity providers, origins, sessions, and reverse proxies.
- [Development](docs/development.md) — checks and publishing.
- [API reference](https://docs.rs/axum-auth-gate) — Rust types and methods.

## License

[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).

# Development

## Prerequisites

Install Rust and Cargo with the `rustfmt` and `clippy` components, `just`, and Python 3.11 or newer. Cargo 1.100 or newer is required to enforce the configured 14-day registry publish-age quarantine; older Cargo versions do not enforce it. The shared dependency-update workflow skips Cargo updates when it cannot enforce the cooldown.

## Checks

```sh
just check
```

The gate checks formatting and Clippy and runs tests with default and all features. `just version get` prints the package version; `just version set X.Y.Z` changes the package version and updates the workspace lockfile without committing or tagging.

## Publishing

The manually dispatched GitHub release workflow uses the [shared release actions](https://github.com/Delnegend/actions/blob/main/docs/configuration.md), packages the crate, publishes new releases to crates.io, and creates a GitHub release. SHA and dry-run dispatches do not publish; dispatching an existing tag retries a failed publication and skips a crate version that is already published. The first release needs an existing `v0.0.0` tag at the repository's root commit for version calculation, and a crates.io API token with permission to publish this crate stored as the GitHub Actions secret `CARGO_REGISTRY_TOKEN`. Ensure the calculated version is the intended first release before dispatching.

[crates.io trusted publishing](https://crates.io/docs/trusted-publishing) requires the crate to have already been published; after the initial release, configure a trusted publisher and migrate the workflow to OIDC before removing the token. Enable GitHub Actions permission to create pull requests and GitHub auto-merge for automated dependency PRs. Keep branch protection compatible with the release workflow's direct version commit and tag push.

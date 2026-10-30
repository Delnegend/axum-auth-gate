default:
    @just --list

# Check both the default and optional OpenAPI feature configurations.
check:
    cargo fmt --all --check
    cargo clippy --locked --all-targets --all-features -- -D warnings
    cargo test --locked
    cargo test --locked --all-features

# Version contract for the shared release action.
version action ver="":
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{action}}" in
      get)
        python3 -c "import tomllib; print(tomllib.load(open('Cargo.toml', 'rb'))['package']['version'])"
        ;;
      set)
        [[ "{{ver}}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'usage: just version set X.Y.Z' >&2; exit 1; }
        sed -i -E '0,/^version = ".*"/s//version = "{{ver}}"/' Cargo.toml
        cargo update --workspace
        ;;
      *) echo 'usage: just version get|set X.Y.Z' >&2; exit 1 ;;
    esac

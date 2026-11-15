#!/usr/bin/env bash
# Build the Lookout Rust workspace; optionally package the desktop app.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$SCRIPT_DIR/source"

RELEASE=true
DEB=false
for arg in "$@"; do
    case "$arg" in
        --release) RELEASE=true ;;
        --debug) RELEASE=false ;;
        --deb) DEB=true ;;
        -h|--help)
            echo "Usage: ./build.sh [--release|--debug] [--deb]"
            echo "  --release   Build with optimizations (default)"
            echo "  --debug     Build without optimizations (cargo build)"
            echo "  --deb       Package a .deb (implies --release; requires cargo-deb)"
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg" >&2
            exit 1
            ;;
    esac
done

if [ "$DEB" = true ]; then
    RELEASE=true
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo not found. Install Rust via https://rustup.rs and re-run." >&2
    exit 1
fi

missing_libs=()
for lib in gtk4 libadwaita-1 webkitgtk-6.0; do
    if ! pkg-config --exists "$lib" 2>/dev/null; then
        missing_libs+=("$lib")
    fi
done
if [ "${#missing_libs[@]}" -gt 0 ]; then
    echo "error: missing development libraries: ${missing_libs[*]}" >&2
    echo "On Debian/Ubuntu: sudo apt-get install libgtk-4-dev libadwaita-1-dev libwebkitgtk-6.0-dev" >&2
    exit 1
fi

if [ "$DEB" = true ]; then
    # `cargo install` puts binaries in $CARGO_HOME/bin (default ~/.cargo/bin).
    # With a distro-packaged cargo that directory is often not on PATH, so
    # `command -v` misses cargo-deb even though `cargo deb` would find it.
    CARGO_BIN_DIR="${CARGO_HOME:-$HOME/.cargo}/bin"
    case ":$PATH:" in
        *":$CARGO_BIN_DIR:"*) ;;
        *) PATH="$CARGO_BIN_DIR:$PATH" ;;
    esac
    export PATH

    if ! command -v dpkg-deb >/dev/null 2>&1; then
        echo "error: dpkg-deb is required for Debian packaging" >&2
        exit 1
    fi
    if ! command -v cargo-deb >/dev/null 2>&1; then
        echo "error: cargo-deb not found. Install it with: cargo install cargo-deb --locked" >&2
        exit 1
    fi
fi

cd "$WORKSPACE_DIR"

if [ "$RELEASE" = true ]; then
    cargo build --locked --workspace --release
    BINARY_PATH="$WORKSPACE_DIR/target/release/lookout"
else
    cargo build --locked --workspace
    BINARY_PATH="$WORKSPACE_DIR/target/debug/lookout"
fi

echo
echo "Built binary: $BINARY_PATH"

if [ "$DEB" = true ]; then
    # cargo-deb stamps every file in the package with a single reproducible
    # timestamp. Absent SOURCE_DATE_EPOCH, it falls back to the mtime of the
    # packaged crate's own Cargo.toml (crates/app/Cargo.toml) - which, since
    # its version is inherited via `version.workspace = true`, never actually
    # changes at release time and so stays pinned to whenever the repo was
    # checked out, not any real build or release date. Pin it to the last
    # git commit instead: still reproducible for a given commit, but an
    # accurate date rather than an arbitrary checkout-time one.
    export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$WORKSPACE_DIR" log -1 --format=%ct)}"
    # Keep the upstream Cargo version, but distinguish this fork's Debian
    # builds from upstream's -1 package. Commit time and hash identify the
    # source revision without depending on a full (non-shallow) history.
    COMMIT_TIME="$(git -C "$WORKSPACE_DIR" log -1 --format=%ct)"
    COMMIT_SHA="$(git -C "$WORKSPACE_DIR" rev-parse --short=12 HEAD)"
    REVISION="${LOOKOUT_DEB_REVISION:-1+lookout.${COMMIT_TIME}.g${COMMIT_SHA}}"

    # Never select an unrelated older .deb by its modification time.
    # Stage the exact output, then derive its final name from its own metadata.
    DEB_DIR="$WORKSPACE_DIR/target/debian"
    mkdir -p "$DEB_DIR"
    STAGING="$(mktemp -d "$DEB_DIR/.lookout-build.XXXXXX")"
    trap 'rm -rf -- "$STAGING"' EXIT
    cargo deb --locked --no-build -p lookout-app --deb-revision "$REVISION" --output "$STAGING/lookout.deb"
    VERSION="$(dpkg-deb -f "$STAGING/lookout.deb" Version)"
    ARCH="$(dpkg-deb -f "$STAGING/lookout.deb" Architecture)"
    DEB_PATH="$DEB_DIR/lookout_${VERSION}_${ARCH}.deb"
    mv -- "$STAGING/lookout.deb" "$DEB_PATH"
    echo "Built package: $DEB_PATH"
fi

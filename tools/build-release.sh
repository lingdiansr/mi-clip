#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
# Keep personal build paths out of the binary. Encoded flags handle spaces safely.
miclip_separator=$(printf '\037')
CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS:+${CARGO_ENCODED_RUSTFLAGS}${miclip_separator}}--remap-path-prefix=$PWD=/src${miclip_separator}--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
export CARGO_ENCODED_RUSTFLAGS
if [ -z "${MI_CLIP_UPDATE_REPOSITORY:-}" ]; then
    miclip_remote=$(git remote get-url origin 2>/dev/null || true)
    case "$miclip_remote" in
        https://github.com/*) MI_CLIP_UPDATE_REPOSITORY=${miclip_remote#https://github.com/} ;;
        git@github.com:*) MI_CLIP_UPDATE_REPOSITORY=${miclip_remote#git@github.com:} ;;
    esac
    MI_CLIP_UPDATE_REPOSITORY=${MI_CLIP_UPDATE_REPOSITORY:-}
    MI_CLIP_UPDATE_REPOSITORY=${MI_CLIP_UPDATE_REPOSITORY%.git}
fi
export MI_CLIP_UPDATE_REPOSITORY
cargo build --release --locked "$@"

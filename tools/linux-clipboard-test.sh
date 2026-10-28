#!/bin/sh
# Runs the ignored native-clipboard test inside a private headless compositor.
set -eu
cd "$(dirname "$0")/.."

runtime=$(mktemp -d)
sway=
cleanup() {
    [ -z "$sway" ] || kill "$sway" 2>/dev/null || true
    rm -rf "$runtime"
}
trap cleanup EXIT

export XDG_RUNTIME_DIR="$runtime"
export WLR_BACKENDS=headless
export WLR_LIBINPUT_NO_DEVICES=1
export WLR_RENDERER=pixman
printf 'output HEADLESS-1 mode 1280x800\n' >"$runtime/sway.conf"
sway -c "$runtime/sway.conf" >"$runtime/sway.log" 2>&1 &
sway=$!

socket=
attempt=0
while [ "$attempt" -lt 300 ]; do
    for candidate in "$runtime"/wayland-*; do
        if [ -e "$candidate" ]; then
            socket=$candidate
            break
        fi
    done
    [ -z "$socket" ] || break
    if ! kill -0 "$sway" 2>/dev/null; then
        cat "$runtime/sway.log" >&2
        echo "Headless compositor exited before publishing a socket." >&2
        exit 1
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
[ -n "$socket" ] || {
    echo "Headless compositor did not publish a Wayland socket." >&2
    exit 1
}
export WAYLAND_DISPLAY=$(basename "$socket")

cargo test --locked --no-default-features --features research --lib \
    clipboard::wayland::tests::native_selection_round_trip -- --ignored --exact

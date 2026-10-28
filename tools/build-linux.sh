#!/bin/sh
# Builds the Linux desktop package (binary + entries + installer) for this host.
set -eu
cd "$(dirname "$0")/.."

if [ "$(uname -s)" != Linux ]; then
    echo "tools/build-linux.sh runs on Linux only." >&2
    exit 1
fi
arch=$(uname -m)
case "$arch" in
    x86_64 | aarch64) ;;
    *)
        echo "Unsupported architecture: $arch (expected x86_64 or aarch64)." >&2
        exit 1
        ;;
esac

manifest=
while [ $# -gt 0 ]; do
    case "$1" in
        --manifest)
            shift
            [ $# -gt 0 ] || {
                echo "--manifest needs a signed manifest path." >&2
                exit 1
            }
            manifest=$1
            shift
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

if [ -z "${MI_CLIP_SKIP_BUILD:-}" ]; then
    sh tools/build-release.sh --bin mi-clip
fi
[ -x target/release/mi-clip ] || {
    echo "target/release/mi-clip is missing; build it first." >&2
    exit 1
}

package="target/linux/Clip-linux-$arch"
archive="target/linux/Clip-linux-$arch.tar.gz"
rm -rf "$package" "$archive" "$archive.sha256"
mkdir -p "$package/bin" \
    "$package/share/applications" \
    "$package/share/kio/servicemenus" \
    "$package/share/icons/hicolor/scalable/apps"
install -m 0755 target/release/mi-clip "$package/bin/mi-clip"
install -m 0644 linux/com.cyeam.miclip.desktop \
    "$package/share/applications/com.cyeam.miclip.desktop"
install -m 0644 linux/mi-clip-share.desktop \
    "$package/share/kio/servicemenus/mi-clip-share.desktop"
install -m 0644 linux/mi-clip.svg \
    "$package/share/icons/hicolor/scalable/apps/mi-clip.svg"
install -m 0644 tools/install-linux.py "$package/install.py"

if [ -n "$manifest" ]; then
    artifact="release-assets/mi-clip-linux-$arch"
    [ -s "$artifact" ] || {
        echo "Missing signed asset: $artifact" >&2
        exit 1
    }
    # Verify the signature independently, then prove the packaged bytes match.
    python3 tests/update_signature_test.py "$manifest" "$artifact"
    if ! cmp -s "$package/bin/mi-clip" "$artifact"; then
        echo "Packaged binary differs from the signed asset." >&2
        rm -rf "$package"
        exit 1
    fi
    install -m 0644 "$manifest" "$package/manifest-linux-$arch.json"
else
    echo "本地未签名构建：可直接安装，发布清单需要签名密钥。" >&2
fi

tar -C target/linux --owner=0 --group=0 --numeric-owner -czf "$archive" "Clip-linux-$arch"
sha256sum "$archive" >"$archive.sha256"
printf 'Package: %s\nArchive: %s\n' "$package" "$archive"

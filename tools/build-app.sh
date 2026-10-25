#!/bin/sh
# Build a containing app: macOS only discovers Share extensions inside .app.
set -eu
cd "$(dirname "$0")/.."
if [ "${MI_CLIP_SKIP_BUILD:-0}" != 1 ]; then
    sh tools/build-release.sh --bin mi-clip
fi
MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-12.0}
export MACOSX_DEPLOYMENT_TARGET
miclip_app=${MI_CLIP_APP_OUTPUT:-target/app/Clip.app}
miclip_extension="$miclip_app/Contents/PlugIns/ClipShare.appex"
mkdir -p "$miclip_app/Contents/MacOS" "$miclip_extension/Contents/MacOS"
cp target/release/mi-clip "$miclip_app/Contents/MacOS/mi-clip"
python3 - "$miclip_app" <<'PY'
import plistlib, sys, re
from pathlib import Path
app = Path(sys.argv[1])
version = re.search(r'^version = "([^"]+)"', Path('Cargo.toml').read_text(), re.M)[1]
common = dict(CFBundleInfoDictionaryVersion='6.0', CFBundleShortVersionString=version,
              CFBundleVersion=version, LSMinimumSystemVersion='12.0', CFBundleSupportedPlatforms=['MacOSX'])
main = dict(common, CFBundleIdentifier='com.cyeam.miclip', CFBundleExecutable='mi-clip',
            CFBundleName='Clip', CFBundleDisplayName='Clip', CFBundlePackageType='APPL', LSUIElement=True)
rule = {'NSExtensionActivationSupportsFileWithMaxCount': 128,
        'NSExtensionActivationSupportsImageWithMaxCount': 128,
        'NSExtensionActivationSupportsMovieWithMaxCount': 128}
ext = dict(common, CFBundleIdentifier='com.cyeam.miclip.share', CFBundleExecutable='ClipShare',
           CFBundleName='Clip 分享', CFBundleDisplayName='Clip 分享', CFBundlePackageType='XPC!',
           NSExtension={'NSExtensionPointIdentifier': 'com.apple.share-services',
                        'NSExtensionPrincipalClass': 'ShareViewController',
                        'NSExtensionAttributes': {'NSExtensionActivationRule': rule}})
for path, value in [(app / 'Contents/Info.plist', main),
                    (app / 'Contents/PlugIns/ClipShare.appex/Contents/Info.plist', ext)]:
    path.write_bytes(plistlib.dumps(value))
PY
xcrun swiftc -swift-version 5 -O -parse-as-library -emit-executable \
    -application-extension -framework Cocoa -framework UniformTypeIdentifiers \
    -Xlinker -e -Xlinker _NSExtensionMain \
    macos/ShareViewController.swift -o "$miclip_extension/Contents/MacOS/ClipShare"
# Developer ID identities can be provided by a distribution build. Ad-hoc
# signing supports local development; it is not Apple notarization.
codesign --force --sign "${MI_CLIP_CODESIGN_IDENTITY:--}" \
    --entitlements macos/Share.entitlements "$miclip_extension"
codesign --force --sign "${MI_CLIP_CODESIGN_IDENTITY:--}" "$miclip_app"
codesign --verify --deep --strict "$miclip_app"
printf '%s\n' "Built $miclip_app"

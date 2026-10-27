"""Exercise the native share picker with a private synthetic queue, never a phone."""
import plistlib
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
app = Path(sys.argv[1]).resolve()
# Check the shipped icon declarations, rather than just testing an image fixture.
for bundle in [app, app / 'Contents/PlugIns/ClipShare.appex']:
    info = plistlib.loads((bundle / 'Contents/Info.plist').read_bytes())
    icon = bundle / 'Contents/Resources' / info['CFBundleIconFile']
    if not icon.suffix:
        icon = icon.with_suffix('.icns')
    assert icon.is_file() and icon.stat().st_size > 0, f'Missing bundle icon: {icon}'
with tempfile.TemporaryDirectory(prefix='miclip-share-ui-') as directory:
    work = Path(directory)
    (work / 'main.swift').write_text('''import Cocoa
let app = NSApplication.shared
app.appearance = NSAppearance(named: .aqua)
try ShareViewController.verifyPreview(output: URL(fileURLWithPath: CommandLine.arguments[1]), icon: URL(fileURLWithPath: CommandLine.arguments[2]))
''')
    subprocess.run([
        'xcrun', 'swiftc', '-swift-version', '5', '-D', 'SHARE_PREVIEW',
        '-framework', 'Cocoa', '-framework', 'UniformTypeIdentifiers', '-framework', 'QuartzCore',
        str(root / 'macos/ShareDeviceBrand.swift'), str(root / 'macos/ShareViewController.swift'), str(work / 'main.swift'),
        '-o', str(work / 'check'),
    ], check=True, cwd=root)
    subprocess.run([str(work / 'check'), str(work), str(icon)], check=True, timeout=30)

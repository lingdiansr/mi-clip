"""Verify first-launch setup without manually registering the extension.

Holding the client lock models installation while an older standalone client is
running. A private HOME prevents access to real account/configuration files.
"""
import fcntl
import os
from pathlib import Path
import subprocess
import sys
import tempfile

app = Path(sys.argv[1]).resolve()
executable = app / 'Contents/MacOS/mi-clip'
extension = app / 'Contents/PlugIns/ClipShare.appex'
assert executable.is_file() and extension.is_dir(), 'Build the complete app first'
with tempfile.TemporaryDirectory(prefix='miclip-first-launch-') as directory:
    root = Path(directory) / 'Library/Application Support/MiClip'
    root.mkdir(parents=True, mode=0o700)
    environment = dict(os.environ, HOME=directory)
    marker = root / 'share-extension-enabled'
    with (root / 'instance.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        subprocess.run([str(executable)], env=environment, check=True,
                       capture_output=True, text=True, timeout=30)
        assert marker.is_file(), 'First launch did not finish setup before exiting'
        stamp = marker.stat().st_mtime_ns
        subprocess.run([str(executable)], env=environment, check=True,
                       capture_output=True, text=True, timeout=30)
        assert marker.stat().st_mtime_ns == stamp, 'Restart rewrote first-install preference'
    registry = subprocess.check_output(
        ['/usr/bin/pluginkit', '-m', '-A', '-D', '-v', '-i', 'com.cyeam.miclip.share'],
        text=True)
    assert any(line.lstrip().startswith('+') and str(extension) in line
               for line in registry.splitlines()), 'Extension not registered/enabled'
print('PASS: app registers/enables its extension on first launch, including when another client holds the lock')

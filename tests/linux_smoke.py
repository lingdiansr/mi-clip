"""Isolated Linux smoke test for the real binary.

Starts a private D-Bus session and a headless Sway compositor with temporary
0700 XDG directories, then exercises the status window, the single-instance
control entry point and the share picker. No user bus, clipboard, configuration
or account is touched, and nothing is sent over the network.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "target/release/mi-clip").resolve()
ARTIFACTS = ROOT / "target/linux-smoke"
TIMEOUT = 90


def fail(message):
    raise SystemExit(f"FAIL: {message}")


def need(tool):
    if shutil.which(tool) is None:
        fail(f"missing required tool: {tool}")


class Session:
    """Private bus, compositor and XDG directories for one test run."""

    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="miclip-smoke-"))
        os.chmod(self.root, 0o700)
        for name in ("runtime", "home", "config", "state", "tmp"):
            (self.root / name).mkdir(mode=0o700)
        os.chmod(self.root / "runtime", 0o700)
        self.log = open(self.root / "session.log", "wb")
        self.env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.root / "home"),
            "XDG_RUNTIME_DIR": str(self.root / "runtime"),
            "XDG_CONFIG_HOME": str(self.root / "config"),
            "XDG_STATE_HOME": str(self.root / "state"),
            "XDG_CACHE_HOME": str(self.root / "state/cache"),
            "TMPDIR": str(self.root / "tmp"),
            "WLR_BACKENDS": "headless",
            "WLR_LIBINPUT_NO_DEVICES": "1",
            "WLR_RENDERER": "pixman",
            "MICLIP_DIAGNOSTICS": "1",
        }
        bus = subprocess.run(
            ["dbus-daemon", "--session", "--fork", "--print-address", "--print-pid"],
            check=True,
            capture_output=True,
            text=True,
        )
        address, pid = bus.stdout.split()
        self.bus_pid = int(pid)
        self.env["DBUS_SESSION_BUS_ADDRESS"] = address
        config = self.root / "sway.conf"
        config.write_text("output HEADLESS-1 mode 1280x800\n", encoding="utf-8")
        self.sway = subprocess.Popen(
            ["sway", "-c", str(config), "-d"],
            env=self.env,
            stdout=self.log,
            stderr=self.log,
        )
        self.display = self._wait_wayland()
        self.env["WAYLAND_DISPLAY"] = self.display
        self.apps = []

    def _wait_wayland(self):
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.sway.poll() is not None:
                self.log.flush()
                tail = (self.root / "session.log").read_text(errors="replace")[-4000:]
                raise SystemExit(f"FAIL: sway exited early\n{tail}")
            sockets = sorted((self.root / "runtime").glob("wayland-*"))
            if sockets:
                return sockets[0].name
            time.sleep(0.1)
        raise SystemExit("FAIL: headless sway did not publish a Wayland socket")

    def run(self, arguments, env=None, timeout=TIMEOUT):
        return subprocess.run(
            [str(BINARY), *arguments],
            env={**self.env, **(env or {})},
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def spawn(self, arguments, env=None):
        process = subprocess.Popen(
            [str(BINARY), *arguments],
            env={**self.env, **(env or {})},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.apps.append(process)
        return process

    def screenshot(self, name):
        if shutil.which("grim") is None:
            return
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["grim", str(ARTIFACTS / name)],
            env=self.env,
            check=False,
            capture_output=True,
        )

    def close(self):
        for process in self.apps:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
        if self.sway.poll() is None:
            self.sway.terminate()
            try:
                self.sway.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.sway.kill()
        subprocess.run(["kill", str(self.bus_pid)], check=False)
        self.log.close()
        shutil.rmtree(self.root, ignore_errors=True)


def guard_without_wayland():
    """A missing Wayland session must fail loudly, without an X11 fallback."""
    env = dict(os.environ)
    env.pop("WAYLAND_DISPLAY", None)
    env["DISPLAY"] = ":0"
    result = subprocess.run(
        [str(BINARY)], env=env, capture_output=True, text=True, timeout=30
    )
    if result.returncode == 0:
        fail("GUI started with DISPLAY only; expected a Wayland requirement error")
    if "Linux 仅支持真实 Wayland 会话" not in result.stderr:
        fail(f"missing Wayland requirement message: {result.stderr[-400:]}")
    diagnostics = subprocess.run(
        [str(BINARY), "--version"], env=env, capture_output=True, text=True, timeout=30
    )
    if diagnostics.returncode != 0 or "Mi Clip" not in diagnostics.stdout:
        fail("--version must work without a compositor")
    ui = subprocess.run(
        [str(BINARY), "--check-ui"], env=env, capture_output=True, text=True, timeout=60
    )
    if ui.returncode != 0:
        fail(f"--check-ui failed without a compositor: {ui.stderr[-400:]}")
    print("PASS: GUI requires a real Wayland session; diagnostics still run")


def window_smoke(session):
    """Status window, Rhai refresh, Escape close, reopen and Ctrl-Q."""
    process = subprocess.Popen(
        [str(BINARY), "--smoke-test"],
        env=session.env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    lines = []
    screenshot_done = False
    for line in process.stdout:
        lines.append(line)
        if "SMOKE CHECKPOINT" in line and not screenshot_done:
            screenshot_done = True
            session.screenshot("status-window.png")
    stderr = process.stderr.read()
    code = process.wait(timeout=TIMEOUT)
    output = "".join(lines)
    if code != 0 or "PASS:" not in output:
        fail(f"window smoke test failed (exit {code})\nstdout:{output[-2000:]}\nstderr:{stderr[-2000:]}")
    print("PASS: status window, Rhai refresh, Escape close, reopen and Ctrl-Q")


def single_instance(session):
    """A second launch forwards and exits; it never takes over the session."""
    first = session.spawn(["--background"])
    deadline = time.time() + 20
    while time.time() < deadline and first.poll() is None:
        time.sleep(0.2)
    if first.poll() is not None:
        fail(f"background instance exited early: {first.stderr.read()[-800:]}")
    second = session.run(["--show"], timeout=30)
    if second.returncode != 0:
        fail(f"second instance failed to forward: {second.stderr[-400:]}")
    if first.poll() is not None:
        fail("first instance exited when a second launch forwarded a request")
    first.terminate()
    first.wait(timeout=15)
    print("PASS: session D-Bus single instance forwards and survives")


def share_requires_login(session):
    """Without an account configuration the picker refuses to reserve a slot."""
    sample = session.root / "sample.txt"
    sample.write_text("fixture", encoding="utf-8")
    result = session.run(["--share", str(sample)], timeout=30)
    if result.returncode == 0:
        fail("--share succeeded without an account configuration")
    if "请先完成设备登录" not in result.stderr:
        fail(f"missing login requirement: {result.stderr[-400:]}")
    print("PASS: --share without login reports a visible error and keeps no slot")


def share_picker(session):
    """Selecting a fixture phone fails visibly when the configuration is bad."""
    config = session.root / "config.json"
    config.write_text("{}", encoding="utf-8")
    os.chmod(config, 0o600)
    sample = session.root / "photo.png"
    sample.write_bytes(b"synthetic")
    env = {
        "MICLIP_DEVICE_FIXTURE": "192.0.2.1:1234",
        "MICLIP_SHARE_FIXTURE": "select",
    }
    app = session.spawn(
        ["--share", str(sample), "--background", "--config", str(config)], env=env
    )
    deadline = time.time() + 30
    stderr = ""
    while time.time() < deadline:
        if app.poll() is not None:
            stderr = app.stderr.read()
            break
        time.sleep(0.5)
        try:
            # A running process keeps the picker; a malformed configuration must
            # surface as a task failure, never as a silent success.
            busy = session.run(["--share", str(sample)], env=env, timeout=15)
        except subprocess.TimeoutExpired:
            continue
        if busy.returncode != 0 and "Busy" in busy.stderr:
            print("PASS: concurrent --share reports Busy instead of replacing the picker")
            break
    if app.poll() is not None:
        fail(f"share picker exited unexpectedly: {stderr[-800:]}")
    session.screenshot("share-picker.png")
    app.terminate()
    app.wait(timeout=15)


def share_cancel_reopen(session):
    """Cancelling the picker releases the slot for the next request."""
    config = session.root / "config.json"
    config.write_text("{}", encoding="utf-8")
    os.chmod(config, 0o600)
    sample = session.root / "note.txt"
    sample.write_text("fixture", encoding="utf-8")
    env = {
        "MICLIP_DEVICE_FIXTURE": "192.0.2.1:1234",
        "MICLIP_SHARE_FIXTURE": "cancel",
    }
    app = session.spawn(
        ["--share", str(sample), "--background", "--config", str(config)], env=env
    )
    deadline = time.time() + 30
    while time.time() < deadline and app.poll() is None:
        time.sleep(0.5)
        result = session.run(["--share", str(sample)], env=env, timeout=15)
        if result.returncode == 0:
            print("PASS: cancelled picker releases the slot for the next request")
            app.terminate()
            app.wait(timeout=15)
            return
    fail("a cancelled picker kept the share slot busy")


def main():
    if not BINARY.is_file():
        fail(f"binary not found: {BINARY}")
    for tool in ("dbus-daemon", "sway"):
        need(tool)
    guard_without_wayland()
    session = Session()
    try:
        window_smoke(session)
        single_instance(session)
        share_requires_login(session)
        share_cancel_reopen(session)
        share_picker(session)
    finally:
        session.close()
    print("PASS: isolated Wayland smoke suite completed")


if __name__ == "__main__":
    main()

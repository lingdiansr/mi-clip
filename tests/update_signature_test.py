"""Independently verify a published manifest and artifact using system OpenSSL."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("manifest", type=Path)
parser.add_argument("binary", type=Path)
args = parser.parse_args()
source = (Path(__file__).resolve().parents[1] / "src/update_key.rs").read_text()
key = base64.b64decode(re.search(r'PUBLIC_KEY:\s*&str\s*=\s*"([^"]+)"', source)[1], validate=True)
assert len(key) == 65 and key[0] == 4
envelope = json.loads(args.manifest.read_bytes())
payload = base64.b64decode(envelope["payload"], validate=True)
signature = base64.b64decode(envelope["signature"], validate=True)
release = json.loads(payload)
kind = release.get("kind", "binary")
name = args.binary.name
# The asset name must belong to the platform its kind describes.
if kind == "binary":
    assert name.startswith("mi-clip-macos-"), name
elif kind == "app_zip":
    assert name == f"Clip-macos-{release['arch']}.zip", name
elif kind == "linux_binary":
    assert name == f"mi-clip-linux-{release['arch']}", name
else:
    raise SystemExit(f"unknown artifact kind: {kind}")
binary = args.binary.read_bytes()
assert len(binary) == release["size"]
assert hashlib.sha256(binary).hexdigest() == release["sha256"]
# The payload format must match the kind too.
if kind == "linux_binary":
    assert binary[:4] == b"\x7fELF" and binary[4] == 2 and binary[5] == 1, "not an ELF64 executable"
elif kind == "binary":
    assert binary[:4] == bytes.fromhex("cffaedfe"), "not a Mach-O executable"
else:
    assert binary[:2] == b"PK", "not a zip archive"
with tempfile.TemporaryDirectory(prefix="miclip-signature-") as directory:
    root = Path(directory)
    # Standard SubjectPublicKeyInfo for an uncompressed P-256 public point.
    der = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200") + key
    (root / "public.der").write_bytes(der)
    subprocess.run(["openssl", "pkey", "-pubin", "-inform", "DER", "-in", str(root / "public.der"), "-out", str(root / "public.pem")], check=True, capture_output=True)
    (root / "payload").write_bytes(payload)
    (root / "signature").write_bytes(signature)
    command = ["openssl", "dgst", "-sha256", "-verify", str(root / "public.pem"), "-signature", str(root / "signature"), str(root / "payload")]
    assert subprocess.run(command, capture_output=True).returncode == 0
    (root / "payload").write_bytes(payload + b" ")
    assert subprocess.run(command, capture_output=True).returncode != 0
print("PASS: real release signature and artifact digest; tampered manifest rejected")

#!/usr/bin/env python3
"""Check the published catalog exactly the way the widget does.

Verifies the Ed25519 signature on catalog/index.json against the widget's
public key, checks every subject file against its SHA-256 in the index, and
validates every entry. Exits non-zero on any problem. Needs no private key.
"""
import base64
import hashlib
import json
import pathlib
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sign_catalog import CATALOG, validate_subject  # noqa: E402

# Must match CATALOG_PUBLIC_KEY_B64 in the widget (src-tauri/src/config.rs).
PUBLIC_KEY_B64 = "SnEV62Zr7GxSXn0+mp5maaYShk/x4fBVMi2oSJYGPJ4="


def main():
    index_bytes = (CATALOG / "index.json").read_bytes()
    sig = base64.b64decode((CATALOG / "index.json.sig").read_text().strip())
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(PUBLIC_KEY_B64))
    try:
        key.verify(sig, index_bytes)
    except InvalidSignature:
        sys.exit("ERROR: index.json signature is invalid. Re-run tools/sign_catalog.py with the signing key.")

    index = json.loads(index_bytes)
    for s in index["subjects"]:
        path = CATALOG / s["file"]
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != s["sha256"]:
            sys.exit(f"ERROR: {s['file']} changed after signing. Re-run tools/sign_catalog.py.")
        validate_subject(path, json.loads(raw))
        print(f"ok  {s['id']}: {s['count']} entries")
    print(f"Catalog revision {index.get('revision')} verified.")


if __name__ == "__main__":
    main()

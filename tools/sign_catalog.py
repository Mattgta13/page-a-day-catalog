#!/usr/bin/env python3
"""Validate the photo catalog, rebuild catalog/index.json and sign it.

Usage:
    python tools/sign_catalog.py --key path/to/catalog-signing-key.pem
    python tools/sign_catalog.py --new-key path/to/catalog-signing-key.pem   (first time only)

The private key must never be committed. The app only trusts an index whose
signature matches the public key compiled into it (src-tauri/src/catalog.rs).
Every subject file is pinned in the index by its SHA-256 hash, so the single
signature covers the whole catalog.
"""
import argparse
import base64
import datetime
import hashlib
import json
import pathlib
import re
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOG = ROOT / "catalog"
SUBJECTS = CATALOG / "subjects"

# Subject id -> (display name, group). Order here is the order in the menu.
KNOWN_SUBJECTS = {
    "sports-cars": ("Sports Cars", "Vehicles"),
    "classic-cars": ("Classic Cars", "Vehicles"),
    "aircraft": ("Aircraft", "Vehicles"),
    "motorcycles": ("Motorcycles", "Vehicles"),
    "boats": ("Boats", "Vehicles"),
    "cats": ("Cats", "Animals"),
    "dogs": ("Dogs", "Animals"),
    "wild-animals": ("Wild Animals", "Animals"),
    "birds": ("Birds", "Animals"),
    "insects": ("Insects", "Animals"),
    "beach-scenes": ("Beach Scenes", "Nature"),
    "national-parks": ("National Parks", "Nature"),
    "mountains": ("Mountains", "Nature"),
    "flowers": ("Flowers", "Nature"),
    "space": ("Space", "Nature"),
    "architecture": ("Architecture", "Art & Places"),
    "lighthouses": ("Lighthouses", "Art & Places"),
    "classic-paintings": ("Classic Paintings", "Art & Places"),
    "vintage-comics": ("Vintage Comics", "Art & Places"),
}

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")
# Must match ALLOWED_HOSTS in src-tauri/src/net.rs.
ALLOWED_IMAGE_HOSTS = {
    "upload.wikimedia.org",
    "commons.wikimedia.org",
    "images-assets.nasa.gov",
    "images.metmuseum.org",
    "www.artic.edu",
    "inaturalist-open-data.s3.amazonaws.com",
    "static.inaturalist.org",
}


def fail(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def validate_subject(path, data):
    sid = data.get("id")
    if sid != path.stem or sid not in KNOWN_SUBJECTS:
        fail(f"{path.name}: id must equal the file name and be a known subject")
    entries = data.get("entries")
    if not isinstance(entries, list) or not entries:
        fail(f"{path.name}: needs at least one entry")
    seen = set()
    for e in entries:
        eid = e.get("id", "")
        if not ID_RE.match(eid):
            fail(f"{path.name}: bad entry id {eid!r}")
        if eid in seen:
            fail(f"{path.name}: duplicate entry id {eid}")
        seen.add(eid)
        title = e.get("title", "")
        if not title or len(title) > 80:
            fail(f"{path.name}/{eid}: title missing or longer than 80 characters")
        if len(e.get("detail", "")) > 80:
            fail(f"{path.name}/{eid}: detail longer than 80 characters")
        img = e.get("image") or {}
        if bool(img.get("wikimedia")) == bool(img.get("url")):
            fail(f"{path.name}/{eid}: image needs exactly one of 'wikimedia' or 'url'")
        if img.get("url"):
            m = re.match(r"^https://([^/:]+)/", img["url"])
            if not m or m.group(1) not in ALLOWED_IMAGE_HOSTS:
                fail(f"{path.name}/{eid}: image url host is not on the allowlist")
        credit = e.get("credit") or {}
        for k in ("author", "license", "source"):
            if not credit.get(k):
                fail(f"{path.name}/{eid}: credit.{k} is required")
        if not e.get("verified"):
            fail(f"{path.name}/{eid}: 'verified' note is required (how the caption was confirmed)")


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--key", help="existing private key (PEM)")
    g.add_argument("--new-key", help="create a new private key at this path")
    args = ap.parse_args()

    if args.new_key:
        p = pathlib.Path(args.new_key)
        if p.exists():
            fail(f"{p} already exists; refusing to overwrite a signing key")
        key = Ed25519PrivateKey.generate()
        p.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        print(f"New private key written to {p}. Keep it safe and never commit it.")
    else:
        key = serialization.load_pem_private_key(pathlib.Path(args.key).read_bytes(), password=None)

    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    subjects = []
    for sid, (name, group) in KNOWN_SUBJECTS.items():
        path = SUBJECTS / f"{sid}.json"
        if not path.exists():
            continue
        raw = path.read_bytes()
        validate_subject(path, json.loads(raw))
        subjects.append({
            "id": sid,
            "name": name,
            "group": group,
            "file": f"subjects/{sid}.json",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "count": len(json.loads(raw)["entries"]),
        })
    for extra in SUBJECTS.glob("*.json"):
        if extra.stem not in KNOWN_SUBJECTS:
            fail(f"{extra.name} is not a known subject")

    revision = int(datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S"))
    index = {"version": 1, "revision": revision, "subjects": subjects}
    index_bytes = (json.dumps(index, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    (CATALOG / "index.json").write_bytes(index_bytes)
    (CATALOG / "index.json.sig").write_text(base64.b64encode(key.sign(index_bytes)).decode() + "\n")
    print(f"Signed index with {len(subjects)} subject(s).")
    print(f"Public key (must match CATALOG_PUBLIC_KEY in catalog.rs): {base64.b64encode(pub).decode()}")


if __name__ == "__main__":
    main()

"""Per-agent signing keys for SLIM identity (P3, docs/P3-design.md §2, decision D3). LAB ONLY.

    python lab/identity/agent_keys.py reader-01 reviewer-01 executor-01 netops-mcp
    python lab/identity/agent_keys.py reader-01 --write-oasf   # thumbprint -> OASF record

Keys live in ~/.agenttrustsec/keys/<name>.pem (PKCS#8 RSA-2048), never in the repo.
An existing key is reused, never overwritten — rotating means deleting it on purpose
and re-issuing the badge. Prints only public thumbprints. --write-oasf sets the
`agenttrustsec.key_thumbprint` annotation in lab/identity/oasf/<name>.json so the next
`identity badge issue oasf` signs the key binding into the AgentBadge.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from agenttrustsec.identity.keys import THUMBPRINT_ANNOTATION, jwk_thumbprint, public_jwk

KEY_DIR = Path.home() / ".agenttrustsec" / "keys"
OASF_DIR = Path(__file__).resolve().parent / "oasf"


def load_or_create(name: str) -> tuple[str, bool]:
    path = KEY_DIR / f"{name}.pem"
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        created = False
    else:
        KEY_DIR.mkdir(parents=True, exist_ok=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        created = True
    return jwk_thumbprint(public_jwk(key.public_key())), created


def write_oasf(name: str, thumbprint: str) -> Path:
    path = OASF_DIR / f"{name}.json"
    record = json.loads(path.read_text())
    record.setdefault("annotations", {})[THUMBPRINT_ANNOTATION] = thumbprint
    path.write_text(json.dumps(record, indent=2) + "\n")
    return path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("names", nargs="+")
    ap.add_argument("--write-oasf", action="store_true")
    args = ap.parse_args(argv)
    for name in args.names:
        thumb, created = load_or_create(name)
        note = ""
        if args.write_oasf:
            note = f"  -> {write_oasf(name, thumb).name}"
        print(f"{name:<12} {'created' if created else 'existing'}  {thumb}{note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

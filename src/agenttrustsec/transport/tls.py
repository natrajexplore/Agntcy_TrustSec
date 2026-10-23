"""mTLS to the SLIM node (item E): only enrolled devices get onto the fabric.

TrustSec analogy: 802.1X + MACsec on the uplink. The node admits a connection only with a
client cert from the lab CA (lab/slim/pki.py), and the hop is TLS 1.3 — before any SLIM
identity token, MLS session or gate check. Each agent's cert is issued over its EXISTING key,
so it is found by that key's RFC 7638 thumbprint: clients/<thumbprint>.crt.

Deny by default: no PKI, no cert for this key, or a cert for another key -> NotEnrolled, never
a fallback to plaintext. Admission is per connection (device): the node does not bind a cert to
a SLIM name — names stay with the SLIM identity token and the gate's `peer` check.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

KEY_DIR = Path.home() / ".agenttrustsec" / "keys"


class NotEnrolled(Exception):
    """This key has no valid lab client cert -> no connection to the node."""


def pki_dir() -> Path:
    return Path(os.environ.get("AGENTTRUSTSEC_PKI") or Path.home() / ".agenttrustsec" / "pki")


def client_cert(private_key_pem: str) -> tuple[str, str]:
    """(client cert PEM, CA cert PEM) for the key in `private_key_pem`."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    from agenttrustsec.identity.keys import jwk_thumbprint, public_jwk
    d = pki_dir()
    try:
        key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    except (ValueError, TypeError):
        raise NotEnrolled("private key unreadable") from None
    thumb = jwk_thumbprint(public_jwk(key.public_key()))
    cert_path, ca_path = d / "clients" / f"{thumb}.crt", d / "ca.crt"
    if not ca_path.exists() or not cert_path.exists():
        raise NotEnrolled(f"key {thumb} is not enrolled in {d} (run lab/slim/pki.py)")
    cert_pem = cert_path.read_text(encoding="ascii")
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    if public_jwk(cert.public_key()) != public_jwk(key.public_key()):
        raise NotEnrolled(f"{cert_path.name} is not issued for this key")
    return cert_pem, ca_path.read_text(encoding="ascii")


def client_config(endpoint: str, private_key_pem: str) -> Any:
    """slim-bindings ClientConfig: TLS 1.3 to the node, verified against the lab CA, presenting
    this key's client cert. Raises NotEnrolled (no plaintext fallback)."""
    import slim_bindings as sb
    if not endpoint.startswith("https://"):
        raise NotEnrolled(f"node endpoint must be https:// (got {endpoint!r}) — no plaintext")
    cert_pem, ca_pem = client_cert(private_key_pem)
    cfg = sb.new_secure_client_config(endpoint)
    cfg.tls = sb.TlsClientConfig(insecure=False, insecure_skip_verify=False,
                                 source=sb.TlsSource.PEM(cert=cert_pem, key=private_key_pem),
                                 ca_source=sb.CaSource.PEM(data=ca_pem),
                                 include_system_ca_certs_pool=False, tls_version="tls1.3")
    return cfg

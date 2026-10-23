r"""Lab PKI for SLIM node admission (item E): mTLS between enrolled devices and the node. LAB ONLY.

    python lab/slim/pki.py                 # CA (once) + node cert + a client cert per agent key
    python lab/slim/pki.py --rotate-ca     # new CA: every existing cert stops being admitted

TrustSec analogy: enrolling devices for 802.1X/MACsec on the fabric uplink. Only a device
holding a cert from the lab CA gets onto the SLIM node at all; the hop is TLS 1.3.

Writes to ~/.agenttrustsec/pki/ (or $AGENTTRUSTSEC_PKI), never the repo:
  ca.crt / ca.key           lab CA (EC P-256, 1 year). ca.key never leaves this folder.
  node/server.crt + .key    the SLIM node (SAN localhost, 127.0.0.1; 30 days) — mounted read-only
  node/ca.crt               the CA the node checks client certs against (copy of ca.crt)
  clients/<thumbprint>.crt  one per key in ~/.agenttrustsec/keys/ (30 days), issued over the
                            agent's EXISTING key: one key backs badge, SLIM token and TLS cert.
Re-running renews node + client certs; the CA is reused unless --rotate-ca. Private keys are
created owner-only (0600) and never printed — only names, thumbprints and expiry dates.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import os
import shutil
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from agenttrustsec.identity.keys import jwk_thumbprint, public_jwk  # noqa: E402
from agenttrustsec.transport.tls import KEY_DIR, pki_dir  # noqa: E402

CA_DAYS, CERT_DAYS = 365, 30


def _write_key(path: Path, key) -> None:
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AgentTrustSec Lab"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _builder(subject: x509.Name, issuer: x509.Name, public_key, days: int) -> x509.CertificateBuilder:
    now = dt.datetime.now(dt.timezone.utc)
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(public_key).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=days)))


def make_ca(d: Path, rotate: bool) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    if (d / "ca.key").exists() and not rotate:
        key = serialization.load_pem_private_key((d / "ca.key").read_bytes(), password=None)
        return x509.load_pem_x509_certificate((d / "ca.crt").read_bytes()), key
    key = ec.generate_private_key(ec.SECP256R1())
    name = _name("AgentTrustSec Lab SLIM CA")
    cert = (_builder(name, name, key.public_key(), CA_DAYS)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    _write_key(d / "ca.key", key)
    _write_cert(d / "ca.crt", cert)
    return cert, key


def _leaf(ca: x509.Certificate, ca_key, cn: str, public_key, eku, san=None) -> x509.Certificate:
    b = (_builder(_name(cn), ca.subject, public_key, CERT_DAYS)
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName(san), critical=False)
    return b.sign(ca_key, hashes.SHA256())


def make_node(d: Path, ca: x509.Certificate, ca_key) -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _leaf(ca, ca_key, "slim-lab", key.public_key(), ExtendedKeyUsageOID.SERVER_AUTH,
                 [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
    _write_key(d / "node" / "server.key", key)
    os.chmod(d / "node" / "server.key", 0o644)       # read by the node container (mounted read-only)
    _write_cert(d / "node" / "server.crt", cert)
    shutil.copyfile(d / "ca.crt", d / "node" / "ca.crt")
    return cert


def make_clients(d: Path, ca: x509.Certificate, ca_key, key_dir: Path) -> list[tuple[str, str]]:
    out, clients = [], d / "clients"
    if clients.exists():
        shutil.rmtree(clients)                         # only enrolled keys of THIS run stay admitted
    for pem in sorted(key_dir.glob("*.pem")):
        key = serialization.load_pem_private_key(pem.read_bytes(), password=None)
        thumb = jwk_thumbprint(public_jwk(key.public_key()))
        _write_cert(clients / f"{thumb}.crt",
                    _leaf(ca, ca_key, pem.stem, key.public_key(), ExtendedKeyUsageOID.CLIENT_AUTH))
        out.append((pem.stem, thumb))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rotate-ca", action="store_true", help="new CA: all existing certs stop being admitted")
    ap.add_argument("--keys", type=Path, default=KEY_DIR)
    a = ap.parse_args(argv)
    d = pki_dir()
    d.mkdir(parents=True, exist_ok=True)
    ca, ca_key = make_ca(d, a.rotate_ca)
    node = make_node(d, ca, ca_key)
    clients = make_clients(d, ca, ca_key, a.keys)
    print(f"PKI {d}  CA expires {ca.not_valid_after_utc:%Y-%m-%d}  node expires {node.not_valid_after_utc:%Y-%m-%d}")
    for name, thumb in clients:
        print(f"  enrolled {name:<12} {thumb}")
    return 0 if clients else 1


if __name__ == "__main__":
    raise SystemExit(main())

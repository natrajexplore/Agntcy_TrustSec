"""Item E: lab PKI (lab/slim/pki.py) + mTLS client config (transport/tls.py). Offline.
Deny by default: no PKI / no cert / a cert for another key / plaintext endpoint -> NotEnrolled."""
import asyncio
import importlib.util
import ipaddress

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from agenttrustsec.identity.keys import jwk_thumbprint, public_jwk
from agenttrustsec.transport import tls

from conftest import ROOT

_spec = importlib.util.spec_from_file_location("pki", ROOT / "lab" / "slim" / "pki.py")
pki = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pki)


def new_key(path):
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    return path.read_text()


@pytest.fixture
def lab(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTTRUSTSEC_PKI", str(tmp_path / "pki"))
    keys = tmp_path / "keys"
    pems = {n: new_key(keys / f"{n}.pem") for n in ("reader-01", "executor-01")}
    assert pki.main(["--keys", str(keys)]) == 0
    return tmp_path / "pki", keys, pems


def cert(path):
    return x509.load_pem_x509_certificate(path.read_bytes())


def eku(c):
    return list(c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)


def test_ca_node_and_client_certs(lab):
    d, _, pems = lab
    ca, node = cert(d / "ca.crt"), cert(d / "node" / "server.crt")
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    node.verify_directly_issued_by(ca)
    san = node.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["localhost"]
    assert san.get_values_for_type(x509.IPAddress) == [ipaddress.ip_address("127.0.0.1")]
    assert eku(node) == [ExtendedKeyUsageOID.SERVER_AUTH]
    for name, pem in pems.items():
        key = serialization.load_pem_private_key(pem.encode(), password=None)
        c = cert(d / "clients" / f"{jwk_thumbprint(public_jwk(key.public_key()))}.crt")
        c.verify_directly_issued_by(ca)
        assert public_jwk(c.public_key()) == public_jwk(key.public_key())     # issued over the agent's key
        assert eku(c) == [ExtendedKeyUsageOID.CLIENT_AUTH] and name in c.subject.rfc4514_string()


def test_ca_private_key_is_never_in_the_node_mount(lab):
    d, _, _ = lab
    assert (d / "ca.key").exists()
    assert sorted(p.name for p in (d / "node").iterdir()) == ["ca.crt", "server.crt", "server.key"]
    assert (d / "node" / "ca.crt").read_bytes() == (d / "ca.crt").read_bytes()


def test_rerun_keeps_the_ca_rotate_replaces_it(lab):
    d, keys, _ = lab
    before = (d / "ca.crt").read_bytes()
    pki.main(["--keys", str(keys)])
    assert (d / "ca.crt").read_bytes() == before
    pki.main(["--keys", str(keys), "--rotate-ca"])
    assert (d / "ca.crt").read_bytes() != before


def test_a_removed_key_is_no_longer_enrolled(lab):
    d, keys, pems = lab
    (keys / "executor-01.pem").unlink()
    pki.main(["--keys", str(keys)])
    with pytest.raises(tls.NotEnrolled, match="not enrolled"):
        tls.client_cert(pems["executor-01"])
    tls.client_cert(pems["reader-01"])


def test_client_config_is_mtls_verified_tls13(lab):
    _, _, pems = lab
    cfg = tls.client_config("https://127.0.0.1:46357", pems["reader-01"])
    t = cfg.tls
    assert (t.insecure, t.insecure_skip_verify, t.include_system_ca_certs_pool, t.tls_version) == \
        (False, False, False, "tls1.3")
    assert t.source.is_pem() and t.ca_source.is_pem()


def test_unknown_key_is_not_enrolled(lab, tmp_path):
    with pytest.raises(tls.NotEnrolled, match="not enrolled"):
        tls.client_cert(new_key(tmp_path / "other.pem"))


def test_cert_for_another_key_is_refused(lab):
    d, _, pems = lab
    r, e = (serialization.load_pem_private_key(pems[n].encode(), password=None) for n in ("reader-01", "executor-01"))
    tr, te = (jwk_thumbprint(public_jwk(k.public_key())) for k in (r, e))
    (d / "clients" / f"{tr}.crt").write_bytes((d / "clients" / f"{te}.crt").read_bytes())   # swapped file
    with pytest.raises(tls.NotEnrolled, match="not issued for this key"):
        tls.client_cert(pems["reader-01"])


def test_no_pki_at_all(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTTRUSTSEC_PKI", str(tmp_path / "nothing"))
    with pytest.raises(tls.NotEnrolled):
        tls.client_cert(new_key(tmp_path / "k.pem"))


def test_plaintext_endpoint_is_refused(lab):
    with pytest.raises(tls.NotEnrolled, match="https"):
        tls.client_config("http://127.0.0.1:46357", lab[2]["reader-01"])


def test_connect_refuses_before_touching_the_node(tmp_path, monkeypatch):
    pytest.importorskip("slim_bindings")
    from agenttrustsec.transport import slim
    monkeypatch.setenv("AGENTTRUSTSEC_PKI", str(tmp_path / "nothing"))
    monkeypatch.setattr(slim, "_get_service", lambda: pytest.fail("must not reach the SLIM service"))
    with pytest.raises(tls.NotEnrolled):
        asyncio.run(slim.connect("agenttrustsec/lab/x", (None, None), key_pem=new_key(tmp_path / "k.pem")))

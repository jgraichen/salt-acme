# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring
# pylint: disable=redefined-outer-name

import os
import stat

from unittest.mock import patch

import pytest

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from salt.exceptions import SaltInvocationError


_EXAMPLE_PUBKEY_DETAILS = {
    "curve": "secp256r1",
    "text": (
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKwDRQj9TeTj9xxukggspQ5fm7bDQ\n"
        "7xb8jk2LpP435SowinL1rvUne2UgPwKjjTA8mPLRo+LMkVr5kfM7vY5tlg==\n"
        "-----END PUBLIC KEY-----\n"
    ),
    "type": "ec",
}


_EXAMPLE_CRT_DETAILS = {
    "algorithm": "sha384",
    "domains": ["example.org", "example.com", "www.example.org", "www.example.com"],
    "not_valid_after": "2020-01-28 09:00:04",
    "not_valid_before": "2020-01-27 09:00:04",
    "public_key": _EXAMPLE_PUBKEY_DETAILS,
    "serial": 180395858746428869291478470917944844439732580634,
}

_EXAMPLE_CSR_DETAILS = {
    "algorithm": "sha384",
    "domains": ["example.org", "example.com", "www.example.org", "www.example.com"],
    "public_key": _EXAMPLE_PUBKEY_DETAILS,
}


def _read(path, mode="r"):
    with open(path, mode) as f:
        return f.read()


def test_create_private_key(mods, tmpdir):
    """
    Creates an elliptic curve private key using prime256v1 curve by default.
    File is written with ``600`` mode.
    """

    keyfile = os.path.join(tmpdir, "example.key")

    assert mods["acme.create_private_key"](keyfile) == {
        "curve": "prime256v1",
        "path": keyfile,
        "type": "ec",
    }

    assert os.path.exists(keyfile)
    assert stat.S_IMODE(os.stat(keyfile).st_mode) == 0o600

    with open(keyfile, "rb") as f:
        key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == "secp256r1"


def test_create_private_key_curve(mods, tmpdir):
    """
    Private key can be created with another curve.
    """

    keyfile = os.path.join(tmpdir, "example.key")

    assert mods["acme.create_private_key"](keyfile, curve="secp192r1") == {
        "curve": "secp192r1",
        "path": keyfile,
        "type": "ec",
    }

    with open(keyfile, "rb") as f:
        key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == "secp192r1"


def test_create_private_key_rsa(mods, tmpdir):
    keyfile = os.path.join(tmpdir, "example.key")

    assert mods["acme.create_private_key"](keyfile, type="rsa", size=512) == {
        "path": keyfile,
        "size": 512,
        "type": "rsa",
    }

    assert os.path.exists(keyfile)
    assert stat.S_IMODE(os.stat(keyfile).st_mode) == 0o600

    with open(keyfile, "rb") as f:
        key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 512


def test_create_private_key_invalid(mods):
    with pytest.raises(SaltInvocationError):
        mods["acme.create_private_key"]("example.key", type="dsa")


def test_create_csr(mods, tmpdir):
    path = os.path.join(tmpdir, "example.csr")

    ret = mods["acme.create_csr"](
        path, key="test/fixtures/example.key", domains=["example.org", "example.com"]
    )

    assert ret == {
        "algorithm": "sha384",
        "domains": ["example.org", "example.com"],
        "path": path,
        "public_key": _EXAMPLE_PUBKEY_DETAILS,
    }

    assert os.path.exists(path)

    with open(path, "rb") as f:
        csr = x509.load_pem_x509_csr(f.read(), default_backend())

    common_name = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    alt_names = csr.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value

    assert csr.signature_hash_algorithm.name == "sha384"
    assert common_name == "example.org"
    assert list(alt_names) == [x509.DNSName("example.org"), x509.DNSName("example.com")]


def test_create_csr_text(mods):
    ret = mods["acme.create_csr"](
        text=True,
        key="test/fixtures/example.key",
        domains=["example.org", "example.com"],
    )

    assert "text" in ret

    csr = x509.load_pem_x509_csr(ret["text"].encode(), default_backend())
    common_name = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    alt_names = csr.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value

    assert csr.signature_hash_algorithm.name == "sha384"
    assert common_name == "example.org"
    assert list(alt_names) == [x509.DNSName("example.org"), x509.DNSName("example.com")]


def test_create_certificate(mods, tmpdir):
    path = os.path.join(tmpdir, "example.crt")

    def _runner(fn, arg, timeout=None):
        assert fn == "acme.sign"
        assert arg == {"csr": _read("test/fixtures/example.csr")}
        assert timeout == 120

        return {"text": _read("test/fixtures/example.crt")}

    with patch.dict(mods, {"publish.runner": _runner}):
        ret = mods["acme.create_certificate"](path, csr="test/fixtures/example.csr")

    assert ret == {**_EXAMPLE_CRT_DETAILS, "path": path}
    assert os.path.exists(path)

    with open(path, "rb") as f:
        crt = x509.load_pem_x509_certificate(f.read(), default_backend())

    common_name = crt.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    alt_names = crt.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value

    assert crt.signature_hash_algorithm.name == "sha384"
    assert common_name == "example.org"
    assert list(alt_names) == [
        x509.DNSName("example.org"),
        x509.DNSName("example.com"),
        x509.DNSName("www.example.org"),
        x509.DNSName("www.example.com"),
    ]


def test_read_csr(mods):
    path = "test/fixtures/example.csr"
    assert mods["acme.read_csr"](path) == _EXAMPLE_CSR_DETAILS


def test_read_csr_pem(mods):
    pem = _read("test/fixtures/example.csr")
    assert mods["acme.read_csr"](pem) == _EXAMPLE_CSR_DETAILS


def test_read_certificate(mods):
    """
    Accepts a path to a PEM encoded certificate file
    """

    path = "test/fixtures/example.crt"
    assert mods["acme.read_certificate"](path) == _EXAMPLE_CRT_DETAILS


def test_read_certificate_pem(mods):
    """
    Accepts a PEM-encoded string too
    """

    pem = _read("test/fixtures/example.crt")
    assert mods["acme.read_certificate"](pem) == _EXAMPLE_CRT_DETAILS

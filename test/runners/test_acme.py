# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring

import pytest

from cryptography import x509
from cryptography.x509 import oid
from cryptography.hazmat.backends import default_backend


def _read(path, mode="r"):
    with open(path, mode) as f:
        return f.read()


def test_sign(runners):
    ret = runners["acme.sign"](_read("test/fixtures/example.csr"))

    assert "text" in ret

    crt = x509.load_pem_x509_certificate(ret["text"].encode(), default_backend())

    cn = crt.subject.get_attributes_for_oid(oid.NameOID.COMMON_NAME)[0].value
    san = crt.extensions.get_extension_for_class(x509.SubjectAlternativeName).value

    assert cn == "example.org"
    assert list(san) == [
        x509.DNSName("example.org"),
        x509.DNSName("example.com"),
        x509.DNSName("www.example.org"),
        x509.DNSName("www.example.com"),
    ]

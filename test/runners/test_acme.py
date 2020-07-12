# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring
# pylint: disable=redefined-outer-name


from cryptography import x509
from cryptography.hazmat.backends import default_backend


def test_sign(master):
    with open("test/fixtures/example.csr", "r") as f:
        csr = f.read()

    result = master.runner["acme.sign"](csr)
    assert "text" in result

    crt = x509.load_pem_x509_certificate(
        result["text"].encode(), backend=default_backend()
    )

    assert isinstance(crt, x509.Certificate)

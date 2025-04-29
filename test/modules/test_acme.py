# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring
# pylint: disable=redefined-outer-name


import logging

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend

import acme
import acme.errors


def test_sign(minion):
    with open("test/fixtures/example.csr", "r") as f:
        csr = f.read()

    result = minion.mods["acme.sign"](csr)
    assert "text" in result

    crt = x509.load_pem_x509_certificate(
        result["text"].encode(), backend=default_backend()
    )

    assert isinstance(crt, x509.Certificate)


def test_sign_wildcard(minion):
    with open("test/fixtures/example_wildcard.csr", "r") as f:
        csr = f.read()

    result = minion.mods["acme.sign"](csr)
    assert "text" in result

    crt = x509.load_pem_x509_certificate(
        result["text"].encode(), backend=default_backend()
    )

    assert isinstance(crt, x509.Certificate)


def test_sign_validation_error(minion, caplog):
    with open("test/fixtures/validation-error.csr", "r") as f:
        csr = f.read()

    with caplog.at_level(logging.ERROR):
        with pytest.raises(acme.errors.ValidationError):
            minion.mods["acme.sign"](csr)

    assert (
        "Challenge for missing.alias.example.com failed: urn:ietf:params:acme:error:"
        in caplog.text
    )

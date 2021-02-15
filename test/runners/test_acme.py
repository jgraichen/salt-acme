# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring
# pylint: disable=redefined-outer-name

import os

from unittest.mock import patch

import pytest
import yaml

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from salt.exceptions import AuthorizationError


@pytest.fixture
def fn(master):
    return master.runner["acme.sign"]


def read_fixture(file, mode="r"):
    with open(os.path.join("test/fixtures", file), mode) as f:
        return f.read()


def test_sign(fn):
    """
    One full roundtrip test. The CSR is passed to the `acme.sign` execution
    module and a dict with {"text": "<certificate>"} is returned.
    """
    csr = read_fixture("example.csr")
    result = fn(csr)
    assert "text" in result

    crt = x509.load_pem_x509_certificate(
        result["text"].encode(), backend=default_backend()
    )

    assert isinstance(crt, x509.Certificate)


def test_sign_broken_pem(fn):
    """
    When a minion invokes a runner using `publish.runner`, the arguments can get
    scrambled. Newlines might be replaced with single spaces.

    The runner must fix these missing newlines in the PEM-encoded csr and pass a
    correct string to the execution module.
    """
    csr = read_fixture("example.csr")

    def check_fn(cmd, pem):
        assert cmd == "acme.sign"
        assert pem == csr.strip()

    with patch.dict(fn.__globals__["__salt__"], {"salt.cmd": check_fn}):
        fn(csr.replace("\n", " "))


def test_sign_authorize(fn, tmpdir):
    auth_file = os.path.join(tmpdir, "auth.yml")

    with open(auth_file, "w") as f:
        yaml.safe_dump(
            {"*": ["example.org", "*.example.org", "example.com", "*.example.com"]}, f
        )

    def fxcmd(*_args):
        return True

    with patch.dict(
        fn.__globals__["__opts__"],
        {"id": "minion", "acme": {"runner": {"auth_file": auth_file}}},
    ):
        with patch.dict(fn.__globals__["__salt__"], {"salt.cmd": fxcmd}):
            assert fn(read_fixture("example.csr"))


def test_sign_reject_unauthorized(fn, tmpdir):
    auth_file = os.path.join(tmpdir, "auth.yml")
    csr = read_fixture("example.csr")

    with open(auth_file, "w") as f:
        yaml.safe_dump({"minion": ["example.org", "*.example.org"]}, f)

    with patch.dict(
        fn.__globals__["__opts__"],
        {"id": "minion", "acme": {"runner": {"auth_file": auth_file}}},
    ):
        with pytest.raises(AuthorizationError) as e:
            fn(csr)

        assert str(e.value) == "Unauthorized domains: example.com, www.example.com"

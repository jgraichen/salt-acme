# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring
# pylint: disable=redefined-outer-name

import os

from unittest.mock import patch

import pytest
import yaml

from cryptography import x509
from cryptography.hazmat.backends import default_backend

import salt.version
from salt.exceptions import AuthorizationError


@pytest.fixture
def runner(master):
    return master.runner


def read_fixture(file, mode="r"):
    with open(os.path.join("test/fixtures", file), mode) as f:
        return f.read()


def _patch_cmd(runner, fn):
    # Salt 3003+ changed how the __salt__ global is handled inside the loader.
    # To patch that in tests, we need to target the loader directly instead of a
    # pack as in previous versions.
    if salt.version.__version__ > '3003':
        return patch.dict(runner, {"salt.cmd": fn})
    else:
        return patch.dict(runner.pack["__salt__"], {"salt.cmd": fn})

def test_sign(runner):
    """
    One full roundtrip test. The CSR is passed to the `acme.sign` execution
    module and a dict with {"text": "<certificate>"} is returned.
    """
    csr = read_fixture("example.csr")
    result = runner["acme.sign"](csr)
    assert "text" in result

    crt = x509.load_pem_x509_certificate(
        result["text"].encode(), backend=default_backend()
    )

    assert isinstance(crt, x509.Certificate)


def test_sign_broken_pem(runner):
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

    with _patch_cmd(runner, check_fn):
        runner["acme.sign"](csr.replace("\n", " "))


def test_sign_authorize(runner, tmpdir):
    auth_file = os.path.join(tmpdir, "auth.yml")

    with open(auth_file, "w") as f:
        yaml.safe_dump(
            {"*": ["example.org", "*.example.org", "example.com", "*.example.com"]}, f
        )

    def fxcmd(*_args):
        return True

    with patch.dict(
        runner.opts,
        {"id": "minion", "acme": {"runner": {"auth_file": auth_file}}},
    ):
        with _patch_cmd(runner, fxcmd):
            assert runner["acme.sign"](read_fixture("example.csr"))


def test_sign_authorize_multiple_rules(runner, tmpdir):
    """
    Test that all matching rules are applied.
    """
    auth_file = os.path.join(tmpdir, "auth.yml")

    with open(auth_file, "w") as f:
        yaml.safe_dump(
            {
                "minion": ["example.org"],
                "minion*": ["*.example.org"],
                "*": ["example.com", "*.example.com"],
            },
            f,
        )

    def fxcmd(*_args):
        return True

    with patch.dict(
        runner.opts,
        {"id": "minion", "acme": {"runner": {"auth_file": auth_file}}},
    ):
        with _patch_cmd(runner, fxcmd):
            assert runner["acme.sign"](read_fixture("example.csr"))


def test_sign_reject_unauthorized(runner, tmpdir):
    auth_file = os.path.join(tmpdir, "auth.yml")
    csr = read_fixture("example.csr")

    with open(auth_file, "w") as f:
        yaml.safe_dump({"minion": ["example.org", "*.example.org"]}, f)

    with patch.dict(
        runner.opts,
        {"id": "minion", "acme": {"runner": {"auth_file": auth_file}}},
    ):
        with pytest.raises(AuthorizationError) as e:
            runner["acme.sign"](csr)

        assert str(e.value) == "Unauthorized domains: example.com, www.example.com"

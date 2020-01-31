# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring,redefined-outer-name

import copy
import re
from unittest.mock import patch

import pytest
import conftest

from salt.utils.dictupdate import update


@pytest.fixture()
def dehydrated(master_opts):
    mod = conftest.load_module("x.dehydrated", "_runners/dehydrated.py")
    mod.__opts__ = copy.deepcopy(master_opts)
    return mod


def test_sign(dehydrated):
    with open("test/fixtures/example.csr", "r") as f:
        csr = f.read()

    out = dehydrated.sign(csr)

    assert out["text"] == (
        "-----BEGIN CERTIFICATE------\n"
        "abcabcabcabcabcabcabcabcabcabcabcabcabcabc\n"
        "-----END CERTIFICATE------\n"
        "-----BEGIN CERTIFICATE------\n"
        "intermediateabcabcabcabcabcabcabcabcabcabc\n"
        "-----END CERTIFICATE------\n"
    )


def test_sign_broken_csr(dehydrated):
    """
    The given CSR may contain spaces instead of newlines when passed from salt
    command line or publish.runner. This must be fixed by the runner.
    """
    with open("test/fixtures/example.csr", "r") as f:
        csr = f.read().replace("\n", " ")

    out = dehydrated.sign(csr)

    assert "text" in out


def test_sign_no_auth_file(dehydrated):
    """
    If not auth_file is configured all requests are permitted
    """
    with open("test/fixtures/example.csr", "r") as f:
        csr = f.read()

    update(dehydrated.__opts__, {"id": "minion", "dehydrated": {"auth_file": None}})

    assert dehydrated.sign(csr)


def test_sign_reject_unauthorized(dehydrated):
    with open("test/fixtures/example.csr", "r") as f:
        csr = f.read()

    with patch.dict(dehydrated.__opts__, {"id": "another-minion"}):
        with pytest.raises(Exception) as e:
            dehydrated.sign(csr)

        assert "Unauthorized names: example.com, www.example.com" in str(e)


def test_sign_arguments(dehydrated):
    with open("test/fixtures/example.csr", "r") as f:
        csr = f.read()

    conf = {"executable": "echo", "args": ["--arg", "1"]}

    with patch.dict(dehydrated.__opts__["dehydrated"], conf):
        assert re.match(
            r"^--arg 1 --signcsr /tmp/tmp(\w+)$", dehydrated.sign(csr)["text"]
        )

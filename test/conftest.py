# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring,redefined-outer-name

import os
import sys
import importlib.util
import tempfile

from contextlib import contextmanager
from subprocess import Popen, PIPE, STDOUT

import pytest
import salt.config


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(os.path.join(ROOT, "test"))


def load_module(name, file):
    path = os.path.join(ROOT, file)
    spec = importlib.util.spec_from_file_location(name, path)
    return spec.loader.load_module()


@pytest.fixture()
def master_opts(tmpdir):
    opts = salt.config.master_config("test/master.yml")
    opts["cachedir"] = tmpdir
    opts["dehydrated"]["executable"] = os.path.join(ROOT, "test/fixtures/dehydrated.sh")
    return opts


@pytest.yield_fixture(scope="session")
def tmpd():
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture(scope="session")
def opts(tmpd):
    opts = salt.config.minion_config(os.path.join(ROOT, "test/minion.yml"))
    opts["cachedir"] = os.path.join(tmpd, "cache")
    opts["pki_dir"] = os.path.join(tmpd, "pki")
    opts["module_dirs"] = [ROOT]

    grains = salt.loader.grains(opts)
    opts["grains"] = grains

    return opts


@pytest.fixture(scope="session")
def utils(opts):
    return salt.loader.utils(opts)


@pytest.fixture(scope="session")
def mods(opts, utils):
    return salt.loader.minion_mods(opts, utils=utils)


@pytest.fixture(autouse=True)
def cleanup_zone():
    # Always cleanup knot zones before each test
    with knotc() as knot:
        knot.send("zone-reload example.com")
        knot.send("zone-reload example.org")

    yield


class knotc:
    def __init__(self):
        self.process = None

    def __enter__(self):
        self.process = Popen(
            ["/usr/sbin/knotc", "--socket", "./test/tmp/knot.sock"], stdin=PIPE
        )
        return self

    @contextmanager
    def zone_edit(self, zone):
        self.send(f"zone-begin {zone}")
        yield self
        self.send(f"zone-commit {zone}")

    def set(self, data):
        self.send(f"zone-set -- {data}")

    def send(self, cmd):
        self.process.stdin.write(cmd.encode() + b"\n")
        self.process.stdin.flush()

    def __exit__(self, *args):
        self.process.communicate()
        self.process.terminate()
        self.process.wait(timeout=1)

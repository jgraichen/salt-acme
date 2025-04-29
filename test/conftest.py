# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring,redefined-outer-name

import logging
import os
import sys
import tempfile
from contextlib import contextmanager
from subprocess import PIPE, Popen

import pytest
import salt.config

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(os.path.join(ROOT, "test"))


class Base:
    def __init__(self, basedir, opts):
        self.opts = opts
        self.opts["cachedir"] = os.path.join(basedir, "cache")
        self.opts["pki_dir"] = os.path.join(basedir, "pki")
        self.opts["module_dirs"] = [ROOT]

        # Setup file_roots to include `acme` state directory only
        file_root = os.path.join(basedir, "states")
        os.makedirs(file_root)
        os.symlink(os.path.join(ROOT, "acme"), os.path.join(file_root, "acme"))
        self.opts["file_roots"] = {
            "base": [file_root, os.path.join(ROOT, "test/fixtures/states")]
        }

        self.grains = salt.loader.grains(opts)
        self.opts["grains"] = self.grains

    @property
    def utils(self):
        return salt.loader.utils(self.opts)

    @property
    def mods(self):
        return salt.loader.minion_mods(self.opts, utils=self.utils)


class Master(Base):
    def __init__(self, tmpd):
        super().__init__(
            os.path.join(tmpd, "master"), salt.config.master_config("test/master.yml")
        )

    @property
    def runner(self):
        return salt.loader.runner(self.opts, utils=self.utils)


class Minion(Base):
    def __init__(self, tmpd):
        super().__init__(
            os.path.join(tmpd, "minion"), salt.config.minion_config("test/minion.yml")
        )


@pytest.yield_fixture(scope="session")
def tmpd():
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture(scope="session")
def master(tmpd):
    return Master(tmpd)


@pytest.fixture(scope="session")
def minion(tmpd):
    return Minion(tmpd)


class knotc:
    def __init__(self):
        self.process = None

    def __enter__(self):
        self.process = Popen(
            ["docker", "exec", "--interactive", "test-knot-1", "knotc"],
            stdin=PIPE,
            stdout=PIPE,
            stderr=PIPE,
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
        result = self.process.communicate()
        stdout = result[0].decode()
        stderr = result[1].decode()
        if stdout:
            logging.debug("knotc: \n%s", stdout)
        if stderr:
            logging.debug("knotc err: \n%s", stderr)
        self.process.terminate()
        self.process.wait(timeout=1)


@pytest.fixture(autouse=True)
def cleanup_zone():
    # Always cleanup knot zones before each test
    with knotc() as knot:
        knot.send("zone-reload example.com")
        knot.send("zone-reload example.org")

    yield


@pytest.fixture(scope="session", autouse=True)
def disable_logging_exceptions():
    try:
        yield
    finally:
        # pytest captures logging but closes the streams when tests are
        # finished. salt still tries to log e.g. at some atexit
        # handlers, which would raise logging exception due to the
        # stream being closed. See pytest-dev/pytest#5577.
        logging.raiseExceptions = False

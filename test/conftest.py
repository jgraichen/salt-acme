# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring,redefined-outer-name

import os
import sys
import importlib.util
import tempfile

import pytest

import salt.config


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(os.path.join(ROOT, 'test'))


def load_module(name, file):
    path = os.path.join(ROOT, file)
    spec = importlib.util.spec_from_file_location(name, path)
    return spec.loader.load_module()


@pytest.fixture()
def master_opts(tmpdir):
    opts = salt.config.master_config('test/master.yml')
    opts['cachedir'] = tmpdir
    opts['dehydrated']['executable'] = os.path.join(ROOT, 'test/fixtures/dehydrated.sh')
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

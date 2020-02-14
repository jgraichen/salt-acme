# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring

import os
import sys
import importlib.util

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
    opts = salt.config.master_config('test/fixtures/master.yml')
    opts['cachedir'] = tmpdir
    opts['dehydrated']['executable'] = os.path.join(ROOT, 'test/fixtures/dehydrated.sh')
    return opts

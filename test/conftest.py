# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring

import logging
import os
import sys

import pytest

import salt.config
import salt.loader

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(os.path.join(ROOT))


__opts__ = salt.config.client_config(os.path.join(ROOT, "test/master.yml"))
__opts__["cachedir"] = os.path.join(ROOT, "tmp/cache")
__opts__["pki_dir"] = os.path.join(ROOT, "tmp/pki")
__opts__["module_dirs"] = [ROOT]

__grains__ = salt.loader.grains(__opts__)
__opts__["grains"] = __grains__

__utils__ = salt.loader.utils(__opts__)
__salt__ = salt.loader.minion_mods(__opts__, utils=__utils__)
__runners__ = salt.loader.runner(__opts__, __salt__)

logging.info('Salt Loader Information:')
logging.info("  utils  : %s", ", ".join(__utils__.module_dirs))
logging.info("  modules: %s", ", ".join(__salt__.module_dirs))
logging.info("  runners: %s", ", ".join(__runners__.module_dirs))


@pytest.fixture
def utils():
    return __utils__


@pytest.fixture
def mods():
    return __salt__


@pytest.fixture
def runners():
    return __runners__

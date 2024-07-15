# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring
# pylint: disable=redefined-outer-name

import pytest
import yaml
from matchlib import Partial


@pytest.fixture
def sls(minion):
    def fn(pillar):
        if isinstance(pillar, str):
            pillar = yaml.safe_load(pillar)

        return {
            k: _transform(v)
            for k, v in minion.mods["state.show_sls"]("acme", pillar=pillar).items()
        }

    return fn


def _transform(state):
    """
    Transforms a state output into something easier to test.
    """

    ret = {}
    for key, value in state.items():
        if key in ("__env__", "__sls__"):
            continue

        data = {}
        for obj in value:
            if isinstance(obj, dict) and "order" not in obj:
                data.update(obj)

        ret[f"{key}.{value[0]}"] = data

    return ret


def test_state(sls):
    state = sls(
        """
        acme:
            basedir: /etc/acme

            default:
                # All options can be overridden in the certificate below
                runner: acme.sign
                key:
                    mode: 640
                    user: root
                    group: root
                    type: ec
                    curve: secp256r1
                    size: 4096  # only with RSA keys

            certificate:
                example.org:
                    domains:
                        - example.org
                        - www.example.org
                    include:
                        - nginx.service
                    watch_in:
                        - service: nginx
        """
    )

    assert state == Partial(
        {
            "/etc/acme/example.org": {"file.directory": {"makedirs": True}},
            "/etc/acme/example.org/privkey.pem": {
                "pki.private_key": {
                    "curve": "secp256r1",
                    "require": [{"file": "/etc/acme/example.org"}],
                    "size": 4096,
                    "type": "ec",
                },
                "file.managed": {
                    "group": "root",
                    "mode": 640,
                    "replace": False,
                    "require": [{"pki": "/etc/acme/example.org/privkey.pem"}],
                    "user": "root",
                },
            },
            "/etc/acme/example.org/fullchain.pem": {
                "pki.certificate": {
                    "domains": ["example.org", "www.example.org"],
                    "key": "/etc/acme/example.org/privkey.pem",
                    "require": [
                        {"pki": "/etc/acme/example.org/privkey.pem"},
                        {"file": "/etc/acme/example.org/privkey.pem"},
                        {"file": "/etc/acme/example.org"},
                    ],
                    "runner": "acme.sign",
                    "watch_in": [{"service": "nginx"}],
                }
            },
            ...: ...,
        }
    )


def test_state_nodir(sls):
    state = sls(
        """
        acme:
            basedir: /etc/acme

            default:
                # All options can be overridden in the certificate below
                runner: acme.sign
                key:
                    mode: 640
                    user: root
                    group: root
                    type: ec
                    curve: secp256r1
                    size: 4096  # only with RSA keys

            certificate:
                example.org:
                    create_directories: False
                    domains:
                        - example.org
                        - www.example.org
                    include:
                        - nginx.service
                    watch_in:
                        - service: nginx
        """
    )

    assert "/etc/acme/example.org" not in state


def test_state_name(sls):
    """
    If no `domains` key is present the certificate name (pillar key) will be
    used as the domain name.
    """
    state = sls(
        """
        acme:
            certificate:
                example.com: {}
        """
    )

    assert state == Partial(
        {
            "/etc/acme/example.com/fullchain.pem": {
                "pki.certificate": {"domains": ["example.com"], ...: ...}
            },
            ...: ...,
        }
    )


def test_state_filename(sls):
    state = sls(
        """
        acme:
            certificate:
                example.com:
                    name: "{name}.crt"
                    key:
                        name: "{name}.crt.key"
        """
    )

    assert state == Partial(
        {
            "/etc/acme/example.com/example.com.crt": {
                "pki.certificate": {"domains": ["example.com"], ...: ...}
            },
            "/etc/acme/example.com/example.com.crt.key": {
                "pki.private_key": ...,
                ...: ...,
            },
            ...: ...,
        }
    )


def test_state_filename_absolute(sls):
    state = sls(
        """
        acme:
            certificate:
                example.com:
                    name: "/etc/haproxy/certs/{name}.crt"
                    key:
                        name: "/etc/haproxy/certs/{name}.crt.key"
        """
    )

    assert state == Partial(
        {
            "/etc/haproxy/certs": {"file.directory": {"makedirs": True}},
            "/etc/haproxy/certs/example.com.crt": {
                "pki.certificate": {"domains": ["example.com"], ...: ...}
            },
            "/etc/haproxy/certs/example.com.crt.key": {
                "pki.private_key": ...,
                ...: ...,
            },
            ...: ...,
        }
    )

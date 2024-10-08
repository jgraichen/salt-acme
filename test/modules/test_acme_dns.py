# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring
# pylint: disable=redefined-outer-name


import pytest
from conftest import knotc
from dns.rdatatype import TXT
from dns.resolver import NXDOMAIN, Resolver


@pytest.fixture()
def resolver():
    resolver = Resolver()
    resolver.nameservers = ["127.0.0.153"]
    return resolver


def test_install(minion, resolver: Resolver):
    minion.mods["acme_dns.install"](
        "example.com",
        [{"name": "example.com", "token": "secret"}],
        nameserver="127.0.0.153",
    )

    answer = resolver.resolve("_acme-challenge.example.com.", TXT)[0]
    assert list(answer.strings) == [b"secret"]  # type: ignore


def test_install_name_and_port(minion, resolver: Resolver):
    minion.mods["acme_dns.install"](
        "example.com",
        [{"name": "example.com", "token": "secret"}],
        nameserver="localhost",
        port=5300,
    )

    answer = resolver.resolve("_acme-challenge.example.com.", TXT)[0]
    assert list(answer.strings) == [b"secret"]  # type: ignore


def test_install_zone(minion, resolver: Resolver):
    minion.mods["acme_dns.install"](
        "default",
        [{"name": "example.com", "token": "secret"}],
        nameserver="127.0.0.153",
        zone="example.com",
    )

    answer = resolver.resolve("_acme-challenge.example.com.", TXT)[0]
    assert list(answer.strings) == [b"secret"]  # type: ignore


def test_install_alias(minion, resolver: Resolver):
    minion.mods["acme_dns.install"](
        "example.com",
        [{"name": "example.com", "token": "secret"}],
        nameserver="127.0.0.153",
        alias="acme.example.com",
    )

    answer = resolver.resolve("acme.example.com.", TXT)[0]
    assert list(answer.strings) == [b"secret"]  # type: ignore


def test_install_tsig(minion, resolver: Resolver):
    minion.mods["acme_dns.install"](
        "example.org",
        [{"name": "example.org", "token": "secret"}],
        nameserver="127.0.0.153",
        tsig="hmac-sha256:acme:opCLn9NMrbY0xKB8lWs2KM2lgQsEW5LdvsVtxnoRJIo=",
    )

    answer = resolver.resolve("_acme-challenge.example.org.", TXT)[0]
    assert list(answer.strings) == [b"secret"]  # type: ignore


def test_remove(minion, resolver: Resolver):
    """
    Removes only given challenges from zone.
    """
    with knotc() as knot:
        with knot.zone_edit("example.com."):
            knot.set('_acme-challenge 120 TXT "value-1"')
            knot.set('_acme-challenge 120 TXT "value-2"')

    minion.mods["acme_dns.remove"](
        "example.com",
        [{"name": "example.com", "token": "value-2"}],
        nameserver="127.0.0.153",
    )

    answer = resolver.resolve("_acme-challenge.example.com.", TXT)[0]
    assert list(answer.strings) == [b"value-1"]  # type: ignore


def test_remove_zone(minion, resolver: Resolver):
    with knotc() as knot:
        with knot.zone_edit("example.com"):
            knot.set('_acme-challenge 120 TXT "secret"')

    minion.mods["acme_dns.remove"](
        "default",
        [{"name": "example.com", "token": "secret"}],
        nameserver="127.0.0.153",
        zone="example.com",
    )

    with pytest.raises(NXDOMAIN):
        resolver.resolve("_acme-challenge.example.org.", TXT)


def test_remove_tsig(minion, resolver: Resolver):
    with knotc() as knot:
        with knot.zone_edit("example.org"):
            knot.set('_acme-challenge 120 TXT "secret"')

    minion.mods["acme_dns.remove"](
        "example.org",
        [{"name": "example.org", "token": "secret"}],
        nameserver="127.0.0.153",
        tsig="hmac-sha256:acme:opCLn9NMrbY0xKB8lWs2KM2lgQsEW5LdvsVtxnoRJIo=",
    )

    with pytest.raises(NXDOMAIN):
        resolver.resolve("_acme-challenge.example.org.", TXT)


def test_remove_alias(minion, resolver: Resolver):
    with knotc() as knot:
        with knot.zone_edit("example.com"):
            knot.set('acme 120 TXT "secret"')

    minion.mods["acme_dns.remove"](
        "example.com",
        [{"name": "example.com", "token": "secret"}],
        nameserver="127.0.0.153",
        alias="acme.example.com",
    )

    with pytest.raises(NXDOMAIN):
        resolver.resolve("acme.example.org.", TXT)

# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring,redefined-outer-name

import pytest
import dns


CHALLENGES_COM = {
    "_acme-challenge.example.com.": "token-1",
    "_acme-challenge.www.example.com.": "token-2",
}

CHALLENGES_ORG = {
    "_acme-challenge.example.org.": "token-3",
    "_acme-challenge.www.example.org.": "token-4",
}

TSIG_KEY = "hmac-sha256:salt:5MDvsVH5W7Vuvm9T3JvDCGnZACV4npdUw44TbdKcHqE="


@pytest.fixture
def resolver():
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["10.30.50.3"]
    return resolver


def test_install_and_remove(runners, resolver):
    runners["acme_nsupdate.install"](
        CHALLENGES_COM, server="10.30.50.3", zone="example.com."
    )

    answer = resolver.query("_acme-challenge.example.com.", "TXT")
    assert str(answer.rrset[0]) == '"token-1"'

    answer = resolver.query("_acme-challenge.www.example.com.", "TXT")
    assert str(answer.rrset[0]) == '"token-2"'

    runners["acme_nsupdate.remove"](
        CHALLENGES_COM, server="10.30.50.3", zone="example.com."
    )

    with pytest.raises(dns.resolver.NXDOMAIN):
        resolver.query("_acme-challenge.example.com.", "TXT")

    with pytest.raises(dns.resolver.NXDOMAIN):
        resolver.query("_acme-challenge.www.example.com.", "TXT")


def test_install_and_remove_tsig(runners, resolver):
    runners["acme_nsupdate.install"](
        CHALLENGES_ORG, server="10.30.50.3", zone="example.org.", tsig=TSIG_KEY
    )

    answer = resolver.query("_acme-challenge.example.org.", "TXT")
    assert str(answer.rrset[0]) == '"token-3"'

    answer = resolver.query("_acme-challenge.www.example.org.", "TXT")
    assert str(answer.rrset[0]) == '"token-4"'

    runners["acme_nsupdate.remove"](
        CHALLENGES_ORG, server="10.30.50.3", zone="example.org.", tsig=TSIG_KEY
    )

    with pytest.raises(dns.resolver.NXDOMAIN):
        resolver.query("_acme-challenge.example.org.", "TXT")

    with pytest.raises(dns.resolver.NXDOMAIN):
        resolver.query("_acme-challenge.www.example.org.", "TXT")

# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring
"""
Installs ACME DNS01 challenges using dynamic DNS updates

:depends: dnspython
"""

import logging

import dns
import dns.tsigkeyring

from contextlib import contextmanager

from dns.update import Update
from dns.rdataclass import IN
from dns.rdatatype import TXT
from dns.rcode import NOERROR

from salt.exceptions import CommandExecutionError


def _make_record(challenge, alias=None, **_kwargs):
    if alias:
        name = dns.name.from_unicode(alias)
    else:
        name = dns.name.from_unicode(f"_acme-challenge.{challenge['name']}")
    rdata = dns.rdata.from_text(IN, TXT, str(challenge["token"]))
    return (name, rdata)


@contextmanager
def _update(zone, nameserver, port=53, timeout=10, tsig=None, **_kwargs):
    update = Update(zone)

    if tsig:
        algorithm, keyname, secret = str(tsig).split(":", 3)
        keyring = dns.tsigkeyring.from_text({keyname: secret})
        update.use_tsig(keyring, keyname=keyname, algorithm=algorithm)

    yield update

    answer = dns.query.tcp(update, nameserver, timeout, port)
    rcode = answer.rcode()

    if rcode is not NOERROR:
        raise CommandExecutionError(f"DNS update failed: {dns.rcode.to_text(rcode)}")


def install(name, challenges, ttl=120, **kwargs):
    with _update(name, **kwargs) as u:
        for challenge in challenges:
            name, rdata = _make_record(challenge, **kwargs)
            u.add(name, ttl, rdata)


def remove(name, challenges, **kwargs):
    with _update(name, **kwargs) as u:
        for challenge in challenges:
            name, rdata = _make_record(challenge, **kwargs)
            u.delete(name, rdata)

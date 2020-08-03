# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring
"""
Installs ACME DNS01 challenges using dynamic DNS updates

:depends: dnspython
"""

import logging
import time

from contextlib import contextmanager

try:
    import dns
    import dns.tsigkeyring

    from dns.update import Update
    from dns.rdataclass import IN
    from dns.rdatatype import TXT
    from dns.rcode import NOERROR

    _HAS_DNS = True
except ImportError:
    _HAS_DNS = False

from salt.exceptions import CommandExecutionError, TimeoutError as SaltTimeoutError


_LOG = logging.getLogger(__name__)


def __virtual__():
    if not _HAS_DNS:
        return False, "dnspython missing"
    return True


def _make_record(token, alias=None, **_kwargs):
    if alias:
        name = dns.name.from_unicode(alias)
    else:
        name = dns.name.from_unicode(f"_acme-challenge.{token['name']}")
    rdata = dns.rdata.from_text(IN, TXT, str(token["token"]))
    return (name, rdata)


def _query(nameserver, port, *args, **kwargs):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [nameserver]
    resolver.nameserver_ports = {nameserver: port}
    return resolver.query(*args, **kwargs)


def _query_nameserver(nameserver, port, zone):
    resolver = dns.resolver.Resolver()
    resolver.nameservers.insert(0, nameserver)
    resolver.nameserver_ports[nameserver] = port

    nameservers = []
    for rdata in _query(nameserver, port, zone, "NS", raise_on_no_answer=False):
        ns = rdata.target.to_unicode()
        for rdtype in ("A", "AAAA"):
            try:
                nameservers.extend([r.to_text() for r in resolver.query(ns, rdtype)])
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass

    return nameservers


def _verify(nameserver, port, zone, verify_timeout=120, **_kwargs):
    """
    Verify all nameservers listed as NS in `zone` serve the current or a newer
    SOA serial.
    """
    # Verify SOA serial propagation to all nameserver
    serial = _query(nameserver, port, zone, "SOA")[0].serial
    deadline = time.monotonic() + verify_timeout
    nameservers = _query_nameserver(nameserver, port, zone)

    if not nameservers:
        _LOG.warning("Skip DNS record verify: No nameservers found for %s", zone)
        return

    _LOG.info("Verify SOA serial %d for %d nameservers...", serial, len(nameservers))

    while deadline > time.monotonic():
        for ns in nameservers[:]:
            ns_serial = _query(ns, 53, zone, "SOA")[0].serial
            if ns_serial < serial:
                _LOG.debug("Nameserver %s still at %d...", ns, ns_serial)
            else:
                nameservers.remove(ns)

        if nameservers:
            _LOG.debug("%d nameservers still pending...", len(nameservers))
            time.sleep(0.5)
        else:
            _LOG.debug("All nameservers up-to-date!")
            break

    if nameservers:
        _LOG.error("Nameserver failed to update: %s", nameservers)
        raise SaltTimeoutError(f"Some nameserver failed to receive DNS updates")


@contextmanager
def _update(zone, nameserver, port=53, timeout=10, tsig=None, verify=True, **kwargs):
    update = Update(zone)

    if tsig:
        algorithm, keyname, secret = str(tsig).split(":", 3)
        keyring = dns.tsigkeyring.from_text({keyname: secret})
        update.use_tsig(keyring, keyname=keyname, algorithm=algorithm)

    yield update

    answer = dns.query.tcp(update, nameserver, timeout, port)
    rcode = answer.rcode()

    if rcode is not NOERROR:
        raise CommandExecutionError(
            f"DNS update for {zone} failed: {dns.rcode.to_text(rcode)}"
        )

    if verify:
        _verify(nameserver, port, zone, **kwargs)


def install(name, tokens, ttl=120, **kwargs):
    if "zone" not in kwargs:
        kwargs["zone"] = name

    with _update(**kwargs) as update:
        for token in tokens:
            name, rdata = _make_record(token, **kwargs)
            update.add(name, ttl, rdata)


def remove(name, tokens, **kwargs):
    if "zone" not in kwargs:
        kwargs["zone"] = name

    # No need to verify propagation when removing challenges
    kwargs["verify"] = False

    with _update(**kwargs) as update:
        for token in tokens:
            name, rdata = _make_record(token, **kwargs)
            update.delete(name, rdata)

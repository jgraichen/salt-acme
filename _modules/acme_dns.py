# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring
"""
Installs ACME DNS01 challenges using dynamic DNS updates

:depends: dnspython
:depends: ipaddress
"""

import ipaddress
import logging
import time
from contextlib import contextmanager

try:
    import dns
    import dns.tsigkeyring
    from dns.rcode import NOERROR
    from dns.rdataclass import IN
    from dns.rdatatype import TXT
    from dns.update import Update

    _HAS_DNS = True
except ImportError:
    _HAS_DNS = False

from salt.exceptions import (
    CommandExecutionError,
    SaltConfigurationError,
)
from salt.exceptions import (
    TimeoutError as SaltTimeoutError,
)

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


def _query_addresses(name, resolver=None):
    if resolver is None:
        resolver = dns.resolver

    addresses = []
    for rdtype in ("A", "AAAA"):
        try:
            addresses.extend([r.to_text() for r in resolver.query(name, rdtype)])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
    return addresses


def _verify(nameserver, port, zone, verify_timeout=120, **_kwargs):
    """
    Verify all nameservers listed as NS in `zone` serve the current or a newer
    SOA serial.
    """

    # Use primary nameserver for NS lookup and as first resolver
    # to handle local or split-horizon scenarios
    resolver = dns.resolver.Resolver(configure=False)

    try:
        ipaddress.ip_address(nameserver)
        resolver.nameservers = [nameserver]
    except ValueError as e:
        resolver.nameservers = _query_addresses(nameserver)
        if not resolver.nameservers:
            raise SaltConfigurationError(f"Nameserver not found: {nameserver}") from e

    # All resolved address of the primary NS must use the configured port
    resolver.nameserver_ports.update({ns: port for ns in resolver.nameservers})

    # The public resolver first tries the primary NS first, otherwise falls
    # back to the system resolver. This is used to lookup e.g. other NS names
    # which might not be served by the primary.
    public = dns.resolver.Resolver()
    public.nameservers = resolver.nameservers + public.nameservers
    public.nameserver_ports.update(resolver.nameserver_ports)

    # Verify SOA serial propagation to all nameserver
    serial = resolver.query(zone, "SOA")[0].serial
    deadline = time.monotonic() + verify_timeout

    # Collect all NS records of the zone. We explicitly use the primary NS
    # as the system resolver might serve internal NS in a split-horizon setup.
    nameservers = []
    resolvers = {}
    for rdata in resolver.query(zone, "NS", raise_on_no_answer=False):
        name = rdata.target.to_unicode()
        resolvers[name] = dns.resolver.Resolver(configure=False)
        resolvers[name].nameservers = _query_addresses(name, resolver=public)
        nameservers.append(name)

    if not nameservers:
        _LOG.warning("Skip DNS record verify: No nameservers found for %s", zone)
        return

    _LOG.info("Verify SOA serial %d for %d nameservers...", serial, len(nameservers))

    while deadline > time.monotonic():
        for ns in nameservers[:]:
            ns_serial = resolvers[ns].query(zone, "SOA")[0].serial
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
        raise SaltTimeoutError("Some nameserver failed to receive DNS updates")


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

    if rcode != NOERROR:
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

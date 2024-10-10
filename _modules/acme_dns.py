# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring
# pyright: reportUnboundVariable=false
"""
Installs ACME DNS01 challenges using dynamic DNS updates

:depends: dnspython
"""

import logging
import socket
import time
from contextlib import contextmanager

try:
    import dns
    import dns.inet
    import dns.name
    import dns.query
    import dns.rcode
    import dns.rdata
    import dns.resolver
    import dns.tsigkeyring
    from dns.nameserver import Do53Nameserver
    from dns.rcode import NOERROR
    from dns.resolver import Resolver
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
    rdata = dns.rdata.from_text("IN", "TXT", str(token["token"]))
    return (name, rdata)


def _verify(address, port, zone, verify_timeout=120, **_kwargs):
    """
    Verify all nameservers listed as NS in `zone` serve the current or a newer
    SOA serial.
    """

    # Use primary nameserver for NS lookup and as first resolver to
    # handle local or split-horizon scenarios
    resolver = Resolver(configure=False)
    resolver.nameservers = [Do53Nameserver(address, port)]

    # The public resolver first tries the primary NS first, otherwise
    # falls back to the system resolver. This is used to lookup e.g.
    # other NS names which might not be served by the primary.
    public = Resolver()
    public.nameservers = resolver.nameservers + public.nameservers  # type: ignore

    # Verify SOA serial propagation to all nameserver
    serial = resolver.resolve(zone, "SOA")[0].serial  # type: ignore
    deadline = time.monotonic() + verify_timeout

    # Collect all NS records of the zone. We explicitly use the primary
    # NS as the system resolver might serve internal NS in a
    # split-horizon setup.
    nameservers = []
    resolvers = {}
    for rdata in resolver.resolve(zone, "NS", raise_on_no_answer=False):  # type: ignore
        name = rdata.target.to_unicode()
        addrs = list(public.resolve_name(name).addresses())
        if addrs:
            resolvers[name] = Resolver(configure=False)
            resolvers[name].nameservers = list(public.resolve_name(name).addresses())
            nameservers.append(name)

    if not nameservers:
        _LOG.warning("Skip DNS record verify: No nameservers found for %s", zone)
        return

    _LOG.info("Verify SOA serial %d for %d nameservers...", serial, len(nameservers))

    while deadline > time.monotonic():
        for ns in nameservers[:]:
            ns_serial = resolvers[ns].resolve(zone, "SOA")[0].serial
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
    if dns.inet.is_address(nameserver):
        addresses = [(nameserver, port)]
    else:
        try:
            addresses = [
                (addr[0], addr[1])
                for _, _, _, _, addr in socket.getaddrinfo(
                    nameserver, port=port, proto=socket.IPPROTO_UDP
                )
            ]
        except socket.gaierror as err:
            raise SaltConfigurationError(
                f"Nameserver {nameserver} not found: {err}"
            ) from err

    update = Update(zone)

    if tsig:
        algorithm, keyname, secret = str(tsig).split(":", 3)
        keyring = dns.tsigkeyring.from_text({keyname: secret})
        update.use_tsig(keyring, keyname=keyname, algorithm=algorithm)

    yield update

    error = None
    for addr, port in addresses:
        try:
            answer = dns.query.tcp(update, addr, timeout, port)
            break
        except OSError as err:
            error = err
            _LOG.warning("Failed to update %s@%s: %s", addr, port, err)
    else:
        raise CommandExecutionError(f"Failed to update nameserver: {error}")

    rcode = answer.rcode()
    if rcode != NOERROR:
        raise CommandExecutionError(
            f"DNS update for {zone} failed: {dns.rcode.to_text(rcode)}"
        )

    if verify:
        _verify(addr, port, zone, **kwargs)


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

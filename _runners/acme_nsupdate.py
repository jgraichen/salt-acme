# -*- coding: utf-8 -*-

import contextlib
import logging

from salt.exceptions import CommandExecutionError

try:
    import dns.query
    import dns.resolver
    import dns.tsigkeyring
    import dns.update

    _HAS_DNS = True
except ImportError:
    _HAS_DNS = False


def __virtual__():
    if not _HAS_DNS:
        return False, "dnspython not available"
    return True


def install(challenges, server, zone, ttl=600, **kwargs):
    '''
    Installs list of ACME DNS challenges.

    challenges:
        List of ACME DNS challenges passed by ``acme.sign``.

    server:
        Nameserver address, e.g. ``127.0.0.1``.

    zone:
        Zone name, e.g. ``example.org.``.

    ttl:
        TTL for challenge TXT records, defaults to ``600``.

    port:
        Nameserver port. Defaults to ``53``.

    tsig:
        TSIG to sign the update message. Format must be
        ``<algorithm>:<name>:<secret>``.

    timeout:
        DDNS timeout. Defaults to ``15`` seconds.
    '''

    logging.debug(challenges)

    with _update(server, zone, **kwargs) as update:
        for name, token in challenges.items():
            update.add(name, ttl, 'TXT', str(token))


def remove(challenges, server, zone, **kwargs):
    '''
    Removes previously installed ACME DNS challenges.

    challenges:
        List of ACME DNS challenges passed by ``acme.sign``.

    server:
        Nameserver address, e.g. ``127.0.0.1``.

    zone:
        Zone name, e.g. ``example.org.``.

    port:
        Nameserver port. Defaults to ``53``.

    tsig:
        TSIG to sign the update message. Format must be
        ``<algorithm>:<name>:<secret>``.

    timeout:
        DDNS timeout. Defaults to ``15`` seconds.
    '''

    with _update(server, zone, **kwargs) as update:
        for name, token in challenges.items():
            update.delete(name, 'TXT', str(token))


@contextlib.contextmanager
def _update(server, zone, port=53, tsig=None, timeout=15, **_kwargs):
    if tsig:
        algorithm, name, secret = str(tsig).split(":", 3)
        keyring = dns.tsigkeyring.from_text({name: secret})
        update = dns.update.Update(
            zone, keyring=keyring, keyname=name, keyalgorithm=algorithm
        )
    else:
        update = dns.update.Update(zone)

    yield update

    answer = dns.query.tcp(update, server, timeout, port)
    rcode = answer.rcode()

    if rcode is not dns.rcode.NOERROR:
        raise CommandExecutionError(
            f"DNS update failed: {dns.rcode.to_text(rcode)}"
        )

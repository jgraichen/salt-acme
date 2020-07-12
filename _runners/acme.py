# -*- coding: utf-8 -*-
"""
Sign certificate signing requests (CSR) using the ACME execution module on the
salt master.
"""

import re

_REGEXP_CSR = re.compile(
    r"\s*((-+BEGIN CERTIFICATE REQUEST-+)\s*([A-Za-z0-9+/=\s]*)\s*(-+END CERTIFICATE REQUEST-+))\s*"
)


def sign(csr):
    """
    Requests to sign a CSR using dehydrated.

    csr:
        Certificate signing request as PEM-encoded string.
    """

    # Restores newlines in a PEM files that might have been lost by salt
    # argument parsing.
    match = _REGEXP_CSR.match(csr)
    if match:
        _, head, body, tail = match.groups()
        csr = "\n".join([head, *body.strip().split(" "), tail])

    return __salt__["salt.cmd"]("acme.sign", csr)

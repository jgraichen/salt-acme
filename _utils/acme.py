# -*- coding: utf-8 -*-

import re

_REGEXP_CSR = re.compile(
    r"\s*((-+BEGIN CERTIFICATE REQUEST-+)\s*([A-Za-z0-9+/=\s]*)\s*(-+END CERTIFICATE REQUEST-+))\s*"
)

def fixup_pem(pem):
    """
    Restores newlines in a PEM files that might have been lost by salt argument
    parsing.
    """

    match = _REGEXP_CSR.match(pem)
    if match:
        _, head, body, tail = match.groups()
        pem = "\n".join([head, *body.strip().split(" "), tail])

    return pem

# -*- coding: utf-8 -*-
"""
Sign certificate signing requests (CSR) using the ACME execution module on the
salt master.
"""


def sign(csr):
    """
    Requests to sign a CSR using dehydrated.

    csr:
        Certificate signing request as PEM-encoded string.
    """

    return __salt__["salt.cmd"]("acme.sign", csr)

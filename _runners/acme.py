# -*- coding: utf-8 -*-
"""
Sign certificate signing requests (CSR) using the ACME execution module on the
salt master.
"""

def __virtual__():
    if 'acme.sign' not in __salt__:
        return False, f"acme module not available"
    return True


def sign(csr):
    """
    Requests to sign a CSR using dehydrated.

    csr:
        Certificate signing request as PEM-encoded string.
    """

    return {"text": None}

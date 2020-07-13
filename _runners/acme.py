# -*- coding: utf-8 -*-
"""
Sign certificate signing requests (CSR) using the ACME execution module on the
salt master.

:depends: cryptography
"""

import fnmatch
import logging
import re
import yaml

_MISSING_MODULES = []

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except ImportError:
    _MISSING_MODULES.append("cryptography")

from salt.exceptions import SaltConfigurationError, AuthorizationError

try:
    from salt.utils.data import traverse_dict_and_list
    from salt.utils.files import fopen
except ImportError:
    from salt.utils import traverse_dict_and_list
    from salt.utils import fopen


_REGEXP_CSR = re.compile(
    r"\s*((-+BEGIN CERTIFICATE REQUEST-+)\s*([A-Za-z0-9+/=\s]*)\s*(-+END CERTIFICATE REQUEST-+))\s*"
)


def __virtual__():
    if _MISSING_MODULES:
        return False, f"module(s) missing: {', '.join(_MISSING_MODULES)}"
    return True


def _extract_domain_names(pem):
    names = set()
    csr = x509.load_pem_x509_csr(pem.encode(), default_backend())

    for name in csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
        names.add(name.value)
    try:
        alt = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in alt.value:
            names.add(name.value)
    except x509.ExtensionNotFound:
        pass

    return sorted(names)


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

    requested = _extract_domain_names(csr)
    auth_file = traverse_dict_and_list(__opts__, "acme:runner:auth_file", None)
    if auth_file:
        logging.debug("Use auth_file from %s", auth_file)

        with fopen(auth_file, "r") as f:
            auth = yaml.safe_load(f)

        if not isinstance(auth, dict):
            raise SaltConfigurationError("Invalid auth_file: must be a dict")

        logging.debug("Authorizing domain names for %s: %s", __opts__["id"], requested)

        for pattern, auth in auth.items():
            if not fnmatch.fnmatch(__opts__["id"], pattern):
                continue

            for name in requested.copy():
                for rule in auth:
                    if fnmatch.fnmatch(name, rule):
                        requested.remove(name)

        if requested:
            raise AuthorizationError(f"Unauthorized domains: {', '.join(requested)}")

    return __salt__["salt.cmd"]("acme.sign", csr)

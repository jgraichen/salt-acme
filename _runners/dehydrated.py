# -*- coding: utf-8 -*-
"""
Sign certificate signing requests (CSR) using the dehydrated ACME command line
client.

dehydrated needs to be installed and configured manually on the salt master.
"""

import fnmatch
import logging
import re
import shutil
import subprocess
import tempfile

from cryptography import x509
from cryptography.hazmat.backends import default_backend as _default_backend

from salt.exceptions import CommandExecutionError, AuthorizationError

try:
    from salt.utils.data import traverse_dict_and_list as _get
except ImportError:
    from salt.utils import traverse_dict_and_list as _get


_REGEXP_CSR = re.compile(
    r"\s*((-+BEGIN CERTIFICATE REQUEST-+)\s*([A-Za-z0-9+/=\s]*)\s*(-+END CERTIFICATE REQUEST-+))\s*"
)


def __virtual__():
    exename = _get_executable_name()
    if not shutil.which(exename):
        return False, f"dehydrated executable not found: {exename}"
    return True


def _get_executable_name():
    return _get(__opts__, "dehydrated:executable", "dehydrated")


def _get_executable_args():
    return _get(__opts__, "dehydrated:args", [])


def _get_requested_names(csr):
    requested_names = set()
    obj = x509.load_pem_x509_csr(csr.encode(), _default_backend())
    for name in obj.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
        requested_names.add(name.value)
    try:
        alt = obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in alt.value:
            requested_names.add(name.value)
    except x509.ExtensionNotFound:
        pass
    return requested_names


def sign(csr):
    """
    Requests to sign a CSR using dehydrated.

    csr:
        Certificate signing request as PEM-encoded string.
    """

    # Fix newlines in PEM lost in salt argument parsing
    match = _REGEXP_CSR.match(csr)
    if match:
        _, head, body, tail = match.groups()
        csr = "\n".join([head, *body.strip().split(" "), tail])

    requested = _get_requested_names(csr)

    for pattern, auth in __salt__["config.get"]("dehydrated:authorization", {}).items():
        if fnmatch.fnmatch(__opts__['id'], pattern):
            for name in requested.copy():
                for rule in auth:
                    if fnmatch.fnmatch(name, rule):
                        requested.remove(name)

    if requested:
        raise AuthorizationError(f"Unauthorized names: {requested}")

    executable = shutil.which(_get_executable_name())
    arguments = _get_executable_args()

    with tempfile.NamedTemporaryFile("w+") as f:
        f.write(csr)
        f.flush()

        cmd = [executable, "--signcsr", f.name, *arguments]

        logging.debug("Execute: %s", cmd)

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        try:
            out, err = process.communicate(timeout=300)
        except subprocess.TimeoutExpired:
            process.kill()
            out, err = process.communicate()

    if process.returncode > 0:
        raise CommandExecutionError(
            f"dehydrated failed with exit code {process.returncode}\n{err.decode()}"
        )

    result = []
    for line in out.decode().split("\n"):
        if len(line) and line[0] != "#" and line[0] != " ":
            result.append(line)

    return {"text": "\n".join(result)}

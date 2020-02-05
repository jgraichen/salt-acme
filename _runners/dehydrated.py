# -*- coding: utf-8 -*-
"""
Sign certificate signing requests (CSR) using the dehydrated ACME command line
client.

dehydrated needs to be installed and configured manually on the salt master.
"""

import fnmatch
import logging
import os
import re
import shutil
import subprocess
import tempfile
import yaml

from cryptography import x509
from cryptography.hazmat.backends import default_backend as _default_backend

from filelock import FileLock

from salt.exceptions import (
    AuthorizationError,
    CommandExecutionError,
    SaltConfigurationError,
)

try:
    from salt.utils.data import traverse_dict_and_list as _get
    from salt.utils.files import fopen as _fopen
except ImportError:
    from salt.utils import fopen as _fopen
    from salt.utils import traverse_dict_and_list as _get


LOGGER = logging.getLogger(__name__)

_REGEXP_CSR = re.compile(
    r"\s*((-+BEGIN CERTIFICATE REQUEST-+)\s*([A-Za-z0-9+/=\s]*)\s*(-+END CERTIFICATE REQUEST-+))\s*"
)


def __virtual__():
    name = _get_executable_name()
    if not _find_executable(name):
        return False, f"dehydrated executable not found: {name}"
    return True


def _get_executable_name():
    return _get(__opts__, "dehydrated:executable", "dehydrated")


def _find_executable(name):
    path = shutil.which(name)
    if path:
        return path
    if os.path.exists(name):
        return os.path.abspath(name)
    return None


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
    return sorted(requested_names)


def _exec_dehydrated(csr):
    name = _get_executable_name()
    path = _find_executable(name)
    if not path:
        raise SaltConfigurationError(f"Dehydrated executable not found: {name}")

    args = _get(__opts__, "dehydrated:args", [])
    cmd = [path, *args, "--signcsr", csr]

    lock = FileLock(os.path.join(__opts__['cache_dir'], '.dehydrated.lock'))
    try:
        lock.acquire(timeout=300)

        LOGGER.debug("Execute: %s", cmd)
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        try:
            out, err = process.communicate(timeout=300)
        except subprocess.TimeoutExpired:
            process.kill()
            out, err = process.communicate()
    finally:
        lock.release()

    if process.returncode > 0:
        raise CommandExecutionError(
            f"dehydrated failed with exit code {process.returncode}\n{err.decode()}"
        )

    return out


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
    auth_file = _get(__opts__, "dehydrated:auth_file", None)
    if auth_file:
        with _fopen(auth_file, "r") as f:
            auth = yaml.safe_load(f)

        if not isinstance(auth, dict):
            raise SaltConfigurationError("Dehydrated auth_file must be a dict")

        for pattern, auth in auth.items():
            if fnmatch.fnmatch(__opts__["id"], pattern):
                for name in requested.copy():
                    for rule in auth:
                        if fnmatch.fnmatch(name, rule):
                            requested.remove(name)

        if requested:
            raise AuthorizationError(f"Unauthorized names: {', '.join(requested)}")

    with tempfile.NamedTemporaryFile("w+") as f:
        f.write(csr)
        f.flush()

        out = _exec_dehydrated(f.name)

    result = []
    for line in out.decode().split("\n"):
        if len(line) and line[0] != "#" and line[0] != " ":
            result.append(line)

    return {"text": "\n".join(result) + "\n"}

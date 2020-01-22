# -*- coding: utf-8 -*-
"""
Manage TLS keys and certificates with ACME

:depends: cryptography
"""

import binascii
import datetime
import os

from salt.exceptions import (
    SaltInvocationError,
    SaltReqTimeoutError,
    CommandExecutionError,
)

try:
    from salt.utils.files import fopen, fpopen
except ImportError:
    from salt.utils import fopen, fpopen

try:
    from cryptography import x509

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec

    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False


def __virtual__():
    if not _HAS_CRYPTOGRAPHY:
        return False, "cryptography not available"

    return True


def create_private_key(path, type="ec", size=4096, curve="prime256v1"):
    """
    Creates an elliptic curve private key in PEM format.

    path:
        The file path to write the private key to. File are written with ``600``
        as file mode.

    type:
        Key type to generate, either ``ec`` (default) or ``rsa``.

    curve:
        Curve to use for an EC key. Defaults to ``prime256v1``.

    size:
        Key length of an RSA key in bits. Defaults to ``4096``.


    CLI example:

    .. code-block:: bash

        salt '*' pki.create_private_key /etc/ssl/private/example.key curve='secp384r1'
    """
    # pylint: disable=redefined-builtin

    ret = {"path": path, "type": type}

    if type == "rsa":
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=size, backend=default_backend()
        )

        ret["size"] = size

    elif type == "ec":
        key = ec.generate_private_key(
            # pylint: disable=protected-access
            curve=ec._CURVE_TYPES[curve.lower()],
            backend=default_backend(),
        )

        ret["curve"] = curve

    else:
        raise SaltInvocationError("Unsupported key type: {}".format(type))

    out = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with fpopen(path, "wb", mode=0o600) as f:
        f.write(out)

    return ret


def create_csr(path=None, text=False, domains=None, key=None, algorithm="sha384"):
    """
    Create a certificate signing request (CSR).

    path:
        Path to write the certificate signing request to.

    text:
        If ``True`` include the CSR as PEM-encoded text in the response.

    domains:
        List or comma separated string of domain names to include in the CSR.

    key:
        Path to PEM-encoded private key to sign the CSR with.

    algorithm:
        The hashing algorithm to be used for this certificate signing request.
        Defaults to ``sha384``.
    """

    if isinstance(domains, str):
        domains = [s.strip() for s in domains.split(",")]

    if not domains:
        raise SaltInvocationError("At least one domains must be given")

    if algorithm not in _HASHES:
        raise SaltInvocationError(f"Unsupported algorithm: {algorithm}")

    subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, domains[0])])
    extensions = x509.Extensions(
        [
            x509.Extension(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                False,
                x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]),
            )
        ]
    )

    with fopen(key, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), None, default_backend())

    csr = x509.CertificateSigningRequestBuilder(subject, extensions).sign(
        key, _HASHES[algorithm](), default_backend()
    )

    ret = _read_csr(csr)
    out = csr.public_bytes(serialization.Encoding.PEM)

    if path:
        with fopen(path, "wb") as f:
            f.write(out)

        ret["path"] = path

    if text:
        ret["text"] = out.decode()

    return ret


def create_certificate(path, csr, chain=True, timeout=120, **kwargs):
    """
    Create a certificate by asking the master to sign a certificate signing
    request (CSR) or create a CSR on-the-fly.

    path:
        Path to write certificate to.

    csr:
        Path to certificate signing request file.

    chain:
        Set to ``False`` to not include any intermediate certificate in the
        output. By default the resulting output will include the certificate and
        all returned intermediates.

    timeout:
        Maximum time to wait on a response from the ``acme.sign`` runner.
    """

    with fopen(csr, "r") as f:
        csr = f.read()

    resp = __salt__["publish.runner"]("acme.sign", arg={"csr": csr}, timeout=timeout)

    if isinstance(resp, str) and "timed out" in resp:
        raise SaltReqTimeoutError(resp)

    if not isinstance(resp, dict):
        raise CommandExecutionError(
            f"Expected 'acme.sign' response to be a dict, but got {type(ret)}"
        )

    if chain and "chain" in resp:
        resp["text"] += "\n" + str(resp["chain"]).strip()

    try:
        ret = read_certificate(resp["text"])
    except ValueError as e:
        raise CommandExecutionError(
            f"Runner 'acme.sign' did not return a valid PEM-encoded certificate: {e}"
        )

    with open(path, 'w') as f:
        f.write(resp['text'])

    ret['path'] = path

    return ret


def read_csr(csr):
    """
    Read details about a certificate signing request.

    csr:
        Path to a certificate signing request file or a PEM-encoded string.
    """

    if os.path.isfile(csr):
        with fopen(csr, "rb") as f:
            csr = x509.load_pem_x509_csr(f.read(), default_backend())
    else:
        csr = x509.load_pem_x509_csr(csr.decode(), default_backend())

    return _read_csr(csr)


def read_certificate(path):
    """
    Read details about a certificate.

    path:
        Path to PEM-encoded certificate file.


    CLI Example:

    .. code-block:: bash

        salt '*' pki.read_certificate /etc/ssl/certs/example.crt
    """

    if os.path.exists(path):
        with fopen(path, "rb") as f:
            crt = x509.load_pem_x509_certificate(f.read(), default_backend())
    else:
        crt = x509.load_pem_x509_certificate(path.encode(), default_backend())

    ret = {
        "algorithm": crt.signature_hash_algorithm.name,
        "domains": _read_domains(crt),
        "not_valid_after": str(crt.not_valid_after),
        "not_valid_before": str(crt.not_valid_before),
        "public_key": _read_public_key(crt.public_key(), text=True),
        "serial": crt.serial_number,
    }

    return ret


def renewal_needed(path, days_remaining=28):
    """
    Check if a certificate expires within the specified days.

    path:
        Path to PEM encoded certificate file.

    days_remaining:
        The minimum number of days remaining when the certificate should be
        renewed. Defaults to 28 days.
    """

    with fopen(path, "rb") as f:
        crt = x509.load_pem_x509_certificate(f.read(), default_backend())

    remaining_days = (crt.not_valid_after - datetime.datetime.now()).days

    return remaining_days < days_remaining


_HASHES = {
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


def _read_public_key(pubkey, text=False):
    ret = {}

    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        ret["type"] = "ec"
        ret["curve"] = pubkey.curve.name

    if isinstance(pubkey, rsa.RSAPublicKey):
        ret["type"] = "rsa"
        ret["size"] = pubkey.key_size

    if text:
        ret["text"] = pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    return ret


def _read_csr(csr):
    return {
        "algorithm": csr.signature_hash_algorithm.name,
        "domains": _read_domains(csr),
        "public_key": _read_public_key(csr.public_key(), text=True),
    }


def _read_domains(obj):
    """
    Extract domain names from a CSR or certificate.
    """

    domains = []

    for name in obj.subject:
        if name.oid == x509.NameOID.COMMON_NAME:
            domains.append(name.value)

    try:
        extension = obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)

        for name in extension.value:
            if isinstance(name, x509.DNSName) and not name.value in domains:
                domains.append(name.value)
    except x509.extensions.ExtensionNotFound:
        pass

    return domains

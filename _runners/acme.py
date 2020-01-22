# -*- coding: utf-8 -*-

import os

try:
    from salt.utils.files import fopen
except ImportError:
    from salt.utils import fopen

try:
    import acme  # pylint: disable=import-self
    import josepy

    _HAS_ACME = True
except ImportError:
    _HAS_ACME = False

try:
    from cryptography import x509

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec

    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False


def __virtual__():
    if not _HAS_ACME:
        return False, "acme not available"

    if not _HAS_CRYPTOGRAPHY:
        return False, "cryptography not available"

    return True


def sign(csr):
    """

    """

    if "pki_dir" in __opts__:
        basedir = os.path.join(os.path.dirname(__opts__["pki_dir"]), "acme")
    else:
        basedir = os.path.join("/var/lib/salt/pki/acme")

    if not os.path.isdir(basedir):
        os.mkdir(basedir, 0o700)

    keyfile = os.path.join(basedir, "account.key")
    if not os.path.exists(keyfile):
        key = ec.generate_private_key(curve=ec.SECP256R1, backend=default_backend())

        with fopen(keyfile, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

    with fopen(keyfile, "rb") as f:
        key = josepy.JWK.load(f.read())

    net = acme.client.ClientNetwork(key, verify_ssl=False)

    client = acme.client.ClientV2("https://0.0.0.0:14000/dir", key, verify_ssl=False)

    client

    csr = x509.load_pem_x509_csr(csr.encode(), default_backend())

    return {"text": csr}

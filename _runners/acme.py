# -*- coding: utf-8 -*-

import datetime
import os
import pprint

try:
    from salt.utils.files import fopen as _fopen
except ImportError:
    from salt.utils import fopen as _fopen

try:
    from acme.client import ClientNetwork, ClientV2
    from acme import errors, messages, challenges
    import josepy as jose

    _HAS_ACME = True
except ImportError:
    _HAS_ACME = False

try:
    from cryptography import x509

    from cryptography.hazmat.backends import default_backend as _default_backend
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
    Requests to create a certificate for the given certificate signing request
    using ACME.

    csr:
        Certificate signing request as PEM-encoded string.
    """

    if "pki_dir" in __opts__:
        basedir = os.path.join(os.path.dirname(__opts__["pki_dir"]), "acme")
    else:
        basedir = os.path.join("/var/lib/salt/pki/acme")

    if not os.path.isdir(basedir):
        os.mkdir(basedir, 0o700)

    keyfile = os.path.join(basedir, "account.key")
    if not os.path.exists(keyfile):
        key = rsa.generate_private_key(65537, 4096, _default_backend())

        with _fopen(keyfile, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

    with _fopen(keyfile, "rb") as f:
        key = jose.JWK.load(f.read())

    net = ClientNetwork(key, verify_ssl=os.getenv("ACME_CAFILE") or True)
    directory = messages.Directory.from_json(
        net.get("https://localhost:14000/dir").json()
    )
    client = ClientV2(directory, net)

    try:
        client.new_account(
            messages.NewRegistration(
                key=key,
                contact=("mailto:certmaster@example.org",),
                terms_of_service_agreed=True,
            )
        )
    except errors.ConflictError:
        pass

    orderr = client.new_order(csr)

    for authzr in orderr.authorizations:
        domain = authzr.body.identifier.value

        for challb in authzr.body.challenges:
            if not isinstance(challb.chall, challenges.DNS01):
                continue

            pprint.pprint(f'{domain}: {challb.typ} {challb}')

            response, validation = challb.response_and_validation(key)

            pprint.pprint(validation)

            client.answer_challenge(challb, response)

    orderr = client.poll_and_finalize(
        orderr, deadline=datetime.datetime.now() + datetime.timedelta(seconds=0)
    )

    crt = orderr.fullchain_pem

    return {"text": crt}

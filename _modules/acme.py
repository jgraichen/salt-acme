# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring
"""
Sign CSRs using the ACMEv2 protocol

:depends: cryptography
:depends: acme
"""

import hashlib
import logging
import os

from collections import defaultdict

_MISSING_IMPORTS = []

try:
    from cryptography import x509

    from cryptography.hazmat.backends import default_backend as _default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
except ImportError:
    _MISSING_IMPORTS.append("cryptography")


try:
    import josepy
except ImportError:
    _MISSING_IMPORTS.append("josepy")

try:
    from acme import client, messages, challenges  # pylint: disable=import-self
except ImportError:
    _MISSING_IMPORTS.append("acme")


from salt.exceptions import SaltConfigurationError

try:
    from salt.utils.files import fopen as _fopen, fpopen as _fpopen
except ImportError:
    from salt.utils import fopen as _fopen, fpopen as _fpopen


_DEFAULT_ACME_SERVER = "https://acme-v02.api.letsencrypt.org/directory"


def __virtual__():
    if _MISSING_IMPORTS:
        return False, f"module(s) missing: {', '.join(_MISSING_IMPORTS)}"
    return True


class ACME:
    def __init__(self, server, email=None, verify_ssl=True, **_kwargs):
        self.base = os.path.join(
            __opts__["cachedir"], "acme", hashlib.sha256(server.encode()).hexdigest()
        )

        logging.info("ACME account directory: %s", self.base)
        logging.info("Using ACME server at %s", server)

        if not os.path.exists(self.base):
            os.makedirs(self.base, exist_ok=True)

        self.net = client.ClientNetwork(key=self._private_key(), verify_ssl=verify_ssl)
        self.directory = messages.Directory.from_json(self.net.get(server).json())
        self.client = client.ClientV2(self.directory, self.net)
        self.net.account = self._registration(email)

    def extract_pending_dns_challenges(self, orderr: messages.OrderResource):
        challs = []
        for authz in orderr.authorizations:
            if authz.body.status == messages.STATUS_PENDING:
                for challb in authz.body.challenges:
                    if isinstance(challb.chall, challenges.DNS01):
                        challs.append(
                            {
                                "name": authz.body.identifier.value,
                                "token": challb.chall.validation(self.net.key),
                            }
                        )
        return challs

    def _private_key(self):
        path = os.path.join(self.base, "private.key")
        if not os.path.exists(path):
            logging.info("ACME: creating new private account key...")
            with _fpopen(path, "wb", mode=0o600) as f:
                f.write(
                    rsa.generate_private_key(
                        public_exponent=65537, key_size=4096, backend=_default_backend()
                    ).private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )
        with _fopen(path, "rb") as f:
            return josepy.JWK.load(f.read())

    def _registration(self, email):
        path = os.path.join(self.base, "registration.json")
        if not os.path.exists(path):
            logging.info("ACME: creating new account...")
            registration = self.client.new_account(
                messages.NewRegistration.from_data(
                    email=email, terms_of_service_agreed=True
                )
            )

            with _fopen(path, "w") as f:
                f.write(registration.json_dumps_pretty())

            return registration

        with _fopen(path, "r") as f:
            return messages.RegistrationResource.from_json(f.read())


class Resolver:
    def __init__(self, name, module, **kwargs):
        self.name = name
        self.module = module
        self.kwargs = kwargs
        self.challenges = []

        for method in [f"{module}.install", f"{module}.remove"]:
            if method not in __salt__:
                raise SaltConfigurationError(
                    f"ACME: Invalid resolver {name}: execution module {method} not found"
                )

    def install(self, challenges):  # pylint: disable=redefined-outer-name
        self._invoke(f"{self.module}.install", challenges)
        self.challenges = challenges

    def remove(self):
        if self.challenges:
            self._invoke(f"{self.module}.remove")

    def _invoke(self, mod, challenges=None):  # pylint: disable=redefined-outer-name
        if not challenges:
            challenges = self.challenges
        return __salt__[mod](self.name, challenges, **self.kwargs)


def sign(csr):
    """
    """
    config = __salt__["config.get"](
        "acme:config",
        merge=True,
        default={"server": _DEFAULT_ACME_SERVER, "email": None, "verify_ssl": True},
    )

    resolvers = {
        name: Resolver(name=name, **args)
        for name, args in __salt__["config.get"]("acme:resolver", {}).items()
    }

    acme = ACME(**config)
    orderr = acme.client.new_order(csr.encode())
    grouped = defaultdict(list)

    for challenge in acme.extract_pending_dns_challenges(orderr):
        labels = challenge["name"].split(".")
        for i in range(0, len(labels)):
            name = ".".join(labels[i:])
            if name in resolvers:
                grouped[resolvers[name]].append(challenge)
                break
        else:
            if "default" in resolvers:
                grouped[resolvers["default"]].append(challenge)
            else:
                raise RuntimeError(f"ACME: No resolver for {challenge['name']} found")

    try:
        for resolver, challs in grouped.items():
            # Resolvers remember installed challenges to ease removing
            # challenges if an error happens, e.g. only resolvers having
            # installed challenges are actually invoke the remove method
            logging.debug("Installing challenges for resolver %s...", resolver.name)
            resolver.install(challs)

        logging.debug("Challenges installed")
    finally:
        for resolver in grouped.keys():
            try:
                resolver.remove()
            except Exception as err:  # pylint: disable=broad-except
                logging.warning(
                    "Error while removing challenges for resolver %s: %s",
                    resolver.name,
                    err,
                )

    return None

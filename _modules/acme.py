# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring
"""
Sign CSRs using the ACMEv2 protocol

:depends: cryptography
:depends: acme
"""

import hashlib
import json
import logging
import os
from collections import defaultdict
from datetime import datetime, timedelta

from salt.exceptions import SaltConfigurationError

_MISSING_IMPORTS = []

try:
    from cryptography.hazmat.backends import default_backend as _default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    _MISSING_IMPORTS.append("cryptography")

try:
    import josepy
except ImportError:
    _MISSING_IMPORTS.append("josepy")

try:
    from acme import challenges, client, messages  # pylint: disable=import-self
except ImportError:
    _MISSING_IMPORTS.append("acme")

try:
    from salt.utils.files import fopen as _fopen
    from salt.utils.files import fpopen as _fpopen
except ImportError:
    from salt.utils import fopen as _fopen
    from salt.utils import fpopen as _fpopen


_DEFAULT_CONFIG = {
    "server": "https://acme-v02.api.letsencrypt.org/directory",
    "verify_ssl": True,
    "account_dir": False,
}


def __virtual__():
    if _MISSING_IMPORTS:
        return False, f"module(s) missing: {', '.join(_MISSING_IMPORTS)}"
    return True


class ACME:
    def __init__(
        self, server, email=None, verify_ssl=True, account_dir=None, **_kwargs
    ):
        if account_dir:
            self.base = account_dir
        else:
            self.base = os.path.join(
                __opts__["cachedir"],
                "acme",
                hashlib.sha256(server.encode()).hexdigest(),
            )

        logging.info("ACME account directory: %s", self.base)
        logging.info("Using ACME server at %s", server)

        if not os.path.exists(self.base):
            os.makedirs(self.base, exist_ok=True)

        self.net = client.ClientNetwork(key=self._private_key(), verify_ssl=verify_ssl)
        self.directory = messages.Directory.from_json(self.net.get(server).json())
        self.client = client.ClientV2(self.directory, self.net)
        self.net.account = self._registration(email)

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
            return messages.RegistrationResource.from_json(json.load(f))


class Resolver:
    def __init__(self, name, module, **kwargs):
        self.name = name
        self.module = module
        self.kwargs = kwargs
        self.tokens = None

        for method in [f"{module}.install", f"{module}.remove"]:
            if method not in __salt__:
                raise SaltConfigurationError(
                    f"ACME: Invalid resolver {name}: execution module {method} not found"
                )

    def install(self, acme, authzs):  # pylint: disable=redefined-outer-name
        challs = []
        tokens = []

        for authz in authzs:
            challb, response, validation = self._build(acme, authz)
            challs.append((challb, response))
            tokens.append({"name": authz.body.identifier.value, "token": validation})

        self._invoke(f"{self.module}.install", tokens)
        self.tokens = tokens

        for challb, response in challs:
            acme.client.answer_challenge(challb, response)

    def remove(self):
        if self.tokens:
            self._invoke(f"{self.module}.remove", self.tokens)

    def _invoke(self, mod, tokens):  # pylint: disable=redefined-outer-name
        return __salt__[mod](self.name, tokens, **self.kwargs)

    @staticmethod
    def _build(acme, authz):
        for challb in authz.body.challenges:
            if isinstance(challb.chall, challenges.DNS01):
                response, validation = challb.response_and_validation(acme.net.key)
                return (challb, response, validation)
        raise KeyError(f"Missing DNS01 challenge for {authz.body.identifier.value}")


def sign(csr):
    """ """

    config = {**_DEFAULT_CONFIG, **__salt__["config.get"]("acme:config", default={})}
    logging.debug("ACME config: %s", config)

    resolvers = {
        name: Resolver(name=name, **args)
        for name, args in __salt__["config.get"]("acme:resolver", {}).items()
    }

    acme = ACME(**config)
    orderr = acme.client.new_order(csr.encode())
    grouped = defaultdict(list)

    pending = [
        authz
        for authz in orderr.authorizations
        if authz.body.status == messages.STATUS_PENDING
    ]

    logging.debug("%d pending authorizations", len(pending))

    for authz in pending:
        identifier = authz.body.identifier.value
        labels = identifier.split(".")
        for i in range(0, len(labels)):
            name = ".".join(labels[i:])
            if name in resolvers:
                grouped[resolvers[name]].append(authz)
                break
        else:
            if "default" in resolvers:
                grouped[resolvers["default"]].append(authz)
            else:
                raise RuntimeError(f"ACME: No resolver for {identifier} found")

    try:
        for resolver, authorizations in grouped.items():
            # Resolvers remember installed challenges to ease removing
            # challenges if an error happens, e.g. only resolvers having
            # installed challenges are actually invoke the remove method
            logging.debug("Setting up authorizations for resolver %s...", resolver.name)
            resolver.install(acme, authorizations)

        logging.debug("Finalizing order...")
        deadline = datetime.now() + timedelta(seconds=300)
        order = acme.client.poll_and_finalize(orderr, deadline)
        return {"text": order.fullchain_pem}
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

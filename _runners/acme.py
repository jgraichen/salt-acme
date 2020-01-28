# -*- coding: utf-8 -*-

import datetime
import fnmatch
import hashlib
import json
import logging
import os

from salt.exceptions import SaltConfigurationError, SaltInvocationError

try:
    from salt.utils.data import traverse_dict_and_list as _traverse
    from salt.utils.files import fopen as _fopen, fpopen as _fpopen
except ImportError:
    from salt.utils import traverse_dict_and_list as _traverse
    from salt.utils import fopen as _fopen, fpopen as _fpopen

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
    from cryptography.hazmat.primitives.asymmetric import rsa

    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False


LOGGER = logging.getLogger(__name__)


def __virtual__():
    if not _HAS_ACME:
        return False, "acme not available"
    if not _HAS_CRYPTOGRAPHY:
        return False, "cryptography not available"
    return True


_DEFAULT = {
    "url": "https://acme-v02.api.letsencrypt.org/directory",
    "cafile": True,
    "contact": None,
}


def sign(csr):
    """
    Requests to create a certificate for the given certificate signing request
    using ACME.

    csr:
        Certificate signing request as PEM-encoded string.
    """

    # Get ACME configuration from master config
    acme = __opts__.get("acme", {}).get("default", _DEFAULT)

    basedir = os.path.join(
        __opts__["cachedir"], "acme", hashlib.sha256(acme["url"].encode()).hexdigest()
    )
    keyfile = os.path.join(basedir, "account.key")
    regfile = os.path.join(basedir, "registration.json")

    if not os.path.isdir(basedir):
        os.makedirs(basedir, 0o755)

    if not os.path.exists(keyfile):
        key = rsa.generate_private_key(65537, 4096, _default_backend())

        with _fpopen(keyfile, "wb", mode=0o600) as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

    with _fopen(keyfile, "rb") as f:
        key = jose.JWK.load(f.read())

    net = ClientNetwork(key, verify_ssl=acme.get("cafile", True))
    directory = messages.Directory.from_json(net.get(acme["url"]).json())
    client = ClientV2(directory, net)

    if os.path.exists(regfile):
        with _fopen(regfile, "r") as f:
            net.account = messages.RegistrationResource.from_json(json.load(f))
    else:
        try:
            if isinstance(acme["contact"], str):
                contact = (acme["contact"],)
            elif isinstance(acme["contact"], list):
                contact = tuple(acme["contact"])
            else:
                contact = None

            registration = client.new_account(
                messages.NewRegistration(
                    key=key, contact=contact, terms_of_service_agreed=True
                )
            )
        except errors.ConflictError:
            registration = client.new_account(
                messages.NewRegistration(key=key, only_return_existing=True)
            )
        with _fopen(regfile, "w") as f:
            f.write(registration.json_dumps_pretty())

    orderr = client.new_order(csr)
    solver = _ChallengeSolver()

    for authzr in orderr.authorizations:
        if authzr.body.status != messages.STATUS_VALID:
            for challb in authzr.body.challenges:
                if isinstance(challb.chall, challenges.DNS01):
                    domain = authzr.body.identifier.value
                    record = challb.validation_domain_name(domain) + "."
                    token = challb.validation(key)
                    solver.add(challb, domain, record, token)

    solver.install()

    try:
        for challb in solver.challenges:
            client.answer_challenge(challb, challb.response(key))

        orderr = client.poll_and_finalize(
            orderr, deadline=datetime.datetime.now() + datetime.timedelta(seconds=60)
        )

        crt = orderr.fullchain_pem

        return {"text": crt}
    finally:
        solver.remove()


class _ChallengeSolver:
    def __init__(self):
        self.challenges = []
        self.providers = {}
        self.pattern = {}

        for name, conf in _traverse(__opts__, "acme:provider", {}).items():
            if not "pattern" in conf:
                continue

            if isinstance(conf["pattern"], str):
                self.pattern[name] = [p.strip() for p in conf["pattern"].split(",")]
            elif isinstance(conf["pattern"], list):
                self.pattern[name] = conf["pattern"]
            else:
                raise SaltConfigurationError(
                    "acme:provider:{name}:pattern must be string or list"
                )

    def add(self, challb, domain, record, txt):
        for name, pts in self.pattern.items():
            for pat in pts:
                if fnmatch.fnmatch(domain, pat):
                    self.challenges.append(challb)
                    self._get_provider(name).add(record, txt)
                    return

        raise SaltConfigurationError(f"No ACME provider matches {domain}")

    def install(self):
        for provider in self.providers.values():
            provider.install()

    def remove(self):
        for provider in self.providers.values():
            provider.remove()

    def _get_provider(self, name):
        if name not in self.providers:
            try:
                self.providers[name] = _Provider(
                    name, **__opts__["acme"]["provider"][name]
                )
            except KeyError:
                raise SaltConfigurationError(f"ACME provider does not exist: {name}")
        return self.providers[name]


class _Provider:
    def __init__(self, name, pattern, runner, **kwargs):
        self.name = name
        self.pattern = pattern
        self.runner = runner
        self.kwargs = kwargs
        self.challenges = {}

    def __len__(self):
        return len(self.challenges)

    def add(self, domain, txt):
        self.challenges[domain] = txt

    def install(self):
        __salt__[f"{self.runner}.install"](self.challenges, **self.kwargs)

    def remove(self):
        __salt__[f"{self.runner}.remove"](self.challenges, **self.kwargs)

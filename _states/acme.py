# -*- coding: utf-8 -*-

import os

import salt.utils

from salt.exceptions import SaltInvocationError


def private_key(name, new=False, type="ec", size=4096, curve="secp256r1", backup=True):
    """
    Manage a private key.

    name:
        Path to private key

    new:
        Always create a new key. Default to ``False``.
        Combining new with :mod:`prereq <salt.states.requsities.preqreq>` can
        allow key rotation whenever a new certificate is generated.

    type:
        Key type to generate, either ``ec`` (default) or ``rsa``.

    curve:
        Curve to use for an EC key. Defaults to ``secp256r1``.

    size:
        Key length of an RSA key in bits. Defaults to ``4096``.

    backup:
        When replacing an existing file, backup the old file on the minion.
        Default is ``True``.
    """
    # pylint: disable=redefined-builtin

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if type == "ec":
        target = {"type": "ec", "curve": curve}
    elif type == "rsa":
        target = {"type": "rsa", "size": size}
    else:
        raise SaltInvocationError(f"Invalid key type: {type}")

    if os.path.isfile(name):
        try:
            current = __salt__["acme.read_private_key"](name)
        except SaltInvocationError as e:
            current = f"{name} is not a valid private key: {e}"
    else:
        current = f"Key file {name} does not exist."

    if not new and current == target:
        ret["result"] = True
        ret["comment"] = "The private key is already in the correct state"
        return ret

    ret["changes"] = {"old": current, "new": target}

    if __opts__["test"] is True:
        ret["result"] = None

        if type == "rsa":
            ret["comment"] = f"A new RSA private key with {size} bits will be generated"
        if type == "ec":
            ret["comment"] = f"A new EC private key with {curve} will be generated"

        return ret

    if os.path.isfile(name) and backup:
        bkroot = os.path.join(__opts__["cachedir"], "file_backup")
        salt.utils.backup_minion(name, bkroot)

    __salt__["acme.create_private_key"](path=name, type=type, size=size, curve=curve)

    ret["result"] = True
    ret["comment"] = "Private key generated"

    return ret


def certificate(name, csr=None, backup=True, key=None, **kwargs):
    """
    Manage a ACME certificate

    name:
        File path to store the certificate.

    domains:
        List of domain names to be present in the certificate. If no domain name
        or list is given ``name`` is expected to be a domain name.

    key:
        Path to private key.

    csr:
        Path to a certificate signing request file to be instead instead of
        generating one.

    days_remaining:
        The minimum number of days remaining when the certificate should be
        renewed. Defaults to 28 days.

    backup:
        When replacing an existing certificate, backup the old file on the
        minion. Default is ``True``.
    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    existing = os.path.exists(name)

    if existing:
        try:
            current = __salt__["acme.read_certificate"](name)
        except SaltInvocationError as err:
            current = "{} is not a valid certificate: {}".format(name, err)
    else:
        current = "{} does not exist".format(name)

    if not csr:
        if key is None or not os.path.exists(key):
            new = "Private key is missing!"
        else:
            new = __salt__["acme.create_csr"](text=True, key=key, **kwargs)
            csr = new.pop("text")
    else:
        new = __salt__["acme.read_csr"](csr, key=key, **kwargs)

    if existing and not __salt__["acme.renewal_needed"](name, **kwargs):
        ret["result"] = True
        ret["comment"] = "The certificate is already in correct state"
        return ret

    if __opts__["test"] is True:
        ret["changes"] = {"current": current, "new": new}
        ret["comment"] = "The certificate will be updated"
        ret["result"] = None
        return ret

    if existing and backup:
        backup_root = os.path.join(__opts__["cachedir"], "file_backup")
        salt.utils.backup_minion(name, backup_root)

    result = __salt__["acme.create_certificate"](name, csr=csr, **kwargs)

    ret["changes"] = {"current": current, "new": result}
    ret["comment"] = "The certificate has been updated"
    ret["result"] = True

    return ret

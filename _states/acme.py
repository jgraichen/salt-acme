# -*- coding: utf-8 -*-

import os

import salt.utils

from salt.exceptions import SaltInvocationError


def certificate(path, csr=None, backup=True, **kwargs):
    """
    Manage a ACME certificate

    path:
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

    ret = {"path": path, "changes": {}, "result": False, "comment": ""}

    if os.path.isfile(path):
        try:
            current = __salt__["acme.read_certificate"](path)
        except SaltInvocationError as err:
            current = "{} is not a valid certificate: {}".format(path, err)
    else:
        current = "{} does not exist".format(path)

    if not csr:
        new = __salt__["acme.create_csr"](text=True, **kwargs)
    else:
        new = __salt__["acme.read_csr"](csr)

    if not __salt__["acme.renewal_needed"](path, new=new, **kwargs):
        ret["result"] = True
        ret["comment"] = "The certificate is already in correct state"
        return ret

    if __opts__["test"] is True:
        ret["changes"] = {"current": current, "new": new}
        ret["comment"] = "The certificate will be updated"
        ret["result"] = None
        return ret

    if os.path.isfile(path) and backup:
        backup_root = os.path.join(__opts__["cachedir"], "file_backup")
        salt.utils.backup_minion(path, backup_root)

    result = __salt__["acme.create_certificate"](path, csr=csr, **kwargs)

    ret["changes"] = {"current": current, "new": result}
    ret["comment"] = "The certificate has been updated"
    ret["path"] = path
    ret["result"] = True

    return ret

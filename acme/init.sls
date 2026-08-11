#!py
# vim: ft=python:sw=4

import os

try:
    from salt.utils.secret import mask_pillar
except ImportError:
    # Salt < 3008 does not mask pillar values.
    mask_pillar = None


def run():
    # Salt >= 3008 masks pillar values by default; the template renderers
    # disable masking while rendering an SLS file, but the `py` renderer does
    # not, so `pillar.get` would return `**********` for every value here.
    token = mask_pillar.set(False) if mask_pillar else None
    try:
        return _run()
    finally:
        if token is not None:
            mask_pillar.reset(token)


def _run():
    basedir = __salt__["pillar.get"]("acme:basedir", "/etc/acme")
    default = __salt__["pillar.get"]("acme:default", {})
    certs = __salt__["pillar.get"]("acme:certificate", {})

    ret = {}
    includes = []

    for name in certs.keys():
        certdir = os.path.join(basedir, name)

        cert = __salt__["pillar.get"](f"acme:certificate:{name}", default, merge=True)

        if "domains" not in cert:
            cert["domains"] = [name]

        create_directories = cert.pop("create_directories", True)

        keyargs = {"require": []}
        fileargs = {"mode": 640}

        if "key" in cert:
            keyargs.update(cert.pop("key"))

        for k in ("mode", "user", "group"):
            if k in keyargs:
                fileargs[k] = keyargs.pop(k)

        cert_name = os.path.join(certdir, cert.pop("name", "fullchain.pem"))
        pkey_name = os.path.join(certdir, str(keyargs.pop("name", "privkey.pem")))

        cert_file = cert_name.format(name=name)
        pkey_file = pkey_name.format(name=name)

        pkey_dir = os.path.dirname(pkey_file)
        cert_dir = os.path.dirname(cert_file)

        if create_directories:
            ret[pkey_dir] = {"file": ["directory", {"makedirs": True}]}
            ret[cert_dir] = {"file": ["directory", {"makedirs": True}]}

        keyargs["require"].append({"file": pkey_dir})

        ret[pkey_file] = {
            "pki": ["private_key", *[{k: v} for k, v in keyargs.items()]],
            "file": [
                "managed",
                {"replace": False},
                {"require": [{"pki": pkey_file}]},
                *[{k: v} for k, v in fileargs.items()],
            ],
        }

        for include in cert.pop("include", []):
            if include not in includes:
                includes.append(include)

        cert["key"] = pkey_file

        if "require" not in cert:
            cert["require"] = []

        cert["require"].append({"pki": pkey_file})
        cert["require"].append({"file": pkey_file})
        cert["require"].append({"file": cert_dir})

        ret[cert_file] = {
            "pki": ["certificate", *[{k: v} for k, v in cert.items()]],
        }

    if includes:
        ret["include"] = includes

    return ret

#!pydsl
# vim: ft=python:sw=4

import os


basedir = __salt__["pillar.get"]("acme:basedir", "/etc/acme")
default = __salt__["pillar.get"]("acme:default", {})
certs = __salt__["pillar.get"]("acme:certificate", {})

for name in certs.keys():
    certdir = os.path.join(basedir, name)

    cert = __salt__["pillar.get"](f"acme:certificate:{name}", default, merge=True)

    if "domains" not in cert:
        cert["domains"] = [name]

    keyargs = {"require": []}
    fileargs = {"mode": 640}

    if "key" in cert:
        keyargs.update(cert.pop("key"))

    for k in ("mode", "user", "group"):
        if k in keyargs:
            fileargs[k] = keyargs.pop(k)

    cert_name = os.path.join(certdir, cert.pop("name", "fullchain.pem"))
    pkey_name = os.path.join(certdir, keyargs.pop("name", "privkey.pem"))

    cert_file = cert_name.format(name=name)
    pkey_file = pkey_name.format(name=name)

    pkey_dir = os.path.dirname(pkey_file)
    state(pkey_dir).file.directory(makedirs=True)

    cert_dir = os.path.dirname(cert_file)
    state(cert_dir).file.directory(makedirs=True)

    keyargs["require"].append({"file": pkey_dir})

    state(pkey_file).pki.private_key(**keyargs)
    state(pkey_file).file.managed(replace=False, require=[{"pki": pkey_file}], **fileargs)

    if "include" in cert:
        for i in cert.pop("include", []):
            include(i)

    cert["key"] = pkey_file

    if "require" not in cert:
        cert["require"] = []

    cert["require"].append({"pki": pkey_file})
    cert["require"].append({"file": pkey_file})
    cert["require"].append({"file": cert_dir})

    state(cert_file).pki.certificate(**cert)

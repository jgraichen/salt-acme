#!pydsl
# -*- mode: python -*-

import os


basedir = __salt__["pillar.get"]("acme:basedir", "/etc/acme")
default = __salt__["pillar.get"]("acme:default", {})
certs = __salt__["pillar.get"]("acme:certificate", {})

for name in certs.keys():
    certdir = os.path.join(basedir, name)
    keyfile = os.path.join(certdir, "key.pem")
    crtfile = os.path.join(certdir, "fullchain.pem")

    state(certdir).file.directory(makedirs=True)

    cert = __salt__["pillar.get"](f"acme:certs:{name}", default, merge=True)

    keyargs = {"require": []}
    fileargs = {"mode": 640}

    if "key" in cert:
        keyargs.update(cert.pop("key"))

    for k in ('mode', 'user', 'group'):
        if k in keyargs:
            fileargs[k] = keyargs.pop()

    keyargs["require"].append({"file": certdir})

    state(keyfile).acme.private_key(**keyargs)
    state(keyfile).file.managed(replace=False, require=[{"acme": keyfile}], **fileargs)

    if "include" in cert:
        for i in cert.pop("include", []):
            include(i)

    cert["key"] = keyfile

    if "require" not in cert:
        cert["require"] = []

    cert["require"].append({"acme": keyfile})
    cert["require"].append({"file": keyfile})
    cert["require"].append({"file": certdir})

    state(crtfile).acme.certificate(**cert)

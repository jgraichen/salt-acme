# salt-acme

Manage TLS certificates with ACME using the salt master for certificate
management and authentication.

Minions create private keys and certificate signing requests that are send to
the `acme.sign` runner on the master. The master authenticates the minion,
checks allowed domains and handles the ACME account, verification and requesting
the certificate. It uses DNS-01 challenge for verification.

## Pillar Example

```yaml
states:
  - acme

acme:
  certificate:
    example.org:
      domains: [example.org, www.example.org]
      include:
        - nginx.service
      watch_in:
        - nginx
```

# State Example

```yaml
/etc/acme/certs/example.org.key:
  acme.private_key:
    - curve: secp256r1
    - user: root
    - group: root
    - mode: 600

/etc/acme/private/example.org.pem:
  acme.certificate:
    - key: /etc/acme/certs/example.org.key
    - domains: [example.org, www.example.org]
    - chain: True
```

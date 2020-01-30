# salt-acme

Manage TLS certificates with ACME using the salt master for certificate
management and authentication.

All cryptographic operations are handled by `salt-pki`. Signing requests are
send to a runner on the salt master, e.g. `dehydrated.sign`.

The runner can authenticate the minion and check if it is permitted to request
certificates for a given domain.

## Signing runners

Currently only `dehydrated.sign` is supported. This runner dispatches the actual
ACME signing to the `dehydrated` script. This script must be configured and set
up explicitly before.

Allow signing actions can be configured in the masters configuration:

```yaml
dehydrated:
  authorization:
    '*.minion.id':
      - 'example.org'
      - '*.example.com
```

Minions and domain names are matched using shell globbing rules (`fnmatch`).

## Pillar Example

Example: Creates certificate and private key in default location (e.g.
`/etc/acme/example.org/{key.pem,certificate.pem}`).

Includes other states (`nginx.service`) and reloads services on certificate
changes (`nginx`).

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

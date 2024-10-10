# salt-acme

Manage TLS certificates with ACME using the salt master for certificate
management and authentication.

All cryptographic operations are handled by `salt-pki`. Signing requests are
send to a runner on the salt master, e.g. `acme.sign`.

The runner can authenticate the minion and check if it is permitted to request
certificates for a given domain.

## Installation

The recommended way uses salts GitFS:

```yaml
# /etc/salt/master
gitfs_remotes:
  - 'https://github.com/jgraichen/salt-acme.git':
      - base: v1.3.0
  - 'https://github.com/jgraichen/salt-pki.git':
      - base: v1.0.1
```

The execution modules usually are used on the master too. Please synchronize the modules and runners on the master with `salt-run`:

```console
$ salt-run saltutil.sync_all
modules:
    - modules.acme
    - modules.acme_dns
runners:
    - modules.acme
```

## Quick Start

An `acme` state is shipped with this file. It will automatically create certificates from the pillar using the `acme.sign` runner on the master.

The master must be configured for ACME and to accept to runner calls from the minions:

```yaml
acme:
  config:
    server: https://acme-v02.api.letsencrypt.org/directory  # default

    # The directory where accounts (e.g. private key, registration) are stored.
    # Defaults to an `acme` subdirectory in salts `cachedir`.
    account_dir: /var/cache/salt/master/acme

    # Email address passed to the CA on registration
    email: certmaster@example.org

  resolver:
    # Setup resolvers to install DNS01 challenges. See more in
    # runner documentation below.
    example.org:
      module: acme_dns
      nameserver: 127.0.0.153
      tsig: hmac-sha256:acme:opCLn9NM...xnoRJIo=
```

### Pillar Example

Example: Creates certificate and private key in default location (e.g.
`/etc/acme/example.org/{privkey.pem,fullchain.pem}`).

Includes other states (`nginx.service`) and reloads services on certificate
changes (`nginx`).

```yaml
acme:
  certificate:
    example.org:
      domains: [example.org, www.example.org]
      include:
        - nginx.service
      watch_in:
        - nginx
```

## Execution modules

The `acme.sign` execution modules accepts a single CSR as arguments and returns an answer with the certificate chain embedded. It can be run on a minion, as well as on the master, e.g. using the runner below. Please note that execution modules must be properly synced on the master using `salt-run saltutil.sync_modules`.

(TODO)

## Runners

The `acme.sign` runner uses the `acme.sign` execution module on the master to sign a CSR.

All involved execution modules, including the modules installing challenges, must be able to run in a salt master context, instead of a minion. The salt master must be configured for the acme module (see above) and to [accept runner invocations from the minion](https://docs.saltstack.com/en/latest/ref/peer.html):

```yaml
# /etc/salt/master
peer_run:
  .*:
    - acme.sign
```

The runner can validation signing requests using an authorization file. This file defines which minion is allowed to request a domain:

```yaml
# /etc/salt/master
acme:
  runner:
    auth_file: /etc/salt/acme.yml
```

```yaml
# /etc/salt/acme.yml
minion_id:
  - example.org
  - '*.example.org'

'*.minion_id':
  - '*'
```

Minion IDs and domain names are matched with a glob-style pattern using [`fnmatch`](https://docs.python.org/3/library/fnmatch.html).

## Resolver

The `acme.sign` execution modules uses other modules to install and remove challenges. These resolver modules must implement a common interface:

An `install` and `remove` function, both accepting a `name`, a list of `tokens` and additional arguments, passed from the resolver configuration. The `tokens` arguments is a list of `{"name": "example.org", "token": "abc....def"}` dictionaries.

The following resolvers are included in this repository.

### `acme_dns`

The `acme_dns` challenge resolver sends DNS01 challenge tokens to a DNS server using DNS update (RFC 2136).

Example configuration:

```yaml
acme:
  resolver:
    example.org:
      module: acme_dns

      # Which name server to use
      nameserver: 127.0.0.153  # required; can be domain name
      port: 53

      # Zone
      #
      # Zone to update. If not given, the resolver name
      # (here: example.org) will be used as the zone name.
      zone: example.org

      # Alias mode
      #
      # If set, this name will be used for the TXT records, for
      # example with a CNAME:
      #   _acme-challenge.example.org CNAME mychallenges.org
      alias: mychallenges.org

      # Timeout in seconds when sending the DNS update
      timeout: 10

      # TTL for added TXT records
      ttl: 120

      # Use a TSIG for authorization. Must be formatted as
      # "<algorithm>:<name>:<secret>"
      tsig: hmac-sha256:acme:opCLn9NM...xnoRJIo=

      # Verify DNS record propagation
      #
      # This will check all nameservers listed in the zone to
      # have at least the serial from the update in their SOA
      # records.
      verify: True

      # Seconds to wait for DNS propagation
      verify_timeout: 120
```

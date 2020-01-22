# salt-acme

Manage TLS certificates with ACME using the salt master for certificate
management and authentication.

Minions create private keys and certificate signing requests that are send to
the `acme.sign` runner on the master. The master authenticates the minion,
checks allowed domains and handles the ACME account, verification and requesting
the certificate. It uses DNS-01 challenge for verification.

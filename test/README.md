# Testing

The tests are using pebble, a small ACME server for testing, and knot, a DNS server as external components.

These tools can be run locally using the `docker-compose.yml` from the test directory:

```console
docker compose --file test/docker-compose.yml up
```

To reset DNS zones between tests the `knotc` control command line tool must be installed on the local system.

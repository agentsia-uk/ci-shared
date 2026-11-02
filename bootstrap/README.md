# Recovery readiness client

`recovery_client.probe_recovery` checks the separate recovery service before a
controller attempts the approved temporary exception. The caller supplies a
TLS client context with its client certificate, a trusted CA, hostname checking
and TLS 1.2 or newer, together with the independently configured SHA-256 pin
for the recovery server certificate. Only a tailnet IPv4 address and an
unprivileged port are accepted. The request contains the selected source and
base commits, and a bounded response must confirm the watchdog is idle and
the protection is readable.

This is a readiness probe only. It does not create a recovery journal, verify a
pull request, authenticate a scanner release, modify a ruleset or grant a
bypass. The release controller, protected credential provisioning, certificate
rotation and live host qualification remain separate prerequisites. The
`_connect` parameter is a trusted test transport, not caller-supplied data.

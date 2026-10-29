# gistly public certificate relay

Published endpoint: https://yangdongmingisok.github.io/briefpebble-google-public-keys/google-certs.json

A small public-data relay for Google's already-public OAuth signing certificates.
It never receives ID tokens, account profiles, cookies, client secrets or private keys.
The only upstream is https://www.googleapis.com/oauth2/v1/certs with normal TLS verification.

The publisher runs every ten minutes through GitHub Actions. Each snapshot expires
within one hour and no later than Google's advertised remaining cache lifetime.
The application rejects stale or malformed snapshots and still verifies Google token
signatures, issuer, audience, expiry, verified email and its session-bound nonce.
Password sign-in remains available when this relay cannot refresh.

Scheduled runs may be delayed or disabled by GitHub. The application must fail closed
when a snapshot expires. This repository and its maintainers are a trusted part of
the application's authentication infrastructure; restrict write access accordingly.
No application code, user records or credentials are included here.

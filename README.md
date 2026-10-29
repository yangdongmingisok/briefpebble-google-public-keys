# gistly public certificate relay

A relay for Google's already-public OAuth signing certificates. It never receives
user ID tokens, profiles, passwords, cookies, client secrets or Google private keys.
The only certificate upstream is https://www.googleapis.com/oauth2/v1/certs with
normal TLS certificate verification.

A dedicated, unprivileged service on the owner's VPS fetches and publishes fresh
snapshots every five minutes using a systemd timer enabled at boot. Its SSH deploy
key is limited to this repository. Snapshot pushes trigger GitHub Pages publication;
this route does not depend on GitHub's scheduled workflow events. The existing
manual/scheduled workflow is retained as a secondary recovery path.

Each snapshot expires within one hour and no later than Google's remaining cache
lifetime or the certificates' validity. The application rejects stale/malformed
snapshots and verifies Google token signatures, issuer, audience, expiry, verified
email and the session-bound nonce. Failed refreshes never enable unsigned login.

Published endpoint:
https://yangdongmingisok.github.io/briefpebble-google-public-keys/google-certs.json

Repository write access and the dedicated publisher key are authentication
infrastructure: restrict maintainers and protect the server and GitHub account.
No application user records or credentials are published here.

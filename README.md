# Zoraxy Cert Warden Sync

![CI](https://github.com/EduardoNespoliRamos/zoraxy_cert_warden/actions/workflows/ci.yml/badge.svg?branch=main)
![Compatibility](https://github.com/EduardoNespoliRamos/zoraxy_cert_warden/actions/workflows/compatibility.yml/badge.svg?branch=main)

> **Built with vibe coding.** This project was developed iteratively with
> AI-assisted pair programming. The codebase, tests, CI, and documentation were
> shaped through conversation, rapid experimentation, and continuous refinement.
> See [AGENTS.md](AGENTS.md) for guidance when working on this repository.

Plugin for [Zoraxy](https://github.com/tobychui/zoraxy) that synchronizes TLS
certificates managed by [Cert Warden](https://certwarden.com/) into Zoraxy's
internal certificate store. A certificate can come from local Cert Warden
Client files or directly from a remote Cert Warden API.

The plugin does **not** handle ACME, DNS challenges, or Cloudflare. Those remain
managed by Cert Warden. The plugin consumes an existing certificate chain and
private key and makes them available to Zoraxy.

## Architecture

```
Cert Warden Client files                 Cert Warden HTTPS API
certchain0.pem + key0.pem                combined privatecertchains endpoint
             \                            /
              -> Zoraxy Cert Warden Sync plugin
              -> /opt/zoraxy/config/conf/certs/example-certificate.pem + .key
              -> Zoraxy TLS
```

## Features

- Reads local Cert Warden Client files or downloads directly from Cert Warden.
- Supports manual remote queries and automatic remote polling.
- Validates the presented certificate chain, validity period, server usage, and
  private key correspondence.
- Transactionally replaces certificate/key pairs using staging files, backups,
  post-install validation, and rollback.
- Compares a SHA-256 bundle digest to skip unnecessary writes.
- `fsnotify` watcher with polling fallback.
- Debounce to handle certificate/key updates as a single event.
- Web UI inside Zoraxy for configuration and status.
- Supports multiple certificates.
- Optional fallback certificate configuration.
- Structured logs that never expose private keys.

## Known limitations

The plugin writes Zoraxy's certificate-store files directly; it does not call a
Zoraxy certificate reload API. For a certificate selected through
`fallback.json`, Zoraxy only reads that selection at startup. Therefore:

- For certificates used as fallback, the plugin writes
  `fallback.json`, but Zoraxy only reads it on startup. **You must restart
  Zoraxy to activate a fallback certificate.** The pending warning persists
  until the operator acknowledges it after the restart; acknowledgement itself
  does not restart or reload Zoraxy.
- Encrypted private keys are not supported. The selected source must provide an
  unencrypted RSA, EC, or PKCS#8 private key.

## Requirements

- Zoraxy v3.3.0 through v3.3.3. These are the supported release versions;
  prereleases and newer releases are not part of the support policy until added
  to the compatibility baseline.
- Linux amd64 or arm64.
- Docker or Podman for the containerized build/test workflow.

## Build

No local Go installation is required. Builds run inside a container.

```bash
make build-amd64
make build-arm64
make build-all
```

Binaries are written to `dist/`:

```
dist/zoraxy-cert-sync-linux-amd64
dist/zoraxy-cert-sync-linux-arm64
```

To use a different container runtime:

```bash
DOCKER=docker make build-all
```

## Installation

1. Create the plugin directory inside Zoraxy's plugin folder:

   ```bash
   mkdir -p /opt/zoraxy/plugin/com.eduardoramos.zoraxy.certwarden
   ```

2. Copy the binary and an icon:

   ```bash
   cp dist/zoraxy-cert-sync-linux-amd64 \
      /opt/zoraxy/plugin/com.eduardoramos.zoraxy.certwarden/com.eduardoramos.zoraxy.certwarden
   cp icon.png /opt/zoraxy/plugin/com.eduardoramos.zoraxy.certwarden/
   ```

3. Restart Zoraxy.

4. Enable the plugin in Zoraxy's plugin manager and open its UI.

## Docker Compose

Example `docker-compose.yml`:

```yaml
services:
  zoraxy:
    image: zoraxydocker/zoraxy:v3.3.3
    container_name: zoraxy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "8000:8000"
    environment:
      - CERT_SYNC_ALLOWED_SOURCE_ROOTS=/cert_warden_plugin
      - CERT_SYNC_ALLOWED_DESTINATION_ROOTS=/opt/zoraxy/config/conf/certs
    volumes:
      - /path/to/zoraxy/config:/opt/zoraxy/config
      - /path/to/zoraxy/plugin:/opt/zoraxy/plugin
      - /path/to/cert-warden/output:/cert_warden_plugin:ro
```

This is a local-source example. A remote-only deployment does not need the
Cert Warden Client output volume or `CERT_SYNC_ALLOWED_SOURCE_ROOTS`. Remote TLS
uses the container's system CA trust. For a private CA, mount a CA bundle and
set `SSL_CERT_FILE` to its in-container path, for example:

```yaml
environment:
  - SSL_CERT_FILE=/etc/ssl/custom/cert-warden-ca.pem
volumes:
  - /path/to/cert-warden-ca.pem:/etc/ssl/custom/cert-warden-ca.pem:ro
```

Place the plugin binary under the mounted plugin volume:

```
/path/to/zoraxy/plugin/
└── com.eduardoramos.zoraxy.certwarden/
    ├── com.eduardoramos.zoraxy.certwarden
    ├── config.json
    └── icon.png
```

## Configuration

The plugin is configured entirely through its web UI. Each entry selects either
**Local files** or **Cert Warden API**. Local defaults match Cert Warden Client
output:

- Source certificate: `/cert_warden_plugin/certchain0.pem`
- Source private key: `/cert_warden_plugin/key0.pem`
- Target directory: `/opt/zoraxy/config/conf/certs`
- Target name: `example-certificate`

Configuration is persisted in `config.json` inside the plugin directory.

### Direct Cert Warden API

For a **Cert Warden API** source, configure these UI fields:

- **Server URL** (`source.cert_warden.server_url`): an HTTPS origin only, with
  no path, query, fragment, or user information.
- **Certificate Name** (`source.cert_warden.certificate_name`): the name used by
  Cert Warden for the requested certificate.
- **Certificate API Key** and **Private Key API Key**
  (`cert_warden_credentials.certificate_api_key` and
  `private_key_api_key`): the two per-certificate download keys issued by Cert
  Warden. Both are required.

The plugin calls Cert Warden's official combined endpoint:

```
GET https://<server>/certwarden/api/v1/download/privatecertchains/<certificate_name>
X-API-Key: <certificate-api-key>.<private-key-api-key>
```

The response must contain a valid PEM certificate chain and exactly one
supported unencrypted private key. Downloads have a 30-second timeout and a
1 MiB response limit. Redirects are not followed, so credentials cannot be
forwarded to a redirect target. HTTPS certificate-chain and hostname validation
must succeed against the process's CA trust; insecure TLS and HTTP are not
supported.

Credentials are stored separately in `secrets.json` beside the plugin binary.
The plugin writes this file with mode `0600`. API responses expose only
`certificate_api_key_configured` and `private_key_api_key_configured` booleans;
the UI uses empty password fields, never reads keys back, and leaves existing
keys unchanged when both fields are blank. Supplying new keys replaces both as
a pair. Treat the plugin directory and its persistent volume as sensitive.

### Path allowlists

The plugin only reads and writes paths below operator-approved roots. Configure
the roots through environment variables; they cannot be changed from the web
UI:

- `CERT_SYNC_ALLOWED_SOURCE_ROOTS` defaults to `/cert_warden_plugin`.
- `CERT_SYNC_ALLOWED_DESTINATION_ROOTS` defaults to
  `/opt/zoraxy/config/conf/certs`.

Use the operating system path-list separator to allow multiple roots. On Linux,
separate them with `:`:

```bash
CERT_SYNC_ALLOWED_SOURCE_ROOTS=/cert_warden_plugin:/mnt/other-certs
```

Paths must be absolute and normalized, and may contain letters, numbers, `/`,
`.`, `_`, and `-`. Symlinks are resolved before access and cannot escape the
configured roots.

### Synchronization modes

- **Manual:** disable Auto Sync. Validate and Sync Now remain available in the
  UI, but no watcher runs for that entry.
- **Polling:** enable Auto Sync and disable Filesystem Watch. The polling
  interval detects source changes.
- **Filesystem events with polling fallback:** enable both Auto Sync and
  Filesystem Watch. `fsnotify` handles prompt updates and polling still detects
  missed events. Changes are debounced so separately written certificate and
  key files can settle before validation.

Remote sources do not support Filesystem Watch. Every enabled entry performs one
fetch, validation, and synchronization when configuration is applied, including
plugin startup, even when Auto Sync is disabled. **Test Connection** fetches and
validates the remote source without installing it; **Sync Now** fetches,
validates, and synchronizes it. With Auto Sync enabled, a non-overlapping poller
repeats Sync Now. The remote poll interval defaults to `300` seconds and must be
at least `60` seconds.

Validation reads and checks the source pair but does not install it. Sync Now
validates the source, validates the existing destination when present, compares
their bundle digests, and replaces the destination only when required.

### Identity and replacement

The UI's certificate fingerprint is the SHA-256 fingerprint of the leaf
certificate's DER bytes. Synchronization equality instead uses a SHA-256 bundle
digest over every certificate in presented order plus the private key's public
key. A changed intermediate chain therefore triggers synchronization even when
the leaf fingerprint is unchanged.

Each destination file is staged and durably written before publication. The
old certificate and key are retained as backups while the new files are renamed
into place, then the installed pair is validated and the directory is synced.
Failures trigger rollback and report rollback state. The operation is
transactional with rollback, but it is **not an atomic two-file filesystem
replacement**: observers can briefly see one new file and one old file between
the two renames.

## UI

The plugin UI is available at:

```
https://<zoraxy>/plugin.ui/com.eduardoramos.zoraxy.certwarden/
```

Zoraxy proxies that inbound path to the plugin's declared `/ui/*` path. The UI
API is consequently registered under `/ui/api/*` in addition to direct plugin
routes. `PermittedAPIEndpoints` has a different purpose: it allowlists outbound
requests from a plugin to Zoraxy APIs. This plugin makes no such calls and
declares no permitted outbound endpoints. Mutating UI requests carry Zoraxy's
CSRF token.

It shows:

- Overall status (Healthy/Error/Unknown) and per-entry Disabled status.
- One card per configured certificate with domain, issuer, expiry, last sync,
  fingerprints, and key match status.
- Buttons to edit, validate, sync now, and add/remove certificates.
- Aggregate remote counts: `remote_sources`, `remote_connected`,
  `remote_checking`, and `remote_errors`.

Source validation, destination validation, synchronization, and watcher errors
are tracked independently. An enabled entry is Healthy only when its source and
destination have validated matching bundle digests. Disabled entries remain
visible, count as Disabled, and do not degrade aggregate health.

Remote entries add a separate **Cert Warden API** status group. In the
`cert_warden_query` object, `status` is `Unknown`, `Healthy`, or `Error`, and
`in_progress` drives the UI's Checking state. The group also reports
`last_attempt`, `last_success`, `next_attempt`, `latency_ms`, `http_status`,
`failure_kind`, and a sanitized `message`. Query health describes retrieval
only; the **Source certificate** and **Zoraxy destination** groups independently
show validation and installation health.

`failure_kind` uses these categories:

- `network`, `tls`, or `timeout` for transport failures.
- `authentication` for HTTP 401/403, `not_found` for HTTP 404, and `server` for
  HTTP 5xx.
- `response_too_large` for responses over 1 MiB.
- `invalid_response` for redirects, other unexpected status codes, or invalid
  or incomplete PEM material.

## Logs

The plugin writes structured logs to stdout. It logs startup, shutdown,
watcher degradation, sync failures, and API failures. For example:

```
INFO starting plugin addr=127.0.0.1:19090
WARN "fsnotify unavailable; using polling only" error="..."
ERROR "cert-sync failed" certificate=example-certificate error="certificate and private key do not match: ..."
```

Private keys are never logged.

## Development

Run unit tests:

```bash
make test
```

Run filesystem integration tests for sync and watcher behavior:

```bash
make integration-test
```

Run the focused Cert Warden client, secret-store, and HTTPS mock tests:

```bash
make certwarden-api-test
```

Run E2E tests with Playwright:

```bash
make e2e-test
```

Run the remote-source Playwright suite:

```bash
make e2e-remote-test
```

Remote tests use `tests/certwardenmock`: an HTTPS data endpoint with a generated
test CA and a separate HTTP control endpoint that switches among valid renewal,
authentication, not-found, server-error, malformed, mismatched, slow, and
oversized-response scenarios. The test Zoraxy container mounts that CA and sets
`SSL_CERT_FILE`; production deployments must provide their own trusted CA.

Run the E2E suite against a different Zoraxy version:

```bash
ZORAXY_VERSION=v3.3.2 make e2e-test
```

Generate local test certificates:

```bash
./scripts/generate-test-cert.sh ./tmp/test-certs
```

## Release process

This project follows Git Flow:

- `main` contains production-ready code.
- `develop` is the integration branch for the next release.
- `feature/*` and `bugfix/*` branches start from and merge back into `develop`.
- `release/X.Y.Z` branches start from `develop` and merge into `main`.
- `hotfix/X.Y.Z` branches start from `main` and merge into `main`.

To develop a change:

```bash
git checkout develop
git pull origin develop
git checkout -b feature/my-change
```

Open the Pull Request against `develop`. Use `bugfix/*` for non-urgent fixes
that belong in the next release.

To prepare a release:

```bash
git checkout develop
git pull origin develop
git checkout -b release/0.0.1
```

Open the release Pull Request against `main`. After it is merged, GitHub Actions
runs the full test suite, creates `vX.Y.Z`, builds both binaries, generates
`SHA256SUMS`, and publishes the GitHub Release.

For an urgent production fix, create `hotfix/X.Y.Z` from `main` and open a Pull
Request back to `main`. Release and hotfix merges must then be synchronized back
into `develop` with a `main` to `develop` Pull Request.

Manual tags matching `v*.*.*` remain supported, but the automated release and
hotfix flows are preferred.

## CI / CD

This repository uses GitHub Actions. See `.github/workflows/`.

- **CI** (`ci.yml`) — runs formatting, unit, race, vet, static analysis,
  repeated watcher/sync, filesystem and Cert Warden API integration, and
  cross-architecture build gates on every PR and push to `main` and `develop`.
- **Compatibility** (`compatibility.yml`) — runs Playwright through Zoraxy for
  every stable version below, with nonblocking prerelease/latest canaries.
- **Release** (`release.yml`) — reruns all quality and stable E2E gates, builds
  versioned `linux/amd64` and `linux/arm64` binaries, and publishes them with
  `SHA256SUMS`.

### Testing matrix

The supported release matrix is:

- `v3.3.0`
- `v3.3.1`
- `v3.3.2`
- `v3.3.3`

CI may probe prerelease or latest images for early compatibility feedback, but
passing those jobs does not make those versions supported releases.

## Troubleshooting

### Source certificate not found

Ensure the Cert Warden Client volume is mounted read-only and the configured
paths are correct.

### Cert Warden API query failed

Use `failure_kind`, `http_status`, and the query timestamps in the Cert Warden
API status group. Confirm that both per-certificate keys are current, the server
URL is an HTTPS origin, DNS/network access works from the Zoraxy container, and
the server certificate is valid for that hostname. For a private CA, mount its
CA bundle and set `SSL_CERT_FILE`; do not disable TLS verification.

### Certificate and private key do not match

Cert Warden Client writes both files. If you see this error, the files may be
from different certificate generations. Wait for the next renewal or trigger a
manual sync after both files are updated.

### Fallback certificate not active

The plugin writes `fallback.json` but Zoraxy only reads it on startup. Restart
Zoraxy after changing fallback configuration, then acknowledge the persistent
warning in the UI. Acknowledging before restart only clears the warning; it does
not apply the fallback configuration.

### Target directory not writable

The plugin must run as a user with write permission to Zoraxy's certificate
store. In Docker, this is usually the same user running the Zoraxy container.

## Security

- Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
- Private keys are never logged or returned by the API.
- Cert Warden API keys are stored in `secrets.json` with mode `0600` and are
  write-only through the UI/API.
- Key files are written with mode `0600`.
- Certificate files are written with mode `0644`.
- Paths are validated to prevent directory traversal.
- Certificate names are sanitized.
- The plugin listens only on `127.0.0.1` and is reached through Zoraxy's
  authenticated management interface.
- Remote server configuration intentionally accepts any syntactically valid
  HTTPS host, including loopback, private, link-local, and internal DNS names.
  This supports private Cert Warden deployments but creates an SSRF/internal-
  service access risk if an administrator configures a hostile endpoint. Limit
  Zoraxy administration to trusted operators and restrict container egress when
  appropriate. Configuration changes require Zoraxy-authenticated management
  access and its CSRF token, but those controls do not replace network policy.

## License

AGPLv3. See [LICENSE](LICENSE).

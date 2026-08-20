# Zoraxy Cert Warden Sync

![CI](https://github.com/eduardoramos/zoraxy-cert-warden/actions/workflows/ci.yml/badge.svg?branch=main)
![Compatibility](https://github.com/eduardoramos/zoraxy-cert-warden/actions/workflows/compatibility.yml/badge.svg?branch=main)

> **Built with vibe coding.** This project was developed iteratively with
> AI-assisted pair programming. The codebase, tests, CI, and documentation were
> shaped through conversation, rapid experimentation, and continuous refinement.
> See [AGENTS.md](AGENTS.md) for guidance when working on this repository.

Plugin for [Zoraxy](https://github.com/tobychui/zoraxy) that synchronizes TLS
certificates managed by [Cert Warden](https://certwarden.com/) (via the Cert
Warden Client) into Zoraxy's internal certificate store.

The plugin does **not** handle ACME, DNS challenges, or Cloudflare. Those stay
managed by Cert Warden and the Cert Warden Client. The plugin only consumes the
local PEM files produced by the client and makes them available to Zoraxy.

## Architecture

```
Cloudflare
    ↓
Let's Encrypt
    ↓
Cert Warden
    ↓
Cert Warden Client
    ↓
/cert_warden_plugin/certchain0.pem
/cert_warden_plugin/key0.pem
    ↓
Zoraxy Cert Warden Sync plugin
    ↓
/opt/zoraxy/config/conf/certs/homealone-wildcard.pem
/opt/zoraxy/config/conf/certs/homealone-wildcard.key
    ↓
Zoraxy TLS
```

## Features

- Detects certificate files written by Cert Warden Client.
- Validates certificate + private key correspondence and validity.
- Atomic writes (`.tmp` + `rename`) to avoid half-written certificates.
- SHA-256 fingerprint comparison to skip unnecessary writes.
- `fsnotify` watcher with polling fallback.
- Debounce to handle certificate/key updates as a single event.
- Web UI inside Zoraxy for configuration and status.
- Supports multiple certificates.
- Optional fallback certificate configuration.
- Structured logs that never expose private keys.

## Known limitations

Zoraxy does not expose an official plugin API to reload certificates or to set
the fallback certificate at runtime. Therefore:

- For host-specific certificates, Zoraxy's legacy filename matching picks up
  the new files immediately.
- For wildcard certificates used as fallback, the plugin writes
  `fallback.json`, but Zoraxy only reads it on startup. **You must restart
  Zoraxy to activate a fallback certificate.** The UI clearly warns about this.

## Requirements

- Zoraxy v3.2.0 or newer.
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
    volumes:
      - /mnt/raid/docker-compose/zoraxy/config:/opt/zoraxy/config
      - /mnt/raid/docker-compose/zoraxy/plugin:/opt/zoraxy/plugin
      - /mnt/raid/docker-compose/zoraxy/certs:/cert_warden_plugin:ro
```

Place the plugin binary under the mounted plugin volume:

```
/mnt/raid/docker-compose/zoraxy/plugin/
└── com.eduardoramos.zoraxy.certwarden/
    ├── com.eduardoramos.zoraxy.certwarden
    ├── config.json
    └── icon.png
```

## Configuration

The plugin is configured entirely through its web UI. Default values match the
Cert Warden Client output:

- Source certificate: `/cert_warden_plugin/certchain0.pem`
- Source private key: `/cert_warden_plugin/key0.pem`
- Target directory: `/opt/zoraxy/config/conf/certs`
- Target name: `homealone-wildcard`

Configuration is persisted in `config.json` inside the plugin directory.

## UI

The plugin UI is available at:

```
https://<zoraxy>/plugin.ui/com.eduardoramos.zoraxy.certwarden/ui/
```

It shows:

- Overall status (Healthy/Error/Unknown).
- One card per configured certificate with domain, issuer, expiry, last sync,
  fingerprints, and key match status.
- Buttons to edit, validate, sync now, and add/remove certificates.

## Logs

The plugin writes structured logs to stdout. Examples:

```
INFO cert-sync certificate=homealone-wildcard source_changed=true
INFO cert-sync certificate=homealone-wildcard validation=success
INFO cert-sync certificate=homealone-wildcard sync=success fingerprint=abc...
INFO cert-sync certificate=homealone-wildcard no_changes=true
ERROR cert-sync certificate=homealone-wildcard validation="certificate and private key do not match"
```

Private keys are never logged.

## Development

Run unit tests:

```bash
make test
```

Run integration tests with Zoraxy v3.3.3:

```bash
make integration-test
```

Run E2E tests with Playwright:

```bash
make e2e-test
```

Test against a different Zoraxy version:

```bash
ZORAXY_VERSION=v3.3.2 make integration-test
```

Generate local test certificates:

```bash
./scripts/generate-test-cert.sh ./tmp/test-certs
```

## CI / CD

This repository uses GitHub Actions. See `.github/workflows/`.

- **CI** (`ci.yml`) — runs unit tests, E2E tests against Zoraxy `v3.3.3`, and
  builds `linux/amd64` and `linux/arm64` binaries on every PR and push to
  `main`.
- **Compatibility** (`compatibility.yml`) — runs integration tests against the
  full Zoraxy version matrix on every PR and push to `main`.
- **Release** (`release.yml`) — triggered by tags `v*.*.*`, creates a GitHub
  Release with the compiled binaries and `SHA256SUMS`.

### Testing matrix

Integration tests run against:

- `v3.3.0`
- `v3.3.1`
- `v3.3.2`
- `v3.3.3`
- `v3.3.4-rc1`
- `v3.3.4-rc2`
- `v3.3.4-rc3`
- `latest`

## Troubleshooting

### Source certificate not found

Ensure the Cert Warden Client volume is mounted read-only and the configured
paths are correct.

### Certificate and private key do not match

Cert Warden Client writes both files. If you see this error, the files may be
from different certificate generations. Wait for the next renewal or trigger a
manual sync after both files are updated.

### Fallback certificate not active

The plugin writes `fallback.json` but Zoraxy only reads it on startup. Restart
Zoraxy after enabling fallback.

### Target directory not writable

The plugin must run as a user with write permission to Zoraxy's certificate
store. In Docker, this is usually the same user running the Zoraxy container.

## Security

- Private keys are never logged or returned by the API.
- Key files are written with mode `0600`.
- Certificate files are written with mode `0644`.
- Paths are validated to prevent directory traversal.
- Certificate names are sanitized.
- The plugin listens only on `127.0.0.1` and is reached through Zoraxy's
  authenticated management interface.

## License

AGPLv3. See [LICENSE](LICENSE).

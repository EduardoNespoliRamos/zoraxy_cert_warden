# AGENTS.md

Agent-focused guidance for the **Zoraxy Cert Warden Sync** plugin.

## Project overview

This is a Zoraxy plugin (ID `com.eduardoramos.zoraxy.certwarden`) that
synchronizes TLS certificates from local Cert Warden Client files or directly
from the Cert Warden HTTPS API into Zoraxy's certificate store. It uses the Go
1.23 language/module baseline and a patched Go 1.25 build toolchain, and is
distributed under AGPLv3.

Key facts:

- The plugin **does not** handle ACME or DNS challenges. It consumes existing
  PEM material from local files or Cert Warden's combined download endpoint.
- It runs as a separate process launched by Zoraxy and exposes a web UI through
  Zoraxy's plugin proxy.
- It listens on `127.0.0.1` and is reached via Zoraxy's authenticated management
  interface.

## Repository layout

```
.
cmd/cert-sync/          # Plugin entry point and embedded web UI
  main.go               # Plugin lifecycle, watchers, sync runner
  web/                  # Embedded static files (HTML/CSS/JS)
internal/
  certwarden/           # HTTPS API client and sanitized fetch errors
  certutil/             # Certificate parsing, validation, fingerprinting
  config/               # Config model, validation, persistence
  poller/               # Non-overlapping remote-source polling
  secretstore/          # Write-only per-entry API credential persistence
  status/               # In-memory status aggregation
  sync/                 # Transactional pair replacement, fallback.json
  watcher/              # fsnotify + polling watcher with debounce
  web/                  # HTTP handlers for the plugin UI API
mod/zoraxy_plugin/      # Zoraxy plugin SDK (vendored minimal module)
tests/
  certwardenmock/       # Controllable HTTPS Cert Warden test double
  integration/          # Go integration tests against real files
  e2e/                  # Playwright tests against Zoraxy in Docker
  docker/               # Docker Compose environment for tests
scripts/                # Helper scripts
dist/                   # Build output (ignored in git)
```

## Build and test

No local Go installation is required. All builds and tests use containers.

```bash
# Build
make build-amd64
make build-arm64
make build-all

# Tests
make test              # unit tests
make integration-test  # integration tests against ZORAXY_VERSION (default v3.3.3)
make certwarden-api-test # focused API client, secrets, and mock tests
make e2e-test          # Playwright E2E tests against v3.3.3
make e2e-remote-test   # remote Cert Warden API Playwright suite

# Use Docker instead of Podman
DOCKER=docker make build-all
DOCKER=docker make e2e-test

# Clean containers and dist
make clean
```

## Architecture

```
Local PEM files -> internal/watcher --\
                                      -> validate -> internal/sync -> Zoraxy store
Cert Warden API -> certwarden/poller -/
```

- **Watcher**: monitors source certificate/key files. Uses `fsnotify` with a
  polling fallback. Debounces rapid changes so certificate + key updates are
  treated as one event.
- **Remote client/poller**: calls the HTTPS-only official combined endpoint with
  the two per-certificate API keys, never follows redirects, validates TLS, and
  classifies sanitized query failures. Enabled remote entries fetch and sync
  once when config is applied; Auto Sync adds polling (300-second default,
  60-second minimum). Manual Test Connection and Sync Now remain available.
- **Secret store**: keeps remote credentials in `secrets.json` with mode `0600`.
  API/UI reads expose only configured booleans; keys are write-only.
- **Syncer**: validates the presented certificate chain and unencrypted private
  key, then compares a SHA-256 bundle digest covering the ordered chain and
  public key. It stages both files and replaces them transactionally with
  backups and rollback; the two-file replacement is not filesystem-atomic as a
  unit. Keys use `0600` and certificates use `0644`.
- **Status**: independently tracks remote query, source validation, destination
  validation, synchronization, and watcher errors. Remote query status includes
  timing, latency, HTTP status, and failure category. Entries are Healthy,
  Error, Unknown, or Disabled; disabled entries remain visible but do not
  degrade aggregate health.
- **Web server**: serves the embedded UI and exposes a JSON API.

## Zoraxy plugin constraints

When changing the web UI or API, keep these constraints in mind:

1. **UI proxy only forwards the declared `ui_path`.** Zoraxy exposes requests
   under `/plugin.ui/<id>/*` and forwards them to the plugin's `/ui/*` path. API endpoints
   must therefore also be registered under the same UI path prefix so the
   browser can reach them. See `cmd/cert-sync/main.go` and
   `internal/web/server.go`.

2. **CSRF is required for mutating requests.** Zoraxy's web UI middleware
   requires the `X-CSRF-Token` header for `POST`/`PUT`/`DELETE`/`PATCH`. Zoraxy
   passes the token to the plugin in the `X-Zoraxy-Csrf` header. The embedded
   `index.html` contains `<meta name="zoraxy.csrf.Token" content="{{.csrfToken}}">`,
   which the `PluginUiRouter` populates. The frontend reads this meta tag and
   attaches the header. Do not remove the placeholder.

3. **Fallback certificates require Zoraxy restart.** Zoraxy only reads
   `fallback.json` at startup. A changed file creates a persistent pending state;
   after restarting Zoraxy, the operator acknowledges the warning in the UI.
   Acknowledgement does not restart or reload Zoraxy.

4. **Inbound and outbound routes are distinct.** `UIPath` controls inbound UI
   and plugin API proxying. `PermittedAPIEndpoints` only allowlists outbound
   calls from the plugin to Zoraxy APIs; this plugin currently declares none.

5. **Filesystem access is allowlisted.** Source and destination roots come from
   `CERT_SYNC_ALLOWED_SOURCE_ROOTS` and
   `CERT_SYNC_ALLOWED_DESTINATION_ROOTS`. Do not make these roots editable from
   the web UI or bypass `config.PathPolicy` at filesystem boundaries.

6. **Remote origins are HTTPS-only but host-unrestricted by design.** Valid TLS
   and hostname verification are mandatory and redirects are disabled. Any
   HTTPS host, including internal or link-local addresses, is accepted to
   support private Cert Warden servers. Preserve this explicit product decision
   unless requirements change, and account for SSRF/internal-service risk.

7. **Remote credentials are write-only.** Both per-certificate keys are required
   and stored by immutable entry name in `secrets.json`. Never return or log
   them. Preserve the UI's masked empty password fields and configured booleans.

## Coding conventions

- Go 1.23. Keep code simple and explicit.
- Use `slog` for structured logging. Never log private keys.
- Prefer table-driven tests.
- Do not commit `dist/` or temporary files.
- Keep the embedded web UI dependency-free (vanilla JS/CSS).

## Release process

This repository uses Git Flow:

- `main` contains production-ready code.
- `develop` is the integration branch.
- `feature/*` and `bugfix/*` start from and merge into `develop`.
- `release/X.Y.Z` starts from `develop` and merges into `main`.
- `hotfix/X.Y.Z` starts from `main` and merges into `main`.
- Release and hotfix changes must be synchronized from `main` back into
  `develop` through a Pull Request.

Only `release/X.Y.Z` and `hotfix/X.Y.Z` branches can be merged into `main`.
Feature and bugfix Pull Requests target `develop`.

1. Create a release branch from `develop` or a hotfix branch from `main`:

   ```bash
   git checkout develop
   git checkout -b release/0.0.1
   ```

2. Apply the release changes and open a Pull Request to `main`.

3. After the PR is merged, GitHub Actions (`tag-on-merge.yml`) automatically:

   - Identifies the merged release/hotfix branch.
   - Extracts the version from the branch name.
   - Runs the full test suite (unit tests, E2E tests, and the integration
     matrix).
   - Creates and pushes a tag `vX.Y.Z`.

4. The workflow dispatches `release.yml`, which builds `linux/amd64` and
   `linux/arm64` binaries, generates `SHA256SUMS`, and creates a GitHub Release
   with auto-generated release notes.

5. Open a Pull Request from `main` to `develop` to synchronize the release or
   hotfix changes.

6. Attach release notes or a manual changelog if needed.

Manual tags matching `v*.*.*` still work for backwards compatibility, but prefer
the automated flow.

### Branch protection

The `main` and `develop` branches are protected by GitHub branch protection
rules applied via `scripts/configure-branch-protection.sh`. They require:

- Pull Request reviews (including code owner review).
- Status checks to pass.
- Up-to-date branches before merging.
- Resolved conversations.
- Only the repository owner can approve protected-branch changes.

Administrators can bypass these settings if needed.

## Common tasks for agents

### Add a new API endpoint

1. Add the handler in `internal/web/server.go`.
2. Register it in both `RegisterRoutes` and `RegisterRoutesUnderPrefix` so it
   works directly and through Zoraxy's UI proxy.
3. Add it to `PermittedAPIEndpoints` in `cmd/cert-sync/main.go` if the plugin
   backend needs to call Zoraxy APIs.
4. Update `cmd/cert-sync/web/js/app.js` if the UI needs to consume it. Remember
   to include CSRF headers for mutating methods.
5. Add tests.

### Change Cert Warden API support

1. Keep `internal/certwarden` transport errors sanitized and credentials out of
   config, status, API responses, and logs.
2. Update `internal/config`, `internal/secretstore`, manager startup/polling, and
   the three UI status groups only as required.
3. Test with `make certwarden-api-test` and `make e2e-remote-test`; extend the
   controllable HTTPS mock rather than depending on a live Cert Warden server.
4. Document custom trust through the system CA store or `SSL_CERT_FILE`; never
   add an insecure TLS option.

### Update the Zoraxy version matrix

Edit the matrix in `.github/workflows/compatibility.yml`.

### Update the testing baseline

Change `ZORAXY_VERSION` in the `Makefile` and in `ci.yml` if the default E2E
baseline changes.

## Notes

- This project was developed with **vibe coding**: iterative AI-assisted
  development. When making changes, prefer minimal, focused edits and run the
  full test suite before considering a task done.
- See `README.md` for user-facing documentation.

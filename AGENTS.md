# AGENTS.md

Agent-focused guidance for the **Zoraxy Cert Warden Sync** plugin.

## Project overview

This is a Zoraxy plugin (ID `com.eduardoramos.zoraxy.certwarden`) that
synchronizes TLS certificates produced by the Cert Warden Client into Zoraxy's
certificate store. It is written in Go 1.23 and distributed under AGPLv3.

Key facts:

- The plugin **does not** handle ACME or DNS challenges. It only consumes PEM
  files already written by the Cert Warden Client.
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
  certutil/             # Certificate parsing, validation, fingerprinting
  config/               # Config model, validation, persistence
  status/               # In-memory status aggregation
  sync/                 # Atomic certificate writes, fallback.json
  watcher/              # fsnotify + polling watcher with debounce
  web/                  # HTTP handlers for the plugin UI API
mod/zoraxy_plugin/      # Zoraxy plugin SDK (vendored minimal module)
tests/
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
make e2e-test          # Playwright E2E tests against v3.3.3

# Use Docker instead of Podman
DOCKER=docker make build-all
DOCKER=docker make e2e-test

# Clean containers and dist
make clean
```

## Architecture

```
Cert Warden Client writes PEM files
              |
              v
    internal/watcher (fsnotify + poll)
              |
              v
    internal/sync (validate, atomic write)
              |
              v
    Zoraxy certificate store (/opt/zoraxy/config/conf/certs)
```

- **Watcher**: monitors source certificate/key files. Uses `fsnotify` with a
  polling fallback. Debounces rapid changes so certificate + key updates are
  treated as one event.
- **Syncer**: validates the certificate chain, checks private key correspondence,
  compares SHA-256 fingerprints, and writes atomically (`.tmp` + rename). Sets
  file modes `0600` for keys and `0644` for certificates.
- **Status**: keeps an in-memory state per certificate (Healthy/Error/Unknown)
  with last sync times, fingerprints, and messages.
- **Web server**: serves the embedded UI and exposes a JSON API.

## Zoraxy plugin constraints

When changing the web UI or API, keep these constraints in mind:

1. **UI proxy only forwards the declared `ui_path`.** Zoraxy proxies requests
   under `/plugin.ui/<id>/ui/*` to the plugin's declared `ui_path`. API endpoints
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
   `fallback.json` at startup. The plugin writes the file, but the UI must warn
   the user that a restart is needed. There is no plugin API to reload fallback
   certificates at runtime.

4. **Introspect spec must match the binary.** The `-introspect` flag prints the
   plugin metadata. Ensure `PermittedAPIEndpoints` and `UIPath` are correct.

## Coding conventions

- Go 1.23. Keep code simple and explicit.
- Use `slog` for structured logging. Never log private keys.
- Prefer table-driven tests.
- Do not commit `dist/` or temporary files.
- Keep the embedded web UI dependency-free (vanilla JS/CSS).

## Release process

This repository uses a Git Flow-inspired release process. Only branches matching
`release/X.Y.Z` or `hotfix/X.Y.Z` can be merged into `main`, and only through a
Pull Request.

1. Create a release or hotfix branch from `main`:

   ```bash
   git checkout -b release/0.0.1
   ```

2. Apply the release changes and open a Pull Request to `main`.

3. After the PR is merged, GitHub Actions (`tag-on-merge.yml`) automatically:

   - Identifies the merged release/hotfix branch.
   - Extracts the version from the branch name.
   - Runs the full test suite (unit tests, E2E tests, and the integration
     matrix).
   - Creates and pushes a tag `vX.Y.Z`.

4. The `release.yml` workflow detects the new tag, builds `linux/amd64` and
   `linux/arm64` binaries, generates `SHA256SUMS`, and creates a GitHub Release
   with auto-generated release notes.

5. Attach release notes or a manual changelog if needed.

Manual tags matching `v*.*.*` still work for backwards compatibility, but prefer
the automated flow.

### Branch protection

The `main` branch is protected by a GitHub branch protection rule applied via
`scripts/configure-branch-protection.sh`. It requires:

- Pull Request reviews (including code owner review).
- Status checks to pass.
- Up-to-date branches before merging.
- Resolved conversations.
- Only the repository owner can push/merge to `main`.

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

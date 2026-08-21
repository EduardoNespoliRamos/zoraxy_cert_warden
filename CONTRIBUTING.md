# Contributing

Thanks for contributing to Zoraxy Cert Warden Sync.

## Branching strategy

This repository uses Git Flow:

- Create `feature/*` and `bugfix/*` branches from `develop`.
- Open feature and bugfix Pull Requests against `develop`.
- Maintainers create `release/X.Y.Z` branches from `develop`.
- Maintainers create `hotfix/X.Y.Z` branches from `main`.
- Do not open feature or bugfix Pull Requests against `main`.

Example:

```bash
git fetch origin
git checkout -b feature/my-change origin/develop
```

## Before opening a Pull Request

Keep changes focused and include tests when behavior changes. Run the relevant
checks with Docker or Podman:

```bash
make test
make integration-test
make e2e-test
make build-all
```

The Pull Request must pass CI and be reviewed by the code owner before merge.

## Security reports

Do not include private keys, credentials, or sensitive certificate material in
issues, logs, test fixtures, or Pull Requests.

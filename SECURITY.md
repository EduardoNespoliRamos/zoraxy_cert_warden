# Security Policy

## Supported versions

Security fixes are provided for the latest published release. Before the first
release, reports affecting the `develop` branch are accepted.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | No |

## Reporting a vulnerability

Do not report vulnerabilities through public GitHub issues, discussions, logs,
or Pull Requests. Use GitHub's private vulnerability reporting form:

https://github.com/EduardoNespoliRamos/zoraxy_cert_warden/security/advisories/new

Include the affected version or commit, the impact, reproduction steps, and any
suggested mitigation. Never attach real private keys, credentials, or sensitive
certificate material.

You should receive an acknowledgement within seven days. Status updates will be
provided while the report is investigated. Please allow time for a fix and
coordinated disclosure before publishing details.

## Scope

Reports about path traversal, arbitrary file access, private-key exposure,
authentication or CSRF bypass, certificate validation, and privilege escalation
are in scope. Vulnerabilities in Zoraxy or Cert Warden themselves should be
reported to their respective maintainers.

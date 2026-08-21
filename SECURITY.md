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
Cert Warden API-key exposure, authentication or CSRF bypass, certificate/TLS
validation, redirect handling, and privilege escalation are in scope.
Vulnerabilities in Zoraxy or Cert Warden themselves should be reported to their
respective maintainers.

## Remote-source security model

Direct Cert Warden sources require an HTTPS origin, valid TLS chain and hostname,
and both per-certificate download API keys. Redirects are disabled. Credentials
are stored separately in `secrets.json` with mode `0600`, are never returned by
the API, and appear in the UI only as configured/not-configured state. Protect
and back up the plugin directory as secret material. Private CAs should be added
through the system trust store or `SSL_CERT_FILE`; TLS verification must not be
disabled.

By explicit product decision, the plugin accepts any valid HTTPS host, including
loopback, private, link-local, and internal DNS destinations. This is necessary
for private Cert Warden deployments and also means a trusted administrator can
direct the plugin to internal services. Treat remote-source configuration as an
SSRF-capable administrative operation: restrict Zoraxy management access,
retain Zoraxy authentication and CSRF protection for mutations, and apply
container/firewall egress policy where appropriate. Authentication and CSRF
reduce who can configure an endpoint; they do not make arbitrary endpoints
safe.

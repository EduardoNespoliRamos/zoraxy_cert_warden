# Vendored Zoraxy Plugin Support Code

This directory contains a locally maintained subset of Zoraxy's plugin support
package. It is compiled into this plugin rather than consumed as a separate Go
module.

## Upstream provenance

- Upstream repository: <https://github.com/tobychui/zoraxy>
- Upstream files:
  - `src/mod/plugins/zoraxy_plugin/zoraxy_plugin.go`
  - `src/mod/plugins/zoraxy_plugin/embed_webserver.go`
- Best identifiable source: Zoraxy `v3.3.3`, commit
  `9ed5fdc4399c0a4c74cf0824bb99a55edb3fa5ce`

The repository history does not record the exact commit from which these files
were first copied. The version above is the best identifiable source because it
matches the project's original Zoraxy baseline and contains the corresponding
upstream files and API shape. Do not infer a more exact import commit without
documentary evidence. To identify one, compare the files against tagged Zoraxy
trees and inspect this repository's history around the initial vendoring commit.

## Local changes

Relative to the `v3.3.3` files, this copy:

- reduces the package to the types and helpers used by this plugin;
- adds concise Go documentation and formatting changes;
- escapes the `X-Zoraxy-Csrf` value before inserting it into embedded HTML;
- factors CSRF escaping into `escapeCSRFToken` and tests that behavior;
- preserves two-space JSON indentation for introspection output;
- simplifies configure argument parsing without changing accepted forms.

## Updating

1. Fetch the desired upstream tag or commit from `tobychui/zoraxy`.
2. Compare both upstream paths above with their local counterparts. For example:

   ```bash
   git diff --no-index /path/to/zoraxy/src/mod/plugins/zoraxy_plugin/zoraxy_plugin.go mod/zoraxy_plugin/zoraxy_plugin.go
   git diff --no-index /path/to/zoraxy/src/mod/plugins/zoraxy_plugin/embed_webserver.go mod/zoraxy_plugin/embed_webserver.go
   ```

3. Review plugin protocol changes first, especially introspection fields,
   configure payloads, UI path rewriting, termination, and CSRF handling.
4. Port only required changes while retaining the local security hardening and
   tests. Do not replace the directory wholesale.
5. Record the new upstream tag and full commit hash here, update the local-change
   list, run `make test`, and run compatibility tests for all supported Zoraxy
   releases.

## License

The upstream files originate from Zoraxy, which is distributed under the GNU
Affero General Public License version 3. This modified vendored copy remains
under AGPLv3 as part of this AGPLv3 project. See the repository's `LICENSE` file
and the upstream repository for provenance and complete license terms.

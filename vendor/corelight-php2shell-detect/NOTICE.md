# Vendored third-party component — Corelight php2shell-detect

- **Upstream:** https://github.com/corelight/php2shell-detect
- **Pinned commit:** `4d5131c7f7812d7b84a85cb61c64837c125920fe`
- **Copyright:** © 2026, Corelight, Inc.
- **License:** BSD-3-Clause (see [`LICENSE`](./LICENSE))
- **Vendored on:** 2026-10-27

## What is included

| Path | Purpose |
|------|---------|
| `suricata/php2shell.rules` | 3 Suricata/Snort rules: request-side `PHP_SESSION_UPLOAD_PROGRESS` in POST body (sid 3000650), response-side vulnerable PHP version banner (sid 3000651), phpinfo version page (sid 3000652). |
| `scripts/*.zeek` | Corelight's Zeek detection package. Entry point is `scripts/__load__.zeek`; the modules cover headers, HTTP body analysis, session tracking, version checks and cluster support. |
| `zkg.meta` | Zeek package-manager metadata, so the package can be loaded with `zkg`. |

## Modifications

**None.** All files are redistributed verbatim from the pinned commit above.

The upstream `testing/` directory (pcaps and btest baselines) is intentionally
**omitted** to keep this vendor copy small — fetch it from upstream if you want the
test suite.

## Attribution note

Per BSD-3-Clause, the copyright notice, the list of conditions and the disclaimer are
retained in [`LICENSE`](./LICENSE). The name "Corelight" is used here solely to identify
the origin of these files and does **not** imply Corelight's endorsement of this
repository.

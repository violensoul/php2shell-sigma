# Vendored third-party component — ikow php2shell-poc (`detection/` subtree only)

- **Upstream:** https://github.com/ikow/php2shell-poc
- **Pinned commit:** `31519e6d8a84dee1df1262961ed1bebb65accadd`
- **Copyright:** © 2026 Qi Deng ([@ikow](https://github.com/ikow))
- **License:** MIT (see [`LICENSE`](./LICENSE))
- **Vendored on:** 2026-10-27

## What is included (detection subtree only)

| Path | Format | Purpose |
|------|--------|---------|
| `detection/php2shell.rules` | Suricata / Snort | 13 rules: request-side, response-side (heap-leak cookie length, OOM in response) and recon. |
| `detection/php2shell.yaml` | Sigma | 5 rules: upload-progress POST, oversized multipart 5xx, PHP-child-shell process creation, session-file poisoning, PHP OOM fatal in logs. |
| `detection/modsecurity.conf` | ModSecurity v2/v3 | Drop-in WAF rules for Apache/Nginx. |
| `detection/php2shell.lua` | OpenResty / Nginx Lua | Lightweight reverse-proxy check. |
| `detection/README.md` | — | Upstream coverage matrix and deployment notes. |

## What is explicitly NOT included

The upstream repository also contains `exploit/` and `poc/` proof-of-concept exploit
code. **Only the `detection/` subtree is vendored here. No exploit code is redistributed
in this repository.**

## Modifications

**None.** The listed files are redistributed verbatim from the pinned commit above. The
MIT permission notice is retained in [`LICENSE`](./LICENSE).

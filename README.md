# php2shell detection pack

Multi-format detection content for the memory-amplification probing/exploitation behind
**php2shell** (**CVE-2026-109618** and **CVE-2026-109619**, disclosed 2026-10-21; a related
third issue, **CVE-2026-115560**, shares the same fix-floor).

This repo started as a Sigma pack for the PHP OOM fatal-error IOC and now also bundles,
**with attribution and upstream licenses intact**, community detection content for other
layers — network IDS (Suricata/Zeek), WAF (ModSecurity), reverse-proxy (OpenResty Lua) and
an active version-exposure check (Nuclei).

> **Patching is the only fix.** Everything here is *detection*, not prevention. Upgrade PHP
> to **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12** (check the package *build date* — 8.4.27 and
> 8.5.12 were rebuilt 2026-10-22). EOL branches (≤ 8.1, and 7.x / 5.x) never get a backport.

---

## Layout & format matrix

| Area | File / dir | Format | Source | License |
|------|-----------|--------|--------|---------|
| **PHP OOM fatal (log)** | `php2shell_oom_multipart.yml` | Sigma | this repo (own) | DRL 1.1 |
| | `php2shell_oom_multipart_keywords.yml` | Sigma (field-agnostic) | this repo (own) | DRL 1.1 |
| | `php2shell_oom_multipart_burst.yml` | Sigma (correlation) | this repo (own) | DRL 1.1 |
| **Version exposure (active)** | `nuclei/php2shell-vulnerable-version.yaml` | Nuclei | this repo (own, clean-room) | DRL 1.1 |
| **Network IDS** | `vendor/corelight-php2shell-detect/suricata/php2shell.rules` | Suricata/Snort | Corelight | BSD-3-Clause |
| | `vendor/corelight-php2shell-detect/scripts/*.zeek` | Zeek package | Corelight | BSD-3-Clause |
| **SIEM / WAF / proxy** | `vendor/ikow-php2shell-poc/detection/php2shell.rules` | Suricata/Snort | Qi Deng (@ikow) | MIT |
| | `vendor/ikow-php2shell-poc/detection/php2shell.yaml` | Sigma | Qi Deng (@ikow) | MIT |
| | `vendor/ikow-php2shell-poc/detection/modsecurity.conf` | ModSecurity v2/v3 | Qi Deng (@ikow) | MIT |
| | `vendor/ikow-php2shell-poc/detection/php2shell.lua` | OpenResty Lua | Qi Deng (@ikow) | MIT |

See **[Attribution & licensing](#attribution--licensing)** below. Each `vendor/*` directory
keeps the upstream `LICENSE` and a `NOTICE.md` pinning the exact source commit.

---

## The core rule — PHP OOM fatal error (this repo's own work)

The original contribution here detects a PHP fatal error of the form:

```
PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0
```

The discriminator is **`in Unknown on line 0`**. A normal application OOM reports a real file
and line (`in /var/www/app/Foo.php on line 123`). The OOM only reports `Unknown` line `0`
when it happens inside PHP's SAPI / rfc1867 **multipart parser**, before any script runs —
exactly where a php2shell memory-amplification probe (thousands of duplicate multipart
part-headers, or deeply nested array keys, in a small body) forces the allocation. The base
rule ANDs **all three** substrings (`Allowed memory size of`, `bytes exhausted`,
`in Unknown on line 0`); without the third you just match ordinary memory bugs.

> **Cross-check:** `vendor/ikow-php2shell-poc/detection/php2shell.yaml` also ships an OOM
> rule (`php2shell005`). It keys on `Allowed memory size` + `exhausted` only — the
> `in Unknown on line 0` context is present but not enforced in its `condition`. The rule in
> *this* repo is the stricter variant; run both and compare if you want the wider net plus
> the low-false-positive view.

### Files (core Sigma)

| File | Purpose |
|------|---------|
| `php2shell_oom_multipart.yml`          | Base rule. Matches a named raw-message field (`message`). |
| `php2shell_oom_multipart_keywords.yml` | Field-agnostic variant (whole-event keyword match) for backends with no message field. Use **instead of** the base rule, not alongside. |
| `php2shell_oom_multipart_burst.yml`    | Correlation: ≥5 hits / 5 min / same `src_ip` = active scan or DoS. Needs the base rule loaded. |

### Log source prerequisites

The PHP OOM fatal must actually reach a log:

- **PHP-FPM:** `log_errors = On`, and the pool's `catch_workers_output = yes` so worker
  stderr lands in the FPM log (and, in containers, on stdout → CloudWatch / your shipper).
- **Apache mod_php:** it appears in Apache's `error_log`.

Map the raw log line to whatever field your pipeline uses (`message`, `msg`, `log`,
`@message`). The base rule assumes `message`; adjust or use the keywords variant.

---

## Usage

**Sigma (sigma-cli / pySigma)** — the correlation rule needs the base rule in scope, so
convert the directory, not a single file:

```bash
sigma check php2shell_oom_multipart.yml php2shell_oom_multipart_keywords.yml php2shell_oom_multipart_burst.yml
sigma convert -t splunk -p splunk_cim .
```

**Suricata** — pick either rule set (Corelight's is lean + recon-focused, ikow's is broader):

```bash
cp vendor/corelight-php2shell-detect/suricata/php2shell.rules /etc/suricata/rules/
suricatasc -c reload-rules
```

**Zeek** — load Corelight's package:

```bash
zeek -C -r traffic.pcap vendor/corelight-php2shell-detect/scripts
```

**ModSecurity** — `cp vendor/ikow-php2shell-poc/detection/modsecurity.conf /etc/modsecurity/conf.d/php2shell.conf` and reload.

**Nuclei (version exposure, non-intrusive)**:

```bash
nuclei -t nuclei/php2shell-vulnerable-version.yaml -u https://target
```

> The Nuclei template is a passive banner check: a single GET, no multipart, no
> exploitation. A match means "vulnerable/EOL version advertised", not "exploitable" —
> on PHP-FPM/php-cgi the public RCE chains do not land, and `expose_php=Off` or a proxy can
> hide the banner (so a non-match isn't proof of "patched").

---

## Tuning / false positives

- A legitimate very large multipart upload on an under-provisioned `memory_limit` can also
  OOM in the parser. Allowlist the known heavy-upload endpoint, or rely on the burst rule.
- Load / stress testing will fire these; suppress during planned tests.

---

## Attribution & licensing

This repository is a mix of first-party and vendored third-party work. **Each part keeps its
own license.**

- **First-party** — the three `php2shell_oom_multipart*.yml` Sigma rules and
  `nuclei/php2shell-vulnerable-version.yaml` — are released under the
  **Detection Rule License (DRL) 1.1** (see [`LICENSE.md`](./LICENSE.md)).
- **`vendor/corelight-php2shell-detect/`** — © 2026 Corelight, Inc., **BSD-3-Clause**.
  Redistributed verbatim from commit `4d5131c`. See its `LICENSE` + `NOTICE.md`.
- **`vendor/ikow-php2shell-poc/`** — © 2026 Qi Deng (@ikow), **MIT**. Only the upstream
  `detection/` subtree is vendored (no exploit code). From commit `31519e6`. See its
  `LICENSE` + `NOTICE.md`.

### External reference — not vendored

- **[Ademking/php2shell-nuclei-templates](https://github.com/Ademking/php2shell-nuclei-templates)**
  (Nuclei) is referenced for completeness but is **not bundled here: the upstream repo
  carries no license**, so it is not redistributable. Use it from its own source. The
  `nuclei/` template in this repo is independent clean-room work, not derived from it.

Thanks to Corelight and to Qi Deng (@ikow) for publishing their detection content under open
licenses.

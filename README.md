# php2shell OOM detection — Sigma rule pack

Detection rules for the memory-amplification probing/exploitation behind **php2shell**
(**CVE-2026-109618** and **CVE-2026-109619**, disclosed 2026-10-21).

## What it detects

A PHP fatal error of the form:

```
PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0
```

The discriminator is **`in Unknown on line 0`**. A normal application OOM reports a real file
and line (`in /var/www/app/Foo.php on line 123`). The OOM only reports `Unknown` line `0` when it
happens inside PHP's SAPI / rfc1867 **multipart parser**, before any script runs — which is exactly
where a php2shell memory-amplification probe (thousands of duplicate multipart part-headers, or
deeply nested array keys, in a small body) forces the allocation. That is why the rules AND this
context in: without it you just match ordinary memory bugs.

This is **detection, not prevention**. It tells you someone is probing/exploiting; it does not block
them. Pair it with an edge rule that rejects anomalous `multipart/form-data` (abnormal part count /
array-key nesting depth), and — the only real fix — patch PHP to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.

## Files

| File | Purpose |
|------|---------|
| `php2shell_oom_multipart.yml`          | Base rule. Matches a named raw-message field (`message`). |
| `php2shell_oom_multipart_keywords.yml` | Field-agnostic variant (whole-event keyword match) for backends with no message field. Use **instead of** the base rule, not alongside. |
| `php2shell_oom_multipart_burst.yml`    | Correlation: >=5 hits / 5 min / same `src_ip` = active scan or DoS. Needs the base rule loaded. |

## Log source prerequisites

The PHP OOM fatal must actually reach a log:

- **PHP-FPM:** `log_errors = On`, and the pool's `catch_workers_output = yes` so worker stderr lands
  in the FPM log (and, in containers, on stdout → CloudWatch / your log shipper).
- **Apache mod_php:** it appears in Apache's `error_log`.

Map the raw log line to whatever field your pipeline uses (`message`, `msg`, `log`, `@message`). The
base rule assumes `message`; adjust or use the keywords variant.

## Usage (sigma-cli / pySigma)

```bash
# Validate
sigma check .

# Convert the whole pack to your backend (examples)
sigma convert -t splunk          -p splunk_cim        .
sigma convert -t elasticsearch   -p ecs_windows       .   # pick the pipeline that matches your fields
sigma convert -t loki            .

# The correlation rule needs the base rule in scope, so convert the directory, not a single file.
```

For ClickHouse / other backends without a dedicated pySigma target, translate the base `detection`
by hand: three case-insensitive substring checks (`Allowed memory size of`, `bytes exhausted`,
`in Unknown on line 0`) AND-ed on one line, then group-by source over a 5-minute window for the burst.

## Tuning / false positives

- A legitimate very large multipart upload on an under-provisioned `memory_limit` can also OOM in the
  parser. Allowlist the known heavy-upload endpoint, or rely on the burst rule (one legit user rarely
  trips 5 in 5 minutes).
- Load / stress testing will fire these; suppress during planned tests.

## License

Released under the **Detection Rule License (DRL) 1.1** — free to use, modify and share. Attribution
appreciated. No warranty.

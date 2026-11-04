# Cloudflare WAF Keyword Mapping — bitcoinvn.io

## Methodology & Discriminator

To distinguish a **Cloudflare edge block** from an **origin (Symfony) response**, I used the
`Content-Security-Policy` header as the reliable fingerprint:

| Response source | CSP header present? | Body size on 403 | Content-Type charset |
|-----------------|---------------------|------------------|--------------------|
| **CF-EDGE (WAF)** | ❌ No | ~886 B or ~189 KB | `iso-8859-1` / none |
| **ORIGIN (Symfony)** | ✅ Yes | n/a | `UTF-8` |

Every probe was sent with the authenticated session cookies so origin behavior reflects a
logged-in user. Requests that reach the origin return Symfony's own pages (CSP + UTF-8).
Requests stopped at the edge never touch the origin and lack the app's CSP.

---

## BLOCKED BY CLOUDFLARE WAF (never reaches server) — 20 patterns

### SQL Injection
- `union select` → 403
- `AND 1=1` tautology → 403
- `benchmark(...)` → 403

### Cross-Site Scripting (XSS)
- `<script>` tag → 403
- `onerror=` attribute → 403
- `javascript:` URI → 403

### Local File Inclusion / Wrappers
- `php://filter` → 403
- Encoded path traversal (`..%2f..%2fetc%2fpasswd`) → **400 Bad Request**

### Sensitive Dotfiles & Config
- `/.env`, `/.gitignore`, `/.git/config` → 403
- `/web.config`, `/config.yml` → 403
- `/.aws/credentials` → 403
- `/composer.json` → 403

### CMS / Webshell Fingerprints
- `/xmlrpc.php`, `/wp-config.php.bak` → 403
- `/shell.php`, `/info.php`, `/admin.php` → 403

---

## PASSED THROUGH TO ORIGIN SERVER — 10 patterns

### Framework debug/admin probes (origin returns its own 404)
- `/_profiler/open` → 404 (origin)
- `/actuator/env` → 404 (origin)
- `/telescope/requests` → 404 (origin)
- `/admin/login` → 404 (origin)
- `/etc/passwd` (as plain path) → 404 (origin)
- random nonexistent page → 404 (origin)

### "Suspicious-looking but benign" tokens that CF does NOT match
- `sleep(5)` alone → 200 (origin)
- bare `union` (no `select`) → 200 (origin)
- `hello world` (literal space) → 200 (origin)
- `cmd=id` query param → 200 (origin)

---

## KEY OBSERVATIONS

1. **CF matches multi-token signatures, not single words.** `union select` is blocked but
   bare `union` passes; `AND 1=1` is blocked but `sleep()`/`cmd=id` pass. The ruleset keys
   on classic attack *phrases* rather than isolated keywords.

2. **The WAF inspects both URL path and query string** — dotfile names in the path and
   injection phrases in parameters are equally caught.

3. **Framework-specific paths bypass CF entirely.** `_profiler`, `actuator`, `telescope`
   are not in the managed-rules keyword set, so they hit the Symfony router and get a
   normal 404. This means CF provides no protection for application-level routes — only
   signature-based attack strings.

4. **Double-layer defense confirmed:** CF handles generic exploit scanning; the origin
   Symfony app independently enforces access control (its own 403/404 for sensitive files
   like `.gitignore`, `config.yml`, `*.php` that were tested earlier).

5. **Bypass surface:** business-logic endpoints (price feeds, order placement, balance
   changes) are invisible to CF's keyword list. Any logic flaw, IDOR, or mass-assignment
   issue there is protected only by the application itself, not the edge WAF.

---

## CUSTOM COMPACT/AGNOSTIC ENCODING RESEARCH (Round 2)

Goal: find encodings that *reconstruct* into a blocked signature at some downstream layer
while evading CF's static matcher. Scripts: `waf_custom_enc.py` … `waf_custom_enc5.py`,
raw results in `enc2_results.txt`–`enc5_results.txt`.

### The separator-class bypass (root cause discovered)

CF normalizes percent-encoded whitespace/control separators before matching, but its
normalization dictionary is finite. Anything outside it breaks the token adjacency the
signature depends on:

| Separator substituted for the space in `union select` | Result |
|---|---|
| `%20`, `+`, `%2b`, literal space | ❌ BLOCKED (normalized) |
| `%09 %0a %0d %0b %0c %00` (SQL-legal whitespace/NUL) | ❌ BLOCKED (normalized — CF mirrors the SQL parser!) |
| `%01 %02 %07 %0e %0f %1b %1f %7f` (other C0/C1 controls) | ✅ BYPASS → origin |
| Overlong UTF-8 (`%C0%AF`, `%E0%80%9F`, `%C1%80`) | ✅ BYPASS → origin |
| Unicode spaces: NBSP, en/em/thin/hair quad, U+2028/29, U+3000 | ✅ BYPASS → origin |
| Invisible chars: ZWSP, ZWJ, WJ, soft-hyphen, BOM-inside, TAG chars | ✅ BYPASS → origin |
| Double/triple URL-encode (`%2520`), `%u0020`, BOM prefix | ❌ BLOCKED (CF recursively decodes) |
| MySQL comments `/**/`, `#` variants | mixed: `/**/` blocked, `%23` bypasses |

**Key insight:** CF's rule engine treats exactly the whitespace set a SQL lexer treats
(space, tab, LF, CR, VT, FF, NUL) as equivalent separators — so classic SQLi whitespace
tricks are dead, but every *other* byte/codepoint silently splits the phrase and the
signature never fires. Payload reaches origin intact as raw bytes.

### Structural bypasses (not encoding, same effect)

- Token wrapping: `(union)(select)` and `` `union``select` `` → origin (200).
- Case-mixed wrapper words: `Php://Filter` → origin; but `unIoN SeLeCt` still blocked
  (CF lowercases before matching keywords — case tricks alone fail).
- `data:text/html;base64,...` → origin (CF matches decoded `<script>` only if it appears
  literally after one decode pass; base64 content is not recursively decoded).
- Fullwidth `<` `>` (`%EF%BC%9C`) → origin (browsers don't parse them, so no XSS risk,
  but proves matcher is ASCII-literal).
- Tag-name splitting with invisible chars (`<sv​g>`) → origin.

### What stays rock-solid against every trick tried

- Dotfile path rules: `.env` matched even through NUL/CRLF/tab insertion, trailing-dot,
  `::$DATA`, `;sysprop`, double-slash, backslash. Only *full-decode-different* names
  (overlong dot `%C0%AE`, fullwidth dot) reach origin — and they also fail to resolve at
  the origin, so no real exposure.
- `<script>`/`</script>` literal and `%u003c` forms (CF implements IE-era `%uXXXX` decoding).
- `or 1=1`, `union all select`, `benchmark(...)` context patterns.

### Reconstruction analysis (the user's hypothesis)

The hypothesis "encode around the WAF, reconstruct at the origin" holds mechanically for
the separator class — PHP/Symfony receives the raw bytes and many parsers (mb-normalizing
libraries, ICU-based collators, legacy GBK/UTF-7 stacks) could re-fold unicode spaces to
ASCII space. However this app uses Doctrine parameterized queries + Symfony's strict UTF-8
request handling, so the delivered payload is treated as inert string data; overlong
sequences are rejected/escaped rather than folded. No reconstruction-to-execution path was
found. The WAF gap is real; the exploit gap is closed by the origin stack.

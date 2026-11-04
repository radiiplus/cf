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

import subprocess, json, sys

BASE = "https://bitcoinvn.io"
COOKIE = "REMEMBERME=%3Ab21uaWNvbm5lY3QwMEBnbWFpbC5jb20~%3A1794982284%3Alogin-method-v1%3AWyJnb29nbGUiLGZhbHNlLCJXaGt0cWxCVUwtdUlLRkI0M1AyQkcxNTJ2UFdXWktfdjhocUVUNzlvbUh3fjU2d0hobWFPRF9Ed0sySzlCUFJmOWpiOWd0dGpzUkJHQWNsMTNBQmZPbWN%2BIl0%3D%3Aca962b8ce904172eb281811fdf1f84efb603a9dc7f3f6382aa79fdf87866f46f; SID=002ed1eb0006b3d9e084200584a9250a"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

paths = [
    "/_profiler/", "/_profiler/open", "/_wdt/", "/admin", "/administrator",
    "/wp-admin", "/phpmyadmin", "/.env", "/.git/config", "/debug",
    "/actuator", "/server-status", "/xmlrpc.php", "/cgi-bin/",
    "/shell.php", "/?cmd=ls", "/select+1,2,3", "/union+select",
    "/etc/passwd", "/../../etc/passwd", "/normal-page-xyz123-notexist",
]

def probe(path):
    url = BASE + path
    cmd = ["curl", "-s", "-i", "--max-time", "10", "-H", f"Cookie: {COOKIE}",
           "-H", f"User-Agent: {UA}", url]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout
    except Exception as e:
        return {"path": path, "error": str(e)}

    lines = out.split("\r\n")
    status = lines[0] if lines else ""
    http_code = status.split()[1] if len(status.split()) > 1 else "?"

    headers = {}
    body_start = False
    body_lines = []
    for i, ln in enumerate(lines):
        if not body_start:
            if ln == "":
                body_start = True
                continue
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        else:
            body_lines.append(ln)
    body = "\n".join(body_lines)

    # Detect Cloudflare block indicators
    cf_block = False
    cf_reason = ""
    server = headers.get("server", "")
    cfw = headers.get("cf-ray", "")
    body_low = body.lower()

    if "cloudflare" in server.lower():
        # Check for challenge/block page markers
        if "cf-browser-verification" in body_low or "attention required" in body_low:
            cf_block = True; cf_reason = "CF Challenge Page"
        elif "blocked" in body_low and "cloudflare" in body_low:
            cf_block = True; cf_reason = "CF Block Page"
        elif http_code == "403":
            cf_block = True; cf_reason = "HTTP 403 via CF"
        elif http_code == "404":
            # Determine if origin 404 or CF 404
            if "<title>" in body_low and ("not found" in body_low or "symfony" in body_low or "404" in body_low):
                cf_reason = "Origin 404 (passed through CF)"
            else:
                cf_reason = f"HTTP {http_code} (unclear source)"
        else:
            cf_reason = f"HTTP {http_code}"
    else:
        cf_reason = f"Non-CF server: {server}, HTTP {http_code}"

    # Extract snippet of body for fingerprinting
    snippet = body[:300].replace("\n", " ").strip()

    return {
        "path": path,
        "code": http_code,
        "server": server,
        "cf_ray": cfw,
        "content_len": headers.get("content-length", str(len(body))),
        "block": cf_block,
        "reason": cf_reason,
        "snippet": snippet[:200],
    }

results = []
for p in paths:
    r = probe(p)
    results.append(r)
    print(f"{p:<40} | {r['code']:<4} | {r['reason']:<35} | len={r['content_len']}")

print("\n=== BODY SNIPPETS (unique fingerprints) ===")
seen = set()
for r in results:
    s = r.get("snippet","")
    key = s[:80]
    if key and key not in seen:
        seen.add(key)
        print(f"\n[{r['path']}] code={r['code']}:\n{s}")

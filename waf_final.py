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
    # discriminator: CF edge responses lack origin headers (cf-cache-status, CSP);
    # origin responses carry Symfony app headers (CSP, cf-cache-status: BYPASS/DYNAMIC)
    is_origin = ("content-security-policy" in hd.lower()) or ("cf-cache-status" in hd.lower())
    return status, len(body), is_origin

# Confirm two distinct 403 sources
print("=== 403 SOURCE DISCRIMINATION ===")
for p in ["/.env", "/shell.php", "/config.yml", "/zzz-not-real"]:
    s,l,o = probe(p)
    src = "ORIGIN(app)" if o else "CF-EDGE(WAF)"
    print(f"{p:<20} HTTP {s:<4} len={l:<8} -> {src}")

# Final keyword map (consolidated)
tests = [
  ("/.env","dotfile secret"),("/.git/HEAD","VCS"),("/.aws/credentials","cloud creds"),
  ("/web.config","IIS config"),("/composer.json","php manifest"),("/xmlrpc.php","WP"),
  ("/wp-login.php","WP login"),("/wp-config.php.bak","WP backup"),
  ("/union+select","SQLi union"),("/search?q=javascript:alert(1)","XSS proto"),
  ("/?page=php://filter","wrapper LFI"),("/shell.php","webshell name"),
  ("/_profiler/open","symfony debug"),("/admin/login","admin"),("/actuator/env","spring"),
  ("/telescope/requests","laravel dbg"),("/cgi-bin/test.cgi","CGI"),("/backup.zip","archive"),
  ("/?q=information_schema","schema kw"),("/?x=sleep(5)","time-based"),
]
print("\n=== KEYWORD MAP ===")
for p,label in tests:
    s,l,o = probe(p)
    src = "origin" if o else "CF-WAF"
    verdict = "BLOCKED" if s=="403" else ("passed→"+s)
    print(f"{label:<18} {p:<35} {s} [{src}] {verdict}")

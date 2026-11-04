import subprocess

BASE = "https://bitcoinvn.io"
COOKIE = "REMEMBERME=%3Ab21uaWNvbm5lY3QwMEBnbWFpbC5jb20~%3A1794982284%3Alogin-method-v1%3AWyJnb29nbGUiLGZhbHNlLCJXaGt0cWxCVUwtdUlLRkI0M1AyQkcxNTJ2UFdXWktfdjhocUVUNzlvbUh3fjU2d0hobWFPRF9Ed0sySzlCUFJmOWpiOWd0dGpzUkJHQWNsMTNBQmZPbWN%2BIl0%3D%3Aca962b8ce904172eb281811fdf1f84efb603a9dc7f3f6382aa79fdf87866f46f; SID=002ed1eb0006b3d9e084200584a9250a"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def probe(path):
    cmd = ["curl", "-s", "-D", "/tmp/h.txt", "-o", "/dev/null", "--max-time", "10",
           "-H", f"Cookie: {COOKIE}", "-H", f"User-Agent: {UA}", BASE + path]
    subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    hd = open("/tmp/h.txt").read()
    code = hd.split("\r\n")[0].split(" ")[1]
    # Origin Symfony pages have CSP header; CF edge-managed pages do not
    has_csp = "content-security-policy:" in hd.lower()
    src = "ORIGIN(Symfony)" if has_csp else "CF-EDGE(WAF)"
    return code, src

tests = [
 ("union select","/?q=union%20select"),("<script>","/?v=%3Cscript%3E"),
 ("/.env","/.env"),("/shell.php","/shell.php"),("/info.php","/info.php"),
 ("/admin/login","/admin/login"),("/actuator/env","/actuator/env"),
 ("/etc/passwd","/etc/passwd"),("/zzz-benign","/zzz-benign-test"),
]
print(f"{'TEST':<18} {'CODE':<5} SOURCE")
for label,p in tests:
    c,s = probe(p)
    print(f"{label:<18} {c:<5} {s}")

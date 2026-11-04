import subprocess

BASE = "https://bitcoinvn.io"
COOKIE = "REMEMBERME=%3Ab21uaWNvbm5lY3QwMEBnbWFpbC5jb20~%3A1794982284%3Alogin-method-v1%3AWyJnb29nbGUiLGZhbHNlLCJXaGt0cWxCVUwtdUlLRkI0M1AyQkcxNTJ2UFdXWktfdjhocUVUNzlvbUh3fjU2d0hobWFPRF9Ed0sySzlCUFJmOWpiOWd0dGpzUkJHQWNsMTNBQmZPbWN%2BIl0%3D%3Aca962b8ce904172eb281811fdf1f84efb603a9dc7f3f6382aa79fdf87866f46f; SID=002ed1eb0006b3d9e084200584a9250a"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def probe(path):
    cmd = ["curl", "-s", "-D", "/tmp/h.txt", "-o", "/tmp/b.txt", "--max-time", "10",
           "-H", f"Cookie: {COOKIE}", "-H", f"User-Agent: {UA}", BASE + path]
    subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    hd = open("/tmp/h.txt").read()
    body = open("/tmp/b.txt", errors="replace").read()
    status = hd.split("\r\n")[0].split(" ")[1]
    hdl = hd.lower()
    # Origin Symfony responses ALWAYS contain CSP header and cf-cache-status
    # CF edge-managed block pages do NOT contain these headers
    is_origin = ("content-security-policy:" in hdl) and ("cf-cache-status:" in hdl)
    return status, len(body), ("ORIGIN" if is_origin else "CF-EDGE")

cases = ["/.gitignore","/.aws/credentials","/composer.json","/wp-login.php",
         "/shell.php","/info.php","/admin.php","/config.yml","/.env",
         "/xmlrpc.php","/web.config","/.git/config","/zzz-nope"]
print(f"{'PATH':<22} {'CODE':<5} {'LEN':<8} SOURCE")
for p in cases:
    s,l,src = probe(p)
    print(f"{p:<22} {s:<5} {l:<8} {src}")

import subprocess

BASE = "https://bitcoinvn.io"
COOKIE = "REMEMBERME=%3Ab21uaWNvbm5lY3QwMEBnbWFpbC5jb20~%3A1794982284%3Alogin-method-v1%3AWyJnb29nbGUiLGZhbHNlLCJXaGt0cWxCVUwtdUlLRkI0M1AyQkcxNTJ2UFdXWktfdjhocUVUNzlvbUh3fjU2d0hobWFPRF9Ed0sySzlCUFJmOWpiOWd0dGpzUkJHQWNsMTNBQmZPbWN%2BIl0%3D%3Aca962b8ce904172eb281811fdf1f84efb603a9dc7f3f6382aa79fdf87866f46f; SID=002ed1eb0006b3d9e084200584a9250a"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def classify(path):
    cmd = ["curl", "-s", "-D", "/tmp/h.txt", "-o", "/tmp/b.txt", "--max-time", "10",
           "-H", f"Cookie: {COOKIE}", "-H", f"User-Agent: {UA}", BASE + path]
    subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    hd = open("/tmp/h.txt").read()
    body = open("/tmp/b.txt", errors="replace").read()
    code = hd.split("\r\n")[0].split(" ")[1]
    ct = ""
    for ln in hd.split("\r\n"):
        if ln.lower().startswith("content-type:"): ct = ln.split(":",1)[1].strip()
    # Origin Symfony pages: content-type charset=UTF-8 + CSP header present
    # CF edge-managed block pages: charset=iso-8859-1 + no CSP
    is_origin = ("UTF-8" in ct) and ("content-security-policy" in hd.lower())
    src = "ORIGIN(Symfony)" if is_origin else "CF-EDGE(WAF)"
    return code, len(body), src

cases = ["/zzz-nope","/shell.php","/.gitignore","/.env","/xmlrpc.php","/web.config","/info.php"]
print(f"{'PATH':<16} {'CODE':<5} {'LEN':<8} SOURCE")
for p in cases:
    c,l,s = classify(p)
    print(f"{p:<16} {c:<5} {l:<8} {s}")

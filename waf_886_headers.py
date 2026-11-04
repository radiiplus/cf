import subprocess

BASE = "https://bitcoinvn.io"
COOKIE = "REMEMBERME=%3Ab21uaWNvbm5lY3QwMEBnbWFpbC5jb20~%3A1794982284%3Alogin-method-v1%3AWyJnb29nbGUiLGZhbHNlLCJXaGt0cWxCVUwtdUlLRkI0M1AyQkcxNTJ2UFdXWktfdjhocUVUNzlvbUh3fjU2d0hobWFPRF9Ed0sySzlCUFJmOWpiOWd0dGpzUkJHQWNsMTNBQmZPbWN%2BIl0%3D%3Aca962b8ce904172eb281811fdf1f84efb603a9dc7f3f6382aa79fdf87866f46f; SID=002ed1eb0006b3d9e084200584a9250a"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def headers(path):
    cmd = ["curl", "-s", "-I", "--max-time", "10", "-H", f"Cookie: {COOKIE}",
           "-H", f"User-Agent: {UA}", BASE + path]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout
    d = {}
    for ln in out.split("\r\n"):
        if ":" in ln and not ln.startswith("HTTP"):
            k,v = ln.split(":",1); d[k.strip().lower()] = v.strip()
    code = out.split("\r\n")[0].split(" ")[1]
    return code, d.get("content-type",""), d.get("cf-cache-status","ABSENT"), d.get("x-frame-options","ABSENT")

for p in ["/zzz-nope-404", "/shell.php", "/.gitignore", "/.env", "/xmlrpc.php"]:
    c,ct,cc,xfo = headers(p)
    print(f"{p:<16} code={c} content-type='{ct}' cf-cache-status={cc} x-frame-options={xfo}")

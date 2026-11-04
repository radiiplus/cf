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
    return status, len(body), body[:200].replace("\n"," ").strip()

# Full header dump for a CF block vs origin page to find discriminator
print("=== FULL HEADERS: /.env (blocked?) ===")
subprocess.run(["curl","-s","-I","--max-time","10","-H",f"Cookie: {COOKIE}","-H",f"User-Agent: {UA}",BASE+"/.env"])
print("\n=== FULL HEADERS: /zzz-not-real (origin 404) ===")
subprocess.run(["curl","-s","-I","--max-time","10","-H",f"Cookie: {COOKIE}","-H",f"User-Agent: {UA}",BASE+"/zzz-not-real"])

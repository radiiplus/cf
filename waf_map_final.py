import subprocess

BASE = "https://bitcoinvn.io"
COOKIE = "REMEMBERME=%3Ab21uaWNvbm5lY3QwMEBnbWFpbC5jb20~%3A1794982284%3Alogin-method-v1%3AWyJnb29nbGUiLGZhbHNlLCJXaGt0cWxCVUwtdUlLRkI0M1AyQkcxNTJ2UFdXWktfdjhocUVUNzlvbUh3fjU2d0hobWFPRF9Ed0sySzlCUFJmOWpiOWd0dGpzUkJHQWNsMTNBQmZPbWN%2BIl0%3D%3Aca962b8ce904172eb281811fdf1f84efb603a9dc7f3f6382aa79fdf87866f46f; SID=002ed1eb0006b3d9e084200584a9250a"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def classify(path):
    cmd = ["curl", "-s", "-D", "/tmp/h.txt", "-o", "/dev/null", "--max-time", "10",
           "-H", f"Cookie: {COOKIE}", "-H", f"User-Agent: {UA}", BASE + path]
    subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    hd = open("/tmp/h.txt").read()
    code = hd.split("\r\n")[0].split(" ")[1]
    ct = ""
    for ln in hd.split("\r\n"):
        if ln.lower().startswith("content-type:"): ct = ln.split(":",1)[1].strip().lower()
    # ORIGIN Symfony => charset=UTF-8 ; CF edge block/challenge => iso-8859-1 or no charset UTF-8
    if "utf-8" in ct: src = "ORIGIN"
    else: src = "CF-EDGE"
    return code, src

tests = [
 ("union select","/?q=union%20select"),("AND tautology","/?q=1%20AND%201=1"),
 ("benchmark","/?q=benchmark(1,md5('a'))"),("' or ''='","/?q=%27%20or%20%27%27=%27"),
 ("<script> tag","/?v=%3Cscript%3E"),("onerror=","/?v=onerror=alert(1)"),
 ("javascript:","/?v=javascript:alert(1)"),("php://filter","/?f=php://filter"),
 ("/.env","/.env"),("/.git/*","/.git/config"),("/web.config","/web.config"),
 ("/xmlrpc.php","/xmlrpc.php"),("/wp-config.bak","/wp-config.php.bak"),
 ("/shell.php","/shell.php"),("/info.php","/info.php"),("/admin.php","/admin.php"),
 ("/.aws/credentials","/.aws/credentials"),("/composer.json","/composer.json"),
 ("/config.yml","/config.yml"),("/.gitignore","/.gitignore"),
 ("/_profiler/open","/_profiler/open"),("/actuator/env","/actuator/env"),
 ("/telescope","/telescope/requests"),("/admin/login","/admin/login"),
 ("/etc/passwd","/etc/passwd"),("/../../etc/passwd","/..%2f..%2fetc%2fpasswd"),
 ("/?cmd=id","/?cmd=id"),("/sleep(5)","/?x=sleep(5)"),("/bare union","/?q=union"),
 ("/benign space","/?q=hello%20world"),
]
print(f"{'TEST':<22} {'CODE':<5} SOURCE")
for label,p in tests:
    c,s = classify(p)
    print(f"{label:<22} {c:<5} {s}")

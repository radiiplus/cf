#!/usr/bin/env python3
"""rev6c: WHY does control escaped-key identity fail? Two candidate causes:
 (a) JSONObject's PyDict_SetDefault on the result dict canonicalises against
     whatever equal key is already in the dict -- but only if one IS present.
     Our doc has no literal twin inside the document, so memo must supply it.
 (b) C scanstring may not consult memo for a single-escape string at all, or
     memo.setdefault only returns an existing entry when the EQUAL string was
     previously scanned INTO THE SAME PARSE (memo starts empty per parse).
Test matrix: escaped spelling vs literal twin INSIDE the doc; escaped vs
module-level literal OUTSIDE the doc; PY path and C path separately."""
import gc, json
from json import JSONDecoder

LIT = "lsecond_key_bbb"

def memo_of(dec, path):
    if path == "PY": return dec.memo
    ms = [r for r in gc.get_referents(dec.scan_once) if isinstance(r, dict)]
    return ms[0] if ms else None

def probe(doc, path, expect_key=LIT):
    seen, holder = [], {}
    def hook(pairs):
        seen.append([k for k, v in pairs])
        return dict(pairs)
    d = JSONDecoder(object_pairs_hook=hook); holder["d"] = d
    res = d.decode(doc)
    outer = seen[-1]
    got = next(k for k in outer if k == expect_key)
    out = {"equal": got == LIT, "is_literal_module": got is LIT,
           "memo_len_after": len(memo_of(d, path)) if memo_of(d, path) is not None else None}
    # if doc contains BOTH spellings, compare them to each other
    if len(outer) >= 2 and outer[0] == outer[1]:
        out["pair_identity"] = outer[0] is outer[1]
    return out

cases = {
    "escaped_only_C":      ('{"\\u006csecond_key_bbb": 1}', "C"),
    "escaped_only_PY":     ('{"\\u006csecond_key_bbb": 1}', "PY"),
    "literal_then_escaped_C": ('{"lsecond_key_bbb": 0, "\\u006csecond_key_bbb": 1}', "C"),
    "escaped_then_literal_C": ('{"\\u006csecond_key_bbb": 0, "lsecond_key_bbb": 1}', "C"),
    "literal_then_escaped_PY":('{"lsecond_key_bbb": 0, "\\u006csecond_key_bbb": 1}', "PY"),
    "two_escapes_C":       ('{"\\u006csecond_key_bbb": 0, "\\u006c\\u0073econd_key_bbb": 1}', "C"),
}
import json.scanner as sm
saved = sm.make_scanner; sm.make_scanner = sm.py_make_scanner
R = {}
try:
    for name, (doc, path) in cases.items():
        R[name] = probe(doc, path) if path == "PY" else None
finally:
    sm.make_scanner = saved
for name, (doc, path) in cases.items():
    if path == "C":
        R[name] = probe(doc, path)
print(json.dumps(R, indent=2))

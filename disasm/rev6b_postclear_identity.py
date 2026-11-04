#!/usr/bin/env python3
"""
rev6b_postclear_identity.py -- the decisive post-clear probe.

rev6 showed: (a) memo cleared mid-outer-parse on BOTH paths, but (b) tail-key
identity unchanged. Reason: in rev6's document the two equal-spelled tail keys
were adjacent; JSONObject canonicalises key2 against key1 via PyDict_SetDefault
on the RESULT DICT, which does not consult the scanner memo at all. So adjacency
masks the memo effect.

Correct construction (source-grounded):
  - memo is consulted only when scanstring produces a NEW string object for an
    ESCAPED spelling (memo.setdefault). A literal spelling never enters memo.
  - Therefore compare: escaped key scanned AFTER the reentrant clear against an
    interned module-level IDENTICAL LITERAL string. If memo were live, setdefault
    would return the interned object -> identity True. Post-clear, the escaped
    scan creates a fresh object -> identity False while equality holds.
  - Control: identical document WITHOUT the reentrant decode -> identity True.

Three outcomes recorded separately (review requirement):
  memo_cleared | identity_diverges | equality_or_result_changed
Works on both C (_json.scanstring) and pure-Python (json.scanner) paths.
"""
import gc, json
from json import JSONDecoder

LIT = "lsecond_key_bbb"                      # interned module-level literal
DOC_TAIL = ', "\\u006csecond_key_bbb": %s}'   # escaped spelling of LIT
HEAD_NESTED = '{"first_key_aaa": {"nested": 1}'
INNER = '{"inner_qq": 1}'
OUT = {}

def run(reentrant, path):
    snaps, holder, escapes = [], {}, []
    def hook(pairs):
        if reentrant and len(snaps) == 0:
            memo = get_memo(holder["d"])
            snaps.append(["before_inner", id(memo), len(memo)])
            holder["d"].decode(INNER)
            snaps.append(["after_inner", id(memo), len(memo)])
            snaps.append(["same_memo_object", memo is get_memo(holder["d"])])
        return dict(pairs)
    def get_memo(dec):
        if path == "PY":
            return dec.memo
        memos = [r for r in gc.get_referents(dec.scan_once) if isinstance(r, dict)]
        return memos[0] if memos else None
    d = JSONDecoder(object_pairs_hook=hook)
    holder["d"] = d
    # values distinct so we can detect result changes; last pair carries escaped key
    doc = HEAD_NESTED + DOC_TAIL % ("2" if not reentrant else "2")
    res = d.decode(doc)
    got = list(res.keys())[-1]               # the escaped key object as stored
    return {"snaps": snaps,
            "equal_to_literal": got == LIT,
            "identity_with_literal": got is LIT,
            "result": {k: v for k, v in res.items()}}

# ---- C path (default scanner) ----
OUT["C"] = {"reentrant": run(True, "C"), "control": run(False, "C")}

# ---- PY path (force py_make_scanner) ----
import json.decoder as jd, json.scanner as sm
saved = sm.make_scanner
sm.make_scanner = sm.py_make_scanner
try:
    OUT["PY"] = {"reentrant": run(True, "PY"), "control": run(False, "PY")}
finally:
    sm.make_scanner = saved

c_re, c_ct = OUT["C"]["reentrant"], OUT["C"]["control"]
p_re, p_ct = OUT["PY"]["reentrant"], OUT["PY"]["control"]
OUT["verdicts"] = {
    "control_validity": {
        "C_control_escapes_canonicalize_to_literal": c_ct["identity_with_literal"],
        "PY_control_escapes_canonicalize_to_literal": p_ct["identity_with_literal"],
    },
    "memo_cleared_mid_outer_parse": {
        "C": bool(c_re["snaps"]) and c_re["snaps"][1][2] == 0 and c_re["snaps"][2][1],
        "PY": bool(p_re["snaps"]) and p_re["snaps"][1][2] == 0 and p_re["snaps"][2][1],
    },
    "post_clear_identity_divergence": {
        "C": (not c_re["identity_with_literal"]) and c_re["equal_to_literal"],
        "PY": (not p_re["identity_with_literal"]) and p_re["equal_to_literal"],
    },
    "equality_or_result_changed": {
        "C": c_re["equal_to_literal"] != c_ct["equal_to_literal"] or c_re["result"] != c_ct["result"],
        "PY": p_re["equal_to_literal"] != p_ct["equal_to_literal"] or p_re["result"] != p_ct["result"],
    },
}
print(json.dumps(OUT, indent=2, default=str))

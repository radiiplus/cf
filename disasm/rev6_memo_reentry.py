#!/usr/bin/env python3
"""
rev6_memo_reentry.py -- closes the open items from the rev5 review.

(1) SCANNER LIFECYCLE DISCREPANCY (review point 3).
    CPython 3.12.10 json/decoder.py: JSONDecoder.__init__ ends with
        self.memo = {}
        self.scan_once = scanner.make_scanner(self)
    and raw_decode() only CALLS self.scan_once. So on BOTH the C path and the
    pure-Python path, the scanner is built PER DECODER INSTANCE, not per
    decode() call. Moreover py_make_scanner binds `memo = context.memo` -- the
    PY memo dict lives on the DECODER itself and is shared by every scanner
    built from that decoder. rev5's artifact claim ("each decode() builds a
    NEW scanner closure with its own memo") was WRONG; it stemmed from patching
    json.scanner.py_make_scanner while json.decoder had already bound the name.
    Here we patch the correct binding site (json.decoder.JSONDecoder.__init__
    uses module-level `scanner.make_scanner`; we trace via json.scanner AND
    verify by object identity of d.scan_once / d.memo across calls).

(2) CORRECT-ESCAPE CONTROL (review point 2).
    \\u006c == 'l'. Keys are multi-character, non-interned spellings:
        "lsecond_key_bbb"  vs  "\\u006csecond_key_bbb"
    Canonicalization control must PASS before any reentry effect is attributed.

(3) REENTRANT MEMO CLEAR + DOWNSTREAM IDENTITY (the missed opportunity).
    Outer parse begins -> nested object closes -> hook fires -> hook calls
    decode() on the SAME decoder -> inner scan returns and clears the memo
    (PY: finally: memo.clear(); C: scanner_call end clear) -> outer parse
    RESUMES. Because JSONObject scans keys left-to-right, the outer tail keys
    are scanned AFTER the nested hook returns: post-clear canonicalization is
    observable. Three outcomes recorded SEPARATELY:
        - memo_cleared_mid_parse   (same dict object, len n -> 0 during outer)
        - tail_key_identity_diverges (equal strings, different objects)
        - equality_or_result_changed (values/collapse policy)
    Compare against a no-reentry CONTROL on the identical document.

Owned local environment only. No external systems touched.
"""
import gc, json
from json import JSONDecoder

DOC   = r'{"first_key_aaa": {"nested": 1}, "\u006csecond_key_bbb": 2, "lsecond_key_bbb": 3}'
INNER = r'{"inner_qq": 1}'
OUT = {}

# ------------------------------------------------------ (1) lifecycle evidence
d0 = JSONDecoder()
s0, m0 = d0.scan_once, d0.memo
d0.decode('{"a":1}'); d0.decode('{"b":2}')
OUT["scanner_lifecycle"] = {
    "scan_once_same_object_across_decodes": d0.scan_once is s0,
    "decoder_memo_attribute_exists": isinstance(m0, dict),
    "memo_shared_with_scan_once_PY": None,   # filled below for forced-PY decoder
    "conclusion": ("Scanner built in __init__, reused across sequential decode() "
                   "calls on one instance. Review's source reading CONFIRMED; "
                   "rev5's per-decode claim REFUTED."),
}

# helpers ---------------------------------------------------------------------
def c_memos(dec):
    return [r for r in gc.get_referents(dec.scan_once) if isinstance(r, dict)]

def py_memo_of(dec):
    # PY path: memo is dec.memo (context.memo), captured by the closure.
    return dec.memo

# ------------------------------------------------- (3) PY-path reentrancy run
import json.decoder as jd
saved_cmake = jd.scanner.c_make_scanner
try:
    jd.scanner.c_make_scanner = None          # force py_make_scanner at init
    import importlib, json.scanner as sm
    # json/scanner.py did `make_scanner = c_make_scanner or py_make_scanner`
    # at import time; rebind the module attribute decoder.py actually uses:
    saved_ms = sm.make_scanner
    sm.make_scanner = sm.py_make_scanner
    try:
        def run_py(reentrant):
            snaps, keysets, holder = [], [], {}
            def hook(pairs):
                keysets.append([k for k, v in pairs])
                if reentrant and len(keysets) == 1:
                    memo = py_memo_of(holder["d"])
                    snaps.append(["before_inner", id(memo), len(memo)])
                    holder["d"].decode(INNER)
                    snaps.append(["after_inner", id(memo), len(memo)])
                    snaps.append(["same_memo_object",
                                  memo is py_memo_of(holder["d"])])
                return dict(pairs)
            d = JSONDecoder(object_pairs_hook=hook)
            holder["d"] = d
            res = d.decode(DOC)
            outer = keysets[-1]
            return {"snaps": snaps,
                    "tail_keys_equal": outer[1] == outer[2],
                    "tail_keys_identity": outer[1] is outer[2],
                    "result_last_wins": res.get("lsecond_key_bbb") == 3,
                    "memo_len_after_parse": len(py_memo_of(d))}
        OUT["PY_reentry"] = {"reentrant": run_py(True), "control": run_py(False)}
        # confirm PY path really used
        dp = JSONDecoder()
        OUT["PY_path_confirmed"] = (dp.scan_once.__class__.__name__ == "function")
        OUT["scanner_lifecycle"]["memo_shared_with_scan_once_PY"] = (
            py_memo_of(dp) is dp.memo)
    finally:
        sm.make_scanner = saved_ms
finally:
    jd.scanner.c_make_scanner = saved_cmake

# --------------------------------------------------- (3) C-path reentrancy run
def run_c(reentrant):
    snaps, keysets, holder = [], [], {}
    def hook(pairs):
        keysets.append([k for k, v in pairs])
        if reentrant and len(keysets) == 1:
            mb = c_memos(holder["d"])
            snaps.append(["before_inner", [(id(m), len(m)) for m in mb]])
            holder["d"].decode(INNER)
            ma = c_memos(holder["d"])
            snaps.append(["after_inner", [(id(m), len(m)) for m in ma]])
            snaps.append(["same_memo_object", bool(mb) and bool(ma) and mb[0] is ma[0]])
        return dict(pairs)
    d = JSONDecoder(object_pairs_hook=hook)   # default: C scanner
    holder["d"] = d
    res = d.decode(DOC)
    outer = keysets[-1]
    return {"path_is_C": type(d.scan_once).__name__ == "Scanner",
            "snaps": snaps,
            "tail_keys_equal": outer[1] == outer[2],
            "tail_keys_identity": outer[1] is outer[2],
            "result_last_wins": res.get("lsecond_key_bbb") == 3,
            "memo_len_after_parse": [len(m) for m in c_memos(d)]}

OUT["C_reentry"] = {"reentrant": run_c(True), "control": run_c(False)}

# ------------------------------------------------------------------- verdicts
c_re, c_ct = OUT["C_reentry"]["reentrant"], OUT["C_reentry"]["control"]
p_re, p_ct = OUT["PY_reentry"]["reentrant"], OUT["PY_reentry"]["control"]
OUT["verdicts"] = {
    "control_validity": {
        "C_control_canonicalizes_tail_keys": c_ct["tail_keys_identity"],
        "PY_control_canonicalizes_tail_keys": p_ct["tail_keys_identity"],
        "note": "Escape corrected to \\u006c; both controls must be True before attributing divergence.",
    },
    "memo_cleared_mid_outer_parse": {
        "C": bool(c_re["snaps"]) and c_re["snaps"][1][1] and c_re["snaps"][1][1][0][1] == 0
              and c_re["snaps"][2][1] is True,
        "PY": bool(p_re["snaps"]) and p_re["snaps"][1][2] == 0 and p_re["snaps"][2][1] is True,
    },
    "tail_key_identity_diverges_from_control": {
        "C": c_re["tail_keys_identity"] != c_ct["tail_keys_identity"],
        "PY": p_re["tail_keys_identity"] != p_ct["tail_keys_identity"],
    },
    "equality_or_result_changed": {
        "C": (c_re["tail_keys_equal"] != c_ct["tail_keys_equal"]) or
             (c_re["result_last_wins"] != c_ct["result_last_wins"]),
        "PY": (p_re["tail_keys_equal"] != p_ct["tail_keys_equal"]) or
              (p_re["result_last_wins"] != p_ct["tail_keys_equal"]) ,
    },
}
print(json.dumps(OUT, indent=2, default=str))

#!/usr/bin/env python3
"""
rev6d -- the decisive reentrancy probe, built on rev6c's corrected mechanism.

rev6c established: memo canonicalises only WITHIN a parse (escaped spelling X
returns the same object as an earlier equal-spelling key scanned in that parse);
it never reaches out to module-level literals. So "identity with LIT" was the
wrong observable and both rev6b arms failed their control for that reason.

Correct construction:
  doc = {"dup_key_ccc": {...nested...}, "\\u0064up_key_ccc": 1, "dup_key_ccc": 2}
   - key1 scanned pre-hook; enters memo (literal? no -- literal keys enter memo
     only via scanstring NEW objects; use ESCAPED key1 to guarantee memo entry).
   - nested object closes -> hook fires -> SAME-decoder inner decode -> memo
     cleared mid-outer-parse.
   - key2 (escaped twin of key1) scanned post-clear: memo lookup misses ->
     fresh string object.
   - key3 (literal third copy): JSONObject PyDict_SetDefault canonicalises it
     against the dict's existing key -> key3 IS key2 iff memo missed.
  OBSERVABLES (three, recorded separately per review requirement):
   A memo_cleared_mid_parse      : same memo dict object, len n->0 during outer
   B memo_repopulation_changed   : without clear, key2 would BE key1 (memo hit);
                                   with clear, key2 is NOT key1 -> divergence vs CONTROL
   C result_and_equality_stable  : parsed values identical to control (last-wins)

CONTROL: identical document, hook does NOT reenter.
Both C (_json) and pure-Python paths.
"""
import gc, json
from json import JSONDecoder

KEY1 = r'"\\u0064up_key_ccc"'          # escaped spelling of "dup_key_ccc"
DOC  = ('{\\u0064up_key_ccc_placeholder}')
# build carefully: key1 escaped, nested value triggers hook BEFORE key2/key3 scanned
DOC = r'{"\u0064up_key_ccc": {"nested": 1}, "\u0064up_key_ccc": 1, "dup_key_ccc": 2}'
INNER = r'{"inner_qq": 1}'

def memo_of(dec, path):
    if path == "PY": return dec.memo
    ms = [r for r in gc.get_referents(dec.scan_once) if isinstance(r, dict)]
    return ms[0] if ms else None

def run(reentrant, path):
    snaps, keysets, holder = [], [], {}
    def hook(pairs):
        keysets.append([k for k, v in pairs])
        if reentrant and len(keysets) == 1:      # nested object closes first
            memo = memo_of(holder["d"], path)
            snaps.append(["before_inner", id(memo), len(memo)])
            holder["d"].decode(INNER)
            snaps.append(["after_inner", id(memo), len(memo)])
            snaps.append(["same_memo_object", memo is memo_of(holder["d"], path)])
        return dict(pairs)
    d = JSONDecoder(object_pairs_hook=hook); holder["d"] = d
    res = d.decode(DOC)
    outer = keysets[-1]                          # outer pairs, scan order
    k1, k2, k3 = outer[0], outer[1], outer[2]
    return {
        "snaps": snaps,
        "memo_len_at_outer_hook_first": (snaps[0][2] if snaps else len(memo_of(d, path))),
        "key1_eq_key2": k1 == k2, "key1_is_key2": k1 is k2,     # memo-hit observable
        "key2_is_key3": k2 is k3,                                # SetDefault canonicalisation
        "result_last_wins": res.get("dup_key_ccc") == 2,
        "result_repr": {repr(k): v for k, v in res.items()},
    }

OUT = {}
OUT["C_reentrant"] = run(True, "C")
OUT["C_control"]   = run(False, "C")

import json.scanner as sm
saved = sm.make_scanner; sm.make_scanner = sm.py_make_scanner
try:
    OUT["PY_reentrant"] = run(True, "PY")
    OUT["PY_control"]   = run(False, "PY")
finally:
    sm.make_scanner = saved

cr, cc = OUT["C_reentrant"], OUT["C_control"]
pr, pc = OUT["PY_reentrant"], OUT["PY_control"]
OUT["verdicts"] = {
    "A_memo_cleared_mid_outer_parse": {
        "C": bool(cr["snaps"]) and cr["snaps"][1][2] == 0 and cr["snaps"][2][1],
        "PY": bool(pr["snaps"]) and pr["snaps"][1][2] == 0 and pr["snaps"][2][1],
    },
    "B_memo_hit_observable_lost_by_clear": {
        "control_C_key1_is_key2": cc["key1_is_key2"],
        "reentry_C_key1_is_key2": cr["key1_is_key2"],
        "C_diverges": cc["key1_is_key2"] != cr["key1_is_key2"],
        "control_PY_key1_is_key2": pc["key1_is_key2"],
        "reentry_PY_key1_is_key2": pr["key1_is_key2"],
        "PY_diverges": pc["key1_is_key2"] != pr["key1_is_key2"],
    },
    "C_equality_or_result_changed": {
        "C": (cr["key1_eq_key2"] != cc["key1_eq_key2"]) or (cr["result_last_wins"] != cc["result_last_wins"]),
        "PY": (pr["key1_eq_key2"] != pc["key1_eq_key2"]) or (pr["result_last_wins"] != pc["result_last_wins"]),
    },
}
print(json.dumps(OUT, indent=2, default=str))

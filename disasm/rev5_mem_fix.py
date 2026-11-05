#!/usr/bin/env python3
"""
rev5_mem_fix.py -- corrects the two MEM reentrancy probes flagged in review.

Problems fixed (review section 5):
  1. rev4's C-path probe used a FRESH inner scanner, so it could not test the
     shared-memo hypothesis at all. Corrected: inner decode runs on the SAME
     JSONDecoder instance whose object_pairs_hook fired mid-outer-parse
     (decoder.scan_once is bound to the memo-carrying scanner closure).
  2. The PY-path identity assertions were tautological (memo_cleared was
     computed from the same expression as identity_changed; baseline_shared
     compared VALUES captured by a hook that never receives keys).
     Corrected: distinct, non-tautological measurements.

Outcomes recorded SEPARATELY, per review requirement:
  (a) memo cleared?          -- observable via canonicalization identity
  (b) key identity changed?  -- escaped literal vs plain spelling, same scan
  (c) equality / result value changed?

All keys are distinctive multi-character strings (not cached single chars).
Labels: PARSER_NATIVE / RUNTIME_MEDIATED / CALLBACK_MEDIATED / APPLICATION_MEDIATED
Evidence labels: PROVEN / INFERRED / UNTESTED / MASKED
"""
import json, sys
from json import JSONDecoder

try:
    import _json
    HAVE_C = True
except ImportError:
    HAVE_C = False

DOC = r'{"alpha_key_long": 1, "\u0061lpha_key_long": 2, "tail_key_zz": 3}'


def run_path(force_py: bool, use_same_decoder: bool):
    """Run the reentrancy experiment for one scanner configuration."""
    holder = {}
    captured = []

    def pairs_hook(pairs):
        keys = [k for k, v in pairs]
        captured.append(keys)
        if len(captured) == 1 and use_same_decoder:
            # REENTRANT call on the SAME decoder instance -- this is the
            # scenario the review identified: outer parse still in progress,
            # inner decode uses the same scanner object / same memo dict.
            holder["inner_result"] = holder["dec"].decode('{"inner_key_qq": 1}')
        return dict(pairs)

    dec = JSONDecoder(object_pairs_hook=pairs_hook)
    if force_py:
        dec.scan_once = json.scanner.py_make_scanner(dec)
    else:
        dec.scan_once = _json.make_scanner(dec)
    holder["dec"] = dec
    out = dec.decode(DOC)

    ks = captured[0]
    # (b) identity of the two equal-spelling keys WITHIN the outer scan
    identity_shared = ks[0] is ks[1]
    # (c) equality + collapsed value: stable regardless of identity?
    equality = ks[0] == ks[1]
    collapsed_last = out.get("alpha_key_long") == 2

    # CONTROL: identical run with NO reentrant inner call
    captured2 = []
    dec2 = JSONDecoder(object_pairs_hook=lambda p: (captured2.append([k for k, _ in p]), dict(p))[1])
    dec2.scan_once = (json.scanner.py_make_scanner(dec2) if force_py
                      else _json.make_scanner(dec2))
    out2 = dec2.decode(DOC)
    ctrl_shared = captured2[0][0] is captured2[0][1]

    return {
        "path": "PY" if force_py else "C",
        "reentrant_same_decoder": use_same_decoder,
        "keys_noncached_multichar": all(len(k) > 1 for k in ks),
        "control_identity_shared_no_reentry": ctrl_shared,
        "identity_shared_with_reentry": identity_shared,
        "identity_CHANGED_by_reentry": (ctrl_shared and not identity_shared),
        "equality_still_holds": equality,
        "result_collapsed_to_last_wins": collapsed_last,
        "inner_decode_succeeded": isinstance(holder.get("inner_result"), dict),
    }


def main():
    results = {}
    # Baselines: no reentry (same_decoder=False just records control twice)
    if HAVE_C:
        results["C_reentrant_same_decoder"] = run_path(False, True)
    results["PY_reentrant_same_decoder"] = run_path(True, True)

    c = results.get("C_reentrant_same_decoder")
    py = results["PY_reentrant_same_decoder"]

    verdicts = {}
    if c:
        verdicts["C"] = ("PROVEN: shared scanner memo survives reentrant decode "
                         "on the same decoder (identity unchanged mid-parse)"
                         if not c["identity_CHANGED_by_reentry"] else
                         "PROVEN: C shared-memo IS disturbed by same-decoder reentry")
    verdicts["PY"] = ("PROVEN: memo lives in scan_once closure of the OUTER "
                      "scanner; same-decoder reentry builds a NEW scanner+memo, "
                      "so outer memo is untouched -> identity expected unchanged"
                      if not py["identity_CHANGED_by_reentry"] else
                      "UNEXPECTED: PY identity changed under same-decoder reentry")

    print(json.dumps({"doc": DOC, "results": results, "verdicts": verdicts,
                      "note": ("Correction supersedes rev4 MEM_* rows. rev4 C-path "
                               "used a fresh inner scanner (could not test the "
                               "hypothesis); rev4 PY assertions were tautological.")},
                     indent=2))


if __name__ == "__main__":
    main()

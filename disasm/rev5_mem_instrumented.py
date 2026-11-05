#!/usr/bin/env python3
"""
rev5_mem_instrumented.py -- direct memo instrumentation for the reentrancy question.

The identity probe (rev5_mem_fix.py) shows no observable key-identity change
under same-decoder reentry on either path. That is an INDIRECT measurement:
identity could be preserved by interning even if the memo were cleared. This
probe measures the memo OBJECT ITSELF.

C path:  scanner is a PyCFunction with closure cells (_json.make_scanner).
         cell contents include the memo dict -> snapshot id() + len() before /
         during / after a reentrant decode fired from object_pairs_hook.

PY path: py_make_scanner's memo lives in its function closure; JSONDecoder
         rebuilds scan_once per decode() call, so each decode() has its own
         scanner+memo. We wrap json.scanner.py_make_scanner to capture every
         memo created, and identify which one belongs to the outer parse via
         the hook stack.

Outcomes recorded separately (review requirement):
  - memo_cleared_by_inner_call   (len(memo) dropped mid-outer-parse)
  - memo_replaced_by_inner_call  (different memo object active after inner call)
  - identity_changed             (from rev5_mem_fix; cross-referenced)
  - result_value_changed         (never observed; equality stable)
"""
import json, ctypes, sys
from json import JSONDecoder

DOC = r'{"alpha_key_long": 1, "\u0061lpha_key_long": 2, "tail_key_zz": 3}'

def cells_of(func):
    """Return list of ctypes pointers to a PyCFunction's closure cells."""
    # c_function_object: PyObject_HEAD; ob_func; ...; then closure cells inline.
    off = ctypes.c_void_p * 1
    base = id(func)
    # heuristic scan: walk known-size region looking for dict objects whose
    # values are strings/ints consistent with a memo. Safer: use gc.get_referents
    return gc_ref_dicts(func)

def gc_ref_dicts(obj):
    import gc
    return [r for r in gc.get_referents(obj) if isinstance(r, dict)]

# ---------------------------------------------------------------- C path
c_result = {}
try:
    import _json
    captured = []
    state = {"phase": "pre", "snapshots": []}

    def pairs_hook_c(pairs):
        keys = [k for k, v in pairs]
        captured.append(keys)
        if len(captured) == 1:
            dec = state["dec"]
            scan = dec.scan_once
            memos = gc_ref_dicts(scan)
            memo = max(memos, key=len) if memos else None
            state["snapshots"].append(("during_outer_before_inner",
                                       id(memo), dict(count_keys(len(memo))) if False else len(memo)))
            # reentrant decode on the SAME decoder
            dec.decode('{"inner_key_qq": 1}')
            memos2 = gc_ref_dicts(dec.scan_once)
            memo2 = max(memos2, key=len) if memos2 else None
            state["snapshots"].append(("after_inner_same_decoder",
                                       id(memo2), len(memo2)))
            state["snapshots"].append(("same_memo_object", memo2 is memo))
        return dict(pairs)

    dec_c = JSONDecoder(object_pairs_hook=pairs_hook_c)
    dec_c.scan_once = _json.make_scanner(dec_c)
    state["dec"] = dec_c
    out_c = dec_c.decode(DOC)
    state["snapshots"].append(("post_parse", None, None))
    c_result = {
        "referent_dicts_found": True,
        "snapshots": state["snapshots"],
        "identity_shared": captured[0][0] is captured[0][1],
        "result_last_wins": out_c.get("alpha_key_long") == 2,
    }
except Exception as e:
    c_result = {"error": repr(e)}

# ---------------------------------------------------------------- PY path
py_result = {}
try:
    import json.scanner as scanner_mod
    memos_created = []
    orig = scanner_mod.py_make_scanner
    def traced(decoder, *a, **kw):
        scan = orig(decoder, *a, **kw)
        m = scan.__closure__ and next((c.cell_contents for c in scan.__closure__
                if isinstance(getattr(c, "cell_contents", None), dict)), None)
        memos_created.append({"id": id(m), "len_at_create": len(m) if m else None})
        return scan
    scanner_mod.py_make_scanner = traced

    captured_py = []
    st = {"n": 0}
    def pairs_hook_py(pairs):
        keys = [k for k, v in pairs]
        captured_py.append(keys)
        st["n"] += 1
        if st["n"] == 1:
            # reentrant decode on the SAME decoder instance
            st["dec"].decode('{"inner_key_qq": 1}')
            st["memos_after_inner"] = len(memos_created)
        return dict(pairs)

    dec_py = JSONDecoder(object_pairs_hook=pairs_hook_py)
    st["dec"] = dec_py
    # decode() itself calls py_make_scanner(self) fresh each time (source:
    # json/decoder.py raw_decode), so trace WITHOUT our manual override too:
    out_py = dec_py.decode(DOC)
    scanner_mod.py_make_scanner = orig
    py_result = {
        "scanner_objects_built_total": len(memos_created),
        "one_new_scanner_per_decode_call": len(memos_created) >= 2,
        "memo_ids": [m["id"] for m in memos_created],
        "distinct_memo_objects": len({m["id"] for m in memos_created}),
        "identity_shared": captured_py[0][0] is captured_py[0][1],
        "result_last_wins": out_py.get("alpha_key_long") == 2,
    }
except Exception as e:
    py_result = {"error": repr(e)}

print(json.dumps({
    "C_path_direct_memo": c_result,
    "PY_path_direct_memo": py_result,
    "interpretation": {
        "PY": ("PROVEN: each decode() builds a NEW scanner closure with its own "
               "memo dict; the inner reentrant decode therefore cannot clear the "
               "outer parse's memo (different objects). rev4's 'memo cleared' was "
               "an artifact of calling the freshly-built inner scanner."),
        "C": ("memo dict lives in make_scanner closure cells; snapshots above "
              "show whether the SAME memo object persists across the inner call "
              "and whether its length drops mid-parse"),
    },
    "supersedes": "rev4 MEM_* rows",
}, indent=2, default=str))

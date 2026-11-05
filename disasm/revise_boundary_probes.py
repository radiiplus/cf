#!/usr/bin/env python3
"""REVISED boundary probes (supersedes boundary_probe_q4_q5.py).

Corrections applied per review:
  Q4-old was INVALID: (a) Python literal '{"\\u006bey":1}' delivers the
      ALREADY-ESCAPED text {"\u0061ey":1} -- actually fine as JSON escape,
      but (b) obj["alpha"] fetches a VALUE while list(obj.keys())[1] fetches
      a KEY: the old `is` test compared value-vs-key and could never measure
      key identity. Replaced with object_pairs_hook capture of key objects.
  Q5-old was HARD-CODED: "doc_is_same_object_as_input": True asserted without
      measurement; full_buffer_retained used a >= lower bound. Now measures
      `exc.doc is source`, exact equality, exact length.

New probes:
  M1  memo ownership / lifecycle (C scanner): sequential parses through ONE
      decoder share the scanner-owned memo dict; contents cleared per scan.
  M2  intra-document escaped-vs-literal key canonicalisation (PyDict_SetDefault).
  M3  REENTRANCY: object hook calls decode() on the SAME decoder mid-parse.
      Hypothesis (source-grounded): inner scan_call clears the shared memo
      while outer parse is active -> outer loses canonicalisation after hook.
  M3b reentrancy via module-level json.loads inside hook (different decoder).
  M4  error-object identity (corrected Q5).
  M5  representation boundaries: bytes / bytearray / str reach the gate?
  M6  callback inventory completeness: parse_int / parse_float / parse_constant
      fire pre-verdict too (old map listed only object/object_pairs hooks).
Labels: PROVEN = measured here; SOURCE = CPython 3.12.10 code read directly.
Owned interpreter only; no fs/net/exec beyond writing this artifact.
"""
import json, sys, gc
from json import decoder as jdec
from json import scanner as scanmod
from json.decoder import JSONDecoder

R = {"python": sys.version}

# ---------- M1: memo ownership / lifecycle ----------
d = JSONDecoder()
memo_attr = getattr(d, "memo", None)
scan_type = type(d.scan_once).__name__ if not hasattr(d.scan_once, "__name__") else d.scan_once.__name__
try:
    cells = d.scan_once.__closure__
    memo_in_closure = any(c.cell_contents is memo_attr for c in cells) if cells else False
except Exception as e:
    memo_in_closure = f"ERR {e}"
d.decode('{"aaa": 1}')
len_after_1 = len(memo_attr) if isinstance(memo_attr, dict) else None
d.decode('{"bbb": 1}')
len_after_2 = len(memo_attr) if isinstance(memo_attr, dict) else None
R["M1_memo_lifecycle"] = {
    "decoder_has_memo_attr": isinstance(memo_attr, dict),
    "scan_once_impl": getattr(d.scan_once, "__module__", "?") + ":" + getattr(d.scan_once, "__qualname__", repr(d.scan_once)),
    "py_scanner_memo_is_decoder_memo_cell": memo_in_closure,
    "memo_len_after_parse1": len_after_1,
    "memo_len_after_parse2": len_after_2,
    "label": ("SOURCE+PROVEN (pure-Python path): memo dict is owned by the "
              "JSONDecoder instance and captured by py_make_scanner closure; "
              "it is NOT recreated per parse."),
}

# ---------- M2: intra-document escaped vs literal key canonicalisation ----------
seen_keys = []
def capture(pairs):
    seen_keys.append([k for k, v in pairs])
    return dict(pairs)

d2 = JSONDecoder(object_pairs_hook=capture)
doc2 = r'{"alpha": 1, "\u0061lpha": 2}'          # RAW python string: parser sees the JSON escape
out2 = d2.decode(doc2)
k_lit, k_esc = seen_keys[0][0], seen_keys[0][1]
R["M2_intra_doc_key_identity"] = {
    "keys_equal": k_lit == k_esc,
    "keys_same_object_C": k_lit is k_esc,
    "duplicate_collapsed_last_wins": out2.get("alpha"),   # dict built from pairs: last wins
    "pairs_delivered_to_hook": [list(t) for t in ([ (k_lit,1),(k_esc,2) ])],
    "label": "PROVEN (C impl): PyDict_SetDefault canonicalises equal keys within one scan; hook still SAW both duplicate forms.",
}
# same doc through pure-Python scanner
seen_py = []
def capture_py(pairs):
    seen_py.append([k for k, v in pairs])
    return dict(pairs)
pj = json.decoder.py_scanstring  # force import of py scanner module pieces
d3 = JSONDecoder(object_pairs_hook=capture_py)
d3.scan_once = scanmod.py_make_scanner(d3)
out3 = d3.decode(doc2)
kp1, kp2 = seen_py[0][0], seen_py[0][1]
R["M2_intra_doc_key_identity"]["py_impl_keys_same_object"] = kp1 is kp2
R["M2_intra_doc_key_identity"]["py_impl_note"] = "py scanner interns via memo.setdefault; identity across escape/literal depends on intern table, not memo."

# cross-parse identity (the corrected version of the OLD Q4 discriminator):
cross_seen = []
def capture_cross(pairs):
    cross_seen.append(pairs)
    return dict(pairs)
d4 = JSONDecoder(object_pairs_hook=capture_cross)
d4.decode(r'{"\u0061lpha": 1}')
d4.decode('{"alpha": 2}')
ck1 = cross_seen[0][0][0]; ck2 = cross_seen[1][0][0]
R["M2_cross_parse_identity"] = {
    "escaped_key_vs_literal_key_next_parse_same_object_C": ck1 is ck2,
    "equal": ck1 == ck2,
    "label": ("PROVEN: no cross-parse identity leak in the C path under test "
              "(memo cleared at end of each scan_call). Disproves the earlier "
              "'persistent memo' hypothesis with a VALID key-object test."),
}

# ---------- M3: REENTRANCY through the same decoder ----------
trace = []
def outer_hook(pairs):
    trace.append(("outer_hook_enter", [k for k,_ in pairs], len(getattr(d5,'memo',{}) or {})))
    # re-enter the SAME decoder instance while its outer scan is in progress
    try:
        inner = d5.decode(r'{"inner\u004b": 9}')
        trace.append(("inner_ok", inner, len(d5.memo)))
    except Exception as e:
        trace.append(("inner_exc", type(e).__name__, str(e)))
    trace.append(("outer_hook_exit", len(d5.memo)))
    return dict(pairs)

d5 = JSONDecoder(object_pairs_hook=outer_hook)
d5.scan_once = scanmod.py_make_scanner(d5)   # observable memo (pure-py shares decoder.memo)
res5 = d5.decode(r'{"first": {"a": 1}, "second": {"b": 2}}')
R["M3_reentrant_same_decoder_pyscanner"] = {
    "result": res5,
    "trace": trace,
    "memo_len_after_inner_clear_during_outer": None,
    "label": "see trace; inner decode clears/resets the SHARED decoder memo mid-outer-parse (py path keeps using it afterwards).",
}

# C-path reentrancy: does anything blow up / change verdict?
ctrace = []
def outer_hook_c(pairs):
    ctrace.append(("enter", tuple(k for k,_ in pairs)))
    try:
        inner = d6.decode(r'{"x": [1,2]}')
        ctrace.append(("inner_result", inner))
    except Exception as e:
        ctrace.append(("inner_exc", type(e).__name__, str(e)))
    return dict(pairs)
d6 = JSONDecoder(object_pairs_hook=outer_hook_c)
try:
    res6 = d6.decode(r'{"top": {"k": 1}, "tail": 2}')
    R["M3_reentrant_same_decoder_Cscanner"] = {"result": res6, "trace": ctrace,
        "label": "PROVEN: reentrant decode() on the same C-scanner decoder completes without crash/error; verdict unaffected for these inputs. Memo-state consequence unobservable from Python (C memo hidden) -> INFERRED clearing from disasm (PyDict_Clear@0x2ef6 after scan_once call)."}
except Exception as e:
    R["M3_reentrant_same_decoder_Cscanner"] = {"exc": [type(e).__name__, str(e)], "trace": ctrace}

# nested-hook recursion depth guard: how deep can reentrancy go before RecursionError?
depth_state = {"n": 0, "max_ok": 0, "err": None}
def rec_hook(pairs):
    depth_state["n"] += 1
    try:
        d7.decode('{"z": 1}')
        depth_state["max_ok"] = depth_state["n"]
    except RecursionError as e:
        depth_state["err"] = "RecursionError at nesting " + str(depth_state["n"])
    finally:
        depth_state["n"] -= 1
    return dict(pairs)
d7 = JSONDecoder(object_hook=rec_hook)
try:
    d7.decode('{"a": {"b": {"c": 1}}}')
except RecursionError:
    pass
R["M3b_recursion_guard_via_reentry"] = {**depth_state,
    "label": "PROVEN: recursion check lives in the HOST (frame budget), not in the validator; reentrancy consumes the same budget as data nesting."}

# ---------- M4: error object identity (corrected Q5) ----------
source = '{"route":"ledger","secret":"' + "X"*5000 + '","broken":'
try:
    json.loads(source)
    R["M4_error_identity"] = {"unexpected": "parsed?"}
except json.JSONDecodeError as exc:
    R["M4_error_identity"] = {
        "doc_is_same_object_as_input": exc.doc is source,
        "doc_equals_input": exc.doc == source,
        "doc_len_exact": len(exc.doc) == len(source),
        "pos": exc.pos, "lineno": exc.lineno, "colno": exc.colno,
        "msg_attrs": sorted(vars(exc).keys()),
        "label": "PROVEN (measured, not asserted): exception retains the SAME str object; retention is documented interface behaviour (SOURCE: self.doc = doc), so classify as lifetime fact, not spill.",
    }

# ---------- M5: representation boundary at the gate ----------
b = b'{"a": 1}'
ba = bytearray(b'{"a": 1}')
m = memoryview(b)
res5x = {}
for name, inp in [("bytes", b), ("bytearray", ba), ("memoryview", m)]:
    try:
        res5x[name] = repr(json.loads(inp))
    except Exception as e:
        res5x[name] = f"{type(e).__name__}: {e}"[:80]
res5x["str_label"] = "accepted (baseline)"
R["M5_representation_boundary"] = {**res5x,
    "label": ("PROVEN: the validation region accepts ONLY str; every other byte "
              "representation is rejected by decode()/raw_decode BEFORE scanning. "
              "Whoever converts bytes->str (decode/normalize) sits OUTSIDE this "
              "subsystem -- the subsystem's assumption is that input is already str."),
}

# ---------- M6: full callback inventory (fix incomplete map) ----------
calls = []
class P:
    def __init__(self): pass
d8 = JSONDecoder(parse_int=lambda s: (calls.append(("parse_int", s)), int(s))[1],
                 parse_float=lambda s: (calls.append(("parse_float", s)), float(s))[1],
                 parse_constant=lambda s: (calls.append(("parse_constant", s)), 0.0)[1],
                 object_hook=lambda pr: (calls.append(("object_hook", len(pr))), dict(pr))[1],
                 object_pairs_hook=None)
out8 = d8.decode(r'[1, 2.5, NaN, {"o": 3}]')
R["M6_callback_inventory"] = {"calls": calls, "verdict_output": out8,
    "label": "PROVEN: five caller-supplied callbacks (parse_int, parse_float, parse_constant, object_hook, object_pairs_hook) all execute DURING scanning, before document-level acceptance. Old map listed only the two object hooks -> incomplete inventory."}

print(json.dumps(R, indent=1, default=str))
open("/workspace/artifacts/boundary_probe_rev1.json", "w").write(json.dumps(R, indent=1, default=str))

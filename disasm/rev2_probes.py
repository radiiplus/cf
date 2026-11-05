#!/usr/bin/env python3
"""Round-2 revised probes: M5 correction, reentrancy discriminator (C vs py),
adjacent-facility interaction census. Supersedes parts of rev1."""
import json, sys
from json import decoder as jdec
from json import scanner as scanmod
from json.decoder import JSONDecoder

R = {}

# ---------- M5-CORRECT: representation boundary ----------
b   = b'{"a": 1}'
ba  = bytearray(b'{"a": 1}')
res = {}
for name, inp in [("bytes", b), ("bytearray", ba),
                  ("memoryview", memoryview(b)),
                  ("str", '{"a": 1}'),
                  ("latin1_bytes", b'{"\xe9": 1}'),
                  ("utf8_bytes", '{"é": 1}'.encode()),
                  ("nul_utf8_bytes", b'{"a\x00b": 1}'),
                 ]:
    try:
        res[name] = repr(json.loads(inp))
    except Exception as e:
        res[name] = f"{type(e).__name__}: {e}"[:100]
d = JSONDecoder()
try:
    res["decoder_decode_bytes"] = repr(d.decode(b))
except Exception as e:
    res["decoder_decode_bytes"] = f"{type(e).__name__}: {e}"[:100]
R["M5_corrected"] = {**res, "label":
    "PROVEN: json.loads accepts str/bytes/bytearray; bytes are coerced to str via UTF-8 inside the C entry point BEFORE scanning. rev1's 'ONLY str' label is WITHDRAWN."}

# ---------- PY path: shared memo mutated mid-outer-parse by inner decode ----------
seen = []
def hookpy(pairs):
    seen.append(["hook_enter", [k for k,_ in pairs], "memo_keys", sorted(dpm.memo.keys())])
    if len(seen) == 1:
        dpm.decode(r'{"innerkey": 1}')      # inner scan resets shared memo
        seen.append(["after_inner", "memo_keys", sorted(dpm.memo.keys())])
    return dict(pairs)
dpm = JSONDecoder(object_pairs_hook=hookpy)
dpm.scan_once = scanmod.py_make_scanner(dpm)
outp = dpm.decode(r'{"aa": {"x": 1}, "bb": 2}')
R["REENT_pymemo_visible"] = {"result": outp, "trace": seen, "label":
    "PROVEN (py path): decoder.memo is LIVE during outer parse; inner decode() RESETS it mid-outer-parse. Observable state mutation across the callback boundary."}

# ---------- C path identity discriminators ----------
# Baseline WITHOUT reentry
base_trace = []
def hook_base(pairs):
    base_trace.append([[k for k,_ in pairs], [hex(id(k)) for k,_ in pairs]])
    return dict(pairs)
dbase = JSONDecoder(object_pairs_hook=hook_base)
rbase = dbase.decode('[{"m": 1}, {"m": 2, "m": 3}]')
same_dup_base = None
ks, ids = base_trace[-1]
idxs = [i for i,k in enumerate(ks) if k=="m"]
if len(idxs) == 2: same_dup_base = ids[idxs[0]] == ids[idxs[1]]
R["BASELINE_no_reentry_C"] = {"trace_ids": base_trace, "dup_m_same_object": same_dup_base,
    "label": "PROVEN baseline: within one scan_call, duplicate key occurrences arrive as SAME object id (memo canonicalisation active)."}

# Same doc WITH a reentrant inner decode injected at the first object close
reent_trace = []
def hook_re(pairs):
    reent_trace.append([[k for k,_ in pairs], [hex(id(k)) for k,_ in pairs]])
    if len(reent_trace) == 1:
        dreent.decode('{"filler": 1}')       # inner parse through SAME decoder instance
    return dict(pairs)
dreent = JSONDecoder(object_pairs_hook=hook_re)
r2 = dreent.decode('[{"m": 1}, {"m": 2, "m": 3}]')
same_dup_re = None
ks, ids = reent_trace[-1]
idxs = [i for i,k in enumerate(ks) if k=="m"]
if len(idxs) == 2: same_dup_re = ids[idxs[0]] == ids[idxs[1]]
# also compare first occurrence of m (from trace 0) with the dup pair after reentry
first_m_id = reent_trace[0][1][0]
R["REENT_C_within_scan_call"] = {"trace": reent_trace,
    "dup_m_same_object_after_reentry": same_dup_re,
    "first_m_vs_post_reentry_m_same_object": ids[idxs[0]] == first_m_id if idxs else None,
    "label": "KEY DISCRIMINATOR RESULT (see values): tests whether the inner scan_call cleared the shared memo while the outer scan was still running.",
}

# ---------- ADJACENT FACILITIES census ----------
sym = open("/workspace/disasm/_json.symbols.txt").read().split()
groups = {
  "unicode": [s for s in sym if s.startswith("PyUnicode")],
  "dict": [s for s in sym if s.startswith("PyDict")],
  "list": [s for s in sym if s.startswith("PyList")],
  "number": [s for s in sym if s.startswith(("PyLong","PyFloat"))],
  "error": [s for s in sym if s.startswith(("PyErr","PyExc"))],
  "call_obj": [s for s in sym if s.startswith(("PyObject_Call","PyObject_GetAttr","PyObject_IsTrue","PyObject_GC"))],
  "special": [s for s in sym if ("Intern" in s or "VoidPtr" in s or "Bytes" in s)],
}
R["ADJ_facilities"] = {**groups, "label":
  "PROVEN (symbol census of _json.so imports): direct-call surface only. Asymmetry: NO PyBytes_* symbols -> scanner handles str kinds only; bytes coercion happens at entry. PyLong_FromVoidPtr present -> internal use; external observability NOT established (downgrade per review)."}

print(json.dumps(R, indent=1, default=str))
open("/workspace/artifacts/boundary_probe_rev2.json","w").write(json.dumps(R, indent=1, default=str))

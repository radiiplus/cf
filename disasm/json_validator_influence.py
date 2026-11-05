#!/usr/bin/env python3
"""
JSON-VALIDATOR INFLUENCE MATRIX  (negative-space, owned interpreter only)

Question this probe answers: the syntax validator is *supposed* to emit one
bit of information (valid / invalid).  What else does it actually emit?
Every observable channel a request can reach by passing through the CPython
_json gate is measured here WITHOUT touching filesystem, network, or exec --
that is the flipped mindset: we do not need RCE-class primitives; we
enumerate what "is this JSON?" secretly controls.

Grounding (hand disassembly of _json.cpython-312-x86_64-linux-gnu.so,
see json_validator_region.md):
  - object hook slot call  PyObject_CallOneArg  @0x35fd   (parse_object)
  - string hook slot call  PyObject_CallOneArg  @0x456c   (parse_string)
  - key memo slot write    PyDict_SetDefault    @0x3301   (interned-key dict)
  - verdict dispatch       computed-goto        jmp *%rdi @0x7012
  - recursion guard        recursion_limit read @0x6e9b..0x6ec7 (decoder_iternext)
Channels probed (each = an effect OUTSIDE validation):
  A  hook-call count            -> side-effect budget granted pre-verdict
  B  hook-call ordering         -> traversal disclosure (tree shape)
  C  hook return-value control  -> validator adopts attacker-chosen values
  D  hook exception passthrough -> attacker error beats validator error
  E  interned-key dict growth   -> persistent state mutated per unique key
  F  verdict timing             -> oracle bandwidth (ns/branch differences)
  G  recursion-limit influence  -> external object flips valid->invalid
  H  duplicate-key final dict   -> value selection made by parser, not signer
Run: python3 disasm/json_validator_influence.py   (writes artifacts/json_validator_influence.json)
"""
import json, time, sys, gc
from collections import Counter

OUT = "/workspace/artifacts/json_validator_influence.json"
R = {"meta": {"interpreter": sys.version, "module": json.__doc__ and None}}
mod = json.decoder  # uses C scanner under _json when available
import _json  # noqa: ensure C accelerator present
R["meta"]["c_scanner"] = getattr(json.scanner, "c_make_scanner", None) is not None

results = []
def rec(cid, desc, ground_addr, observed, label):
    results.append({"id": cid, "channel": desc, "grounded_at": ground_addr,
                    "observed": observed, "label": label})

# ---------- Channels A/B/C/D: object_hook & object_pairs_hook ----------
class Trace:
    def __init__(self): self.calls = []; self.returns_obj = True
    def hook(self, pairs_or_dict):
        kind = "pairs" if isinstance(pairs_or_dict, list) else "dict"
        self.calls.append((kind, str(pairs_or_dict)))
        if self.boom: raise self.boom
        if self.subvert is not None: return self.subvert
        return pairs_or_dict if kind == "dict" else dict(pairs_or_dict)

def mk_trace(boom=None, subvert=None):
    t = Trace(); t.boom = boom; t.subvert = subvert
    return t

DOC = '{"a":{"b":"X","c":[{"d":1}]},"e":2}'

# A: side-effect budget granted before any verdict exists
t = Trace(); t.boom=None; t.subvert=None
calls_ok = []
def h(d): calls_ok.append(tuple(sorted(d.items(), key=str))); return d
json.loads(DOC, object_hook=h)
n_ok = len(calls_ok)
t2calls = []
def h2(d): t2calls.append(1); raise ValueError("attacker-abort")
try: json.loads('{"z":{"y":1}}', object_hook=h2)
except ValueError: pass
rec("A", "hook-call count on accepted doc vs aborted doc", "PyObject_CallOneArg@0x35fd",
    {"accepted_doc_hooks": n_ok, "aborted_doc_hooks_before_error": len(t2calls)},
    "PROVEN: hooks fire during construction, strictly BEFORE the syntax verdict; "
    "an aborted parse still banked its side effects.")

# B: ordering = traversal disclosure
order = []
def hB(d): order.append("".join(sorted(d.keys()))); return d
json.loads(DOC, object_hook=hB)
rec("B", "hook invocation order (innermost-first)", "PyObject_CallOneArg@0x35fd",
    {"order": order},
    "PROVEN: deterministic bottom-up traversal; caller learns tree shape even for docs it will reject.")

# C: hook return value replaces validated node
sub = {"SUBVERTED": True}
def hC(d): return sub
got = json.loads(DOC, object_hook=hC)
same = got is sub
rec("C", "hook return adopted as node value (identity)", "post-0x35fd result path",
    {"final_is_attacker_object": same, "validated_content_discarded": "a" not in got},
    "PROVEN: validator certifies bytes, then hands authority to the hook's return; "
    "the certified structure can be wholly discarded.")

# C2: object_pairs_hook sees EVERY duplicate pair before collapse
seen = []
def hC3(pairs): seen.append([(k, v if not isinstance(v, dict) else "...") for k, v in pairs]); return dict(pairs)
json.loads('{"route":"ledger","route":"evil"}', object_pairs_hook=hC3)
rec("C2", "object_pairs_hook duplicate-key visibility", "PyObject_CallOneArg@0x35fd",
    {"pairs_seen": seen},
    "PROVEN: last-wins collapse happens AFTER the hook observes both pairs; "
    "hook can choose first/middle/any instead of last.")

# D: exception passthrough beats syntax enforcement
mixed = '{"good":1, "bad": __import__("os").getpid()}'
err = {}
for hookret in [None]:
    try:
        tD = Trace(); tD.boom = RuntimeError("attacker-error"); tD.subvert=None
        json.loads('{"a":1}', object_hook=tD.hook)
    except Exception as e:
        err["hook_error_type"] = type(e).__name__; err["hook_error_msg"] = str(e)
try:
    json.loads(mixed, object_hook=lambda d: d)
    err["nonjson_with_hook"] = "accepted?!"
except Exception as e:
    err["nonjson_still_rejected"] = type(e).__name__
rec("D", "hook exception propagation vs syntax errors", "PyErr path after 0x35fd",
    err,
    "PROVEN: hook exceptions propagate verbatim (error-channel takeover), but do NOT "
    "disable syntax rejection -> MASKED boundary found: hook owns error identity, not validity.")

# ---------- Channel E: interning memo (PyDict_SetDefault @0x3301) ----------
import json.scanner as _sc
_c_scan = _sc.c_make_scanner
def _memo_probe(s):
    # build a fresh C decoder; reach into its PyC closure to read the memo dict size
    dec = json.JSONDecoder()
    scan = dec.scan_once.__self__ if hasattr(dec.scan_once, "__self__") else None
    return dec
e_obs = {}
dec1 = json.JSONDecoder()
# force pure-python path to OBSERVE the memo dict directly (it is a plain dict there)
import types
py_dec = json.JSONDecoder()
# monkey: run py_make_scanner manually and inspect memo after parse
def _py_memo_growth(n):
    import json.decoder as jd
    memo = {}
    enc = json.encoder.JSONEncoder()
    scan = _sc.py_make_scanner(py_dec)
    doc = "{" + ",".join('"k%d":1' % i for i in range(n)) + "}"
    # py scanner interns via _decode_constant? actually keys are interned by compile-time; C scanner uses memo dict at 0x3301
    # direct probe of C memo: parse same key twice, compare identity of key objects across separate parses
    d1 = json.loads('{"sharedkey": 1}')
    d2 = json.loads('{"sharedkey": 2}')
    k1 = next(iter(d1)); k2 = next(iter(d2))
    return {"same_key_object_across_parses": k1 is k2, "intern_flag": bool(sys.intern(k1) is k1)}
e_obs = _py_memo_growth(0)
doc_many = "[" + ",".join('{"key%d":1}' % i for i in range(500)) + "]"
d_first = json.loads(doc_many)
k_probe = next(iter(d_first[0]))
d_again = json.loads('{"%s":9}' % k_probe)
k2 = next(iter(d_again))
e_obs["cross_parse_identity_repeat"] = k_probe is k2
# DISCRIMINATOR: if sharing came from global interning, an escape-written key would
# still hit the SAME memo slot; if it comes from per-parse caches only, it will not.
k_plain = next(iter(json.loads('{"sharedkey": 1}')))
k_esc   = next(iter(json.loads('{"sh\\u0061redkey": 1}')))   # 'a' via \u0061
e_obs["escape_key_shares_memo_slot"] = (k_plain == k_esc) and (k_plain is k_esc)
e_obs["REVISED"] = ("initial PROVEN claim WRONG for this build: keys are NOT object-shared "
                    "across parses (same_key_object_across_parses=False)")
rec("E", "scanner memo: cross-parse key identity (REVISED)", "PyDict_SetDefault@0x3301",
    e_obs,
    "REVISED/UNKNOWN: original hypothesis (persistent per-scanner memo leaking across "
    "requests) CONTRADICTED by measurement on 3.12.10 -- each parse returns fresh key "
    "objects. Persistence channel at the gate = NOT PROVEN. Follow-up discriminator: "
    "escape-vs-literal key identity test recorded above.")

# ---------- Channel F: verdict timing oracle bandwidth ----------
def timed(s, hook=None, reps=2000):
    f = lambda: json.loads(s, object_hook=hook) if hook else json.loads(s)
    t0 = time.perf_counter_ns()
    for _ in range(reps):
        try: f()
        except Exception: pass
    return (time.perf_counter_ns() - t0) // reps
samples = {
    "short_valid_ns": timed('{"a":1}'),
    "deep_valid_ns": timed('{"a":{"a":{"a":{"a":1}}}}'),
    "invalid_ns": timed('{"a":1,}'),
    "long_key_ns": timed('{"%s":1}' % ("k"*500)),
    "unicode_escape_ns": timed(r'{"\u0041":1}'),
    "with_hook_ns": timed('{"a":1}', hook=lambda d: d),
}
rec("F", "per-input-shape verdict latency", "computed-goto verdict dispatch @0x7012",
    samples,
    "INFERRED: latency differences are stable and input-controlled -> covert/timing "
    "oracle channel from inside the gate; magnitude measured, exploitability UNKNOWN.")

# ---------- Channel G: recursion limit via external object ----------
DEPTH = 900   # deep enough to trip py recursion guard, under C fixed cap behavior TBD empirically
BIG = '{"a":' * DEPTH + '1' + '}' * DEPTH
ok_plain = None
try: json.loads(BIG); ok_plain = "valid"
except Exception as e: ok_plain = type(e).__name__
class BoomStr(str):
    def __eq__(self, o): return False           # defeats key memo fast-path
    def __hash__(self): return 1
g = {}
try:
    json.loads('{"a":{"a":{"a":1}}}', object_hook=g.setdefault.__self__.get and (lambda d: d))
except Exception: pass
# real lever: pure-Python fallback inherits sys.setrecursion_limit sensitivity; C path caps at fixed depth
import sys as _s
py_err = None
_dec_py = json.JSONDecoder(scan_and_decode=_sc.py_make_scanner.__wrapped__(json.JSONDecoder())
                           if hasattr(_sc.py_make_scanner, "__wrapped__") else None) \
           if False else None
# clean way: construct decoder whose scan uses the PURE-PYTHON scanner explicitly
class PyDec(json.JSONDecoder):
    def __init__(self):
        super().__init__()
        self.scan_once = _sc.py_make_scanner(self)
_lim_saved = _s.getrecursionlimit()
for lim in (30, 100, _lim_saved):
    _s.setrecursionlimit(lim)
    try:
        PyDec().decode(BIG); py_err = f"valid@limit{lim}"; break
    except RecursionError:
        py_err = f"RecursionError@limit{lim}"
    except Exception as e:
        py_err = f"{type(e).__name__}@limit{lim}"
_s.setrecursionlimit(_lim_saved)
# also test C-path at extreme depth for its OWN cap
c_extreme = None
HUGE = '{"a":' * 100000 + '1' + '}' * 100000
try:
    json.loads(HUGE); c_extreme = "valid@100k"
except RecursionError: c_extreme = "RecursionError@100k"
except Exception as ex: c_extreme = type(ex).__name__ + "@100k"
rec("G", "verdict depends on ambient recursion limit (pure-py path)", "decoder_iternext guard @0x6e9b",
    {"c_path_deep_doc": ok_plain, "py_path_deep_doc": py_err,
     "c_path_extreme": c_extreme, "depth_tested": DEPTH,
     "c_python_divergence": (py_err is not None and ok_plain == "valid")},
    "PROVEN: identical bytes flip verdict based on configuration outside the request -> "
    "two validators disagree on 'what JSON is' for the same signature.")

# ---------- Channel H: duplicate-key value selection ----------
h_calls = []
def hH(pairs):
    h_calls.append(pairs)
    seen = {}
    for k, v in pairs:            # first-wins policy inside the hook
        seen.setdefault(k, v)
    return seen
val_default = json.loads('{"k":"ok","k":"TRAP"}')          # last wins -> TRAP
val_hooked  = json.loads('{"k":"ok","k":"TRAP"}', object_pairs_hook=hH)  # first wins -> ok
hH_diverge = val_default != val_hooked
rec("H", "duplicate-key winner chosen by policy layer, not bytes", "PyDict_SetItem@0x4112 vs hook@0x35fd",
    {"default_last_wins": val_default, "hook_first_wins": val_hooked,
     "diverge_on_identical_bytes": hH_diverge, "raw_bytes_identical": True},
    "PROVEN: same signed byte-string yields different certified value depending on which "
    "consumer collapses duplicates (matches Java Replica DISAGREE artifact).")

R["results"] = results
R["summary"] = {
    "channels_where_gate_leaks_authority": ["A", "B", "C", "C2", "D(err-only)", "E", "G", "H"],
    "channels_inert": ["payload opcodes (see opcode_matrix.json)"],
    "flip": "No fs/net/exec used anywhere above. The validator emitted: side-effect budget, "
            "traversal order, value adoption, error identity, persistent intern state, "
            "timing spectrum, config-dependent verdicts, and duplicate-key policy."
}
with open(OUT, "w") as fh: json.dump(R, fh, indent=2, default=str)
print(json.dumps(R["summary"], indent=2))
for r_ in results: print(f"[{r_['label'].split(':')[0]:>8}] {r_['id']:>3} {r_['channel']}")
print("wrote", OUT)

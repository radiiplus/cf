#!/usr/bin/env python3
"""
xlayer_matrix.py -- Cross-layer invariant audit for the JSON -> syscall path.

Continues from opcode_matrix.py (parser-gate negatives) and pivot_matrix.json
(route allow-list negatives). This harness does NOT try to inject content into
protected interfaces. It tests whether two *individually permitted* operations,
composed across layers, violate a component invariant:

  L1 native parser hooks      : object_hook / object_pairs_hook fire during
                                scanning, BEFORE whole-document acceptance.
  L2 identity/lifetime        : do the hook's arguments survive rejection?
                                Is the same dict object reused/mutated?
  L3 representation/normalize : raw bytes vs decoded str vs parsed value vs
                                reserialized bytes -- where can they diverge
                                in a security-relevant way (route selection)?
  L4 ordering                 : side effect (hook) vs verdict (400/200).
  L5 shared persistent state  : idempotency store keyed on WHAT identity?
  L6 authorization context    : kernel peercred vs body 'role'/'uid'.

Probes are grouped; each records PROVEN / INFERRED / UNKNOWN / MASKED labels
per EVIDENCE-DRIVEN-NEGATIVE-SPACE-GUIDE.md. Nothing here opens sockets; the
syscall leg is exercised only against the local synthetic shim (peershim) by
pivot_matrix_v2.py.
"""

import json, sys, io, hashlib, unicodedata, traceback

RESULTS = []

def rec(pid, layer, question, observation, label, consequence="none observed"):
    RESULTS.append({"id": pid, "layer": layer, "question": question,
                    "observation": observation, "label": label,
                    "security_consequence": consequence})

# --------------------------------------------------------------- X1: lifetime
# Hypothesis: if a hook stores its argument, rejected documents still leave
# live objects derived from untrusted bytes in process memory.
# Invariant under test: "rejection means nothing from this request survives."
class Registry:
    """Simulates any framework feature that retains hook output:
    class registries, interning tables, validator caches, audit buffers."""
    def __init__(self):
        self.by_id = {}          # id(obj) -> obj  (strong refs!)
    def add(self, obj):
        self.by_id[id(obj)] = obj
REG = Registry()

def retaining_hook(obj):
    REG.add(obj)                 # side effect BEFORE document verdict
    return obj

def x1():
    events = []
    orig_add = REG.add
    def traced(o):
        events.append(("hook", repr(o), hex(id(o))))
        return orig_add(o)
    REG.add = traced
    doc = '{"audit":{"user":"alice","action":"grant"},'   # child completes,
    try:
        json.loads(doc, object_hook=retaining_hook)       # outer FAILS
        verdict = "accept"
    except json.JSONDecodeError as e:
        verdict = f"reject ({e.msg}@{e.pos})"
    REG.add = orig_add
    live = [repr(v) for v in REG.by_id.values()]
    rec("X1", "lifetime",
        "Does a retained object outlive whole-document rejection?",
        f"verdict={verdict}; hook fired {len(events)}x; registry now holds {live}",
        "PROVEN",
        "Side effect of a REJECTED request persists in shared state; "
        "rejection does not reverse producer-visible effects made by hooks.")

# ------------------------------------------------------- X2: identity vs value
# Two documents that parse to EQUAL dicts but have different raw bytes.
# If any layer keys decisions on equality (dict ==) and another on identity
# or raw bytes, they disagree.
def x2():
    a_raw = b'{"dest":"audit","id":"7"}'
    b_raw = b'{ "id" : "7" , "dest" : "audit" }'
    va = json.loads(a_raw.decode())
    vb = json.loads(b_raw.decode())
    eq = (va == vb)
    ha = hashlib.sha256(a_raw).hexdigest()[:12]
    hb = hashlib.sha256(b_raw).hexdigest()[:12]
    ident = id(va) != id(vb)
    # dedupe test: a store keyed on VALUE identity ('==') collapses them;
    # a store keyed on RAW BYTES keeps both.
    val_store = {}
    val_store[json.dumps(va, sort_keys=True)] = "first"
    dup_collapsed = json.dumps(vb, sort_keys=True) in val_store
    rec("X2", "identity",
        "Equal-value/different-bytes requests: same identity to all layers?",
        f"dicts equal={eq}, distinct objects={ident}, raw hashes {ha} vs {hb}; "
        f"value-keyed store collapses second={dup_collapsed}",
        "PROVEN",
        "A value-keyed idempotency/dedup store treats byte-different requests "
        "as one; a raw-byte-keyed audit or HMAC check treats them as two. "
        "Same logical request, inconsistent cross-layer identity.")

# ------------------------------------------- X3: duplicate key, pair-vs-dict
def x3():
    doc = '{"dest":"worker","dest":"audit"}'
    d = json.loads(doc)                                  # last-wins
    pairs = json.loads(doc, object_pairs_hook=lambda p: p)
    first = dict(pairs)                                  # also last-wins, but
    seen_first = pairs[0][1]                             # pair consumer CAN see first
    # simulate: gate reads PAIRS (first occurrence), router reads DICT (last)
    gate_dest  = pairs[0][1]     # what a policy check iterating pairs sees first
    route_dest = d["dest"]       # what dict-based routing sees
    agree = gate_dest == route_dest
    rec("X3", "representation",
        "Can a pairs-based consumer and a dict-based consumer select different routes?",
        f"pairs={pairs}, dict dest={route_dest}, pairs-first dest={gate_dest}, "
        f"agree={agree}",
        "PROVEN (mechanism) / UNKNOWN (any real service mixing consumers)",
        "Only harmful if one component iterates pairs and another indexes the "
        "dict. CPython default config makes both last-wins; divergence needs "
        "mixed consumer styles -- none found in peershim (single strstr scan).")

# ------------------------------ X4: lossy decode -> slot collision (pivot!)
# The documented pipeline decodes invalid UTF-8 with errors='replace' AFTER a
# strict gate logs REJECT. If routing runs on the lossy string, U+FFFD
# substitutions can COLLIDE distinct byte strings onto the same route name...
# or split one route name across replacement boundaries.
def x4():
    cases = []
    for name_bytes, label in [
        (b'audit',                'clean audit'),
        (b'audi\xFFt',            'invalid byte inside'),
        (b'\xEF\xBF\xBDaudit',    'literal U+FFFD before audit'),
        (b'aud\xE9it'.encode('latin-1',errors='ignore') if False else b'audit', 'noop'),
    ]:
        s = name_bytes.decode('utf-8', 'replace')
        cases.append((label, name_bytes, s, s == 'audit'))
    # stronger form: two DIFFERENT invalid byte strings that normalize to the
    # SAME accepted token via replacement char adjacency is impossible for
    # plain 'audit'; but NFKC + casefold CAN collide legit names:
    coll = []
    for w in ['AUDIT', 'Audit', 'audit\u200B', unicodedata.normalize('NFKC','ａｕｄｉｔ')]:
        k = unicodedata.normalize('NFKC', w).casefold().strip('\u200b')
        coll.append((w, k, k == 'audit'))
    rec("X4", "normalization",
        "Can lossy decode or unicode normalization collide distinct inputs onto one allowed slot?",
        f"replace-decode hits={[(l,c) for l,_,_,c in cases]}; "
        f"NFKC+casefold collisions with 'audit': {coll}",
        "PROVEN (fullwidth 'ａｕｄｉｔ' normalizes to 'audit')",
        "IF a stack applies NFKC/casefold before allow-listing, non-obvious "
        "spellings reach the 'audit' slot while an audit LOG written pre-"
        "normalization shows a different name -> log/decision mismatch. "
        "peershim uses strcmp (no normalization): slot unreachable that way. MASKED in shim.")

# ------------------------------------ X5: hook mutates -> post-hook re-check
# Some frameworks "sanitize" in object_hook then re-validate the FINAL object.
# Invariant: validation must run on exactly the object that is consumed.
def x5():
    doc = '{"dest":"evil","note":"x"}'
    def sanitize_hook(obj):
        # well-intentioned hook: rewrite unknown dest at parse time
        if isinstance(obj, dict) and 'dest' in obj and obj['dest'] not in ('audit','worker'):
            obj['dest'] = 'audit'          # MUTATES in place
        return obj
    v = json.loads(doc, object_hook=sanitize_hook)
    rec("X5", "ordering",
        "Does an in-place-mutating hook change what later validators see?",
        f"raw said dest='evil'; final object says dest='{v['dest']}' (same object mutated by hook)",
        "PROVEN (mechanism)",
        "A pre-parse audit record (raw bytes) and a post-parse decision "
        "(mutated object) describe DIFFERENT requests. Any component holding "
        "the pre-hook view is now desynchronized from the consumer.")

# ---------------------------------------- X6: representation drift on round trip
def x6():
    # (a) textual form changes even when value is preserved
    v = json.loads('{"amount": 1000000000000000000}')   # int, exact
    rt_int = json.dumps(v)                              # stays int in py3
    v2 = json.loads('{"amount": 1e18}')                 # float spelling
    rt_flt = json.dumps(v2)
    same_value_diff_text = (v2 == 10**18) and (rt_flt != '{"amount": 1e18}')
    # (b) the REAL drift: >2^53 integers routed through a JS/V8 consumer
    #     (Node JSON.parse -> String()) lose low bits; Python keeps them.
    n = 9007199254740993  # 2^53 + 1
    js_view = float(n) == float(n + 2)                  # both round to same double
    rec("X6", "representation",
        "Does a value keep identical TEXT and identical IDENTITY across runtimes?",
        f"py int roundtrip: {rt_int}; py float 1e18 re-spelled as {rt_flt} "
        f"(same_value_diff_text={same_value_diff_text}); "
        f"2^53+1 vs 2^53+3 collapse to one double in a JS hop: {js_view}",
        "PROVEN (Python text drift) / INFERRED (JS collapse, standard IEEE-754 "
        "semantics; reproduced live in pivot harness against node)",
        "Reserialization changes authenticated bytes (MAC target) even when "
        "the value is unchanged; and an amount validated in one runtime can "
        "arrive at a second runtime as a DIFFERENT integer. Ordering: "
        "validation happens pre-collapse, effect happens post-collapse.")

# ---------------------------------- X7: control-char key smuggling past strstr
# peershim's scanner is strstr("\"dest\"") + naive escape skip. Does a crafted
# body make it read a dest the strict JSON parser would reject (or vice versa)?
def x7():
    bodies = [
        b'{"dest":"audit","de\\u0073t":"worker"}',      # escaped key alias
        b'{"dest":"a\\u0075dit"}',                       # escaped value char
        b'{"prefixdest":"x","dest":"audit"}',            # substring decoy
        b'{"dest":"worker"}garbage{"dest":"audit"}',     # trailing second doc
        b'{"dest\\":\\"audit\\"}"; {"dest":"worker"}',   # quote-balance attack
    ]
    out = []
    for b in bodies:
        s = b.decode('utf-8', 'replace')
        try:
            strict = json.loads(s)
            sv = strict.get('dest')
        except Exception as e:
            sv = f"<strict-reject:{type(e).__name__}>"
        # emulate shim: strstr('"dest"') then read next quoted run w/ escape-skip
        i = s.find('"dest"')
        shim = None
        if i >= 0:
            j = s.find(':', i); k = s.find('"', j)
            buf, p = [], k+1
            while p < len(s) and s[p] != '"':
                if s[p] == '\\' and p+1 < len(s): p += 2; continue
                buf.append(s[p]); p += 1
            shim = ''.join(buf)
        out.append((b[:44], sv, shim, sv == shim))
    dis = [o for o in out if o[3] is False]
    rec("X7", "interpretation",
        "Do the strict parser and the shim's strstr scanner extract DIFFERENT dest values?",
        "; ".join(f"{p!r}: strict={a} shim={b} agree={c}" for p,a,b,c in out),
        "PROVEN (divergence exists between parsers on these inputs)" if dis else "PROVEN (no divergence on this set)",
        "Two-parser systems (validate here, forward there) can act on "
        "different field values from ONE byte stream. See xlayer results for which rows diverge.")

# ------------------------------------- X8: NaN/Infinity leak into downstream
def x8():
    v = json.loads('{"amount": NaN}')
    try:
        json.dumps(v, allow_nan=False)
        strict_dump = "ok"
    except ValueError as e:
        strict_dump = f"ValueError: {e}"
    rec("X8", "shared-state",
        "Non-standard literals accepted by parser -> representable downstream?",
        f"parsed={v}; strict re-dump={strict_dump}",
        "PROVEN",
        "Acceptance at L1 does not guarantee serializability at L5. A worker "
        "MAC computed over reserialized bytes fails/mutates only AFTER the "
        "request was already counted valid -- ordering asymmetry.")

# ------------------------------------------ X9: BOM/whitespace envelope skew
def x9():
    raw = b'\xef\xbb\xbf{"dest":"audit"}'
    try:
        json.loads(raw.decode('utf-8'))
        py = "accept"
    except Exception as e:
        py = f"reject {type(e).__name__}"
    shim_style = raw.lstrip(b'\xef\xbb\xbf').find(b'"dest"') >= 0  # strstr ignores prefix
    rec("X9", "interpretation",
        "Does a BOM reject at the JSON gate while a substring scanner still routes?",
        f"python json: {py}; shim strstr would find \"dest\": {shim_style}",
        "PROVEN (mechanism divergence)",
        "If HTTP framing strips/keeps the BOM differently than the validator "
        "does, one layer 400s while another forwards. Unreachable in peershim "
        "because its ONLY gate is the strstr scanner (no strict parser).")

# -------------------------------------- X10: peercred authority provenance
def x10():
    body = '{"uid":0,"role":"admin","dest":"audit"}'
    v = json.loads(body)
    rec("X10", "authorization",
        "Can request data define the authorization principal?",
        f"body carries uid/role={v}; kernel SO_PEERCRED is a separate channel "
        f"(see peershim deliver_to_slot: uc.uid/uc.pid never read from JSON)",
        "PROVEN in shim / MASKED for real services behind TLS proxies",
        "In shim, role is echoed but never feeds privilege. Real deployments "
        "behind L7 proxies lose kernel peercred entirely; principal then "
        "depends on forwarded headers -- a DIFFERENT trust channel, untested here.")

def main():
    for fn in (x1, x2, x3, x4, x5, x6, x7, x8, x9, x10):
        try:
            fn()
        except Exception:
            RESULTS.append({"id": fn.__name__, "error": traceback.format_exc()[-300:]})
    print(f"{'id':4} {'layer':16} {'label':46}")
    print("-"*110)
    for r in RESULTS:
        print(f"{r.get('id','?'):4} {r.get('layer','?'):16} {r.get('label','?')[:46]}")
        print(f"     Q: {r.get('question','')}")
        print(f"     O: {str(r.get('observation',''))[:150]}")
        print(f"     C: {r.get('security_consequence','')}")
        print()
    import os
    os.makedirs("artifacts", exist_ok=True)
    with open("artifacts/xlayer_matrix.json", "w") as f:
        json.dump(RESULTS, f, indent=1, default=str)
    print("full detail -> artifacts/xlayer_matrix.json")

if __name__ == "__main__":
    main()

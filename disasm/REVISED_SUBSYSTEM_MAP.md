# REVISED component map — the JSON validation subsystem as an execution GRAPH (not a pipeline)

This document **supersedes §1–§2 of `validator_subsystem_map.md`** after review.
The old map ("C0 host loader → C1 decoder object → C2 recursive-descent engine →
C3 scanner micro-components → C4 hook slots → C5 error emitter → C6 reserializer")
was rejected for four concrete reasons, each corrected below:

1. **Too linear.** The error emitter is an exceptional path, not a stage; hooks are
   invoked *from within* scanning, not after it; the reserializer belongs to a
   separate encoding path that parsing never transitions into; the C scanner and
   the pure-Python scanner are **alternative implementations**, not successive stages.
2. **"Caller-supplied opcodes" was a category error.** Callbacks are caller-supplied
   *construction policies*, not instructions selected by the input. Nothing in the
   input picks an opcode; the input only determines *when* a configured callback runs.
3. **Callback inventory was incomplete.** The old map listed only `object_hook` /
   `object_pairs_hook`. There are **five** decoder callbacks (parse_int, parse_float,
   parse_constant added), all firing during scanning, before document-level
   acceptance — measured in `artifacts/boundary_probe_rev1.json` M6.
4. **One disassembly annotation was wrong.** `PyObject_CallOneArg@0x456c` sits in the
   **number-matching routine**, not "the parse_string tail": its argument is built by
   `PyUnicode_FromKindAndData@0x4559` from the digit-run span, and the callee slot is
   `[scanner+0x28] = context.parse_float` (set at `decoder.py:317`; sibling branch at
   `0x4517` tests `E` exponent → float path). The `parse_int` sibling call is at
   `0x58db`. Verified against installed CPython 3.12.10 source + this repo's
   `_json.intel.txt`.

---

## 1. The actual execution graph (CPython 3.12.10)

```
                         ENTRY / COERCION  [measured: rev2 M5]
  bytes / bytearray ──► json.loads: utf-8 decode INSIDE the C entry point,
                        BEFORE any scanning.  memoryview & friends: TypeError.
  str ────────────────► straight through.
  NOTE: JSONDecoder().decode(bytes) FAILS (py path: regex on bytes) —
        coercion lives in loads()/c_make_scanner, not in the decoder object.

  DECODER ENTRY AND DISPATCH                      [SOURCE: json/decoder.py]
  JSONDecoder.decode(s) ─► raw_decode(s, idx) ─► self.scan_once(s, idx)
        │                                          ├─ C impl: _json.Scanner (c_make_scanner)
        │                                          └─ py impl: py_make_scanner closure  ◄─ ALTERNATIVES
        └─ trailing-whitespace + end-of-document check happens HERE, after scan_once returns

  PARSING OPERATIONS (recursive; each may invoke the others)      [PROVEN: disasm + probes]
  scan_once dispatch ─┬─ JSONObject / c_scanstring: escape decoding, strict ctrl-char guard
                      ├─ JSONArray / list assembly
                      ├─ number match ─► parse_int(str) | parse_float(str)   ← CALLBACK
                      ├─ NaN|Infinity|-Infinity ─► parse_constant(str)       ← CALLBACK
                      └─ '}' close ─► object_pairs_hook(pairs) | object_hook(pairs) ← CALLBACK
                     key canonicalisation: memo.setdefault (py @scanner.py:169)
                                           PyDict_SetDefault @0x3301 (C)

  CROSS-COMPONENT INTERACTIONS (what parsing actually touches)    [PROVEN: symbol census rev2 ADJ_]
  dict ops · list ops · unicode objects (FromKindAndData/New/Substring/Intern) ·
  long/float conversion · configured callbacks (PyObject_Call*) · exception
  construction (PyErr_*) · recursion budget (host frame counter, NOT internal) ·
  refcounting/GC (PyObject_GC_UnTrack)

  RETURN TO CALLER
  complete document-level check (end != len ⇒ ExtraData) → object or exception.

  SEPARATE PATH — NOT DOWNSTREAM OF PARSING
  JSONEncoder / _json encoder ─► serialization. Parsing does not flow into it;
  only the *caller* can hand parsed objects to it.
```

## 2. State ownership and lifecycle (the part the old report got mostly right but stated loosely)

- The memo dict is owned by the **Scanner object** (C: field at +0x40, allocated in
  `scan_once_unicode` prologue @0x3258 `PyDict_New`, cleared via `PyDict_Clear@0x2ef6`
  when the top-level `scanner_call` (`PyArg_ParseTupleAndKeywords` @0x2ec1 → inner call
  @0x2eea) returns). Python twin: `JSONDecoder.memo` created once in `__init__`
  (@decoder.py:329), captured by the `py_make_scanner` closure, **reset to `{}` at the
  end of every `scan_once`** (@scanner.py:282-283).
- Precise wording (per review): *allocated with the scanner, contents cleared per scan
  operation* — not "allocated per parse".

## 3. Reentrancy — NEW finding, tested this round (rev2 artifact)

Hypothesis (review-raised): a hook calling `decode()` on the same decoder mid-parse
lets the inner scan clear the shared memo while the outer parse is live.

Measured outcomes:

- **PY path: hypothesis CONFIRMED as observable state mutation.** Trace shows
  `decoder.memo` live during the outer parse (`['aa','innerkey','x']`), then RESET to
  `[]` immediately after the inner `decode()` returns, while the outer parse continues.
  Consequence observed: keys interned *before* the reentry lose their canonicalisation
  anchor for the remainder of the outer scan (later `aa` re-interned fresh). No verdict
  change, no crash: effect confined to key-object identity/memo behaviour.
- **C path: hypothesis DISCONFIRMED, decisively.** Two discriminators run:
  (a) baseline vs reentrant on `[{"m":1},{"m":2,"m":3}]` — post-reentry duplicate `m`
  occurrences arrive as the SAME object id, identical to baseline; (b) the stronger
  pre-vs-post test on `[{"x": {"t": 1}}, {"x": 2}]` with the inner
  `decode('{"filler":1}')` injected at the first close — the key `x` canonicalised
  BEFORE the reentry keeps the SAME object identity AFTER it (`x_ids_equal_across_reentry
  = True`). Therefore the inner scan_call does NOT clear the shared memo out from under
  the live outer scan. Mechanism (disasm-grounded): `PyDict_Clear@0x2ef6` fires in the
  epilogue of each top-level `scanner_call` completion; the outer recursive `scan_once`
  frames never pass through that epilogue mid-parse. Residual caveat kept honest: the
  inner call DOES wipe memo contents at ITS completion — but since the outer scan
  re-derives canonical keys via SetDefault against the (now cleared) dict on next use,
  observed behaviour remained identity-stable because the same live key objects were
  retained by the memo values themselves during the outer parse. Effect boundary: key
  identity/memoisation only; no verdict change, no crash, no consumer-visible semantic
  difference (dict lookup uses equality).
- **Verdict-impact sweep (rev2 `REENT_verdict_impact`):** across duplicate-key,
  escaped/literal, and nested-trigger documents, plain-py == reentrant-py ==
  reentrant-C outputs. The py memo reset is real internal-state mutation but changes no
  verdict or value for any tested input. Caveat recorded honestly: identity survival in
  the probe used short ASCII keys that CPython's global intern table keeps alive anyway;
  the memo only supplies the parse-local anchor, so non-interned key forms could diverge
  in *identity* (never equality) across a mid-parse reset — invisible to dict consumers.
- **Recursion guard location:** reentrancy and data nesting share the HOST frame budget;
  RecursionError raised at nesting ~333 through the hook path. The validator has no
  internal depth counter of its own on these paths (C-vs-py depth divergence at ~900
  remains an implementation difference between ALTERNATIVE scanners — do not describe it
  as a signer/crypto disagreement without two real consumers wired to different scanners).

## 4. Downgraded conclusions (explicit withdrawal list)

| Old claim | Status now |
|---|---|
| "Seven components form a linear validation pipeline" | Withdrawn; replaced by execution graph §1 |
| "Caller-supplied opcodes" | Withdrawn; category error (§ intro 2) |
| "Hook return values take authority from the validator" | Reworded: documented decoder construction policy; not a security transfer by itself |
| "Tree-shape disclosure" | Downgraded to UNKNOWN: callback receives structures built from the input; disclosure requires an unintended recipient, not demonstrated |
| "Error document escape" | Downgraded: retention in the documented exception interface (`self.doc = doc`); lifetime fact, not spill. Identity NOW measured (`exc.doc is source == True`, exact length) instead of hardcoded |
| "No writable external surface / no fs/net/exec" | Scope fixed: symbol census establishes *no direct imported calls*; cannot exclude indirect effects or anything reachable through caller-configured callbacks |
| "Same bytes produce different certified values" | Downgraded: different configured decoding policies ≠ cryptographic/authorization vulnerability until a signer/verifier boundary is in the experiment |
| "PyLong_FromVoidPtr pointer leak" | Downgraded to internal-use-only until observability outside encoder circularity bookkeeping is shown |
| Q4 escaped-key identity test | INVALID (compared value vs key; escaping muddled). Superseded by rev1 M2: intra-doc escaped/literal keys ARE same object (C and py); cross-parse they are NOT. Old `boundary_probe_q4_q5.py` marked HISTORICAL |
| Q5 `doc_is_same_object_as_input: True` | Was asserted, not measured. Now measured (rev1 M4) |
| rev1 M5 "accepts ONLY str" | Wrong; superseded by rev2 M5 (loads accepts str/bytes/bytearray; utf-8 coercion inside entry point) |

## 5. What is accepted as established right now

PROVEN: five-callback inventory executing pre-verdict; construction/validation fusion;
memo ownership + per-scan clearing (source) and mid-parse reset under reentry (py path,
measured); C-path reentry benign for key identity (measured discriminator); duplicate
last-wins lives in `PyDict_SetItem@0x4112` while pairs_hook sees both; escaped/literal
key canonicalisation within one scan; exception retains the same str object (measured);
representation boundary at loads() vs decoder.decode(); recursion guard is host-side.
SOURCE-confirmed: memo lifecycle, JSONDecodeError.doc assignment, parse_* call sites.
UNTESTED/OPEN: adjacent-facility assumption audit beyond what was done here (GC finalisers
re-entering the decoder; surrogate handling across the coercion boundary); signer/consumer
experiments where representation choice flips a policy decision.

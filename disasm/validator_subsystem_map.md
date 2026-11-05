> **STATUS: §1–§2 SUPERSEDED.** The linear seven-component pipeline, the
> "caller-supplied opcodes" framing, the two-hook callback inventory, and the
> `PyObject_CallOneArg@0x456c` annotation are corrected in `REVISED_SUBSYSTEM_MAP.md`
> (execution graph, five-callback inventory, number-routine attribution, reentrancy
> results, withdrawal table). Boundary probes Q4/Q5 were invalid/hardcoded; see
> `artifacts/boundary_probe_rev1.json` / `rev2.json`.

# THE JSON-VALIDATION SUBSYSTEM — component map, boundaries, and cross-boundary state

Scope discipline (per objective): this document studies the subsystem **as an
interconnected set of components** — responsibilities, internals, guards,
assumptions, cleanup — and traces how input moves through it. It is *not* a
crash/break exercise. Every claim is labeled **PROVEN** (disassembly or repro),
**INFERRED** (mechanism-consistent, unmeasured), or **UNKNOWN**. No filesystem,
network, or exec primitives appear anywhere; that is the flipped premise.

Target implementation (established from the actual binary, not assumed):
`/usr/local/lib/python3.12/lib-dynload/_json.cpython-312-x86_64-linux-gnu.so`
under CPython 3.12.10, with its Python-side neighbours in
`/usr/local/lib/python3.12/json/{decoder.py,scanner.py}`. The `.so` exports only
`PyInit__json` (`nm -D --defined-only`) — every other component is reached
through data structures, not symbols. All addresses below are file-vaddrs from
`objdump -d --section=.text` (full listing: `disasm/_json.intel.txt`, 5687 lines).

---

## 1. Component map — the actual components, established mechanically

The validation region is **seven cooperating components across two languages**,
not one function. Disassembly + stdlib source identify them:

| # | Component | Where | Responsibility | Owned by |
|---|-----------|-------|----------------|--------|
| C0 | `JSONDecoder.__init__` / `scan_once` closure assembly | `json/decoder.py:326-330` | builds the validator's *capability table*: picks parse_object/parse_array, wraps `c_make_scanner(self)` or pure-Python fallback | caller/host |
| C1 | `decoder` object (`tp_new` @indirect call `0x6bc7`) | `_json.so` | holds slots: object_hook, object_pairs_hook, parse_float/int/constant memo dict, strict flag, memo (key-interning) dict | per-decoder |
| C2 | `decoder_iternext` — recursive descent engine | `_json.so` (`0x6e9b` prologue reads thread-state recursion fields) | the verdict machine: scan → dispatch (computed goto `jmp rdi @0x7012`) → construct | validator |
| C3 | Scanner/consumer micro-components inside C2: `parse_object`, `parse_array`, `parse_string`, number path | `_json.so` | each consumes bytes and emits typed objects; each has its own guard set (§3) | validator |
| C4 | Hook slots — caller-supplied opcodes | calls at `0x35fd` (object/pairs hooks after `'}'` scan @0x35cb) and `0x456c` (parse_float after `PyUnicode_FromKindAndData` @0x4559) | *construction policy*: what a validated node actually becomes | **caller** (attacker-visible if host exposes decoder config) |
| C5 | Error emitter | `PyErr_SetString/SetObject/Format@plt`; raises `JSONDecodeError(msg, doc, pos)` whose `doc` field retains the **entire input buffer** (`decoder.py:26-38`) | verdict reporting + failure-state retention | validator, but exception object escapes to caller |
| C6 | Downstream: reserializer (`encoder_*`, iterables `tp_iter` @0x5a23/0x6803, circularity markers via `PyLong_FromVoidPtr` + `id(obj)+0xabd8/0xe958` around 0x687f/0x68a9) | same `.so` | turns constructed objects back into bytes for forwarding — the half where byte/value identity diverges | validator library, owned by the *owner* process |

Cross-language twin note: every C component above has a pure-Python twin
(`JSONObject` @decoder.py:137, `JSONArray` @218, `py_scanstring`) that the same
host may load instead. They are **different implementations with different
guards** (§4, divergence G).

### Negative-space baseline (what the subsystem does NOT contain)
PLT census (`disasm/json_validator_region.md` §1): 53 distinct imported effect
classes; **zero** `open/read/write/socket/execve/fork`-class calls. The
subsystem's entire outside-world surface is: callbacks, containers, identities,
errors, timing, ambient config. Any "capability beyond validation" must arrive
through those six wires — established before any hypothesis about spill.

---

## 2. Input trace — one request's path through the components

```
raw bytes ──► [HTTP framing] ──► str (decoded, surrogatepass/locale-dependent)
   ──► C0 scan_once closure chosen (C vs py scanner: HOST decision, invisible to signer)
   ──► C2 whitespace skip → first-char dispatch (computed goto @0x7012)
        ├─ '{' ► C3 parse_object:
        │     key: scanstring → memo PyDict_SetDefault @0x3301 (intern fast path)
        │     value: recurse C2
        │     '}' hit @0x35cb ► IF pairs_hook slot set: build pair LIST, call @0x35fd
        │                       ELSE: build dict, collapse duplicates via
        │                             PyDict_SetItem @0x4112 (last-wins lives HERE)
        │                       then hook call @0x35fd with the finished node
        ├─ '[' ► C3 parse_array (recursion depth tracked against limit read at 0x6e9b..0x6ec7)
        ├─ '"' ► C3 parse_string (escape decode; \uXXXX materialized BEFORE syntax done)
        └─ digit ► number path: token scan → PyFloat_FromString @0x445f OR
                   parse_float slot call @0x456c (hook fires on EVERY numeric literal)
   ──► adopted return values by IDENTITY (probe C: final_is_attacker_object=true)
   ──► verdict bit returned; C5 error object (if any) carries doc+pos out
   ──► [owner logic] policy check on constructed value
   ──► C6 reserialize (dumps) ──► forwarded bytes ≠ signed bytes (X2 / Replica DISAGREE)
```

Key structural facts established from code, not assumed:
- Construction is **interleaved with validation**: side effects bank while the
  verdict is still undetermined (A: aborted_doc_hooks_before_error=1).
- There is no "validation phase" followed by "conversion phase". The phases are
  fused; the boundary everyone assumes exists does not.
- The output of validation is not a bit — it is a **live object graph** handed
  to whoever reads the slot next, plus retained state in C1/C5 (§4).

---

## 3. Guards, constraints, assumptions, cleanup — per component

| Component | Guards present | Assumptions it makes | Cleanup mechanisms |
|---|---|---|---|
| C2 recursion engine | depth counter vs `sys.getrecursionlimit()`-adjacent thread field (read @0x6e9b..0x6ec7); `max_depth` param | that the limit is process-wide ambient config, **not** per-request budget | stack unwind on error; GC track/untrack (`PyObject_GC_UnTrack@plt`) |
| C3 parse_string | `strict` flag rejects control chars <0x20; escape-table computed goto (@0x2a05 encoder side analogue) | that callers pass `str`, never raw bytes; that decoded `\uXXXX` equals its literal form semantically (FALSE for downstream consumers — X4 collisions) | frees temp unicode buffers on error paths |
| C3 parse_object | duplicate keys are NOT a guard violation — silently collapsed @0x4112 | that last-wins is acceptable policy (RFC says parsers MAY; consumers downstream assume single interpretation) | dict teardown |
| C4 hook slots | **none.** No return-type check, no re-validation of hook output, no call-count budget, no try/except isolation | that the host configured trusted callables; that hook returns correspond to the node passed in | none — hook exceptions propagate verbatim (D), hook side effects are never rolled back (A) |
| C5 error emitter | fixed message table | that error text/pos is safe to expose (it embeds the whole doc in `err.doc`) | exception object lifetime = caller's |
| C6 encoder | circularity markers keyed on `id(obj)`; ensure_ascii default | that the object graph is acyclic-or-marker-safe; that reserialization is "equivalent" to input bytes | marker dict freed post-encode |
| Host loader (C0) | falls back to py scanner if `_json` import fails | implicitly chooses WHICH validator semantics apply — a configuration fact signers cannot see in the HMAC | — |

The load-bearing asymmetry: **every guard protects the validator's own
consistency; no guard protects the *neighbours* from the validator's outputs.**

---

## 4. Interaction boundaries — what crosses, what doesn't, tested

Boundaries were established first, then probed (house rule: don't assume spill;
test whether the invariant holds).

### B1: validator ↔ caller code (hooks) — OPEN BY DESIGN, UNBOUNDED IN PRACTICE
- PROVEN (A/B/C/D, artifacts/json_validator_influence.json): call count, order,
  return adoption, and exception channel all cross this boundary with zero
  mediation. The boundary isn't a leak; it's an *inverted dependency* — the
  validator executes caller policy mid-verdict.

### B2: validator ↔ validator (C impl ↔ pure-Python impl) — DISAGREEMENT SURFACE
- PROVEN (G): identical bytes, depth-900 nesting: C scanner ACCEPTS, py scanner
  RecursionError-rejects under the same default limit. Two validators shipped
  in one stdlib disagree about "is this JSON?" ⇒ an HMAC over raw bytes
  certifies a verdict made by whichever implementation the host happened to
  load. Boundary crossing here is *semantic*, carried by the environment, not
  by the request.

### B3: validator ↔ owner-forwarder (validate→reserialize round trip) — BYTE/VALUE SPLIT
- PROVEN (H, Python twin of Java Replica DISAGREE): identical signed bytes yield
  different certified values depending on collapse policy (default last-wins
  `{k:TRAP}` vs first-wins pairs-hook `{k:ok}`). Machine-level origin traced to
  the single instruction @0x4112.
- PROVEN (encoder §5 of region doc): identity-graph effects — hooks returning
  shared subtrees change circularity-marker behaviour, so two semantically
  equal trees serialize to different bytes. State crosses B3 as *identity*, not
  content.

### B4: validator ↔ ambient process state — READS IT, WRITES PARTIALLY CONFIRMED
- PROVEN read: recursion limit consumed inside C2 (config-dependent verdict).
- REVISED write claim (honest failure, E): initial hypothesis "memoized intern
  keys persist across requests" CONTRADICTED on 3.12.10
  (`same_key_object_across_parses=false`; escape-vs-literal keys share no slot).
  Persistence channel: **CLOSED by Q4** (artifacts/boundary_probe_q4_q5.json):
  memo scope is per-parse in BOTH implementations — C scanner and forced
  py_make_scanner show no key-object sharing across parses even through one
  long-lived decoder; within-one-parse sharing confirmed (escape-vs-literal
  still separate slots). No cross-request state leak via C1 memo.

### B5: validator ↔ error consumer — FULL INPUT RETENTION ESCAPES
- PROVEN structurally (decoder.py:26-38): `JSONDecodeError.doc` holds the entire
  input string, `pos/lineno/colno` hold precise failure coordinates. Whatever
  the host logs/returns on parse failure, the *whole request buffer* crossed
  the boundary inside the exception object — a retention property of the
  component, independent of any logging choice.

### B6: timing as an implicit boundary — INFERRED
- Measured spectrum: invalid≈3629ns vs valid≈1472ns vs hook≈3226ns (F). Label
  INFERRED pending SNR re-runs across processes (queue Q3): the mechanism
  (computed-goto dispatch depth) is consistent with an oracle, but we have not
  yet established signal stability, so we do not call it a channel.

---

## 5. Valid vs invalid vs unusual representations — component-by-component handling

| Input shape | Which component decides | What each neighbour receives |
|---|---|---|
| Well-formed doc | C2 accepts; C3 constructs | owner gets live object graph (not bytes); C6 can mutate byte shape on forward |
| Syntax-invalid AFTER deep structure | C2 rejects at point of failure | **hooks already fired** (A); partial tree garbage-collected but side effects banked; err.doc carries full buffer (B5) |
| Duplicate keys | invisible to C2; decided at @0x4112 | gate reads first occurrence when pairs-hook used, forwards last-wins dict otherwise — the DISAGREE pattern, now pinned to one instruction |
| `\uXXXX`-escaped vs literal keys | C3 parse_string normalizes early | memo slot NOT shared (E revised); downstream consumers that compare pre-normalization strings see two keys where validator sees one (X4) |
| Depth near limit | C2 guard, but *which* guard depends on C0 loader choice | verdict flips between accept/reject across implementations (B2) |
| Numbers beyond f64 precision (>2^53) | number path @0x445f/0x456c | value drifts across runtimes (P11 in pivot_matrix_v2) — validator's lossy conversion is inherited silently by every consumer |
| Non-UTF8 / BOM prefix | upstream framing, not C2 (C2 only sees `str`) | assumption audit: C3 assumes `str` ever arrives clean — false at the HTTP boundary (P5 divergence) |

---

## 6. Interpretation / state / control-flow / memory boundary hypotheses — status

Stated as testable claims with current labels (nothing asserted without evidence):

1. Control-flow spill INTO validator-owned memory: **NOT SUPPORTED** — PLT
   census shows no writable external surface; hijack class (Popov-style UAF)
   requires refcount/GC misuse which our probes did not reach and the objective
   explicitly excludes pursuing.
2. Control-flow spill OUT: **PROVEN but authorized** — the hook mechanism is a
   designed inversion; the finding is its *unboundedness* (no re-validation of
   hook returns, no rollback), not its existence.
3. State spill across requests via memo dict: **NOT PROVEN** (E contradicted);
   residual UNKNOWN scoped to decoder-instance lifetime (Q4).
4. Semantic state spill across validator implementations (C vs py): **PROVEN**
   (G) — the most under-appreciated boundary because it's invisible to both
   signer and requester.
5. Byte-level state spill validate→forward: **PROVEN** (H + encoder identity
   markers) — authorization-relevant when policy reads the constructed value
   but transport sends reserialized bytes.
6. Timing state spill: **INFERRED**, awaiting SNR measurement (Q3).

---

## 7. Repro

```bash
SO=/usr/local/lib/python3.12/lib-dynload/_json.cpython-312-x86_64-linux-gnu.so
objdump -d --section=.text $SO > disasm/_json.intel.txt
# component anchors: 0x35cb/0x35fd (object hook), 0x4112 (dup collapse),
# 0x3301 (memo SetDefault), 0x445f/0x456c (number path), 0x6e9b (depth guard),
# 0x7012 (verdict dispatch), 0x6bc7 (decoder tp_new), 0x5a23/0x6803 (encode iter)
python3 disasm/json_validator_influence.py    # rebuild influence artifact
grep -n 'self.scan_once\|make_scanner' /usr/local/lib/python3.12/json/decoder.py  # C0
```

## 8. Queue (smallest next probes, unchanged + new)
- Q1 policy-flip: route allow-list check behind pairs-hook vs plain loads (does
  B3/H reach authorization?)
- Q2 identity-graph serialization diff (B3 second half)
- Q3 timing SNR across processes (upgrade/downgrade B6)
- Q4 DONE — memo scope closed: per-parse, both scanners (see B4)
- Q5 (new) err.doc retention: measure how far the full buffer propagates in the
  replica's error path (B5 consequence for logging)

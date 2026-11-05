# REV6 — Reentrancy closure + first real process-boundary measurement

CPython 3.12.10, owned local environment only (no external systems; gate and
worker are both processes we spawn on an AF_UNIX socket we bind ourselves).

## 1. Review-point corrections (all rerun, artifacts current)

**Scanner lifecycle discrepancy (review §3) — RESOLVED IN FAVOR OF THE REVIEW.**
`json/decoder.py JSONDecoder.__init__` ends with `self.memo = {}` and
`self.scan_once = scanner.make_scanner(self)`; `raw_decode()` only *calls* it.
Measured (`artifacts/rev6_memo_reentry.json`): `scan_once_same_object_across_decodes: true`.
The scanner is **per-decoder-instance**, on BOTH paths. rev5's "each decode()
builds a NEW scanner" was wrong — its trace patched `json.scanner.py_make_scanner`
while `json.decoder` had already bound the name at import. Additional finding:
the PY memo dict is `decoder.memo` itself (shared by every scanner built from
that decoder), so PY reentrancy mutates decoder-owned state directly.

**Correct-escape control (review §2) — FIXED AND DECISIVE.**
`\u006c`/`\u0064` (= 'l'/'d') with multi-char keys. First corrected attempt
(rev6b) failed its own control on BOTH arms; mechanism investigation (rev6c)
established why: **memo canonicalises only WITHIN a parse** (escaped spelling X
returns the same object as an earlier equal key scanned in that parse); it never
reaches out to module-level literals, and literal spellings never enter memo.
Comparing against a module constant was the wrong observable.

## 2. PROVEN — reentrant memo clear has an observable downstream consequence

`artifacts/rev6d_memo_entry.json` (nested-object hook fires mid-outer-parse,
same-decoder inner decode, tail escaped twin scanned AFTER the clear):

| outcome (recorded separately, per review) | C path | PY path |
|---|---|---|
| A. memo cleared mid-outer-parse (same dict obj, len 2→0) | TRUE | TRUE |
| B. memo-hit observable lost by clear (control k1 is k2 = **True**; reentrant = **False**) | DIVERGES | DIVERGES |
| C. equality / parsed result changed | FALSE | FALSE |

Mediation class: RUNTIME_MEDIATED (input does not cause this alone; a
caller-supplied callback must reenter the same decoder — documented in rev5
already, now closed with valid controls). The effect is real allocator-level
key-object identity divergence inside the parsing process; values, verdicts and
collapse policy are untouched. This closes rev5's "downstream effect untested"
gap: the consequence exists and is measurable, but only through object identity,
not through content.

## 3. FIRST PROCESS-BOUNDARY MEASUREMENT (the review's "most valuable milestone")

`artifacts/rev6e_boundary.json`: Process G (gate, pid 5768) parses raw bytes →
reserialises → forwards over AF_UNIX → Process W (worker, pid 5769, separate
address space) reparses and reports facts about objects it constructed itself.

- **E1 (parser-native, zero callbacks):** raw `{"\u0064up_key_ccc":1,"dup_\u006bey_ccc":2,"dup_key_ccc":3}`
  — gate sees memo-hit identity (`k1 is k2: true`) among pre-collapse key
  objects. Forwarded bytes are `{"dup_key_ccc": 3}`. Worker cannot recover the
  identity graph: reserialisation flattens shared key objects into one byte
  sequence. **Data crosses the boundary; identity-graph information is absorbed.**
- **E2 (reentrancy-induced state):** reentrant and control gate parses produce
  byte-identical forwarded payloads; worker responses identical. The rev6d
  state change is real in G and **NOT observable in W through this authorised
  channel**. Propagation ruled out for this channel — honestly bounded rather
  than assumed.

So: boundary handoff demonstrated in a controlled local system (processes,
socket, observations on both sides), with the propagation question answered
NEGATIVE for the identity channel and POSITIVE-only-for-values. No isolation
failure claimed or needed; the channel works exactly as designed, which is the
invariant established before testing spill (per the standing methodology).

## 4. Status table (supersedes rev5 rows)

| area | status |
|---|---|
| Scanner/memo ownership (per-decoder, PY memo on decoder) | PROVEN (source + measurement) |
| Reentrant memo clear mid-parse | PROVEN both paths |
| Post-clear key-identity divergence vs control | **PROVEN** (was UNRESOLVED in rev5) |
| Value/equality/result impact of reentry | PROVEN NONE |
| Identity-graph crossing process boundary via reserialising IPC | PROVEN ABSORBED (E1/E2) |
| Cross-process influence beyond existing authorised channels | NOT ESTABLISHED (none found; none required to be defeated) |
| Kernel-boundary interaction | NOT INVESTIGATED |

## 5. Files
- disasm/rev6_memo_reentry.py → artifacts/rev6_memo_reentry.json (lifecycle, adjacency probe)
- disasm/rev6b_postclear_identity.py → artifacts/rev6b_postclear.json (failed-control probe, kept as logged negative)
- disasm/rev6c_canonical_probe.py (mechanism: memo scope within-parse)
- disasm/rev6d_memo_entry_observable.py → artifacts/rev6d_memo_entry.json (decisive B observable)
- disasm/rev6e_boundary_handoff.py → artifacts/rev6e_boundary.json (two-process E1/E2)

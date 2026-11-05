# THE VALIDATOR REGION — hand disassembly of "what JSON is"

Target: `/usr/local/lib/python3.12/lib-dynload/_json.cpython-312-x86_64-linux-gnu.so`
(ELF, stripped except `PyInit__json`; all addresses below are file-vaddr from
`objdump -d`, reproducible with the commands in §6).

Framing (per current objective): we do NOT care what the request says. We care
about the region that decides *whether a byte-string is a JSON value at all* —
and what that region influences **outside** of validation. The default attacker
reaches for fs/net/exec primitives; this document starts small and inventories
every wire the validator actually touches.

---

## 1. Capability inventory — what the gate CAN reach (PLT census)

53 distinct `@plt` call targets in `.text`. Grouped by *effect class outside validation*:

| Effect class | Symbols (from `.dynsym`) | Why it matters |
|---|---|---|
| **Arbitrary code execution as policy** | `PyObject_CallOneArg`, `PyObject_CallFunction`, `PyCFunction_GetFunction` | the hook slots — validator *calls back into caller-owned objects mid-parse* |
| Persistent state mutation | `PyDict_SetDefault`, `PyDict_SetItem`, `PyDict_Contains`, `PyDict_DelItem`, `PyDict_Clear`, `PyList_Append` | memo/intern tables, container construction side effects |
| Object identity control | `PyUnicode_InternFromString`, `PyLong_FromVoidPtr`, `PyUnicode_New`, `PyUnicode_Substring` | key sharing across parses; pointer-as-int leaks (`FromVoidPtr` is used by the *encoder*'s circularity marker — see §5) |
| Error-channel ownership | `PyErr_SetString`, `PyErr_SetObject`, `PyErr_Format` | verdict error identity is chosen here, consumed upstream as signal |
| Type-system interrogation | `PyType_IsSubtype`, `PyObject_GetAttrString`, `PyObject_IsTrue`, `PyMapping_Items`, `PySequence_Fast` | duck-typed values get *probed* during parse/encode decisions |
| Ambient-config reads | thread-state access feeding `recursion_limit` (§3), `PyFloat_FromString`, `PyLong_FromString` | verdict depends on process state, not just bytes |
| GC-visible lifetime | `PyObject_GC_UnTrack`, `_Py_Dealloc` | refcount paths = the UAF-shaped surface class Popov catalogued |

**Negative-space result (what the gate does NOT have):** zero calls to
`open/read/write/socket/execve/fork`-class symbols, no `system()`-style imports.
The validator cannot touch fs/net/exec *directly*. Everything it can influence
flows through **callbacks, containers, identities, errors, timing, and ambient
config**. That is the flipped premise confirmed mechanically: if the validator
gives "capabilities beyond validation", they must appear in these six classes.

## 2. Indirect-call sites — the exact wires where authority transfers

All non-PLT indirect calls in `.text` (the complete set; each is a place where
control leaves the validator through a pointer it does not own):

| Site | Instruction | Region | Meaning |
|---|---|---|---|
| `0x35fd` | `call PyObject_CallOneArg` | parse_object loop, right after `cmp $0x7d` ('}') scan @0x35cb | **object_hook / object_pairs_hook fires when the closing brace validates.** Syntax verdict for the node → immediate callback with the node's contents. |
| `0x456c` | `call PyObject_CallOneArg` | parse_string tail (after `PyUnicode_FromKindAndData` @0x4559) | **parse_float slot**: every numeric token literal is handed to a caller-supplied callable before adoption. |
| `0x45a6→0x7220` | helper wrapping `PyLong_FromSsize_t` | integer path | int construction (hook-free by default — discriminator vs float). |
| `0x445f` | `call PyFloat_FromString` | number path | default float materialization. |
| `0x4112` | `call PyDict_SetItem` | object assembly | **duplicate-key collapse point** — last-wins policy lives on this single instruction. |
| `0x3301` | `call PyDict_SetDefault` | key handling | memoized-interning fast path for object keys (probe E tests its actual scope). |
| `0x5a23`, `0x6803` | `call *0x58(%rax)` | encoder iterables path | `tp_iter` invocation on dict/list during encode — same class of wire on the output side. |
| `0x6bc7` | `call *0x130(%rbx)` | decoder-init (offset 0x130 = `tp_new`) | scanner object creation. |
| `0x6d1e` | `call *0x140(%r12)` (×2 sites) | tp_free paths (0x6d00, 0x68de) | `tp_free` slot dispatch on teardown. |
| `0x7012` | `jmp *%rdi` | computed-goto | **verdict dispatch itself** — the valid/invalid branch is a data-driven jump table; latency shape = channel F. |
| `0x2a05` | `jmp *%r13` (`cmp $0x1a` + jump-table @0x86e0) | encoder escape switch | output-side computed goto (escape encoding). |

Machine-code ground truth, same discipline as `peershim.c`: **the parser is not
a predicate — it is an interpreter with caller-supplied opcodes.** The only
"VM-ish" capability the gate already ships, pre-authorized, is exactly the hook
slot at `0x35fd`/`0x456c`. We don't build a VM; we audit the one the validator
already runs.

## 3. Ambient-state read inside the gate

`decoder_iternext` prologue @`0x6e9b..0x6ec7`: loads thread state, reads
`recursion_trigger`-adjacent fields (`shr $0x2 / and $0x7` kind-extract,
`testb $0x10,0xab(...)` unicode compact flag). Consequence, measured in probe G:
the C scanner accepts depth-900 nesting while the pure-Python scanner raises
`RecursionError` at the *same* bytes under the *same* default limit — two
validators shipped in one stdlib disagree about "is this JSON?" ⇒ any HMAC over
raw bytes certifies a verdict made by whichever implementation the host loaded.

## 4. What the region emits besides the bit (measured — see artifact)

`disasm/json_validator_influence.py` → `artifacts/json_validator_influence.json`:

- **A PROVEN** — side-effect budget granted pre-verdict: hooks fired on a doc
  whose parse then aborted (`aborted_doc_hooks_before_error=1`).
- **B PROVEN** — deterministic innermost-first traversal order ⇒ tree-shape
  disclosure even for docs later rejected.
- **C PROVEN** — hook return value adopted *by identity*; certified structure
  wholly discardable (`final_is_attacker_object=true`).
- **C2 PROVEN** — `object_pairs_hook` sees every duplicate pair *before* the
  `0x4112` collapse; the policy of which value wins is the hook's, not the bytes'.
- **D PROVEN/MASKED boundary** — hook exceptions propagate verbatim (error
  channel takeover) but syntax rejection survives (`nonjson_still_rejected=JSONDecodeError`).
- **E REVISED (honest failure)** — initial claim "memo persists across requests"
  CONTRADICTED: `same_key_object_across_parses=false`, escape-vs-literal keys
  share no slot (`escape_key_shares_memo_slot=false`). Persistence channel:
  NOT PROVEN on 3.12.10. Logged per house style (Popov §revision-at-contradiction).
- **F INFERRED** — verdict latency spectrum input-controlled: invalid≈3629ns vs
  valid≈1472ns, hook≈3226ns ⇒ oracle bandwidth exists inside the gate.
- **G PROVEN** — config-dependent verdict divergence between C and py scanners
  (`c_python_divergence=true`, depth 900).
- **H PROVEN** — identical signed bytes → different certified value depending on
  collapse policy (`diverge_on_identical_bytes=true`: default `{k:TRAP}` vs
  first-wins hook `{k:ok}`) — Python-side twin of the Java Replica DISAGREE.

## 5. Encoder note (the other half of the transition)

`PyLong_FromVoidPtr` @PLT + `id(obj)+0xabd8/0xe958` marker arithmetic around
`0x687f/0x68a9` = circularity markers keyed on **object identity**. Combined
with C (hooks returning shared objects), identity is load-bearing across the
validate→reserialize round trip: two semantically equal trees with different
identity graphs serialize differently. Byte/value identity mismatch (X2) has a
concrete machine-level origin here.

## 6. Repro

```bash
SO=/usr/local/lib/python3.12/lib-dynload/_json.cpython-312-x86_64-linux-gnu.so
objdump -d --section=.text $SO > disasm/_json.intel.txt        # full listing
objdump -d --start-address=0x35c0 --stop-address=0x3640 $SO    # hook site 0x35fd
objdump -d --start-address=0x4540 --stop-address=0x4600 $SO    # float-hook site 0x456c
objdump -d --start-address=0x6e90 --stop-address=0x6f00 $SO    # recursion guard
nm -D --defined-only $SO                                       # only PyInit__json exported
python3 disasm/json_validator_influence.py                     # rebuild artifact
```

## 7. Next smallest probes (queue)

1. **Policy-flip test:** put a route allow-list check *behind* `object_pairs_hook`
   vs behind plain `loads` on the same replica; measure whether the verdict flips
   under H-style duplicates (does the gate's value-selection reach authorization?).
2. **Identity-graph serialization:** hook returns shared subtrees; diff reserialized
   bytes against signer's raw bytes (expect byte divergence with zero semantic change).
3. **Timing-oracle stability:** re-run F across processes; establish SNR before calling it a channel.
4. E's negative result: confirm whether memo scope is per-decoder-instance by parsing
   through a *single long-lived* `JSONDecoder` (vs module-level `loads`).

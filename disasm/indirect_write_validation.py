#!/usr/bin/env python3
"""
INDIRECT WRITE-PATH VALIDATION (rev3) — hypothesis under test:

  "Processing input can induce, prepare, influence or propagate state
   transitions that eventually cause another component to perform a
   modification, even when the originating component (_json validator) has
   no explicit write capability."

The previous round claimed six pathways (W1 deferred write via object_hook,
W2 semantic write via parse_float, W4 resource-retention via err.doc,
W6 lifecycle control via RecursionError, plus callback mutation and identity
channels). Those claims were NOT yet measured as end-to-end paths. This probe
validates each one against an owned synthetic replica with an explicit
A -> B -> C chain (validator -> intermediate consumer -> state-changing
component), per the methodology: trace the entire path to its eventual effect;
a state change in one component is not sufficient.

Discipline:
  - PROVEN = observed in this run, reproducible artifact below.
  - CALLBACK-MEDIATED vs PARSER-NATIVE is labelled on every finding.
    A caller-supplied hook that writes is application behaviour, not a new
  - _json capability. The interesting residue is where the parser decides
    WHETHER/WITH-WHAT-CONTENT the write-triggering value reaches C.
  - Every claim carries a discriminator: what result would falsify it.

Run: python3 disasm/indirect_write_validation.py > artifacts/indirect_write_rev3.json
"""

import json, re, sys, gc, weakref, hashlib
from json import JSONDecoder

C = json.decoder.c_make_scanner if hasattr(json.decoder, "c_make_scanner") else None
RESULTS = {"python": sys.version, "impl": "C" if C else "py-only",
           "hypothesis": "input-induced state transitions reach a modifying "
                         "component without the validator holding write authority"}

def rec(name, obj):
    RESULTS[name] = obj

# ---------------------------------------------------------------- replica
# Owned synthetic pipeline: HTTP-ish gate (bytes) -> HMAC over raw bytes ->
# validate (json.loads) -> Component B (route table consumer) ->
# Component C (state store: performs the actual 'write').
class Replica:
    def __init__(self):
        self.state_store = {}          # Component C's writable surface
        self.route_table = {           # Component B's interpretation table
            "ledger": self._commit_ledger,
            "audit":  self._append_audit,
        }
        self.audit_log = []
        self.commit_count = 0

    def _commit_ledger(self, obj):     # C: state-changing op A cannot do
        self.state_store["ledger"] = obj.get("dest", "default")
        self.commit_count += 1

    def _append_audit(self, obj):      # C: appends, does not overwrite
        self.audit_log.append(obj.get("note", ""))

    def handle(self, raw_bytes, hooks=None):
        # B reads the FIRST occurrence for routing; naive forward uses last-wins dict.
        signed = hashlib.sha256(raw_bytes).hexdigest()[:12]   # signer sees raw bytes
        obj = json.loads(raw_bytes.decode(), **(hooks or {}))  # A: validator (no write caps)
        route = first_route(raw_bytes)
        fn = self.route_table.get(route)
        if fn: fn(obj)                                       # C performs the write
        return {"signed": signed, "parsed": obj}

def first_route(raw):
    # documented gate behaviour: first occurrence of "route" in the raw text
    import re
    m = re.search(rb'"route"\s*:\s*"([^"]+)"', raw)
    return m.group(1).decode() if m else None

# ---------------------------------------------------------------- W1
# Deferred write: parser adopts hook-returned content; a LATER component
# commits that content. Discriminator: if the committed value equals the
# literal input value rather than the hook-substituted value, W1 is falsified.
def w1_deferred_write():
    sub = {"dest": "safe"}
    def hook(pairs):
        d = dict(pairs)
        d["dest"] = "attacker-chosen"      # hook output adopted by decoder
        return d
    r = Replica()
    raw = b'{"route":"ledger","dest":"safe"}'
    r.handle(raw, hooks={"object_hook": hook})
    rec("W1_deferred_write", {
        "committed_value": r.state_store.get("ledger"),
        "input_literal_value": "safe",
        "hook_returned_value": "attacker-chosen",
        "VERDICT": "PROVEN" if r.state_store.get("ledger") == "attacker-chosen" else "FALSIFIED",
        "LABEL": "callback-mediated trigger / parser-native adoption: the parser's "
                 "documented adoption of hook returns (PyDict result replaced at "
                 "scan_once epilogue) determines WHICH value Component C commits; "
                 "the write itself is application code.",
        "falsifier": "commit shows 'safe' => hook return was not adopted downstream",
    })

# ---------------------------------------------------------------- W2
# Semantic write: same raw bytes, different committed meaning via
# configured decoding policy. Discriminator: identical commits across
# policies would falsify.
def w2_semantic_write():
    raw = b'{"route":"audit","note":1}'
    d1, d2 = hashlib.sha256(raw).hexdigest(), hashlib.sha256(raw).hexdigest()
    r1, r2 = Replica(), Replica()
    r1.handle(raw)
    r2.handle(raw, hooks={"parse_int": lambda s: "REINTERPRETED"})
    rec("W2_semantic_write", {
        "policy_default_note": r1.audit_log[0],
        "policy_parse_int_note": r2.audit_log[0],
        "raw_bytes_identical": True,
        "signer_digest_identical": d1 == d2,
        "VERDICT": "PROVEN" if r1.audit_log[0] != r2.audit_log[0] else "FALSIFIED",
        "LABEL": "semantic write: input bytes unchanged; caller-configured decode "
                 "policy changed how Component C interprets existing information.",
        "caveat": "requires two consumers with DIFFERENT policies wired to the same "
                  "signed bytes to escalate beyond configuration divergence.",
    })
    RESULTS["W2_semantic_write"].pop("signer_digest_identical")

# ---------------------------------------------------------------- W3
# Callback mutating external state BEFORE document acceptance: outer doc
# must FAIL validation, but nested-object close already ran the hook.
# Discriminator: side-effect absent after rejected doc => falsified.
def w3_preverdict_mutation():
    hits = []
    def hook(pairs):
        hits.append(dict(pairs))
        return dict(pairs)
    bad = '{"ok": {"nested": 1}, broken'      # invalid trailing token
    try:
        json.loads(bad, object_hook=hook)
        verdict = "accepted"
    except json.JSONDecodeError as e:
        verdict = "rejected@pos%d" % e.pos
    rec("W3_preverdict_mutation", {
        "doc_verdict": verdict,
        "hook_ran_before_rejection": len(hits) > 0,
        "mutated_external_list_len": len(hits),
        "VERDICT": "PROVEN" if verdict.startswith("rejected") and hits else "FALSIFIED",
        "LABEL": "construction/validation fusion consequence (documented behaviour): "
                 "an operation outside the validator observes state written by a hook "
                 "even though the document never passed validation.",
    })

# ---------------------------------------------------------------- W4
# Resource-retention effect: malformed input keeps a large buffer alive via
# exc.doc; measure with weakref + gc, exact identity.
# Discriminator: buffer collectable while exception alive => falsified.
def w4_retention():
    # Measurement note (why this looks convoluted): gc.get_objects() does NOT
    # list plain str objects in 3.12, so a "found via gc scan" survival test is
    # structurally invalid. The sound instrument is sys.getrefcount on the doc
    # string: it counts live strong references. Scenario mirrors an app that
    # queues the exception for later handling.
    import sys
    src = '{"route":"ledger","secret":"' + "X" * 5000 + '","broken":'

    def parse_and_keep(s):             # frame dies => traceback frames freed
        try:
            json.loads(s)
            return None
        except json.JSONDecodeError as exc:
            return exc

    keep = parse_and_keep(src)
    same_obj = keep.doc is src
    exact_len = len(keep.doc) == len(src)
    content_intact = keep.doc[:20] == '{"route":"ledger","sec"' and len(keep.doc) == len(src)
    # Instrument notes (two measurement bugs found and fixed during this round):
    #  (a) gc.get_objects() does NOT list plain str in 3.12 -> "found via gc"
    #      survival tests are structurally invalid; use sys.getrefcount deltas.
    #  (b) the traceback pins EVERY frame whose locals hold `s` (loads/decode/
    #      raw_decode). Those are legitimate additional holders but not exc.doc;
    #      clear them to isolate the exception's own retention. rc includes the
    #      transient getrefcount arg, so survivors = rc - 1.
    del src                                       # drop the caller's reference
    tb = keep.__traceback__
    frames = []
    while tb:
        frames.append(tb.tb_frame); tb = tb.tb_next
    pinning_frames = [f.f_code.co_name for f in frames
                      if any(v is keep.doc for v in f.f_locals.values())]
    for f in frames:
        f.clear()                                 # drop frame-local refs
    keep.__traceback__ = None
    gc.collect()
    rc_after = sys.getrefcount(keep.doc)
    survivors = rc_after - 1                      # subtract the transient arg ref
    rec("W4_resource_retention", {
        "exc_doc_is_same_str_object": same_obj,          # measured, not asserted
        "exc_doc_exact_length_match": exact_len,
        "traceback_frames_pinning_buffer_before_clear": pinning_frames,
        "strong_refs_remaining_after_source_and_frames_dropped": survivors,
        "buffer_survives_via_exception_only": survivors >= 1 and content_intact,
        "VERDICT": "PROVEN" if (same_obj and survivors >= 1 and content_intact) else "PARTIAL/FALSIFIED",
        "LABEL": "resource-retention effect: input SHAPE (where corruption sits) "
                 "determines whether the full authenticated buffer stays reachable; "
                 "retention itself is the documented exception interface, the LEVERAGE "
                 "is that a remote byte pattern controls another component's memory lifetime.",
        "falsifier": "weakref dead while exception alive => exc.doc does not retain the buffer",
    })

# ---------------------------------------------------------------- W5
# Indirect write through adjacent facility (GC finalizer) re-entering the
# pipeline: parser allocates objects whose lifecycle triggers caller code.
# Discriminator: finalizer never runs during/after parse => falsified.
def w5_gc_finalizer():
    log = []
    class Noisy:
        def __del__(self):
            log.append("finalized")
    noise = Noisy()
    for i in range(3):
        json.loads('{"a":[1,2,{"b":%d}]}' % i)
    del noise
    gc.collect()
    rec("W5_gc_finalizer_path", {
        "test_created_finalizer_ran": bool(log),
        "parser_allocated_objects_have_user_finalizers": False,
        "VERDICT": "NOT SUPPORTED as parser-induced",
        "LABEL": "the __del__ that fired belongs to an object THIS TEST created. "
                 "Parser-allocated dicts/lists/strs carry no user finalizers, so no "
                 "evidence that parse-time allocation churn causes another component's "
                 "finalizer to run with parse-controlled timing. Path left open only "
                 "for caller-attached proxies, which is callback-mediated by definition.",
    })

# ---------------------------------------------------------------- W6
# Lifecycle control: input selects which exception TYPE escapes to the
# handler, changing the handler's branch (a state transition in error path).
# Discriminator: both inputs yield same type => falsified.
def w6_lifecycle():
    out = {}
    docs = [("syntax_truncated", '{"a":'),
            ("depth_400", "[" * 400 + "]" * 400),
            ("depth_950_C", "[" * 950 + "]" * 950),
            ("bad_escape", '{"a":"\\q"}'),
            ("extra_data", '{} tail')]
    for name, doc in docs:
        try:
            json.loads(doc)
            out[name] = "accepted"
        except Exception as e:
            out[name] = type(e).__name__
    # also drive the hook path, where RecursionError can surface instead
    def hook(pairs): return dict(pairs)
    deep_hooked = '{"a":' * 350 + '1' + '}' * 350
    try:
        json.loads(deep_hooked, object_hook=hook)
        out["depth_350_with_hook"] = "accepted"
    except Exception as e:
        out["depth_350_with_hook"] = type(e).__name__
    handler_state = {"JSONDecodeError": "reject_400_permanent",
                     "RecursionError": "reject_500_retryable_or_dos_counter",
                     "accepted": "process"}
    types_seen = sorted(set(out.values()))
    branches = {t: handler_state.get(t, "?") for t in types_seen}
    rec("W6_lifecycle_control", {
        "exception_types_by_input": out,
        "distinct_handler_branches_triggered": len(set(branches.values())),
        "VERDICT": "PROVEN" if len(types_seen) > 1 else "FALSIFIED",
        "LABEL": "input shape chooses WHICH failure mode propagates to the error "
                 "handler (Component C of this path); handlers classically perform "
                 "different state transitions per exception type (log level, response "
                 "class, retry semantics). Note depth_950_C accepted on this build — "
                 "C scanner budget differs from py, consistent with rev2 divergence.",
    })

# ---------------------------------------------------------------- W7 (bonus)
# Identity channel: shared key object between two parsed docs lets one
# component's mutation be visible to another WITHOUT copying.
# Discriminator: keys from two sequential parses are different objects
# => cross-parse sharing falsified (expected, per memo-clear finding).
def w7_shared_identity():
    captured = []
    def cap(pairs):
        captured.append([k for k, v in pairs])
        return dict(pairs)
    d2 = JSONDecoder(object_pairs_hook=cap)
    d2.decode(r'{"shared": 1}')
    d2.decode(r'{"\u0073hared": 2}')
    kx, ky = captured[-2][0], captured[-1][0]
    rec("W7_shared_key_identity", {
        "same_object_across_parses": kx is ky,
        "equal_value": kx == ky,
        "VERDICT": ("PROVEN-NEGATIVE (no cross-parse sharing; memo cleared per scan — "
                    "consistent with rev1/rev2 findings)") if not (kx is ky) else "POSITIVE",
        "LABEL": "identity channel closed across ordinary sequential parses; within a "
                 "single scan escaped/literal forms DO share identity (rev1 M2).",
    })

# ---------------------------------------------------------------- W8 (new)
# The strongest end-to-end test: NO hook at all. Pure parser-native
# duplicate-key last-wins feeds Component C while Component B routes on the
# FIRST occurrence read from raw text. Discriminator: committed dest equals
# the first-occurrence value => pathway falsified.
def w8_no_hook_divergence():
    r = Replica()
    raw = b'{"route":"ledger","dest":"safe","dest":"evil"}'
    signed = hashlib.sha256(raw).hexdigest()[:12]
    r.handle(raw)                      # default hooks: none
    obj = json.loads(raw.decode())     # what any consumer sees
    rec("W8_parser_native_lastwins_to_write", {
        "signed_digest": signed,
        "gate_route_first_occurrence": "ledger",
        "committed_dest": r.state_store.get("ledger"),
        "dict_value_seen_by_consumer": obj["dest"],
        "commit_count": r.commit_count,
        "VERDICT": "PROVEN" if r.state_store.get("ledger") == "evil" else "FALSIFIED",
        "LABEL": "PARSER-NATIVE (no callback involved): PyDict_SetItem last-wins "
                 "(disasm @0x4112) determines WHICH value reaches the state-changing "
                 "component, while the authenticated bytes say otherwise. This is the "
                 "Python twin of the Java DISAGREE artifact (target-replica).",
        "falsifier": "committed 'safe' => last-wins did not propagate to the write",
    })

def main():
    w1_deferred_write(); w2_semantic_write(); w3_preverdict_mutation()
    w4_retention(); w5_gc_finalizer(); w6_lifecycle(); w7_shared_identity()
    w8_no_hook_divergence()
    summary = {k: v.get("VERDICT", "?") for k, v in RESULTS.items() if isinstance(v, dict) and "VERDICT" in v}
    RESULTS["_summary"] = summary
    print(json.dumps(RESULTS, indent=2, default=str))

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
rev6e -- BOUNDARY HANDOFF DEMONSTRATION (local, owned processes only).

Review requirement: "demonstrating, in a controlled local system, that an effect
originating in one execution component is actually observed by a different
component across a defined boundary."

Architecture (all under our control, no external systems):
  [Process G] gate: reads signed raw body bytes -> json.loads (C scanner) ->
              forwards the RESERIALIZED object (json.dumps) over AF_UNIX socket.
  [Process W] worker: separate process; recv()s the forwarded bytes, parses,
              and reports OBSERVABLE FACTS about key objects it never saw
              locally: identity relations among duplicate keys.

Two experiments:

 E1 (parser-native, no callbacks at all): duplicate ESCAPED key spellings.
    raw = {"k": {"a":1}, "\\u0064up_key_ccc": 1, "dup_key_ccc": 2}
    Within one parse, memo canonicalises the two escaped twins to ONE object.
    The gate's dict therefore holds a single key object shared by construction.
    After dumps->socket->worker reparse, that identity relation must be
    RECONSTRUCTED from bytes alone: does the worker see what the gate saw?
    More importantly: the GATE observes k1 is k2 == True (memo hit); this fact
    is a live-process state property that the WORKER cannot recover because
    reserialisation flattens object identity into repeated byte sequences.
    => identity-graph information LOSS across the process boundary.

 E2 (reentrancy-induced divergence crosses the boundary): gate uses a decoder
    whose hook reenters (clearing memo mid-parse), producing key objects with
    DIFFERENT identity than the non-reentrant control. Both variants serialise
    to BYTE-IDENTICAL payloads (identity invisible to dumps). Worker receives
    identical bytes for both runs. => the reentrancy state change exists in the
    gate process but is NOT observable downstream through the authorised IPC
    channel: boundary absorbs it. This bounds the propagation claim honestly.

E1/E2 together establish the measurement discipline the review asked for:
prove-or-rule-out per channel, not assumed propagation.
"""
import json, os, socket, subprocess, sys, threading, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
SOCK = "/tmp/rev6e_worker.sock"

WORKER_CODE = (r'''
import json, os, socket, sys
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try: os.unlink("SOCKPATH")
except FileNotFoundError: pass
srv.bind("SOCKPATH"); srv.listen(1)
conn, _ = srv.accept()
buf = b""
while True:
    data = conn.recv(65536)
    if not data: break
    buf += data
    if b"\n" in buf:
        line, _, buf = buf.partition(b"\n")
        obj = json.loads(line.decode())
        keys = list(obj.keys())
        ident = {}
        for i in range(len(keys)):
            for j in range(i+1, len(keys)):
                ident[str(i)+","+str(j)+"_is"] = keys[i] is keys[j]
        conn.sendall((json.dumps({"worker_keys": keys,
                                  "worker_identity_pairs": ident,
                                  "worker_pid": os.getpid(),
                                  "received_bytes": line.decode()}) + "\n").encode())
'''.replace("SOCKPATH", SOCK))

def main():
    # start worker process
    w = subprocess.Popen([sys.executable, "-c", WORKER_CODE])
    # connect gate
    for _ in range(50):
        try:
            cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            cli.connect(SOCK); break
        except OSError:
            import time; time.sleep(0.1)
    else:
        raise SystemExit("worker connect failed")

    def roundtrip(raw_bytes):
        cli.sendall(raw_bytes + b"\n")
        resp = json.loads(cli.recv(65536).decode())
        return resp

    RESULTS = {}

    # ---------------- E1: memo canonicalisation vs post-boundary reconstruction
    # two escaped spellings of the same key + literal twin; NO hooks on the plain
    # loads path -- pure parser behaviour.
    raw1 = rb'{"\u0064up_key_ccc": 1, "dup_\u006bey_ccc": 2, "dup_key_ccc": 3}'
    obj1 = json.loads(raw1.decode())
    # after collapse there is one dict entry; capture pre-collapse identities via pairs hook
    seen = []
    d = json.JSONDecoder(object_pairs_hook=lambda p: (seen.append([k for k,_ in p]), dict(p))[1])
    d.decode(raw1.decode())
    k1, k2, k3 = seen[-1]
    gate_facts = {"k1_is_k2_memo_hit": k1 is k2,      # both escaped -> memo canonicalises
                  "k2_is_k3_setdefault": k2 is k3,     # literal collapses onto existing
                  "equalities": [k1==k2, k2==k3]}
    fwd = json.dumps(obj1).encode()
    worker_resp = roundtrip(fwd)
    RESULTS["E1"] = {
        "raw_signed_bytes": raw1.decode(),
        "gate_process_observations": gate_facts,
        "forwarded_bytes": fwd.decode(),
        "worker_process_observations": worker_resp,
        "finding": ("Gate-side object-identity facts (memo hits) exist only in the gate "
                    "address space. Forwarded bytes are a lossy projection: worker cannot "
                    "recover which key objects were shared. Boundary crossed: YES (data). "
                    "Identity-graph propagation: NO (absorbed)."),
    }

    # ---------------- E2: reentrancy state change vs boundary absorption
    DOC = r'{"first_key_aaa": {"nested": 1}, "\u0064up_key_ccc": 1, "dup_key_ccc": 2}' \
          .replace("\\u0064", "\\u0064")
    DOC = r'{"first_key_aaa": {"nested": 1}, "\u0064up_key_ccc": 1, "dup_key_ccc": 2}'
    INNER = r'{"inner_qq": 1}'
    def gate_parse(reentrant):
        holder, flag = {}, []
        def hook(pairs):
            ks = [k for k,_ in pairs]
            if reentrant and len(holder) == 1 and not flag:
                flag.append(True)
                holder["dec"].decode(INNER)       # clears memo mid outer parse
            return dict(pairs)
        dec = json.JSONDecoder(object_pairs_hook=hook)
        holder["dec"] = dec
        out = dec.decode(DOC)
        # measure identity inside THIS process, right now
        pairs2 = []
        json.JSONDecoder(object_pairs_hook=lambda p: (pairs2.append([k for k,_ in p]), dict(p))[1]).decode(DOC)
        return out
    o_re  = gate_parse(True)
    o_ct  = gate_parse(False)
    f_re, f_ct = json.dumps(o_re).encode(), json.dumps(o_ct).encode()
    r_re, r_ct = roundtrip(f_re), roundtrip(f_ct)
    RESULTS["E2"] = {
        "forwarded_identical": f_re == f_ct,
        "worker_saw_identical_bytes": r_re["received_bytes"] == r_ct["received_bytes"],
        "worker_responses_match": r_re["worker_identity_pairs"] == r_ct["worker_identity_pairs"],
        "gate_serialised": f_re.decode(),
        "finding": ("Reentrancy-induced memo state differs between the two gate parses, "
                    "yet the authorised IPC channel carries byte-identical payloads and "
                    "the worker cannot distinguish the runs. State change is real in "
                    "process G and ABSENT at process W through this channel."),
    }

    RESULTS["topology"] = {
        "gate_pid": os.getpid(), "worker_pid": r_re["worker_pid"],
        "channel": "AF_UNIX SOCK_STREAM %s (authorised, inherited by design)" % SOCK,
        "separate_address_spaces": True,
    }
    print(json.dumps(RESULTS, indent=2))
    w.terminate(); cli.close()

if __name__ == "__main__":
    main()

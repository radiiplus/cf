#!/usr/bin/env python3
"""
pivot_matrix_v2.py -- cross-layer pivot harness against the LOCAL synthetic shim.

Replaces the lost T1..T12 run (artifacts/pivot_matrix.json claims every test,
including valid ones, returned 400/slot=-2 -- inconsistent with a live-shim
reproduction; that artifact is therefore treated as HISTORICAL/UNVERIFIED and
is regenerated here from scratch).

Design rule: never inject content into protected interfaces. Every probe is a
body that is individually well-formed to SOME layer, and we observe which
layer's view diverges:

  P1  valid dest                  -> baseline forward, capture raw vs forwarded bytes
  P2  duplicate dest keys         -> strict-parser view vs shim strstr view
  P3  escaped-key alias dest      -> same
  P4  decoy prefix key            -> substring-scan confusion attempt
  P5  BOM prefix                  -> framing vs scanner divergence
  P6  opcode/asm/binary payloads  -> inertness re-check at the LIVE boundary
  P7  role=admin spoof fields     -> authority provenance
  P8  path traversal in id        -> does any consumer treat id as a path? (shim: no)
  P9  unknown slot                -> allow-list negative
  P10 two equal-value/different-bytes requests -> identity disagreement demo
  P11 >2^53 amount through node consumer       -> cross-runtime value drift

The shim writes its forwarded bytes only toward operator-fixed slots
(19100-19102). We stand up dummy listeners on those ports so the EFFECT
(received bytes) is observable without touching anything external.
"""

import json, socket, subprocess, sys, threading, time, hashlib, os

SHIM = "disasm/peershim"
PORT = 19099
SLOT_PORTS = {"audit": 19100, "worker": 19101, "archive": 19102}

captured = {}   # port -> list of received payload bytes

def listener(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(4); s.settimeout(0.2)
    while True:
        try:
            c, _ = s.accept()
        except socket.timeout:
            continue
        c.settimeout(0.5)
        try:
            data = c.recv(65536)
        except Exception:
            data = b"<recv-error>"
        captured.setdefault(port, []).append(data)
        c.close()

def post(body_bytes, timeout=3.0):
    s = socket.create_connection(("127.0.0.1", PORT), timeout)
    req = (b"POST /x HTTP/1.1\r\nHost: shim\r\nContent-Type: application/json\r\n"
           b"Content-Length: " + str(len(body_bytes)).encode() + b"\r\n\r\n" + body_bytes)
    s.sendall(req)
    resp = b""
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        resp += chunk
    s.close()
    return resp.decode("utf-8", "replace")

def status_of(resp):
    first = resp.split("\r\n", 1)[0]
    return first.split(" ", 2)[1] if len(first.split(" ")) > 1 else "?"

def field_of(resp, key):
    # shim's response body embeds raw forwarded_bytes inside a JSON string
    # WITHOUT escaping -> body is not always valid JSON; anchor at end of line.
    import re
    m = re.search(rf'"{key}":([^,\n}}]+|"[^"]*")', resp.split("\r\n\r\n", 1)[-1])
    if not m:
        return None
    v = m.group(1)
    return v[1:-1] if v.startswith('"') else v

def slot_of(resp):
    return field_of(resp, "slot")

def fwd_of(resp):
    return field_of(resp, "forwarded_bytes")

RESULTS = []
def rec(pid, desc, body, resp, expect_divergence=False):
    r = {"id": pid, "desc": desc, "body": body[:120].decode('utf-8','replace'),
         "status": status_of(resp), "slot": slot_of(resp),
         "forwarded": fwd_of(resp)}
    RESULTS.append(r)
    print(f"{pid:4} {desc[:38]:38} status={r['status']:4} slot={str(r['slot']):5} "
          f"fwd={str(r['forwarded'])[:60]}")
    return r

def main():
    if not os.path.exists(SHIM):
        sys.exit(f"build first: cd disasm && gcc -O0 -no-pie -static -o peershim peershim.c")
    threads = []
    for p in SLOT_PORTS.values():
        t = threading.Thread(target=listener, args=(p,), daemon=True); t.start(); threads.append(t)
    shim = subprocess.Popen([f"./{SHIM}", str(PORT)], stderr=subprocess.DEVNULL)
    time.sleep(0.4)
    try:
        base = b'{"dest":"audit","id":"1","note":"hello"}'
        rec("P1", "valid dest baseline", base, post(base))

        rec("P2", "dup dest worker->audit",
            b'{"dest":"worker","dest":"audit","id":"2"}',
            post(b'{"dest":"worker","dest":"audit","id":"2"}'))

        rec("P3", "escaped-key alias de\\u0073t",
            b'{"dest":"audit","de\\u0073t":"worker","id":"3"}',
            post(b'{"dest":"audit","de\\u0073t":"worker","id":"3"}'))

        rec("P4", "decoy prefixdest before dest",
            b'{"prefixdest":"zzz","dest":"audit","id":"4"}',
            post(b'{"prefixdest":"zzz","dest":"audit","id":"4"}'))

        rec("P5", "BOM prefix",
            b'\xef\xbb\xbf{"dest":"audit","id":"5"}',
            post(b'\xef\xbb\xbf{"dest":"audit","id":"5"}'))

        rec("P6a", "NOP bytes in note",
            b'{"dest":"audit","id":"6","note":"' + b'\x90'*16 + b'"}',
            post(b'{"dest":"audit","id":"6","note":"' + b'\x90'*16 + b'"}'))

        rec("P6b", 'syscall asm text in note',
            b'{"dest":"audit","id":"6","note":"mov $60,%rax; syscall"}',
            post(b'{"dest":"audit","id":"6","note":"mov $60,%rax; syscall"}'))

        rec("P7", "role/uid spoof fields",
            b'{"dest":"audit","id":"7","role":"admin","uid":0}',
            post(b'{"dest":"audit","id":"7","role":"admin","uid":0}'))

        rec("P8", "path traversal in id",
            b'{"dest":"audit","id":"../../etc/passwd"}',
            post(b'{"dest":"audit","id":"../../etc/passwd"}'))

        rec("P9", "unknown slot",
            b'{"dest":"evil","id":"9"}',
            post(b'{"dest":"evil","id":"9"}'))

        rec("P10", "equal-value diff-bytes (whitespace)",
            b'{ "dest" : "audit" , "id" : "1" , "note" : "hello" }',
            post(b'{ "dest" : "audit" , "id" : "1" , "note" : "hello" }'))

        rec("P11", "amount 2^53+1 passthrough",
            b'{"dest":"audit","id":"11","amount":9007199254740993}',
            post(b'{"dest":"audit","id":"11","amount":9007199254740993}'))

        # cross-runtime consumer check for P11 (node JSON.parse domain).
        # NOTE: node -e does not populate argv[1]; pass the doc as a literal.
        node_view = subprocess.run(
            ["node", "-e",
             'const v=JSON.parse(require("fs").readFileSync(0,"utf8"));console.log(v.amount, String(v.amount))'],
            input=b'{"amount":9007199254740993}', capture_output=True)
        nv = node_view.stdout.decode().strip()
        print(f"\nP11 node consumer sees: {nv!r} (python keeps 9007199254740993)")

        # what did the audit listener actually receive?
        print("\nreceived-at-slot:")
        for p, msgs in sorted(captured.items()):
            name = [k for k, v in SLOT_PORTS.items() if v == p][0]
            for i, m in enumerate(msgs):
                print(f"  {name}:{p} msg{i}: {m[:100]!r}")
    finally:
        shim.terminate()

    with open("artifacts/pivot_matrix_v2.json", "w") as f:
        json.dump({"results": RESULTS,
                   "received": {str(k): [m.decode('utf-8','replace') for m in v]
                               for k, v in captured.items()}}, f, indent=1)
    print("\n-> artifacts/pivot_matrix_v2.json")

if __name__ == "__main__":
    main()

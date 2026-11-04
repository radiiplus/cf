"""
target_replay.py -- Phase 2/4/5 driver against target-replica (Java/Jackson 2.17).
Starts the replica on loopback, sends HMAC-signed requests exercising each
cross-component invariant candidate, captures S1..S4 + WORKER views from stdout.
Every request is signed over its EXACT raw bytes, so any forwarded byte sequence
that differs from the authenticated one is attributable to the reserialization
boundary, not to a signature bug.
"""
import hashlib, hmac, http.client, json as pyjson, subprocess, sys, time, threading, queue

HTTP_PORT, WORKER_PORT = 18090, 18091
API_KEY = b"synthetic-api-key"

def sign(ts, method, path, raw): return hmac.new(API_KEY, ts+method+path+raw, hashlib.sha256).hexdigest()

def send(raw_body: bytes, biz=None):
    ts = b"1730000000"; m = b"POST"; p = b"/api/v3/wallet/withdraw"
    c = http.client.HTTPConnection("127.0.0.1", HTTP_PORT, timeout=5)
    c.request("POST", p.decode(), body=raw_body, headers={
        "Content-Type":"application/json","X-Timestamp":ts.decode(),
        "X-Signature":sign(ts,m,p,raw_body),"Content-Length":str(len(raw_body))})
    r = c.getresponse(); out = (r.status, r.read().decode()); c.close(); return out

CASES = [
 # id, description, raw body bytes
 ("C0-baseline", "valid, whitespace-free", b'{"dest":"ledger","amount":100,"bizId":"b-c0"}'),
 ("C1-whitespace", "same logical value, different bytes (spaces)", b'{ "dest" : "ledger" , "amount" : 100 , "bizId" : "b-c1" }'),
 ("C2-dupkey-route", "duplicate dest: ledger then evil (last-wins strict?)", b'{"dest":"ledger","dest":"evil","amount":100,"bizId":"b-c2"}'),
 ("C3-dupkey-amt", "duplicate amount: 100 then 999999", b'{"dest":"ledger","amount":100,"amount":999999,"bizId":"b-c3"}'),
 ("C4-bigint", "amount 2^53+1 (float-domain boundary)", b'{"dest":"ledger","amount":9007199254740993,"bizId":"b-c4"}'),
 ("C5-esc-name", "escaped key de\\u0073t decoy after real dest", b'{"dest":"ledger","de\\u0073t":"evil","amount":100,"bizId":"b-c5"}'),
 ("C6-nested-order", "key order differs from insertion order expectations", b'{"bizId":"b-c6","amount":100,"dest":"ledger"}'),
 ("C7-idem-replay", "idempotent replay of C0 body with NEW bizId? no: same bizId b-c0", b'{"dest":"ledger","amount":100,"bizId":"b-c0"}'),
]

def main():
    cp = "lib/jackson-core-2.17.0.jar:lib/jackson-databind-2.17.0.jar:lib/jackson-annotations-2.17.0.jar:target-replica/classes"
    proc = subprocess.Popen(["java","-cp",cp,"-DhttpPort=%d"%HTTP_PORT,"-DworkerPort=%d"%WORKER_PORT,"research.target.Replica"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    lines = queue.Queue()
    def rd():
        for l in proc.stdout: lines.put(l.rstrip())
    threading.Thread(target=rd, daemon=True).start()
    time.sleep(2.0)
    results = []
    for cid, desc, body in CASES:
        st, resp = send(body)
        time.sleep(0.4)
        obs = []
        while True:
            try: obs.append(lines.get_nowait())
            except queue.Empty: break
        results.append({"case":cid,"desc":desc,"sent_raw":body.decode("utf-8","replace"),
                        "status":st,"resp":resp,"server_log":obs})
        print("="*70); print(cid, "|", desc); print("  sent:", body)
        print("  status:", st, resp)
        for o in obs: print("   ", o)
    proc.terminate()
    import pathlib; pathlib.Path("artifacts/target_replay.json").write_text(json.dumps(results, indent=1))
main()

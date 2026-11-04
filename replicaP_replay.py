import hashlib, hmac, http.client, subprocess, time, threading, queue
HTTP_PORT, WORKER_PORT = 18092, 18093
API_KEY = b"synthetic-api-key"
def sign(ts,m,p,raw): return hmac.new(API_KEY, ts+m+p+raw, hashlib.sha256).hexdigest()
def send(raw):
    ts=b"1730000000"; m=b"POST"; p=b"/api/v3/wallet/withdraw"
    c=http.client.HTTPConnection("127.0.0.1",HTTP_PORT,timeout=5)
    c.request("POST",p.decode(),body=raw,headers={"X-Timestamp":ts.decode(),"X-Signature":sign(ts,m,p,raw)})
    r=c.getresponse(); out=(r.status,r.read().decode()); c.close(); return out
cp="lib/jackson-core-2.17.0.jar:lib/jackson-databind-2.17.0.jar:lib/jackson-annotations-2.17.0.jar:target-replica/classes"
proc=subprocess.Popen(["java","-cp",cp,"research.target.ReplicaP"],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
q=queue.Queue()
threading.Thread(target=lambda:[q.put(l.rstrip()) for l in proc.stdout],daemon=True).start()
time.sleep(2)
CASES=[
 ("D1 evil->ledger (pairs-first gate?)", b'{"dest":"evil","dest":"ledger","amount":100,"bizId":"d1"}'),
 ("D2 ledger->evil", b'{"dest":"ledger","dest":"evil","amount":100,"bizId":"d2"}'),
 ("D3 amount dup 100->999999", b'{"dest":"ledger","amount":100,"amount":999999,"bizId":"d3"}'),
 ("D4 escaped key de\\u0073t after dest", b'{"dest":"ledger","de\\u0073t":"evil","amount":100,"bizId":"d4"}'),
]
res=[]
for d,b in CASES:
    st,resp=send(b); time.sleep(0.4)
    obs=[]
    while True:
        try: obs.append(q.get_nowait())
        except queue.Empty: break
    print("="*70); print(d); print(" sent:",b); print(" status:",st,resp)
    for o in obs: print("  ",o)
    res.append({"case":d,"sent":b.decode(),"status":st,"log":obs})
proc.terminate()
open("artifacts/replicaP_matrix.json","w").write(__import__("json").dumps(res,indent=1))

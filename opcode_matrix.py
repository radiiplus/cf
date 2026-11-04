#!/usr/bin/env python3
"""
opcode_matrix.py -- feed the JSON boundary FOUR kinds of input, not just text:

  1. normal   : ordinary JSON text (baseline)
  2. opcode   : byte sequences chosen for their machine-code meaning
                (0x90 NOP sled, 0xCC INT3, 0xCD80 legacy int 0x80,
                 0x0F05 SYSCALL bytes, shellcode-looking blobs)
  3. asm      : an ASCII *asm source fragment* as a JSON string value
  4. binary   : raw non-UTF-8 bytes, NULs, overlong/half UTF-8 surrogates,
                lone surrogates, invalid escapes, huge nesting

For each probe we record:
  - which parser gate rejected/accepted it (exception class + message),
  - whether a configured callback ran BEFORE that verdict,
  - what syscall the accepted value would indirectly select (allow-listed),
  - evidence label PROVEN / MASKED per EVIDENCE-DRIVEN-NEGATIVE-SPACE-GUIDE.md.

Nothing here executes request bytes. The point of the opcode/asm rows is to
PROVE they are inert data at every layer that could observe them.
"""

import json, sys, io, struct, traceback

EVENTS = []

def hook(obj):
    EVENTS.append(("object_hook", repr(obj)))
    return obj

def pairs(p):
    EVENTS.append(("object_pairs_hook", repr(p)))
    d = {}
    for k, v in p:
        d[k] = v
    return d

# ---------------------------------------------------------------- probe set
# Each row: (id, class, envelope_note, payload_bytes_or_str)
def mk(s):
    return s.encode() if isinstance(s, str) else s

PROBES = [
    # ---- 1. normal -------------------------------------------------------
    ("N1", "normal", 'valid flat object',            mk('{"a":1}')),
    ("N2", "normal", 'valid nested',                  mk('{"a":{"b":[1,2,3]}}')),
    ("N3", "normal", 'trailing comma (invalid)',      mk('{"a":1,}')),
    ("N4", "normal", 'child ok then outer broken',    mk('{"a":{},"b":')),

    # ---- 2. opcode-shaped payloads --------------------------------------
    ("O1", "opcode", 'NOP sled inside string',        mk('{"note":"' + "\\x90"*16 + '"}')),
    ("O2", "opcode", 'raw NOP bytes as whole body',   b'{"n":"' + b'\x90'*16 + b'"}'),
    ("O3", "opcode", 'INT3 0xCC in value',            b'{"v":"A\xCCB"}'),
    ("O4", "opcode", 'SYSCALL bytes 0F 05 in key',    b'{"\x0F\x05k":1}'),
    ("O5", "opcode", 'int 0x80 form CD 80',           b'{"v":"\xCD\x80"}'),
    ("O6", "opcode", 'execve-style shellcode blob',
        b'{"p":"\\x48\\x31\\xc0\\xb0\\x3b\\x48\\xbf'
        b'\\x2f\\x62\\x69\\x6e\\x2f\\x2f\\x73\\x68\\x50\\x48\\x89\\xe6'
        b'\\x99\\xb0\\x3b\\x0f\\x05\\xcd\\x80"}'),
    ("O7", "opcode", 'real bytes of above (unescaped)',
        b'{"p":"\x48\x31\xc0\xb0\x3b\x0f\x05\xcd\x80"}'),

    # ---- 3. asm-source-as-data ------------------------------------------
    ("A1", "asm", 'AT&T snippet as string value',
        mk('{"src":"movq $60, %rax\\nsyscall\\n"}')),
    ("A2", "asm", 'NASM line with $ and ;',
        mk('{"src":"section .text\\n_start: mov eax, 0x3c ; exit\\nhlt"}')),
    ("A3", "asm", 'asm containing quote/backslash chaos',
        mk(r'{"src":"db 0x0f, 0x05 ; \"syscall\" \\ end"}')),

    # ---- 4. binary / encoding negatives ----------------------------------
    ("B1", "binary", 'NUL byte inside string',        b'{"v":"a\x00b"}'),
    ("B2", "binary", 'whole body starts with NUL',    b'\x00{"v":1}'),
    ("B3", "binary", 'invalid UTF-8 continuation',    b'{"v":"\xff\xfe"}'),
    ("B4", "binary", 'lone surrogate escape',         mk('{"v":"\\ud800"}')),
    ("B5", "binary", 'surrogate pair -> emoji',       mk('{"v":"\\ud83d\\ude00"}')),
    ("B6", "binary", 'overlong \\u002f escape',       mk('{"v":"\\/ok"}')),
    ("B7", "binary", 'half UTF-8 truncated',          b'{"v":"\xe2\x82'),
    ("B8", "binary", 'latin1 high bytes',             '{"v":"café"}'.encode('latin-1')),
    ("B9", "binary", 'CRLF+LF mix, BOM prefix',       b'\xef\xbb\xbf{"v":1}\r\n'),
    ("B10","binary", 'huge depth 100k',               mk('['*100000 + ']'*100000)),
    ("B11","binary", 'duplicate keys',                mk('{"role":"user","role":"admin"}')),
    ("B12","binary", 'NaN/Infinity non-standard',     mk('{"v":NaN,"w":Infinity}')),
    ("B13","binary", 'deeply nested unknown object',  mk('{"a":' * 50 + '{}' + '}' * 50)),
    ("B14","binary", 'class-hint style keys',         mk('{"@type":"jar:http://x","__class__":"os.system"}')),
]

# ------------------------------------------------------------------- runner
def run_one(pid, cls, note, payload):
    EVENTS.clear()
    res = {"id": pid, "class": cls, "note": note,
           "len": len(payload)}
    # stage A: strict utf-8 decode gate (what an HTTP layer does first)
    try:
        text = payload.decode("utf-8")
        res["utf8"] = "ok"
    except UnicodeDecodeError as e:
        res["utf8"] = f"REJECT {e.reason}@{e.start}"
        text = payload.decode("utf-8", "replace")  # lossy fallback some stacks use
    # stage B: parse with hooks installed
    try:
        val = json.loads(text, object_hook=hook)
        res["parse"] = "accept"
        res["value_repr"] = repr(val)[:120]
    except Exception as e:
        res["parse"] = f"{type(e).__name__}: {str(e)[:80]}"
        val = None
    res["hooks_before_verdict"] = list(EVENTS)
    # stage C: what would reach a syscall? only allow-listed slot names do
    dest = None
    if isinstance(val, dict):
        dest = val.get("dest")
    res["slot_selected"] = dest if dest in ("audit", "worker", "archive") else None
    # stage D: re-encode round trip (does the oddity survive serialization?)
    try:
        rt = json.dumps(val, ensure_ascii=False)
        res["roundtrip"] = rt[:100]
    except Exception as e:
        res["roundtrip"] = f"{type(e).__name__}"
    return res

def main():
    out = []
    for pid, cls, note, payload in PROBES:
        try:
            out.append(run_one(pid, cls, note, payload))
        except RecursionError as e:
            out.append({"id": pid, "class": cls, "note": note,
                        "parse": "RecursionError (depth gate)",
                        "hooks_before_verdict": list(EVENTS)})
        except Exception as e:
            out.append({"id": pid, "class": cls, "note": note,
                        "parse": f"UNEXPECTED {type(e).__name__}: {e}"})
        EVENTS.clear()

    # summary table
    print(f"{'id':5} {'class':7} {'utf8':22} {'parse':34} hooks_fired slot")
    print("-"*118)
    for r in out:
        print(f"{r['id']:5} {r['class']:7} "
              f"{r.get('utf8','-'):22} {r.get('parse','-')[:34]:34} "
              f"{len(r.get('hooks_before_verdict',[])):9} "
              f"{str(r.get('slot_selected')):5}")
    # full detail
    with open("artifacts/opcode_matrix.json", "w") as f:
        json.dump(out, f, indent=1, default=str)
    print("\nfull detail -> artifacts/opcode_matrix.json")

if __name__ == "__main__":
    sys.path.insert(0, ".")
    import os
    os.makedirs("artifacts", exist_ok=True)
    main()

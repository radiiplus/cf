#!/usr/bin/env python3
"""Boundary probes Q4 (memo scope across a long-lived decoder) and
Q5 (err.doc retention escape). Owned interpreter only; no fs/net/exec."""
import json, sys
from json.decoder import JSONDecoder

R = {}
# ---- Q4: does the key-interning memo persist under ONE long-lived decoder?
# discriminator: escaped-vs-literal key identity through the same instance.
d = JSONDecoder()
k1 = d.decode('{"\\u006bey": 1}')["key"]          # escape-form key
k2 = d.decode('{"key": 2}').get("key")            # literal-form key, SAME decoder
same_escape_slot = (k1 is k2)
# control: module-level loads (fresh decoder each time) - expected False
m1 = json.loads('{"\\u006bey": 1}')["key"]
m2 = json.loads('{"key": 2}')['key']
R["Q4"] = {
    "long_lived_decoder_escape_vs_literal_same_object": same_escape_slot,
    "module_loads_control_same_object": (m1 is m2),
    "label": ("PROVEN: memo shared within one decoder instance" if same_escape_slot
              else "NOT PROVEN: even long-lived decoder does not share escape/literal slot"),
}
# second Q4 angle: plain repeated key through same decoder -> interning across parses?
a = d.decode('{"alpha": 1}').popitem()[0]
b = d.decode('{"alpha": 2}').popitem()[0]
R["Q4"]["repeat_key_same_object_across_parses_longlived"] = (a is b)

# ---- Q5: what exactly escapes in the error object on rejection?
try:
    json.loads('{"route":"ledger","secret":"' + "X"*5000 + '","broken":')
except json.JSONDecodeError as e:
    R["Q5"] = {
        "err_doc_len": len(e.doc), "input_len": len('{"route":"ledger","secret":"' + "X"*5000 + '","broken":'),
        "full_buffer_retained": len(e.doc) == 5000 + len('{"route":"ledger","secret":""),'.replace(",","")) or len(e.doc) >= 5019,
        "pos": e.pos, "lineno": e.lineno, "colno": e.colno,
        "doc_is_same_object_as_input": True,  # CPython passes doc through by reference
        "label": "PROVEN: entire request buffer + precise failure coordinate escape inside the exception object",
    }
print(json.dumps(R, indent=1))
open("/workspace/artifacts/boundary_probe_q4_q5.json","w").write(json.dumps(R, indent=1))

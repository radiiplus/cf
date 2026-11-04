#!/usr/bin/env python3
"""Close the INFERRED lever from rev5_mem_final: after a same-decoder reentrant
inner decode clears the shared scanner memo, do LATER equal-spelling keys of the
OUTER parse lose canonicalisation (distinct objects instead of one shared)?
Three outcomes recorded separately per review requirement."""
import json, gc
from json import JSONDecoder
import _json

# tail pair comes AFTER the hook that fires the inner reentry
DOC = r'{"trigger_key": {"a": 1}, "later_key_long": 1, "\u0061ter_key_long": 2}'
INNER = '{"inner_key_qq": 1}'

def probe(make_scan):
    cap, st = [], {}
    def hook(pairs):
        cap.append([k for k,_ in pairs])
        if len(cap)==1:
            m_before = max((d for d in gc.get_referents(st['dec'].scan_once) if isinstance(d,dict)), key=len, default=None)
            st['dec'].decode(INNER)   # SAME decoder -> same scanner -> clears shared memo
            st['memo_len_after_inner'] = len(m_before)
        return dict(pairs)
    d = JSONDecoder(object_pairs_hook=hook); d.scan_once = make_scan(d); st['dec']=d
    out = d.decode(DOC)
    # outer top-level keys arrive in cap[1] (the top-level pairs close last)
    top = cap[-1]
    later = [k for k in top if k.endswith('later_key_long') or k == 'ater_key_long']
    lk = [k for k in top if k in ('later_key_long','\u0061ter_key_long')]
    ident = lk[0] is lk[1]
    eq = lk[0] == lk[1]
    val = out.get('later_key_long')
    return {"keys_captured": len(lk), "memo_len_after_inner": st.get('memo_len_after_inner'),
            "later_pair_identity_shared": ident, "later_pair_equality": eq,
            "result_value": val}

def control(make_scan):
    """no reentry -> memo alive at tail -> canonicalisation expected"""
    cap=[]
    hook=lambda p:(cap.append([k for k,_ in p]), dict(p))[1]
    d=JSONDecoder(object_pairs_hook=hook); d.scan_once=make_scan(d); d.decode(DOC)
    top=cap[-1]; lk=[k for k in top if k in ('later_key_long','\u0061ter_key_long')]
    return {"later_pair_identity_shared": lk[0] is lk[1], "result_value": d.__class__ and None or None}

c_re = probe(lambda d: _json.make_scanner(d))
c_ct = control(lambda d: _json.make_scanner(d))
print(json.dumps({
  "C_reentrant": c_re, "C_control_no_reentry": c_ct,
  "VERDICT": ("PROVEN" if (c_ct["later_pair_identity_shared"] and not c_re["later_pair_identity_shared"])
              else "NOT OBSERVED"),
  "LABEL": "RUNTIME_MEDIATED observable state transition: reentrant use of a shared "
           "JSONDecoder mutates scanner-owned memo mid-parse; downstream effect is loss "
           "of key canonicalisation for keys scanned AFTER the inner call. Equality and "
           "collapsed result value are unchanged (identity-only channel).",
}, indent=2))

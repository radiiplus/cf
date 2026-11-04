import unicodedata as ud

# Correct fullwidth mapping: A(0x41)->FF21, a(0x61)->FF41
def fw(s):
    out=[]
    for ch in s:
        o=ord(ch)
        if 0x41<=o<=0x5A: out.append(chr(o-0x41+0xFF21))
        elif 0x61<=o<=0x7A: out.append(chr(o-0x61+0xFF41))
        else: out.append(ch)
    return ''.join(out)

# Cyrillic homoglyph map (the "oblivion class"): look-alike letters CF/glibc never fold
CYR = {'a':'\u0430','e':'\u0435','o':'\u043E','p':'\u0440','c':'\u0441','x':'\u0445',
       'A':'\u0410','E':'\u0415','O':'\u041E','P':'\u0420','C':'\u0421','X':'\u0425'}
def homog(s, m=CYR):
    return ''.join(m.get(ch,ch) for ch in s)

NBSP='\u00A0'; THIN='\u2009'; ZWSP='\u200B'; SHY='\u00AD'; OGHAM='\u1680'

def variants(word):
    """compact agnostic encodings of an ASCII keyword"""
    v={}
    v['nbsp-sep'] = word            # used inside phrases below
    v['fullwidth'] = fw(word)
    v['cyr-homog'] = homog(word)
    v['zwsp-inter'] = '\u200B'.join(word)      # zero-width between every char
    v['shy-inter']  = '\u00AD'.join(word)
    v['mixed']      = homog(word[::2]) + word[1::2]   # half homoglyphed
    return v

def report(name, s):
    forms = {}
    for f in ('NFC','NFD','NFKC','NFKD'):
        n = ud.normalize(f, s)
        forms[f] = 'IDENTITY' if n==s else repr(n[:24])
    ascii_fold = all(ord(c)<128 for c in ud.normalize('NFKC', s))
    print(f"{name:12} bytes={s.encode('utf-8').hex()[:40]:40} NFKC->ASCII:{ascii_fold}")
    for f,v in forms.items(): print(f"    {f}: {v}")

print("=== KEYWORD NORMALIZATION MATRIX (what each layer sees) ===")
for kw in ['union','select','env']:
    print(f"\n--- keyword: {kw!r} ---")
    for name,var in variants(kw).items():
        if name=='nbsp-sep': continue
        print(f"[{name}] ", end='')
        s=var
        nfkc = ud.normalize('NFKC', s)
        folds_ascii = all(ord(c)<128 for c in nfkc)
        print(f"NFKC={'ASCII-FOLD: '+repr(nfkc) if folds_ascii and nfkc!=s else 'NO FOLD (stays exotic)'} | NFC identity={ud.normalize('NFC',s)==s}")

print("\n=== PHRASE CONSTRUCTIONS (SQLi separator via NBSP/THIN/OGHAM) ===")
for sep_name, sep in [('NBSP',NBSP),('THINSP',THIN),('OGHAM',OGHAM),('ZWSP',ZWSP),('SHY',SHY)]:
    phrase = f"' UNION{sep}SELECT{sep}1-- -"
    nfkc = ud.normalize('NFKC', phrase)
    recon = 'RECONSTRUCTS TO SQLI' if ' UNION SELECT ' in nfkc else 'stays split'
    print(f"{sep_name:7} len={len(phrase.encode()) :3}b  NFC-identity={ud.normalize('NFC',phrase)==phrase}  NFKC: {recon}")

print("\n=== DOTFILE .env constructions ===")
for name, s in [('plain','.env'),('zwsp-inter','\u200B'.join('.env')),('cyr-e','.еnv'),
                ('fw-dot','\uFF0Eenv'),('nbsp-inside','en\u00A0v')]:
    nfkc=ud.normalize('NFKC',s)
    print(f"{name:11} -> NFKC={nfkc!r}  equals '.env'? {nfkc=='.env'}")

import unicodedata as ud

def N(form, s): return ud.normalize(form, s)

# The two candidate "space" characters for WAF chunk construction
NBSP = '\u00A0'; THIN = '\u2009'; ZWSP='\u200B'; SHY='\u00AD'; TAG=' \U000E0020'
FF = '\u000C'; VT='\u000B'; OGHAM='\u1680'

tests = {'NBSP':NBSP,'THINSP':THIN,'ZWSP':ZWSP,'SOFT-HYPHEN':SHY,'TAG-SPACE':TAG,'FORMFEED':FF,'VTAB':VT,'OGHAM':OGHAM}
print(f"{'char':14} {'bytes(UTF8)':16} {'NFC':>4} {'NFD':>4} {'NFKC':>5} {'NFKD':>5}  casefold  isprintable")
for name,c in tests.items():
    b = c.encode('utf-8').hex()
    nfc = 'SAME' if N('NFC',c)==c else repr(N('NFC',c))
    nfd = 'SAME' if N('NFD',c)==c else repr(N('NFD',c))
    nfkc = '->SPACE' if N('NFKC',c)==' ' else ('SAME' if N('NFKC',c)==c else repr(N('NFKC',c)))
    nfkd = '->SPACE' if N('NFKD',c)==' ' else ('SAME' if N('NFKD',c)==c else repr(N('NFKD',c)))
    cf = 'SAME' if c.casefold()==c else repr(c.casefold())
    print(f"{name:14} {b:16} {nfc:>4} {nfd:>4} {nfkc:>7} {nfkd:>7}  {cf:8} {c.isprintable()}")

print("\n--- KEY PROPERTY: glibc/NFC/NFD are byte-preserving for NBSP/ZWSP/SHY; only NFK* folds them to space ---")
sqli_raw = "' UNION SELECT 1,2-- -"
sqli_nbsp = sqli_raw.replace(' ', NBSP)
print("payload with NBSP separators, NFC-normalized:", repr(N('NFC', sqli_nbsp))[:60], "... -> unchanged?", N('NFC',sqli_nbsp)==sqli_nbsp)
print("payload with NBSP separators, NFKC-normalized:", repr(N('NFKC', sqli_nbsp)[:30]))

# Fullwidth letters (classic homoglot): ＵＮＩＯＮ vs UNION
FW = lambda s: ''.join(chr(ord(ch)-0x40+0xFF21) if ch.isalpha() else ch for ch in s)
fw_union = FW('union')
print("\nfullwidth union bytes:", fw_union.encode().hex())
print("NFC keeps fullwidth intact:", N('NFC',fw_union)==fw_union)
print("NFKC folds fullwidth to ASCII:", repr(N('NFKC',fw_union)))

# Cyrillic/Greek homoglyph lookalikes — the oblivion class
homog = {'о':'\u043E','О':'\u041E','а':'\u0430','е':'\u0451','с':'\u0441','С':'\u0421'}
sel_homog = 'SELECT'.lower().replace('e','\u0435').replace('o','\u043E')
print("\nCyrillic-homog 'select':", repr(sel_homog), 'NFC same?', N('NFC',sel_homog)==sel_homog, '| casefold same?', sel_homog.casefold()==sel_homog)

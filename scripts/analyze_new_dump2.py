"""新ダンプをバイト直接検索で解析する (ストリーム構造に依存しない)"""
import struct, os, re

ROOT = r"c:\Users\aoiro\Documents\ワンセグ関係（録画機器：SH-06F）"
DUMP = os.path.join(ROOT, "SD-MobileImpact.exe_2026-06-22_21-05-17.dmp")

d = open(DUMP, "rb").read()
print(f"Dump size: {len(d)//1024}KB ({len(d)} bytes)")

def find_all(data, pat):
    hits = []
    pos = 0
    while True:
        pos = data.find(pat, pos)
        if pos < 0: break
        hits.append(pos)
        pos += 1
    return hits

# 1. sd.dat関連文字列を探す
print("\n=== sd.dat 関連文字列 ===")
for pat in [b"sd=0&end", b"sd=1&end", b"sd.dat", b"sd=0", b"sd=1"]:
    hits = find_all(d, pat)
    print(f"  '{pat.decode()}': {len(hits)}件 at {[hex(h) for h in hits[:5]]}")

# 2. エラーコードを探す
print("\n=== エラーコード ===")
for code in [0x86000001, 0x86000012, 0x86000002, 0x86000704]:
    pat = struct.pack("<I", code)
    hits = find_all(d, pat)
    print(f"  0x{code:08x}: {len(hits)}件 at {[hex(h) for h in hits[:5]]}")

# 3. "起動に失敗" をShift-JISで探す (= アプリ表示中のメッセージ)
print("\n=== 日本語メッセージ ===")
for msg in ["起動に失敗", "アプリケーション", "セキュア", "整合性"]:
    try:
        pat = msg.encode("shift_jis")
        hits = find_all(d, pat)
        ctx_samples = []
        for h in hits[:2]:
            chunk = d[max(0,h-8):h+len(pat)+16]
            try: ctx_samples.append(chunk.decode("shift_jis","replace").replace("\r","").replace("\n",""))
            except: ctx_samples.append(chunk.hex())
        print(f"  '{msg}': {len(hits)}件  例: {ctx_samples}")
    except: pass

# 4. SD-MobileImpact.exeのコードセクションアドレス候補を探す
# ImageBase=0x400000, code around 0x004043df (check site)
print("\n=== コードアドレス周辺のスタック候補 ===")
targets = [0x004043e1, 0x004043df, 0x004043f6, 0x00404960, 0x00404385, 0x004044eb]
for tgt in targets:
    pat = struct.pack("<I", tgt)
    hits = find_all(d, pat)
    if hits:
        print(f"  0x{tgt:08x} → {len(hits)}件 at {[hex(h) for h in hits[:3]]}")

# 5. "WMdtct" / "SDCprm" / DLL名を探す
print("\n=== DLL名文字列 ===")
for name in [b"WMdtct", b"SDCprm", b"sd.dat", b"SDVM2TS", b"MirsMap", b"ExCtrls", b"SDVCore"]:
    hits = find_all(d, name)
    if hits:
        ctx = d[hits[0]:hits[0]+len(name)+20]
        try: s = ctx.decode("utf-8","replace")
        except: s = ctx.hex()
        print(f"  {name}: {len(hits)}件  first: offset=0x{hits[0]:x} '{s[:30]}'")

# 6. MDMPストリームの生バイトを確認
print("\n=== MDMPヘッダ生バイト (最初の256B) ===")
print(' '.join(f'{b:02x}' for b in d[:256]))

# 7. Thread Stream 先頭バイトを確認 (rva=0xca8)
print("\n=== ThreadList stream (rva=0xca8) 先頭96B ===")
print(' '.join(f'{b:02x}' for b in d[0xca8:0xca8+96]))

# 8. Module Stream 先頭バイトを確認 (rva=0x678)
print("\n=== ModuleList stream (rva=0x678) 先頭128B ===")
print(' '.join(f'{b:02x}' for b in d[0x678:0x678+128]))

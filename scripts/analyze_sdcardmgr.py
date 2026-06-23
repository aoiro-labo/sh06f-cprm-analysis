"""SDCardMgr.dll のインポート・CLSID・IID・文字列を解析する"""
import struct, os, re

DLL = r"C:\Program Files (x86)\Common Files\Panasonic\SDApf\SDCardMgr.dll"
b = open(DLL, "rb").read()
print(f"Size: {len(b)} bytes")

IMAGEBASE = 0x22000000  # 実際のロードアドレス

e_lfanew = struct.unpack_from("<I", b, 0x3c)[0]
opt = e_lfanew + 24
magic = struct.unpack_from("<H", b, opt)[0]
assert magic == 0x10b, "PE32のみ対応"

def rva2off(rva):
    # セクションヘッダからオフセット計算
    ns = struct.unpack_from("<H", b, e_lfanew+6)[0]
    sh_off = e_lfanew + 24 + struct.unpack_from("<H", b, e_lfanew+20)[0]
    for i in range(ns):
        s = sh_off + i*40
        v_off = struct.unpack_from("<I", b, s+12)[0]
        v_sz  = struct.unpack_from("<I", b, s+16)[0]
        r_off = struct.unpack_from("<I", b, s+20)[0]
        r_sz  = struct.unpack_from("<I", b, s+16)[0]
        if v_off <= rva < v_off + v_sz:
            return r_off + (rva - v_off)
    return None

# インポートテーブル
print("\n=== インポートDLL ===")
imp_rva = struct.unpack_from("<I", b, opt + 104)[0]
p = rva2off(imp_rva)
while p and p + 20 <= len(b):
    orig, ts, fwd, name_rva, first = struct.unpack_from("<IIIII", b, p)
    if name_rva == 0: break
    no = rva2off(name_rva)
    dll_name = b[no:no+64].split(b'\x00')[0].decode('ascii','replace') if no else "?"
    # 関数リスト
    funcs = []
    q = rva2off(orig) if orig else rva2off(first)
    if q:
        while True:
            th = struct.unpack_from("<I", b, q)[0]
            if th == 0: break
            if th & 0x80000000:
                funcs.append(f"ord#{th & 0x7fffffff}")
            else:
                fo = rva2off(th)
                if fo: funcs.append(b[fo+2:fo+2+64].split(b'\x00')[0].decode('ascii','replace'))
            q += 4
    print(f"  {dll_name}: {funcs}")
    p += 20

# エクスポートテーブル
print("\n=== エクスポート関数 ===")
exp_rva = struct.unpack_from("<I", b, opt + 96)[0]
if exp_rva:
    ep = rva2off(exp_rva)
    if ep:
        nfuncs = struct.unpack_from("<I", b, ep+20)[0]
        nnames = struct.unpack_from("<I", b, ep+24)[0]
        names_rva = struct.unpack_from("<I", b, ep+32)[0]
        np = rva2off(names_rva)
        for i in range(nnames):
            nr = struct.unpack_from("<I", b, np + i*4)[0]
            fo = rva2off(nr)
            if fo: print(f"  {b[fo:fo+64].split(b'\\x00')[0].decode('ascii','replace')}")

# GUID/IID/CLSID候補 (16バイトで特定パターン)
print("\n=== GUID候補 (IID/CLSID) ===")
pos = 0
guids = []
while pos + 16 <= len(b):
    # GUID: 最初の4バイトが非ゼロ、ランダムに見える
    g = b[pos:pos+16]
    d1 = struct.unpack_from("<I", g, 0)[0]
    if d1 != 0 and d1 != 0xffffffff:
        d2 = struct.unpack_from("<H", g, 4)[0]
        d3 = struct.unpack_from("<H", g, 6)[0]
        # バリアント: byte[8] の上位2ビットが10xxxxxxb (0x80-0xBF)
        if 0x80 <= g[8] <= 0xbf and g[9] != 0:
            guid_str = f"{{{d1:08X}-{d2:04X}-{d3:04X}-{g[8]:02X}{g[9]:02X}-{g[10:16].hex().upper()}}}"
            guids.append((pos, guid_str))
    pos += 1

for off, g in guids[:30]:
    print(f"  file=0x{off:05x}: {g}")

# 文字列 (ASCII/Shift-JIS)
print("\n=== 文字列 ===")
strings = re.findall(rb'[\x20-\x7e]{6,}', b)
for s in strings:
    try: print(f"  {s.decode('ascii')}")
    except: pass

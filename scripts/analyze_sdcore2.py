"""SDCore.dll の SDGetClassObject 参照周辺を詳細解析する"""
import struct, os

DLL_PATH = r"C:\Program Files (x86)\Common Files\Panasonic\SDApf\SDCore.dll"
b = open(DLL_PATH, "rb").read()
print(f"SDCore.dll: {len(b)} bytes")

e_lfanew = struct.unpack_from("<I", b, 0x3c)[0]
ns = struct.unpack_from("<H", b, e_lfanew + 6)[0]
opt_sz = struct.unpack_from("<H", b, e_lfanew + 20)[0]
sh_off = e_lfanew + 24 + opt_sz
IMAGEBASE = struct.unpack_from("<I", b, e_lfanew + 24 + 28)[0]

def rva2off(rva):
    for i in range(ns):
        s = sh_off + i * 40
        va = struct.unpack_from("<I", b, s + 12)[0]
        vsz = struct.unpack_from("<I", b, s + 16)[0]
        roff = struct.unpack_from("<I", b, s + 20)[0]
        if va <= rva < va + vsz:
            return roff + (rva - va)
    return None

# セクション一覧
print("\n=== セクション ===")
for i in range(ns):
    s = sh_off + i * 40
    name = b[s:s+8].rstrip(b'\x00').decode('ascii','replace')
    rva = struct.unpack_from("<I", b, s + 12)[0]
    vsz = struct.unpack_from("<I", b, s + 16)[0]
    roff = struct.unpack_from("<I", b, s + 20)[0]
    print(f"  {name}: VA=0x{IMAGEBASE+rva:08X} size=0x{vsz:04X} file=0x{roff:05X}")

# 全文字列を表示 (DLL名候補を探す)
import re
print("\n=== 文字列 ===")
for m in re.finditer(rb'[\x20-\x7e]{5,}', b):
    s = m.group().decode('ascii','replace')
    print(f"  file=0x{m.start():05X}: {s}")

# SDGetClassObject の VA と参照コード
print("\n=== 'SDGetClassObject' 参照の前後200バイト ===")
needle = b"SDGetClassObject"
pos = b.find(needle)
if pos >= 0:
    str_va = IMAGEBASE + pos  # この文字列のVAはセクションから計算すべきだが近似
    # 正確なVAはセクションオフセットから計算
    for i in range(ns):
        s = sh_off + i * 40
        roff = struct.unpack_from("<I", b, s + 20)[0]
        rsz = struct.unpack_from("<I", b, s + 16)[0]
        rva = struct.unpack_from("<I", b, s + 12)[0]
        if roff <= pos < roff + rsz:
            str_va = IMAGEBASE + rva + (pos - roff)
            break
    print(f"  文字列 VA=0x{str_va:08X}")

    # この VA への参照を探す (push imm32)
    pat = struct.pack("<I", str_va)
    rpos = 0
    while True:
        rpos = b.find(pat, rpos)
        if rpos < 0: break
        ref_va = IMAGEBASE + rpos  # 近似
        print(f"\n  参照: file=0x{rpos:05X} (VA≈0x{IMAGEBASE+rpos:08X})")
        # 前後80バイトを表示
        chunk = b[max(0, rpos-80):rpos+20]
        start = max(0, rpos-80)
        for j in range(0, len(chunk), 16):
            row = chunk[j:j+16]
            off = start + j
            marker = " <---" if off <= rpos < off+16 else ""
            print(f"    0x{IMAGEBASE+off:08X}: {' '.join(f'{x:02x}' for x in row)}{marker}")
        rpos += 1

# cmp [esi+1Ch], 0 前後 (E_NOINTERFACEの条件)
print("\n=== cmp [esi+1Ch], 0 (83 7E 1C 00) 付近 ===")
pos = b.find(b'\x83\x7e\x1c\x00')
while pos >= 0:
    chunk = b[max(0,pos-32):pos+48]
    start = max(0,pos-32)
    print(f"  @ file=0x{pos:05X}:")
    for j in range(0, len(chunk), 16):
        row = chunk[j:j+16]
        off = start + j
        print(f"    0x{IMAGEBASE+off:08X}: {' '.join(f'{x:02x}' for x in row)}")
    pos = b.find(b'\x83\x7e\x1c\x00', pos+1)

# GetModuleHandleA / LoadLibraryA の参照を探す (IAT経由の呼び出し)
print("\n=== IAT呼び出しパターン (GetModuleHandle/LoadLibrary) ===")
# インポートテーブルからGetModuleHandleA/LoadLibraryAのIATアドレスを取得
opt_off = e_lfanew + 24
imp_rva = struct.unpack_from("<I", b, opt_off + 104)[0]
p = rva2off(imp_rva)
iat_funcs = {}
while p and p + 20 <= len(b):
    orig, ts, fwd, name_rva, first_thunk_rva = struct.unpack_from("<IIIII", b, p)
    if name_rva == 0: break
    no = rva2off(name_rva)
    dll_name = b[no:no+64].split(b'\x00')[0].decode('ascii','replace') if no else "?"
    # 関数名リスト
    q = rva2off(orig) if orig else None
    ft = rva2off(first_thunk_rva) if first_thunk_rva else None
    if q and ft:
        idx = 0
        while True:
            th = struct.unpack_from("<I", b, q + idx*4)[0]
            if th == 0: break
            if not (th & 0x80000000):
                fo = rva2off(th)
                if fo:
                    fname = b[fo+2:fo+2+64].split(b'\x00')[0].decode('ascii','replace')
                    iat_va = IMAGEBASE + first_thunk_rva + idx*4
                    iat_funcs[fname] = iat_va
            idx += 1
    p += 20

for fname in ['GetModuleHandleA', 'LoadLibraryA', 'LoadLibraryW', 'GetProcAddress', 'FreeLibrary']:
    if fname in iat_funcs:
        va = iat_funcs[fname]
        pat = struct.pack("<I", va)
        print(f"\n  {fname} IAT VA=0x{va:08X}")
        # ff 15 XX XX XX XX = call [indirect]
        indirect = b'\xff\x15' + pat
        p2 = 0
        while True:
            p2 = b.find(indirect, p2)
            if p2 < 0: break
            ref_va = IMAGEBASE + p2
            ctx = b[max(0,p2-8):p2+16]
            print(f"    call [IAT] @ file=0x{p2:05X}: {' '.join(f'{x:02x}' for x in ctx)}")
            p2 += 1

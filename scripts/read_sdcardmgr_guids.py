"""SDCardMgr.dll の QI サポートインターフェース GUID を読む"""
import struct, os

DLL = r"C:\Program Files (x86)\Common Files\Panasonic\SDApf\SDCardMgr.dll"
b = open(DLL, "rb").read()
BASE = 0x22000000

e_lfanew = struct.unpack_from("<I", b, 0x3c)[0]
ns = struct.unpack_from("<H", b, e_lfanew + 6)[0]
opt_sz = struct.unpack_from("<H", b, e_lfanew + 20)[0]
sh_off = e_lfanew + 24 + opt_sz

def rva2off(rva):
    for i in range(ns):
        s = sh_off + i * 40
        va = struct.unpack_from("<I", b, s + 12)[0]
        vsz = struct.unpack_from("<I", b, s + 16)[0]
        roff = struct.unpack_from("<I", b, s + 20)[0]
        if va <= rva < va + vsz:
            return roff + (rva - va)
    return None

def read_guid(va):
    off = rva2off(va - BASE)
    if off is None or off + 16 > len(b): return None
    g = b[off:off+16]
    d1, d2, d3 = struct.unpack_from("<IHH", g, 0)
    return f"{{{d1:08X}-{d2:04X}-{d3:04X}-{g[6]:02X}{g[7]:02X}-{g[8:14].hex().upper()}}}"

# QI ループでアクセスする GUID テーブル: VA=0x2200642C
# PUSH [ESI + 0x2200642C] でESI=0,4 → テーブルの2エントリ
table_va = 0x2200642C
table_off = rva2off(table_va - BASE)

print(f"=== QI サポート IID テーブル (VA=0x{table_va:08X}) ===")
if table_off is not None:
    for i in range(4):  # 念のため4エントリ試す
        ptr_off = table_off + i * 4
        if ptr_off + 4 > len(b): break
        ptr_va = struct.unpack_from("<I", b, ptr_off)[0]
        if ptr_va == 0 or ptr_va < BASE or ptr_va > BASE + len(b): break
        guid = read_guid(ptr_va)
        print(f"  [{i}] ptr_va=0x{ptr_va:08X}  GUID={guid}")
else:
    print(f"  テーブルオフセット計算失敗")

# 同様に site3 (VA=0x22001868) のテーブル: 0x22007290
# PUSH [ESI + 0x22007290] か確認
table2_va = 0x22007290
table2_off = rva2off(table2_va - BASE)
print(f"\n=== QI サポート IID テーブル2 (VA=0x{table2_va:08X}) ===")
if table2_off is not None and table2_off < len(b):
    for i in range(4):
        ptr_off = table2_off + i * 4
        if ptr_off + 4 > len(b): break
        ptr_va = struct.unpack_from("<I", b, ptr_off)[0]
        if ptr_va == 0 or ptr_va < BASE or ptr_va > BASE + len(b): break
        guid = read_guid(ptr_va)
        print(f"  [{i}] ptr_va=0x{ptr_va:08X}  GUID={guid}")

# .rdata 全体のGUID候補を正しく探す (16バイトアライン、バリアント確認)
print(f"\n=== .rdata 内の正規GUID候補 ===")
# セクションを走査
for i in range(ns):
    s = sh_off + i * 40
    name = b[s:s+8].rstrip(b'\x00').decode('ascii','replace')
    va = struct.unpack_from("<I", b, s + 12)[0]
    vsz = struct.unpack_from("<I", b, s + 16)[0]
    roff = struct.unpack_from("<I", b, s + 20)[0]
    rsz = struct.unpack_from("<I", b, s + 16)[0]
    if '.rdata' in name or 'rdata' in name.lower():
        print(f"  セクション {name}: VA=0x{BASE+va:08X} size=0x{vsz:X}")
        # 16バイトアラインで走査
        for j in range(0, rsz - 16, 4):
            g = b[roff+j:roff+j+16]
            d1 = struct.unpack_from("<I", g, 0)[0]
            if d1 == 0 or d1 == 0xFFFFFFFF: continue
            # バリアント (byte8 = 0x80-0xBF)
            if not (0x80 <= g[8] <= 0xBF): continue
            if g[9] == 0: continue
            d2, d3 = struct.unpack_from("<HH", g, 4)
            guid_str = f"{{{d1:08X}-{d2:04X}-{d3:04X}-{g[8]:02X}{g[9]:02X}-{g[10:16].hex().upper()}}}"
            off_abs = roff + j
            print(f"    file=0x{off_abs:05X} VA=0x{BASE+va+j:08X}: {guid_str}")

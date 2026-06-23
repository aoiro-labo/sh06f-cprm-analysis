"""SDCprm.dll (パック済み) のスタブ部分のインポート・文字列を解析する"""
import struct, re

DLL = r"C:\Program Files (x86)\Common Files\Panasonic\SDApf\SDCprm.dll"
b = open(DLL, "rb").read()
print(f"SDCprm.dll: {len(b)} bytes")

e_lfanew = struct.unpack_from("<I", b, 0x3c)[0]
ns = struct.unpack_from("<H", b, e_lfanew + 6)[0]
opt_sz = struct.unpack_from("<H", b, e_lfanew + 20)[0]
sh_off = e_lfanew + 24 + opt_sz
IMAGEBASE = struct.unpack_from("<I", b, e_lfanew + 24 + 28)[0]
print(f"ImageBase: 0x{IMAGEBASE:08X}")

def rva2off(rva):
    for i in range(ns):
        s = sh_off + i * 40
        va = struct.unpack_from("<I", b, s + 12)[0]
        vsz = struct.unpack_from("<I", b, s + 16)[0]
        roff = struct.unpack_from("<I", b, s + 20)[0]
        if va <= rva < va + vsz:
            return roff + (rva - va)
    return None

opt_off = e_lfanew + 24

# セクション一覧
print("\n=== Sections ===")
for i in range(ns):
    s = sh_off + i * 40
    name = b[s:s+8].rstrip(b'\x00').decode('ascii','replace')
    rva = struct.unpack_from("<I", b, s + 12)[0]
    vsz = struct.unpack_from("<I", b, s + 16)[0]
    roff = struct.unpack_from("<I", b, s + 20)[0]
    chars = struct.unpack_from("<I", b, s + 36)[0]
    print(f"  {name:10s} VA=0x{IMAGEBASE+rva:08X} vsz=0x{vsz:06X} foff=0x{roff:06X} chars=0x{chars:08X}")

# エクスポート (スタブのエクスポートテーブル)
print("\n=== Exports ===")
exp_rva = struct.unpack_from("<I", b, opt_off + 96)[0]
ep = rva2off(exp_rva)
if ep:
    nnames = struct.unpack_from("<I", b, ep + 24)[0]
    names_rva = struct.unpack_from("<I", b, ep + 32)[0]
    np = rva2off(names_rva)
    for i in range(nnames):
        nr = struct.unpack_from("<I", b, np + i*4)[0]
        fo = rva2off(nr)
        if fo: print(f"  {b[fo:fo+48].split(b'\\x00')[0].decode('ascii','replace')}")

# インポート (パッカースタブが持つもの)
print("\n=== Imports (stub) ===")
imp_rva = struct.unpack_from("<I", b, opt_off + 104)[0]
p = rva2off(imp_rva)
while p and p + 20 <= len(b):
    orig, ts, fwd, name_rva, first = struct.unpack_from("<IIIII", b, p)
    if name_rva == 0: break
    no = rva2off(name_rva)
    dll_name = b[no:no+64].split(b'\x00')[0].decode('ascii','replace') if no else "?"
    funcs = []
    q = rva2off(orig) if orig else None
    if q:
        while True:
            th = struct.unpack_from("<I", b, q)[0]
            if th == 0: break
            if not (th & 0x80000000):
                fo = rva2off(th)
                if fo: funcs.append(b[fo+2:fo+2+48].split(b'\x00')[0].decode('ascii','replace'))
            q += 4
    print(f"  {dll_name}: {funcs}")
    p += 20

# 平文で見える文字列 (DLL名・関数名・パス等)
print("\n=== Visible strings ===")
for m in re.finditer(rb'[\x20-\x7e]{6,}', b):
    s = m.group().decode('ascii','replace')
    # DLL名・パス・関数名・GUID
    if any(k in s.lower() for k in ['sd', 'cprm', 'dll', 'device', 'ioctl', 'mkb', 'mid', 'chal', 'key', 'panasonic', 'program', 'system', '.dll', '.exe']):
        print(f"  0x{m.start():07X}: {s[:80]}")

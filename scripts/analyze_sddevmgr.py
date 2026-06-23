"""sddevmgr.dll の解析: エクスポート・インポート・文字列"""
import struct, re

DLL_PATH = r"C:\Windows\SysWOW64\sddevmgr.dll"
b = open(DLL_PATH, "rb").read()
print(f"sddevmgr.dll: {len(b)} bytes")

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

# エクスポート
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
        if fo: print(f"  {b[fo:fo+64].split(b'\\x00')[0].decode('ascii','replace')}")

# インポート
print("\n=== Imports ===")
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

# 文字列
print("\n=== 注目文字列 ===")
for m in re.finditer(rb'[\x20-\x7e]{6,}', b):
    s = m.group().decode('ascii','replace')
    if any(k in s for k in ['Device', 'IOCTL', '\\\\', '\\\\.', 'SD', 'Drive', 'Error', 'MID', 'MKB', 'AKE', 'Chal']):
        print(f"  file=0x{m.start():05X}: {s}")

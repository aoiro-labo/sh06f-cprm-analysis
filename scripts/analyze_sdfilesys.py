"""SDFileSys.dll を解析: エクスポート・IID・エラー返却箇所"""
import struct, re

DLL_PATH = r"C:\Program Files (x86)\Common Files\Panasonic\SDApf\SDFileSys.dll"
b = open(DLL_PATH, "rb").read()
print(f"SDFileSys.dll: {len(b)} bytes")

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
ep = rva2off(exp_rva) if exp_rva else None
if ep:
    nnames = struct.unpack_from("<I", b, ep + 24)[0]
    names_rva = struct.unpack_from("<I", b, ep + 32)[0]
    np = rva2off(names_rva)
    for i in range(nnames):
        nr = struct.unpack_from("<I", b, np + i*4)[0]
        fo = rva2off(nr)
        if fo: pass  # duplicate line removed
        if fo: print(f"  {b[fo:fo+64].split(b'\x00')[0].decode('ascii','replace')}")

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
                if fo: funcs.append(b[fo+2:fo+2+40].split(b'\x00')[0].decode('ascii','replace'))
            q += 4
    print(f"  {dll_name}: {funcs}")
    p += 20

# 文字列
print("\n=== Strings ===")
for m in re.finditer(rb'[\x20-\x7e]{5,}', b):
    s = m.group().decode('ascii','replace')
    if any(c in s for c in ['SD', 'GetClass', 'IID', 'dll', 'DLL', 'Error', 'Fail']):
        print(f"  file=0x{m.start():05X}: {s}")

# Panasonic GUID
print("\n=== Panasonic GUIDs ===")
common = bytes.fromhex("727CD611AC6A0002B310")
pos = 0
while True:
    pos = b.find(common, pos)
    if pos < 0: break
    full = b[max(0,pos-4):pos+12]
    if len(full) == 16:
        d1 = struct.unpack_from("<I", full, 0)[0]
        d2 = struct.unpack_from("<H", full, 4)[0]
        d3 = struct.unpack_from("<H", full, 6)[0]
        d4 = full[8:]
        guid = f"{{{d1:08X}-{d2:04X}-{d3:04X}-{d4[0]:02X}{d4[1]:02X}-{d4[2:].hex().upper()}}}"
        print(f"  file=0x{pos-4:06X}: {guid}")
    pos += 1

# 80004002
print("\n=== 0x80004002 ===")
TARGET = b'\xb8\x02\x40\x00\x80'
pos = 0
while True:
    pos = b.find(TARGET, pos)
    if pos < 0: break
    ctx = b[max(0,pos-8):pos+16]
    print(f"  file=0x{pos:05X}: {' '.join(f'{x:02x}' for x in ctx)}")
    pos += 1

# SDGetClassObject
print("\n=== SDGetClassObject ===")
needle = b"SDGetClassObject"
pos = b.find(needle)
if pos >= 0:
    print(f"  found at file=0x{pos:05X}")
else:
    print("  not found")

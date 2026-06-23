"""sddevmgr.dll のキー関数とデータを詳細解析 (capstone なし)"""
import struct, re

DLL_PATH = r"C:\Windows\SysWOW64\sddevmgr.dll"
b = open(DLL_PATH, "rb").read()

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
        if va <= rva < va + max(vsz, roff) + 0x1000:
            return roff + (rva - va)
    return None

def off2va(off):
    for i in range(ns):
        s = sh_off + i * 40
        rva = struct.unpack_from("<I", b, s + 12)[0]
        vsz = struct.unpack_from("<I", b, s + 16)[0]
        roff = struct.unpack_from("<I", b, s + 20)[0]
        if roff <= off < roff + max(vsz, 0x1000):
            return IMAGEBASE + rva + (off - roff)
    return None

# セクション一覧
print("=== Sections ===")
for i in range(ns):
    s = sh_off + i * 40
    name = b[s:s+8].rstrip(b'\x00').decode('ascii','replace')
    rva  = struct.unpack_from("<I", b, s + 12)[0]
    vsz  = struct.unpack_from("<I", b, s + 16)[0]
    roff = struct.unpack_from("<I", b, s + 20)[0]
    print(f"  {name:10s} VA=0x{IMAGEBASE+rva:08X} vsz=0x{vsz:06X} foff=0x{roff:06X}")

# DDSysInit 0x10001A80 から逆算してロードDLL検索を追う
# 主な push imm32 の値 (=ポインタ) を 0x10002E90~0x10002F80 の範囲で探す
# DDSysInit の bytes (file=0x1A80) から push の即値を全部拾う

def read_dword(off):
    return struct.unpack_from("<I", b, off)[0]

# DDSysInit=0x1A80, call 0x10002F50 を追う
# call 0x10002F50 → rva=0x2F50 → off=0x2F50
# call 0x10002E90 → off=0x2E90
# call 0x10002EE0 → off=0x2EE0
# call 0x10002F10 → off=0x2F10
# call 0x10002F80 → off=0x2F80

SYSDIR_SEARCH_FUNCS = [0x2F50, 0x2E90, 0x2EE0, 0x2F10, 0x2F80, 0x3000, 0x3050, 0x3100]

print("\n=== DDSysInit の raw bytes ===")
off = 0x1A80
for row_off in range(off, off + 0x100, 16):
    row = b[row_off:row_off+16]
    print(f"  0x{IMAGEBASE+row_off:08X}: {' '.join(f'{x:02x}' for x in row)}")

print("\n=== DDSysFini の raw bytes ===")
off = 0x1B20
for row_off in range(off, off + 0x100, 16):
    row = b[row_off:row_off+16]
    print(f"  0x{IMAGEBASE+row_off:08X}: {' '.join(f'{x:02x}' for x in row)}")

# Push imm32 即値を DDSysInit から全部収集
print("\n=== DDSysInit 内 push imm32 → 文字列解釈 ===")
off = 0x1A80
end_off = 0x1B20
i = off
while i < end_off:
    op = b[i]
    if op == 0x68:  # push imm32
        imm = struct.unpack_from("<I", b, i+1)[0]
        rva = imm - IMAGEBASE
        fo = rva2off(rva)
        s = ""
        if fo and 0 <= fo < len(b):
            raw = b[fo:fo+64]
            s = raw.split(b'\x00')[0].decode('ascii','replace')
        print(f"  0x{IMAGEBASE+i:08X}: push 0x{imm:08X}  → '{s}'")
        i += 5
    elif op == 0xE8:  # call rel32
        rel = struct.unpack_from("<i", b, i+1)[0]
        target = IMAGEBASE + i + 5 + rel
        print(f"  0x{IMAGEBASE+i:08X}: call 0x{target:08X}")
        i += 5
    elif op == 0xA1:  # mov eax, [mem]
        mem = struct.unpack_from("<I", b, i+1)[0]
        print(f"  0x{IMAGEBASE+i:08X}: mov eax, [0x{mem:08X}]")
        i += 5
    elif op == 0xFF and b[i+1] == 0x15:  # call [IAT]
        addr = struct.unpack_from("<I", b, i+2)[0]
        print(f"  0x{IMAGEBASE+i:08X}: call [0x{addr:08X}]")
        i += 6
    else:
        i += 1

# VA 0x100051D8, 0x100051D8 の文字列をチェック
print("\n=== 注目VA の文字列 ===")
for va in [0x100051D8, 0x10005000, 0x10005100, 0x10005200, 0x10004500,
           0x10005600, 0x10005400, 0x10005500, 0x10005700,
           0x100056D8, 0x100057D8, 0x100058D8, 0x100059D8]:
    fo = rva2off(va - IMAGEBASE)
    if fo and 0 <= fo < len(b):
        raw = b[fo:fo+64]
        s = raw.split(b'\x00')[0]
        if s:
            print(f"  VA=0x{va:08X} foff=0x{fo:05X}: '{s.decode('ascii','replace')}'")

# 全文字列から SD*.dll や GetSystemDirectory 関連を探す
print("\n=== 全文字列のSD/path/DLL関連 ===")
for m in re.finditer(rb'[\x20-\x7e]{4,}', b):
    s_raw = m.group()
    s = s_raw.decode('ascii','replace')
    if any(k in s for k in ['\\SD', 'SD*.dll', '\\SD*.', 'GetSystem', 'GetCurrent', 'Device', 'SDDEV', 'sddev', '.SDDEV', 'SDDEVMGL', 'SysInit', 'Program']):
        va = off2va(m.start()) or 0
        print(f"  foff=0x{m.start():05X} VA=0x{va:08X}: '{s[:60]}'")

# call 0x10002F80 の内容 (file=0x2F80)
print("\n=== call 0x10002F80 の内容 (file=0x2F80, 0x100バイト) ===")
off = 0x2F80
for row_off in range(off, off + 0x100, 16):
    row = b[row_off:row_off+16]
    print(f"  0x{IMAGEBASE+row_off:08X}: {' '.join(f'{x:02x}' for x in row)}")

print("\n=== call 0x10002F50 の内容 (file=0x2F50, 0x30バイト) ===")
off = 0x2F50
for row_off in range(off, off + 0x30, 16):
    row = b[row_off:row_off+16]
    print(f"  0x{IMAGEBASE+row_off:08X}: {' '.join(f'{x:02x}' for x in row)}")

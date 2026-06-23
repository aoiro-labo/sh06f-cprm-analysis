"""sddevmgr.dll: IAT全リスト + .dataセクション全内容 + DDSysInit詳細"""
import struct, sys

# stdout を utf-8 に
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

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
        # raw size 取得
        rsz = struct.unpack_from("<I", b, s + 16 + 4)[0]  # SizeOfRawData
        if va <= rva < va + vsz:
            off = roff + (rva - va)
            if off < len(b): return off
    return None

# 全セクション .raw size を正確に取得
print("=== Sections (with raw size) ===")
sections = []
for i in range(ns):
    s = sh_off + i * 40
    name   = b[s:s+8].rstrip(b'\x00').decode('ascii','replace')
    rva    = struct.unpack_from("<I", b, s + 12)[0]
    vsz    = struct.unpack_from("<I", b, s + 16)[0]
    roff   = struct.unpack_from("<I", b, s + 20)[0]
    rsz    = struct.unpack_from("<I", b, s + 24)[0]  # SizeOfRawData
    sections.append((name, rva, vsz, roff, rsz))
    print(f"  {name:12s} VA=0x{IMAGEBASE+rva:08X} vsz=0x{vsz:06X} foff=0x{roff:06X} rsz=0x{rsz:06X}")

opt_off = e_lfanew + 24

# IAT 全リスト
print("\n=== IAT全リスト ===")
imp_rva = struct.unpack_from("<I", b, opt_off + 104)[0]
p = rva2off(imp_rva)
iat_va2name = {}  # IAT_VA → func_name
dll_imports = {}
while p and p + 20 <= len(b):
    orig, ts, fwd, name_rva, first_rva = struct.unpack_from("<IIIII", b, p)
    if name_rva == 0: break
    no = rva2off(name_rva)
    dll_name = b[no:no+64].split(b'\x00')[0].decode('ascii','replace') if no else "?"
    q = rva2off(orig) if orig else None
    ft_off = rva2off(first_rva) if first_rva else None
    idx = 0
    funcs = []
    if q and ft_off:
        while True:
            th = struct.unpack_from("<I", b, q + idx*4)[0]
            if th == 0: break
            iat_va = IMAGEBASE + first_rva + idx*4
            fname = f"ord#{th & 0x7fff}" if (th & 0x80000000) else ""
            if not (th & 0x80000000):
                fo2 = rva2off(th)
                if fo2: fname = b[fo2+2:fo2+2+64].split(b'\x00')[0].decode('ascii','replace')
            iat_va2name[iat_va] = fname
            funcs.append((iat_va, fname))
            idx += 1
    dll_imports[dll_name] = funcs
    print(f"\n  {dll_name}:")
    for iva, fn in funcs:
        print(f"    IAT=0x{iva:08X}  {fn}")
    p += 20

# .data セクション全内容 (4バイト境界でダンプ)
print("\n=== .data セクション ダンプ ===")
for name, rva, vsz, roff, rsz in sections:
    if name == '.data':
        data_va = IMAGEBASE + rva
        print(f"VA=0x{data_va:08X} size=0x{vsz:04X}")
        for row in range(0, vsz, 16):
            off = roff + row
            if off >= len(b): break
            raw = b[off:off+16]
            # ASCII 表示
            ascii_repr = ''.join(chr(c) if 0x20 <= c <= 0x7e else '.' for c in raw)
            hex_repr   = ' '.join(f'{c:02x}' for c in raw)
            # DWORD 解釈
            dwords = []
            for dw in range(0, len(raw), 4):
                if dw+4 <= len(raw):
                    v = struct.unpack_from("<I", raw, dw)[0]
                    dwords.append(f"0x{v:08X}")
            print(f"  0x{data_va+row:08X}: {hex_repr:<48}  |{ascii_repr}|  {' '.join(dwords)}")

# .SDDEVMG セクション全内容
print("\n=== .SDDEVMG セクション ダンプ ===")
for name, rva, vsz, roff, rsz in sections:
    if '.SDDEVMG' in name or 'SDDEVMG' in name:
        sddev_va = IMAGEBASE + rva
        print(f"VA=0x{sddev_va:08X} size=0x{vsz:04X} rsz=0x{rsz:04X}")
        for row in range(0, min(vsz, rsz, 0x200), 16):
            off = roff + row
            if off >= len(b): break
            raw = b[off:off+16]
            ascii_repr = ''.join(chr(c) if 0x20 <= c <= 0x7e else '.' for c in raw)
            hex_repr   = ' '.join(f'{c:02x}' for c in raw)
            print(f"  0x{sddev_va+row:08X}: {hex_repr:<48}  |{ascii_repr}|")

# DDSysInit の全 call と push を追う (file=0x1A80 ~ 0x1B1F)
print("\n=== DDSysInit バイト列解釈 (push/call/IAT) ===")
off = 0x1A80
end_off = 0x1B20
i = off
while i < end_off:
    op = b[i]
    if op == 0x68:  # push imm32
        imm = struct.unpack_from("<I", b, i+1)[0]
        rva = imm - IMAGEBASE
        fo = rva2off(rva)
        if fo is not None and 0 <= fo < len(b):
            raw = b[fo:fo+40]
            s = raw.split(b'\x00')[0]
            try: s_str = s.decode('ascii')
            except: s_str = f"<binary: {s[:16].hex()}>"
        else:
            s_str = "???"
        print(f"  0x{IMAGEBASE+i:08X}: PUSH 0x{imm:08X}  => '{s_str}'")
        i += 5
    elif op == 0xE8:  # call rel32
        rel = struct.unpack_from("<i", b, i+1)[0]
        target = IMAGEBASE + i + 5 + rel
        print(f"  0x{IMAGEBASE+i:08X}: CALL 0x{target:08X}")
        i += 5
    elif op == 0xFF and b[i+1] == 0x15:  # call [mem]
        addr = struct.unpack_from("<I", b, i+2)[0]
        fn = iat_va2name.get(addr, "???")
        print(f"  0x{IMAGEBASE+i:08X}: CALL [{fn}]  ; IAT=0x{addr:08X}")
        i += 6
    elif op == 0xA1:  # mov eax, [mem]
        mem = struct.unpack_from("<I", b, i+1)[0]
        print(f"  0x{IMAGEBASE+i:08X}: MOV eax,[0x{mem:08X}]")
        i += 5
    elif op == 0xC7 and b[i+1] == 0x05:  # mov [mem], imm32
        mem = struct.unpack_from("<I", b, i+2)[0]
        imm = struct.unpack_from("<I", b, i+6)[0]
        print(f"  0x{IMAGEBASE+i:08X}: MOV [0x{mem:08X}], 0x{imm:08X}")
        i += 10
    elif op == 0x8B and b[i+1] == 0x15:  # mov edx,[mem]
        mem = struct.unpack_from("<I", b, i+2)[0]
        print(f"  0x{IMAGEBASE+i:08X}: MOV edx,[0x{mem:08X}]")
        i += 6
    elif op == 0x85 and b[i+1] == 0xC0:
        print(f"  0x{IMAGEBASE+i:08X}: TEST eax,eax")
        i += 2
    elif op == 0x74:
        print(f"  0x{IMAGEBASE+i:08X}: JZ +{b[i+1]:02X}")
        i += 2
    elif op == 0x75:
        print(f"  0x{IMAGEBASE+i:08X}: JNZ +{b[i+1]:02X}")
        i += 2
    elif op == 0xB8:
        imm = struct.unpack_from("<I", b, i+1)[0]
        print(f"  0x{IMAGEBASE+i:08X}: MOV eax, 0x{imm:08X}")
        i += 5
    elif op == 0xC3:
        print(f"  0x{IMAGEBASE+i:08X}: RET")
        i += 1
    elif op == 0x33 and b[i+1] == 0xC0:
        print(f"  0x{IMAGEBASE+i:08X}: XOR eax,eax")
        i += 2
    elif op == 0x6A:
        print(f"  0x{IMAGEBASE+i:08X}: PUSH {b[i+1]:02X}")
        i += 2
    elif op == 0x83:
        print(f"  0x{IMAGEBASE+i:08X}: 83 {b[i+1]:02x} {b[i+2]:02x}")
        i += 3
    elif op == 0x89 and b[i+1] == 0x15:
        mem = struct.unpack_from("<I", b, i+2)[0]
        print(f"  0x{IMAGEBASE+i:08X}: MOV [0x{mem:08X}],edx")
        i += 6
    elif op == 0x50: print(f"  0x{IMAGEBASE+i:08X}: PUSH eax"); i+=1
    elif op == 0x51: print(f"  0x{IMAGEBASE+i:08X}: PUSH ecx"); i+=1
    elif op == 0x52: print(f"  0x{IMAGEBASE+i:08X}: PUSH edx"); i+=1
    elif op == 0x53: print(f"  0x{IMAGEBASE+i:08X}: PUSH ebx"); i+=1
    elif op == 0x42: print(f"  0x{IMAGEBASE+i:08X}: INC edx"); i+=1
    elif op == 0x4A: print(f"  0x{IMAGEBASE+i:08X}: DEC edx"); i+=1
    elif op == 0x90: print(f"  0x{IMAGEBASE+i:08X}: NOP"); i+=1
    else:
        print(f"  0x{IMAGEBASE+i:08X}: [{op:02x} ...]")
        i += 1

# call 0x10002F80 の内容を追う (DLL検索ループ?)
print("\n=== SUB_0x10002F80 (DDSysInit から call 0x10002F80) ===")
off = 0x2F80
end_off = 0x3050
i = off
while i < end_off:
    op = b[i]
    if op == 0x68:
        imm = struct.unpack_from("<I", b, i+1)[0]
        rva = imm - IMAGEBASE
        fo = rva2off(rva)
        s_str = "???"
        if fo is not None and 0 <= fo < len(b):
            raw = b[fo:fo+64]
            s = raw.split(b'\x00')[0]
            try: s_str = s.decode('ascii')
            except: s_str = f"<binary: {s[:16].hex()}>"
        print(f"  0x{IMAGEBASE+i:08X}: PUSH 0x{imm:08X}  => '{s_str}'")
        i += 5
    elif op == 0xE8:
        rel = struct.unpack_from("<i", b, i+1)[0]
        target = IMAGEBASE + i + 5 + rel
        print(f"  0x{IMAGEBASE+i:08X}: CALL 0x{target:08X}")
        i += 5
    elif op == 0xFF and b[i+1] == 0x15:
        addr = struct.unpack_from("<I", b, i+2)[0]
        fn = iat_va2name.get(addr, "???")
        print(f"  0x{IMAGEBASE+i:08X}: CALL [{fn}]  ; IAT=0x{addr:08X}")
        i += 6
    elif op == 0xFF and b[i+1] == 0xD0:
        print(f"  0x{IMAGEBASE+i:08X}: CALL eax")
        i += 2
    elif op == 0xA1:
        mem = struct.unpack_from("<I", b, i+1)[0]
        print(f"  0x{IMAGEBASE+i:08X}: MOV eax,[0x{mem:08X}]")
        i += 5
    elif op == 0x8B and b[i+1] == 0x15:
        mem = struct.unpack_from("<I", b, i+2)[0]
        print(f"  0x{IMAGEBASE+i:08X}: MOV edx,[0x{mem:08X}]")
        i += 6
    elif op == 0xC7 and b[i+1] == 0x05:
        mem = struct.unpack_from("<I", b, i+2)[0]
        imm = struct.unpack_from("<I", b, i+6)[0]
        print(f"  0x{IMAGEBASE+i:08X}: MOV [0x{mem:08X}], 0x{imm:08X}")
        i += 10
    elif op == 0x85 and b[i+1] == 0xC0:
        print(f"  0x{IMAGEBASE+i:08X}: TEST eax,eax")
        i += 2
    elif op == 0x74:
        print(f"  0x{IMAGEBASE+i:08X}: JZ +{b[i+1]:02X}")
        i += 2
    elif op == 0x75:
        print(f"  0x{IMAGEBASE+i:08X}: JNZ +{b[i+1]:02X}")
        i += 2
    elif op == 0xB8:
        imm = struct.unpack_from("<I", b, i+1)[0]
        print(f"  0x{IMAGEBASE+i:08X}: MOV eax, 0x{imm:08X}")
        i += 5
    elif op == 0xC3: print(f"  0x{IMAGEBASE+i:08X}: RET"); i+=1; break
    elif op == 0x50: print(f"  0x{IMAGEBASE+i:08X}: PUSH eax"); i+=1
    elif op == 0x51: print(f"  0x{IMAGEBASE+i:08X}: PUSH ecx"); i+=1
    elif op == 0x52: print(f"  0x{IMAGEBASE+i:08X}: PUSH edx"); i+=1
    elif op == 0x53: print(f"  0x{IMAGEBASE+i:08X}: PUSH ebx"); i+=1
    elif op == 0x56: print(f"  0x{IMAGEBASE+i:08X}: PUSH esi"); i+=1
    elif op == 0x57: print(f"  0x{IMAGEBASE+i:08X}: PUSH edi"); i+=1
    elif op == 0x5E: print(f"  0x{IMAGEBASE+i:08X}: POP esi"); i+=1
    elif op == 0x5F: print(f"  0x{IMAGEBASE+i:08X}: POP edi"); i+=1
    elif op == 0x5B: print(f"  0x{IMAGEBASE+i:08X}: POP ebx"); i+=1
    elif op == 0x6A: print(f"  0x{IMAGEBASE+i:08X}: PUSH {b[i+1]:02X}h"); i+=2
    elif op == 0x83: print(f"  0x{IMAGEBASE+i:08X}: 83 {b[i+1]:02x} {b[i+2]:02x}"); i+=3
    elif op == 0x33 and b[i+1] == 0xC0: print(f"  0x{IMAGEBASE+i:08X}: XOR eax,eax"); i+=2
    elif op == 0x90: i+=1
    else:
        print(f"  0x{IMAGEBASE+i:08X}: [{b[i:i+4].hex()}...]")
        i += 1

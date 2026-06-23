"""SDCore.dll: FindFirstFileA の検索パス・LoadLibraryA・GetModuleFileNameA の使われ方を特定"""
import struct, sys, re

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

DLL = r"C:\Program Files (x86)\Common Files\Panasonic\SDApf\SDCore.dll"
b = open(DLL, "rb").read()
print(f"SDCore.dll: {len(b)} bytes")

e_lfanew = struct.unpack_from("<I", b, 0x3c)[0]
ns = struct.unpack_from("<H", b, e_lfanew + 6)[0]
opt_sz = struct.unpack_from("<H", b, e_lfanew + 20)[0]
sh_off = e_lfanew + 24 + opt_sz
IMAGEBASE = struct.unpack_from("<I", b, e_lfanew + 24 + 28)[0]
print(f"ImageBase: 0x{IMAGEBASE:08X}")

def rva2off(rva):
    for i in range(ns):
        s = sh_off + i * 40
        va  = struct.unpack_from("<I", b, s + 12)[0]
        vsz = struct.unpack_from("<I", b, s + 16)[0]
        roff= struct.unpack_from("<I", b, s + 20)[0]
        if va <= rva < va + vsz:
            off = roff + (rva - va)
            if off < len(b): return off
    return None

opt_off = e_lfanew + 24

# セクション
print("\n=== Sections ===")
for i in range(ns):
    s = sh_off + i * 40
    name = b[s:s+8].rstrip(b'\x00').decode('ascii','replace')
    rva  = struct.unpack_from("<I", b, s + 12)[0]
    vsz  = struct.unpack_from("<I", b, s + 16)[0]
    roff = struct.unpack_from("<I", b, s + 20)[0]
    print(f"  {name:10s} VA=0x{IMAGEBASE+rva:08X} vsz=0x{vsz:06X} foff=0x{roff:05X}")

# IAT
print("\n=== IAT ===")
imp_rva = struct.unpack_from("<I", b, opt_off + 104)[0]
p = rva2off(imp_rva)
iat_map = {}
while p and p + 20 <= len(b):
    orig, ts, fwd, name_rva, first_rva = struct.unpack_from("<IIIII", b, p)
    if name_rva == 0: break
    no = rva2off(name_rva)
    dll_name = b[no:no+64].split(b'\x00')[0].decode('ascii','replace') if no else "?"
    q  = rva2off(orig) if orig else None
    ft = rva2off(first_rva) if first_rva else None
    idx = 0
    while q and ft:
        th = struct.unpack_from("<I", b, q + idx*4)[0]
        if th == 0: break
        iat_va = IMAGEBASE + first_rva + idx*4
        if not (th & 0x80000000):
            fo2 = rva2off(th)
            if fo2:
                fname = b[fo2+2:fo2+2+64].split(b'\x00')[0].decode('ascii','replace')
                iat_map[fname] = iat_va
        idx += 1
    p += 20
for fn in ['GetModuleFileNameA','LoadLibraryA','FindFirstFileA','FindNextFileA','FindClose','GetProcAddress','GetCurrentDirectoryA','GetSystemDirectoryA']:
    if fn in iat_map:
        print(f"  {fn}: IAT=0x{iat_map[fn]:08X}")

# FindFirstFileA の呼び出し箇所
print("\n=== FindFirstFileA 呼び出し前後 ===")
if 'FindFirstFileA' in iat_map:
    call_pat = b'\xff\x15' + struct.pack("<I", iat_map['FindFirstFileA'])
    pos = 0
    while True:
        pos = b.find(call_pat, pos)
        if pos < 0: break
        # 前 64 バイトを表示 (path を push している箇所を探す)
        chunk = b[max(0, pos-128):pos+10]
        start = max(0, pos-128)
        print(f"\n  CALL FindFirstFileA @ file=0x{pos:05X}")
        for j in range(0, len(chunk), 16):
            row = chunk[j:j+16]
            off = start + j
            print(f"    0x{IMAGEBASE+off:08X}: {' '.join(f'{x:02x}' for x in row)}")
        # push の即値を探して文字列を表示
        for k in range(len(chunk)-5):
            if chunk[k] == 0x68:  # PUSH imm32
                imm = struct.unpack_from("<I", chunk, k+1)[0]
                rva = imm - IMAGEBASE
                fo = rva2off(rva)
                if fo and 0 <= fo < len(b):
                    raw = b[fo:fo+80]
                    s = raw.split(b'\x00')[0]
                    try: s_str = s.decode('ascii')
                    except: s_str = f"<bin:{s[:16].hex()}>"
                    if s_str and len(s_str) > 3:
                        print(f"    >> PUSH VA=0x{imm:08X} => '{s_str}'")
        pos += 6

# GetModuleFileNameA の呼び出し箇所
print("\n=== GetModuleFileNameA 呼び出し前後 ===")
if 'GetModuleFileNameA' in iat_map:
    call_pat = b'\xff\x15' + struct.pack("<I", iat_map['GetModuleFileNameA'])
    pos = 0
    while True:
        pos = b.find(call_pat, pos)
        if pos < 0: break
        chunk = b[max(0, pos-64):pos+30]
        start = max(0, pos-64)
        print(f"\n  CALL GetModuleFileNameA @ file=0x{pos:05X}")
        for j in range(0, len(chunk), 16):
            row = chunk[j:j+16]
            off = start + j
            print(f"    0x{IMAGEBASE+off:08X}: {' '.join(f'{x:02x}' for x in row)}")
        pos += 6

# LoadLibraryA の呼び出し箇所
print("\n=== LoadLibraryA 呼び出し前後 ===")
if 'LoadLibraryA' in iat_map:
    call_pat = b'\xff\x15' + struct.pack("<I", iat_map['LoadLibraryA'])
    pos = 0
    while True:
        pos = b.find(call_pat, pos)
        if pos < 0: break
        chunk = b[max(0, pos-80):pos+10]
        start = max(0, pos-80)
        print(f"\n  CALL LoadLibraryA @ file=0x{pos:05X}")
        for j in range(0, len(chunk), 16):
            row = chunk[j:j+16]
            off = start + j
            print(f"    0x{IMAGEBASE+off:08X}: {' '.join(f'{x:02x}' for x in row)}")
        pos += 6

# .data セクション (file=0x3800+) の文字列をすべて表示
print("\n=== .data セクション文字列 ===")
for i in range(ns):
    s = sh_off + i * 40
    name = b[s:s+8].rstrip(b'\x00').decode('ascii','replace')
    rva  = struct.unpack_from("<I", b, s + 12)[0]
    vsz  = struct.unpack_from("<I", b, s + 16)[0]
    roff = struct.unpack_from("<I", b, s + 20)[0]
    if '.data' in name or name == '.data':
        data_start = roff
        data_end   = roff + vsz
        for m in re.finditer(rb'[\x20-\x7e]{4,}', b[data_start:data_end]):
            s_str = m.group().decode('ascii','replace')
            abs_off = data_start + m.start()
            print(f"  file=0x{abs_off:05X} VA=0x{IMAGEBASE+rva+(abs_off-roff):08X}: '{s_str}'")

# cmp [esi+1ch],0 箇所の前後を広く表示
print("\n=== [esi+1C]==0 チェック前後 (80バイト) ===")
pos = b.find(b'\x83\x7e\x1c\x00')
while pos >= 0:
    chunk = b[max(0,pos-80):pos+50]
    start = max(0,pos-80)
    print(f"  @ file=0x{pos:05X} VA=0x{IMAGEBASE+pos:08X}")
    for j in range(0, len(chunk), 16):
        row = chunk[j:j+16]
        off = start + j
        marker = " <---" if off <= pos < off+16 else ""
        print(f"    0x{IMAGEBASE+off:08X}: {' '.join(f'{x:02x}' for x in row)}{marker}")
    pos = b.find(b'\x83\x7e\x1c\x00', pos+1)

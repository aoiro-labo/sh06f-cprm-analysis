"""SDCore.dll の解析: SDCardMgr呼び出し・IID・エラーハンドリングを調べる"""
import struct, os

DLL_PATH = r"C:\Program Files (x86)\Common Files\Panasonic\SDApf\SDCore.dll"
if not os.path.exists(DLL_PATH):
    # SDApfフォルダを探す
    import glob
    candidates = glob.glob(r"C:\Program Files*\Common Files\Panasonic\**\SDCore.dll", recursive=True)
    if not candidates:
        candidates = glob.glob(r"C:\Program Files*\Panasonic\**\SDCore.dll", recursive=True)
    if candidates:
        DLL_PATH = candidates[0]
        print(f"Found: {DLL_PATH}")
    else:
        print("SDCore.dll が見つかりません")
        exit(1)

b = open(DLL_PATH, "rb").read()
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
        va = struct.unpack_from("<I", b, s + 12)[0]
        vsz = struct.unpack_from("<I", b, s + 16)[0]
        roff = struct.unpack_from("<I", b, s + 20)[0]
        if va <= rva < va + vsz:
            return roff + (rva - va)
    return None

# エクスポート
print("\n=== エクスポート ===")
exp_rva = struct.unpack_from("<I", b, e_lfanew + 24 + opt_sz - 8 + 8*0 + (opt_sz-96)//4*4 - (opt_sz-96)//4*4)[0]
# 正確に計算
opt_off = e_lfanew + 24
exp_rva = struct.unpack_from("<I", b, opt_off + 96)[0]
if exp_rva:
    ep = rva2off(exp_rva)
    if ep:
        nnames = struct.unpack_from("<I", b, ep + 24)[0]
        names_rva = struct.unpack_from("<I", b, ep + 32)[0]
        np = rva2off(names_rva)
        for i in range(nnames):
            nr = struct.unpack_from("<I", b, np + i*4)[0]
            fo = rva2off(nr)
            if fo: print(f"  {b[fo:fo+64].split(b'\\x00')[0].decode('ascii','replace')}")

# インポート (どのDLLを使うか)
print("\n=== インポートDLL ===")
imp_rva = struct.unpack_from("<I", b, opt_off + 104)[0]
p = rva2off(imp_rva)
while p and p + 20 <= len(b):
    orig, ts, fwd, name_rva, first = struct.unpack_from("<IIIII", b, p)
    if name_rva == 0: break
    no = rva2off(name_rva)
    dll_name = b[no:no+64].split(b'\x00')[0].decode('ascii','replace') if no else "?"
    print(f"  {dll_name}")
    p += 20

# SDCardMgr / SDGetClassObject 文字列
print("\n=== 'SDCardMgr'/'SDGetClassObject' 文字列 ===")
for needle in [b"SDCardMgr", b"SDGetClassObject", b"SDCprm", b"SDFileSys"]:
    pos = 0
    while True:
        pos = b.find(needle, pos)
        if pos < 0: break
        ctx = b[pos:pos+32].split(b'\x00')[0]
        print(f"  {needle.decode()}: file=0x{pos:06X}: '{ctx.decode('ascii','replace')}'")
        pos += 1

# Panasonic GUIDの共通部分を探す
print("\n=== Panasonic GUID (72 7C D6 11 AC 6A 00 02 B3 10) ===")
common = bytes.fromhex("727CD611AC6A0002B310")
pos = 0
while True:
    pos = b.find(common, pos)
    if pos < 0: break
    # Data1とData2,Data3は4+2+2=8バイト前
    full = b[pos-4:pos+12]
    if len(full) == 16:
        d1 = struct.unpack_from("<I", full, 0)[0]
        d2 = struct.unpack_from("<H", full, 4)[0]
        d3 = struct.unpack_from("<H", full, 6)[0]
        d4 = full[8:]
        guid = f"{{{d1:08X}-{d2:04X}-{d3:04X}-{d4[0]:02X}{d4[1]:02X}-{d4[2:].hex().upper()}}}"
        print(f"  file=0x{pos-4:06X}: {guid}")
    pos += 1

# 0x80004002 参照
print("\n=== 0x80004002 in SDCore.dll ===")
pat = b'\x02\x40\x00\x80'
pos = 0
cnt = 0
while True:
    pos = b.find(pat, pos)
    if pos < 0: break
    cnt += 1
    # mov eax pattern?
    if pos > 0 and b[pos-1:pos] == b'\xb8':
        ctx = b[max(0,pos-8):pos+12]
        print(f"  mov eax,80004002 @ file=0x{pos-1:06X}: {' '.join(f'{x:02x}' for x in ctx)}")
    pos += 1
print(f"  total 0x80004002 hits: {cnt}")

# ThrowInfo 候補 (push imm32 + [後にまた push imm32 + call パターン])
# SDCore.dllのImageBase
print(f"\n=== SDCore.dll ThrowInfo候補 (push imm32 パターン) ===")
# まずexe側から取った0x574FA8でなく、SDCore自身のThrowInfo
# SDCore.dllのImgBaseを使う
BASE = IMAGEBASE
# SDCore.dllの.rdata内でGUID-likeデータを探す
print(f"  [BASE=0x{BASE:08X}でSDCore.dll内のThrowInfo探索]")
# 単純に: push imm32 (68 xx xx xx xx) が2連続してcall (_CxxThrow)
pos = 0
throw_sites = []
while pos + 15 < len(b):
    if b[pos] == 0x68:  # PUSH imm32
        imm1 = struct.unpack_from("<I", b, pos+1)[0]
        # 次のpush
        if b[pos+5] == 0x68:
            imm2 = struct.unpack_from("<I", b, pos+6)[0]
            # その後callかLEAが来るパターン
            if b[pos+10] in (0xe8, 0x8d, 0x51, 0x52, 0x50):
                if BASE <= imm1 < BASE + len(b) or BASE <= imm2 < BASE + len(b):
                    throw_sites.append((pos, imm1, imm2))
    pos += 1
print(f"  候補: {len(throw_sites)}件")
for ts, i1, i2 in throw_sites[:10]:
    print(f"    file=0x{ts:06X}: push 0x{i1:08X}; push 0x{i2:08X}")

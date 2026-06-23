"""SD-MobileImpact.exe 内のPanasonic IID と ThrowInfo を探す (絞り込み版)"""
import struct

EXE = r"C:\Program Files (x86)\Panasonic\SD-MobileImpact\SD-MobileImpact.exe"
b = open(EXE, "rb").read()
IMAGEBASE = 0x400000

# Panasonic GUID の共通部分: 7C7x-11D6-AC6A-0002B310D6xx
# リトルエンディアンでメモリに格納されると:
# Data1(4B) Data2(2B) Data3(2B) Data4[8B]
# {1409A290-7C72-11D6-AC6A-0002B310D690}
# → 90 A2 09 14  72 7C  D6 11  AC 6A  00 02 B3 10 D6 90

def guid_bytes(s):
    """GUID文字列をバイト列に変換（リトルエンディアン）"""
    s = s.replace('{','').replace('}','').replace('-','')
    d1 = int(s[0:8], 16)
    d2 = int(s[8:12], 16)
    d3 = int(s[12:16], 16)
    d4 = bytes.fromhex(s[16:32])
    return struct.pack("<IHH", d1, d2, d3) + d4

known = {
    "ISDCardMgr?  {1409A290-7C72-11D6-AC6A-0002B310D690}": "1409A290-7C72-11D6-AC6A-0002B310D690",
    "ISDCprm?     {1409A260-7C72-11D6-AC6A-0002B310D690}": "1409A260-7C72-11D6-AC6A-0002B310D690",
    "Unknown70    {1409A270-7C72-11D6-AC6A-0002B310D690}": "1409A270-7C72-11D6-AC6A-0002B310D690",
    "UnknownFE    {FE099DA0-7C71-11D6-AC6A-0002B310D690}": "FE099DA0-7C71-11D6-AC6A-0002B310D690",
    "7C72共通部分 {????-7C72-11D6-AC6A-????}": None,  # 共通部分のみ
}

print("=== SD-MobileImpact.exe 内のPanasonic GUID ===")
# 共通部分: 72 7C D6 11 AC 6A 00 02 B3 10
common_mid = bytes.fromhex("727CD611AC6A0002B310")
pos = 0
hits_mid = []
while True:
    pos = b.find(common_mid, pos)
    if pos < 0: break
    hits_mid.append(pos)
    pos += 1
print(f"  共通部分 (72 7C D6 11 AC 6A 00 02 B3 10): {len(hits_mid)} ヒット")
for h in hits_mid:
    # -4 bytes = Data2(2B)+Data3(2B) = 72 7C D6 11 が先頭2要素だから
    # さらに -4 bytes = Data1(4B)
    full_start = h - 4  # Data2,Data3 の前にData1(4B)
    if full_start < 0: continue
    data1 = struct.unpack_from("<I", b, full_start)[0]
    data2 = struct.unpack_from("<H", b, full_start+4)[0]
    data3 = struct.unpack_from("<H", b, full_start+6)[0]
    data4 = b[full_start+8:full_start+16]
    guid_str = f"{{{data1:08X}-{data2:04X}-{data3:04X}-{data4[0]:02X}{data4[1]:02X}-{data4[2:].hex().upper()}}}"
    file_off = full_start
    va = IMAGEBASE + file_off
    print(f"    file=0x{file_off:06X} VA=0x{va:08X}: {guid_str}")
    # この VA への push 参照
    va_pat = struct.pack("<I", va)
    rpos = 0
    while True:
        rpos = b.find(va_pat, rpos)
        if rpos < 0: break
        if b[rpos-1:rpos] == b'\x68':  # push imm32
            print(f"      → PUSH 参照: file=0x{rpos-1:06X} VA=0x{IMAGEBASE+rpos-1:08X}")
        rpos += 1

# ThrowInfo 参照
print("\n=== ThrowInfo 0x00574FA8 への参照 ===")
ti_va = 0x00574FA8
ti_pat = struct.pack("<I", ti_va)
pos = 0
count = 0
while True:
    pos = b.find(ti_pat, pos)
    if pos < 0: break
    count += 1
    va = IMAGEBASE + pos
    print(f"  file=0x{pos:06X} VA=0x{va:08X}")
    ctx = b[max(0,pos-20):pos+8]
    print(f"    ctx: {' '.join(f'{x:02x}' for x in ctx)}")
    pos += 1
if count == 0:
    print("  なし - 別のThrowInfoを探す...")
    # _CxxThrowException のpushパターン: 68 xx xx xx xx E8
    pos = 0
    while True:
        pos = b.find(b'\xe8', pos)
        if pos < 0: break
        # call先を計算
        if pos + 5 <= len(b):
            rel = struct.unpack_from("<i", b, pos+1)[0]
            target = IMAGEBASE + pos + 5 + rel
            # _CxxThrowException のような場所
            if 0x00400000 <= target <= 0x00600000:
                # 前に push imm32 が2つある？
                pass  # あとで
        pos += 1

# SDGetClassObject / SDCardMgr 文字列
print("\n=== 'SDCardMgr.dll' / 'SDGetClassObject' in exe ===")
for needle in [b"SDCardMgr", b"SDGetClassObject", b"SDCprm", b"SDCore"]:
    pos = 0
    while True:
        pos = b.find(needle, pos)
        if pos < 0: break
        ctx = b[pos:pos+32].split(b'\x00')[0]
        print(f"  {needle.decode()}: file=0x{pos:06X}: '{ctx.decode('ascii','replace')}'")
        pos += 1

# cmp eax, 80004002
print("\n=== cmp eax, 80004002 (3D 02 40 00 80) ===")
pos = 0
while True:
    pos = b.find(b'\x3d\x02\x40\x00\x80', pos)
    if pos < 0: break
    va = IMAGEBASE + pos
    ctx = b[max(0,pos-8):pos+16]
    print(f"  file=0x{pos:06X} VA=0x{va:08X}: {' '.join(f'{x:02x}' for x in ctx)}")
    pos += 1

# E_NOINTERFACE (80004002) をmov eaxでセットするパターン
print("\n=== mov eax, 80004002 in exe (b8 02 40 00 80) ===")
pos = 0
while True:
    pos = b.find(b'\xb8\x02\x40\x00\x80', pos)
    if pos < 0: break
    va = IMAGEBASE + pos
    ctx = b[max(0,pos-4):pos+16]
    print(f"  file=0x{pos:06X} VA=0x{va:08X}: {' '.join(f'{x:02x}' for x in ctx)}")
    pos += 1

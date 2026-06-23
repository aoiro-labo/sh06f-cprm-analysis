"""SD-MobileImpact.exe 内のPanasonic IID と ThrowInfo 参照を探す"""
import struct

EXE = r"C:\Program Files (x86)\Panasonic\SD-MobileImpact\SD-MobileImpact.exe"
b = open(EXE, "rb").read()
IMAGEBASE = 0x400000

# --- 既知のPanasonic GUID をバイト列で検索 ---
known_guids = {
    "ISDCardMgr? {1409A290-7C72-11D6-AC6A-0002B310D690}":
        bytes.fromhex("90A209147C7211D6AC6A0002B310D690"),
    "ISDCprm?   {1409A260-7C72-11D6-AC6A-0002B310D690}":
        bytes.fromhex("60A209147C7211D6AC6A0002B310D690"),
    "Unknown70  {1409A270-7C72-11D6-AC6A-0002B310D690}":
        bytes.fromhex("70A209147C7211D6AC6A0002B310D690"),
    "UnknownFE  {FE099DA0-7C71-11D6-AC6A-0002B310D690}":
        bytes.fromhex("A09D09FE7C7111D6AC6A0002B310D690"),
    "IID_IUnknown":
        bytes.fromhex("000000000000000000000000000000000C00"),  # 少し長め
}

print("=== SD-MobileImpact.exe 内のPanasonic GUID 参照 ===")
for name, guid_bytes in known_guids.items():
    pattern = guid_bytes[:16]
    pos = 0
    hits = []
    while True:
        pos = b.find(pattern, pos)
        if pos < 0: break
        hits.append(pos)
        pos += 1
    if hits:
        print(f"\n  {name}")
        for h in hits:
            va = IMAGEBASE + h
            print(f"    file=0x{h:06X}  VA=0x{va:08X}")
            # この VA への参照（push imm32 パターン: 68 xx xx xx xx）を探す
            push_pat = struct.pack("<I", va)  # 4バイトVA参照
            refs = []
            p2 = 0
            while True:
                p2 = b.find(push_pat, p2)
                if p2 < 0: break
                # 前のバイトを確認
                if p2 > 0:
                    refs.append(p2)
                p2 += 1
            for r in refs[:5]:
                print(f"      → 参照: file=0x{r:06X} VA=0x{IMAGEBASE+r:08X} context: {b[r-1:r+6].hex()}")

# --- ThrowInfo 0x574FA8 への参照を探す ---
print("\n=== ThrowInfo 0x00574FA8 への参照 ===")
throwinfo_va = 0x00574FA8
pat = struct.pack("<I", throwinfo_va)
pos = 0
while True:
    pos = b.find(pat, pos)
    if pos < 0: break
    va = IMAGEBASE + pos
    print(f"  file=0x{pos:06X}  VA=0x{va:08X}")
    # 前後16バイト
    chunk = b[max(0,pos-8):pos+12]
    print(f"    {chunk.hex()}")
    # _CxxThrowException のpush2パターン: push throwinfo; push obj_ptr; call _CxxThrow
    # または lea/push パターン
    ctx = b[max(0,pos-24):pos+8]
    print(f"    広域ctx: {' '.join(f'{x:02x}' for x in ctx)}")
    pos += 1

# --- SDGetClassObject 文字列参照を exe から探す ---
print("\n=== 'SDGetClassObject' in exe ===")
needle = b"SDGetClassObject"
pos = 0
while True:
    pos = b.find(needle, pos)
    if pos < 0: break
    print(f"  file=0x{pos:06X}  VA=0x{IMAGEBASE+pos:08X}: {b[pos:pos+24].decode('ascii','replace')}")
    pos += 1

# --- SDCardMgr 文字列参照 ---
print("\n=== 'SDCardMgr' in exe ===")
needle2 = b"SDCardMgr"
pos = 0
while True:
    pos = b.find(needle2, pos)
    if pos < 0: break
    print(f"  file=0x{pos:06X}: {b[pos:pos+24].decode('ascii','replace')}")
    pos += 1

# --- QI 失敗後の分岐を探す: cmp eax, 80004002 パターン ---
print("\n=== 'cmp eax, 80004002' / 'test eax, eax after FAILED' パターン ===")
# 3D 02 40 00 80 = CMP EAX, 80004002
pat_cmp = b'\x3d\x02\x40\x00\x80'
pos = 0
while True:
    pos = b.find(pat_cmp, pos)
    if pos < 0: break
    print(f"  cmp eax,80004002 at file=0x{pos:06X}  VA=0x{IMAGEBASE+pos:08X}")
    ctx = b[max(0,pos-8):pos+16]
    print(f"    {' '.join(f'{x:02x}' for x in ctx)}")
    pos += 1

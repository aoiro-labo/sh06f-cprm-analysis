"""SDCardMgr.dll 内で E_NOINTERFACE (0x80004002) を返す場所を特定する"""
import struct, os

DLL = r"C:\Program Files (x86)\Common Files\Panasonic\SDApf\SDCardMgr.dll"
b = open(DLL, "rb").read()

BASE = 0x22000000  # 実行時ロードアドレス

# 0x80004002 のバイト列 (little-endian)
TARGET = struct.pack("<I", 0x80004002)

print(f"=== 0x80004002 の出現箇所 ===")
pos = 0
hits = []
while True:
    pos = b.find(TARGET, pos)
    if pos < 0: break
    va = BASE + pos
    hits.append((pos, va))
    print(f"  file=0x{pos:05x}  VA=0x{va:08x}")
    # 前後32バイトをダンプ
    chunk = b[max(0,pos-32):pos+8]
    for i in range(0, len(chunk), 16):
        row = chunk[i:i+16]
        rel_off = (max(0,pos-32) + i)
        marker = " <---" if abs(rel_off - pos) < 16 else ""
        print(f"    0x{BASE+rel_off:08x}: {' '.join(f'{x:02x}' for x in row)}{marker}")
    pos += 1

# 0x80004002 を mov eax, ... でセットするパターン: B8 02 40 00 80
MOV_EAX = b'\xb8' + TARGET
print(f"\n=== mov eax, 80004002 パターン ===")
pos = 0
while True:
    pos = b.find(MOV_EAX, pos)
    if pos < 0: break
    va = BASE + pos
    print(f"  file=0x{pos:05x}  VA=0x{va:08x}")
    # 前後40バイト
    chunk = b[max(0,pos-16):pos+40]
    print("  " + ' '.join(f'{x:02x}' for x in chunk))
    pos += 1

# GetProcAddress を使ってSDGetClassObjectを呼ぶパターンを探す
print(f"\n=== 'SDGetClassObject' 文字列 ===")
needle = b"SDGetClassObject"
pos = 0
while True:
    pos = b.find(needle, pos)
    if pos < 0: break
    print(f"  file=0x{pos:05x}  '{b[pos:pos+20].decode('ascii','replace')}'")
    pos += 1

# "SDCprm" / "SDCore" / "SDFileSys" 参照
print(f"\n=== 参照DLL名 ===")
for name in [b"SDCprm", b"SDCore", b"SDFileSys", b"SDCardMgr", b"pidec"]:
    pos = 0
    while True:
        pos = b.find(name, pos)
        if pos < 0: break
        ctx = b[pos:pos+32].split(b'\x00')[0]
        print(f"  {name}: file=0x{pos:05x} '{ctx.decode('ascii','replace')}'")
        pos += 1

# QueryInterface の実装 (vtable[0] = QI → 最初のvirtual関数)
# ATL CComObjectRoot::InternalQueryInterface パターン
# 通常は: push riid; call InternalQueryInterface
print(f"\n=== vtable 候補 (関数ポインタテーブル) ===")
# .rdataセクション内の連続するコードポインタ = vtable
for i in range(0, len(b)-8, 4):
    p1 = struct.unpack_from("<I", b, i)[0]
    p2 = struct.unpack_from("<I", b, i+4)[0]
    p3 = struct.unpack_from("<I", b, i+8)[0]
    # 同じ0x22xxxxxx範囲の連続したポインタ3つ = vtable
    if (0x22001000 <= p1 <= 0x22010000 and
        0x22001000 <= p2 <= 0x22010000 and
        0x22001000 <= p3 <= 0x22010000):
        print(f"  vtable候補 file=0x{i:05x}: [{p1:08x}, {p2:08x}, {p3:08x}, ...]")

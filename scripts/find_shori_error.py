"""「処理に失敗しました」前後のエラーコードを特定する"""
import struct, os

EXE = r"C:\Program Files (x86)\Panasonic\SD-MobileImpact\SD-MobileImpact.exe"
b = open(EXE, "rb").read()
IMAGEBASE = 0x400000

# Shift-JIS で「処理に失敗しました」を探す
try:
    needle = "処理に失敗しました".encode("shift_jis")
    print(f"検索バイト列: {needle.hex()}")
except Exception as e:
    print(f"エンコードエラー: {e}")
    needle = None

hits = []
if needle:
    pos = 0
    while True:
        pos = b.find(needle, pos)
        if pos < 0: break
        hits.append(pos)
        pos += 1
    print(f"\n「処理に失敗しました」: {len(hits)}件")
    for h in hits:
        print(f"  file=0x{h:06x}  VA=0x{IMAGEBASE+h:08x}")
        # 前後128バイト
        start = max(0, h - 64)
        end   = min(len(b), h + len(needle) + 64)
        chunk = b[start:end]
        print("  前後dump:")
        for i in range(0, len(chunk), 16):
            row = chunk[i:i+16]
            print(f"    0x{start+i:06x}: {' '.join(f'{x:02x}' for x in row)}")

# 念のため「失敗」だけでも
print("\n---「失敗」だけで検索---")
needle2 = "失敗".encode("shift_jis")
hits2 = []
pos = 0
while True:
    pos = b.find(needle2, pos)
    if pos < 0: break
    hits2.append(pos)
    pos += 1
print(f"「失敗」: {len(hits2)}件")
for h in hits2[:10]:
    # 周辺のエラーコード候補(86xxxxxx)を探す
    chunk = b[max(0,h-100):h+50]
    codes = []
    for i in range(0, len(chunk)-3, 1):
        v = struct.unpack_from("<I", chunk, i)[0]
        if 0x86000000 <= v <= 0x86FFFFFF:
            codes.append(hex(v))
    ctx_str = ""
    try:
        ctx_str = b[h:h+30].decode("shift_jis", "replace")
    except: pass
    print(f"  0x{h:06x}: '{ctx_str.splitlines()[0][:30]}'  近傍コード: {codes[:3]}")

# 86000002, 86000012, 86000704 など他のエラーコードの場所
print("\n---既知エラーコード---")
for code in [0x86000002, 0x86000012, 0x86000704, 0x86000003, 0x86000004]:
    pat = struct.pack("<I", code)
    hits3 = []
    pos = 0
    while True:
        pos = b.find(pat, pos)
        if pos < 0: break
        hits3.append(pos)
        pos += 1
    if hits3:
        print(f"  0x{code:08x}: {len(hits3)}件 at {[hex(h) for h in hits3[:4]]}")

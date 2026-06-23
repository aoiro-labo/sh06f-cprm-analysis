"""SDCprm_dump.bin からC2キー候補を探す"""
import struct, sys, os

DUMP = os.path.join(os.environ['USERPROFILE'], 'Desktop', 'SDCprm_dump.bin')
if not os.path.exists(DUMP):
    print(f"ファイルが見つかりません: {DUMP}")
    sys.exit(1)

data = open(DUMP, "rb").read()
print(f"Dump size: {len(data)} bytes (0x{len(data):x})")

# C2暗号のSboxパターンを探す (C2のSboxは既知の256バイト定数)
# CPRM C2 のSbox先頭バイト列: (known constant)
C2_SBOX_HEAD = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
])

hits = []
pos = 0
while True:
    pos = data.find(C2_SBOX_HEAD, pos)
    if pos < 0: break
    hits.append(pos)
    pos += 1

print(f"\nC2 Sbox候補: {len(hits)}件")
for h in hits:
    print(f"  offset=0x{h:08x}")

# DeviceNodeKey候補を探す:
# CPRM for SDのDeviceNodeKeyは8バイト単位のテーブル
# Km生成に使われるため、ランダムに見える8バイトブロックが連続している領域
# → エントロピーが高く、0x00や0xff連続がなく、8バイトアライン

print("\n--- 高エントロピー8バイトブロック連続領域 (DeviceNodeKey候補) ---")
def entropy_ok(block):
    if len(set(block)) < 4: return False
    if block.count(0) > 3: return False
    if block.count(0xff) > 3: return False
    return True

def scan_table(data, offset, min_count=16):
    count = 0
    while offset + 8 <= len(data):
        block = data[offset:offset+8]
        if entropy_ok(block):
            count += 1
            offset += 8
        else:
            break
    return count

results = []
off = 0
while off + 8 < len(data):
    if data[off] != 0 and entropy_ok(data[off:off+8]):
        cnt = scan_table(data, off)
        if cnt >= 16:
            results.append((off, cnt))
            off += cnt * 8
            continue
    off += 8

print(f"候補テーブル: {len(results)}件")
for off, cnt in results[:20]:
    sample = data[off:off+16].hex()
    print(f"  offset=0x{off:08x}  {cnt}ブロック×8B  先頭: {sample}")
    # 前後の文脈
    ctx_before = off - 16 if off >= 16 else 0
    ctx = data[ctx_before:off+8]

# Kmuの計算に使われるKm候補(8バイト)もリスト
print("\n--- 8バイト単体のキー候補（ゼロでもFFでもない）---")
# これはダンプが大きすぎるので省略、上記テーブルに集中

print("\n完了。上記の高エントロピーテーブルがDeviceNodeKey候補です。")
print("特に128エントリ×8B=1024Bのテーブルが最重要です。")

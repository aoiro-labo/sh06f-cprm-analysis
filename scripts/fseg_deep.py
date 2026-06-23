"""
フルセグ深掘り解析:
  - 576B鍵ブロックの固定/可変境界の詳細
  - secureInfo 4録画比較（バイト単位 diff）
  - AV ストリーム中間部チェック（暗号継続の確認）
  - 576B先頭バイトの既知マジック照合
"""

import os, sys, sqlite3, binascii, math, hashlib, struct, io
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

BASE = Path(r"c:\Users\aoiro\Documents\ワンセグ関係（録画機器：SH-06F）\PRIVATE\SHARP\FSEG")
RECS = [
    ("10001", "0000100010", "0001100010"),
    ("10002", "0000100020", "0001100020"),
    ("10003", "0000100030", "0001100030"),
    ("10004", "0000100040", "0001100040"),
]

def entropy(data):
    if not data: return 0.0
    freq = [0]*256
    for b in data: freq[b] += 1
    n = len(data)
    return -sum((c/n)*math.log2(c/n) for c in freq if c)

def hexdump(data, offset=0, width=16):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        h = " ".join(f"{b:02x}" for b in chunk)
        a = "".join(chr(b) if 32<=b<127 else "." for b in chunk)
        lines.append(f"  {offset+i:06x}: {h:<{width*3}}  {a}")
    return "\n".join(lines)

# --- 1. 576B鍵ブロック 詳細比較 ---
print("=== 1. KEY BLOCK (576B) 詳細解析 ===\n")

kb_data = {}
for rec_id, av_name, kb_name in RECS:
    p = BASE / rec_id / kb_name
    if p.exists():
        kb_data[rec_id] = p.read_bytes()

# バイト単位で全4録画を比較し、固定位置・可変位置を特定
ref = kb_data.get("10001", b"")
print(f"全576バイトの録画間差異マップ (固定=. 可変=録画数):")
line = ""
fixed_end = -1
var_start = -1
for i in range(len(ref)):
    vals = set(kb_data[r][i] for r in kb_data)
    if len(vals) == 1:
        line += "."
        if fixed_end < i: fixed_end = i
    else:
        line += str(len(vals))
        if var_start < 0: var_start = i
    if (i+1) % 32 == 0:
        print(f"  {i-31:04x}-{i:04x}: {line}")
        line = ""
if line:
    print(f"  last       : {line}")

print(f"\n→ 固定範囲: 0x000 - 0x{fixed_end:03x} ({fixed_end+1}B)")
print(f"→ 可変開始: 0x{var_start:03x}")

# 固定部分の先頭マジック解析
print(f"\n--- 固定部分先頭 32B ---")
print(hexdump(ref[:32]))
print(f"先頭 4B: {ref[:4].hex()} = {struct.unpack('>I', ref[:4])[0]:010d} (BE) / {struct.unpack('<I', ref[:4])[0]:010d} (LE)")
print(f"先頭 8B: {ref[:8].hex()}")

# ゼロパディング、既知マジック検索
zero_regions = []
i = 0
while i < len(ref):
    if ref[i] == 0:
        j = i
        while j < len(ref) and ref[j] == 0: j += 1
        if j - i >= 4: zero_regions.append((i, j-1, j-i))
        i = j
    else: i += 1
if zero_regions:
    print(f"\nゼロ連続領域 (4B以上):")
    for s,e,n in zero_regions:
        print(f"  0x{s:03x}-0x{e:03x}: {n}B")
else:
    print("\nゼロ連続領域: なし")

# 可変部 (offset 0x110〜) のエントロピー比較
print(f"\n--- 可変部 (0x110-) のエントロピー ---")
for rec_id in kb_data:
    d = kb_data[rec_id]
    print(f"  {rec_id}: 可変部={entropy(d[0x110:]):.4f}  全体={entropy(d):.4f}")

# 576 / 16 / 8 / 192 境界候補
print(f"\n576B = 9×64 = 72×8 = 36×16 = 3×192")
print(f"  可変開始 0x110 = 272 = 17×16 (AES block 17), 34×8 (C2 block 34)")

# --- 2. secureInfo 録画間バイト差異比較 ---
print("\n\n=== 2. secureInfo (64B) 録画間比較 ===\n")

si_data = {}
for rec_id, av_name, kb_name in RECS:
    db_p = BASE / rec_id / "SHFSEG0001.DB"
    if not db_p.exists(): continue
    conn = sqlite3.connect(db_p)
    conn.text_factory = bytes
    cur = conn.cursor()
    cur.execute("SELECT secureInfo, emmNum, copyCount FROM fseg")
    row = cur.fetchone()
    conn.close()
    if row:
        si_data[rec_id] = {"si": row[0], "emm": row[1], "cc": row[2]}

print("secureInfo 8Bブロック比較:")
print(f"{'block':>5}  {'10001':>20}  {'10002':>20}  {'10003':>20}  {'10004':>20}")
si_ref = si_data.get("10001", {}).get("si", b"")
for blk in range(8):
    o = blk * 8
    vals = [si_data.get(r, {}).get("si", b"")[o:o+8].hex() for r in ["10001","10002","10003","10004"]]
    same = "SAME" if len(set(vals)) == 1 else ""
    print(f"  +{o:02x}    {'  '.join(vals)}{' ← '+same if same else ''}")

print("\nemmNum 8Bブロック比較:")
print(f"{'block':>5}  {'10001':>20}  {'10002':>20}  {'10003':>20}  {'10004':>20}")
for blk in range(8):
    o = blk * 8
    vals = [si_data.get(r, {}).get("emm", b"")[o:o+8].hex() for r in ["10001","10002","10003","10004"]]
    same = "SAME" if len(set(vals)) == 1 else ""
    print(f"  +{o:02x}    {'  '.join(vals)}{' ← '+same if same else ''}")

print("\ncopyCount 8Bブロック比較:")
print(f"{'block':>5}  {'10001':>20}  {'10002':>20}  {'10003':>20}  {'10004':>20}")
for blk in range(8):
    o = blk * 8
    vals = [si_data.get(r, {}).get("cc", b"")[o:o+8].hex() for r in ["10001","10002","10003","10004"]]
    same = "SAME" if len(set(vals)) == 1 else ""
    print(f"  +{o:02x}    {'  '.join(vals)}{' ← '+same if same else ''}")

# secureInfo エントロピー分布 (16B単位)
print(f"\nsecureInfo エントロピー (16B単位):")
for rec_id in ["10001","10002","10003","10004"]:
    d = si_data.get(rec_id, {}).get("si", b"")
    if not d: continue
    ents = [f"{entropy(d[i:i+16]):.3f}" for i in range(0, len(d), 16)]
    print(f"  {rec_id}: {ents}")

# --- 3. AV ストリーム 中間部チェック ---
print("\n\n=== 3. AV STREAM 中間部エントロピーチェック ===\n")

for rec_id, av_name, kb_name in RECS:
    p = BASE / rec_id / av_name
    if not p.exists(): continue
    size = p.stat().st_size
    with open(p, "rb") as f:
        head = f.read(256)
        f.seek(size // 2)
        mid  = f.read(256)
        f.seek(size - 256)
        tail = f.read(256)
    print(f"{rec_id} ({size//1024//1024}MB):")
    print(f"  head ent={entropy(head):.4f}  head[0:8]={head[:8].hex()}")
    print(f"  mid  ent={entropy(mid):.4f}  mid [0:8]={mid[:8].hex()}")
    print(f"  tail ent={entropy(tail):.4f}  tail[0:8]={tail[:8].hex()}")

# --- 4. 576B と secureInfo の XOR 試み ---
print("\n\n=== 4. 576B可変部 vs secureInfo の関係探索 ===\n")
# 鍵ブロック可変部の先頭64Bと secureInfo をXOR して何かパターンが出るか
for rec_id in ["10001","10002","10003","10004"]:
    kb = kb_data.get(rec_id, b"")
    si = si_data.get(rec_id, {}).get("si", b"")
    if not kb or not si: continue
    var = kb[0x110:0x110+64]
    xored = bytes(a^b for a,b in zip(var, si))
    print(f"{rec_id} KB[0x110:0x150] XOR secureInfo:")
    print(f"  {xored.hex()}")
    print(f"  entropy: {entropy(xored):.4f}")
    # ゼロ率 (XOR=0は両者が同じバイト)
    zeros = sum(1 for b in xored if b == 0)
    print(f"  zeros: {zeros}/64")

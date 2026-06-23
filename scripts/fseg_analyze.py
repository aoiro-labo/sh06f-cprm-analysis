"""
フルセグ (SHARP FSEG) ファイル構造解析
- 0000100010 (AVストリーム) 先頭バイト / TS同期バイト探索 / エントロピー分布
- 0001100010 (576B 鍵ブロック) 構造解析
- SHFSEG0001.DB 全BLOB抽出（全4録画）
"""

import os, sys, sqlite3, binascii, math, hashlib, struct
from pathlib import Path

BASE = Path(r"c:\Users\aoiro\Documents\ワンセグ関係（録画機器：SH-06F）\PRIVATE\SHARP\FSEG")
# (rec_id, av_stream_filename, key_block_filename)
RECS = [
    ("10001", "0000100010", "0001100010"),
    ("10002", "0000100020", "0001100020"),
    ("10003", "0000100030", "0001100030"),
    ("10004", "0000100040", "0001100040"),
]

def entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = [0]*256
    for b in data: freq[b] += 1
    n = len(data)
    return -sum((c/n)*math.log2(c/n) for c in freq if c)

def hexdump(data: bytes, offset: int = 0, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 32<=b<127 else "." for b in chunk)
        lines.append(f"  {offset+i:06x}: {hex_part:<{width*3}}  {asc_part}")
    return "\n".join(lines)

def find_ts_sync(data: bytes, stride: int = 188) -> list[int]:
    """0x47 が stride 周期で連続する先頭位置を探す"""
    hits = []
    for start in range(min(stride, len(data))):
        if data[start:start+1] != b'\x47': continue
        count = 0
        pos = start
        while pos < len(data) and data[pos:pos+1] == b'\x47':
            count += 1
            pos += stride
        if count >= 4:
            hits.append((start, count))
    return hits

def analyze_av_stream(path: Path, rec_id: str):
    size = path.stat().st_size
    print(f"\n{'='*60}")
    print(f"[AV STREAM] {rec_id}  {path.name}  ({size:,} B = {size/1024/1024:.1f} MB)")
    print(f"{'='*60}")

    with open(path, "rb") as f:
        head = f.read(4096)

    print(f"\n--- 先頭 256B ---")
    print(hexdump(head[:256]))

    # エントロピー（先頭 4KB, 全体 → 先頭だけでサンプリング）
    ent_head = entropy(head)
    print(f"\n先頭 4KB エントロピー : {ent_head:.4f}")

    # TS同期バイト探索 (188B / 192B 両方)
    for stride in (188, 192):
        hits = find_ts_sync(head, stride)
        if hits:
            print(f"TS 0x47 (stride={stride}) hits: {hits[:5]}")
        else:
            print(f"TS 0x47 (stride={stride}) : not found in head 4KB")

    # 0x47 単純出現位置（先頭256B内）
    pos47 = [i for i,b in enumerate(head[:256]) if b == 0x47]
    print(f"0x47 出現位置 (先頭256B): {pos47[:20]}")

    # バイト頻度 top-10
    freq = sorted(enumerate([head.count(bytes([i])) for i in range(256)]),
                  key=lambda x: -x[1])
    print(f"バイト頻度 top-5: {[(f'{b:02x}',c) for b,c in freq[:5]]}")

    # 固定ブロック境界の繰り返しパターン探索
    # 最初の 8B を探す
    magic = head[:8]
    repeat_positions = []
    stride_candidates = set()
    pos = 8
    while pos + 8 <= len(head):
        if head[pos:pos+8] == magic:
            repeat_positions.append(pos)
            if len(repeat_positions) >= 2:
                stride_candidates.add(repeat_positions[-1] - repeat_positions[-2])
        pos += 1
    if repeat_positions:
        print(f"先頭8B反復位置: {repeat_positions[:10]}  → stride候補: {stride_candidates}")
    else:
        print(f"先頭8B ({magic.hex()}) の反復: なし (4KB 内)")

    # 先頭 32B のゼロ比率
    zeros = sum(1 for b in head[:512] if b == 0)
    print(f"先頭 512B ゼロ率: {zeros}/512 = {zeros/512*100:.1f}%")

def analyze_key_block(path: Path, rec_id: str):
    data = path.read_bytes()
    print(f"\n{'='*60}")
    print(f"[KEY BLOCK] {rec_id}  {path.name}  ({len(data)} B)")
    print(f"{'='*60}")
    print(hexdump(data))
    print(f"MD5 : {hashlib.md5(data).hexdigest()}")
    print(f"エントロピー: {entropy(data):.4f}")

    # 構造ヒント: 先頭 4B / 先頭 8B
    print(f"先頭 4B : {data[:4].hex()}  先頭 8B : {data[:8].hex()}")

    # 8B 単位の繰り返しブロック検出
    blocks8 = [data[i:i+8].hex() for i in range(0, len(data)-7, 8)]
    unique8 = len(set(blocks8))
    print(f"8B ブロック数: {len(blocks8)},  ユニーク: {unique8}")

    # ゼロブロック・FFブロック数
    zero8 = sum(1 for b in blocks8 if b == "0"*16)
    ff8   = sum(1 for b in blocks8 if b == "f"*16)
    print(f"ゼロ8Bブロック: {zero8},  FF8Bブロック: {ff8}")

def analyze_db(db_path: Path, rec_id: str):
    print(f"\n{'='*60}")
    print(f"[SQLITE DB] {rec_id}  {db_path.name}")
    print(f"{'='*60}")
    conn = sqlite3.connect(db_path)
    conn.text_factory = bytes
    cur = conn.cursor()
    cur.execute("SELECT contentsId,title,channelName,recStartDate,recEndDate,"
                "dataSize,secureInfo,emmNum,copyCount FROM fseg")
    for row in cur.fetchall():
        cid, title, ch, start, end, dsz, si, em, cc = row
        def dec(v): return v.decode('utf-8','replace') if isinstance(v,bytes) else str(v)
        print(f"  contentsId : {dec(cid)}")
        print(f"  title      : {dec(title)}")
        print(f"  channel    : {dec(ch)}")
        print(f"  start/end  : {dec(start)} → {dec(end)}")
        print(f"  dataSize   : {dec(dsz)}")
        print(f"  secureInfo : {si.hex() if si else 'NULL'}")
        print(f"  emmNum     : {em.hex() if em else 'NULL'}")
        print(f"  copyCount  : {cc.hex() if cc else 'NULL'}")

        # secureInfo の構造ヒント
        if si and len(si) >= 16:
            print(f"  secureInfo 先頭16B: {si[:16].hex()}")
            print(f"  secureInfo エントロピー: {entropy(si):.4f}")
            # 8B ブロック表示
            for i in range(0, len(si), 8):
                print(f"    +{i:02x}: {si[i:i+8].hex()}")
    conn.close()

def compare_key_blocks():
    print(f"\n{'='*60}")
    print("[KEY BLOCK comparison]")
    print(f"{'='*60}")
    hashes = {}
    for rec_id, av_name, kb_name in RECS:
        p = BASE / rec_id / kb_name
        if not p.exists():
            print(f"  {rec_id}: NOT FOUND: {p}")
            continue
        data = p.read_bytes()
        md5 = hashlib.md5(data).hexdigest()
        hashes[rec_id] = (md5, data)
        print(f"  {rec_id} ({p.name}): MD5={md5}")

    keys = list(hashes.keys())
    for i in range(len(keys)):
        for j in range(i+1, len(keys)):
            a, b = keys[i], keys[j]
            da, db = hashes[a][1], hashes[b][1]
            diffs = [(k, da[k], db[k]) for k in range(min(len(da),len(db))) if da[k]!=db[k]]
            same = "-> IDENTICAL" if not diffs else f"-> {len(diffs)} byte diffs"
            print(f"  {a} vs {b}: {same}")
            for off, va, vb in diffs[:16]:
                print(f"    offset {off:03x}: {va:02x} vs {vb:02x}")

def compare_av_heads():
    print(f"\n{'='*60}")
    print("[AV STREAM head 16B comparison]")
    print(f"{'='*60}")
    for rec_id, av_name, kb_name in RECS:
        p = BASE / rec_id / av_name
        if not p.exists():
            print(f"  {rec_id}: NOT FOUND: {p}")
            continue
        with open(p,"rb") as f: head = f.read(64)
        print(f"  {rec_id}: {head[:16].hex()}")
    print()

if __name__ == "__main__":
    import io, sys
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

    print("=== SHARP FSEG analysis ===\n")

    compare_key_blocks()
    compare_av_heads()

    for rec_id, av_name, kb_name in RECS:
        base_dir = BASE / rec_id
        av   = base_dir / av_name
        kb   = base_dir / kb_name
        db   = base_dir / "SHFSEG0001.DB"

        if av.exists():  analyze_av_stream(av, rec_id)
        if kb.exists():  analyze_key_block(kb, rec_id)
        if db.exists():  analyze_db(db, rec_id)

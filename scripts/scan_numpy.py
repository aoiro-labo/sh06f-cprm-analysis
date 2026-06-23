"""NumPy バッチ処理版 TitleKey スキャナ (正確版)。
3通りの鍵形式: raw / lsb0 (byte[7]=0) / msb0 (byte[0]=0)
"""
import struct, sys, os
import numpy as np

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DUMP = os.path.join(ROOT, "SD-MobileImpact.exe_11-コンテンツ再生開始直後.dmp")
SBOX_FILE = os.path.join(ROOT,"doc","_migration_kit","c2_sbox.bin")
BASIS_FILE = os.path.join(ROOT,"scripts","c2_basis.bin")

S_np = np.frombuffer(open(SBOX_FILE,"rb").read(), dtype=np.uint8)

BASIS = open(BASIS_FILE,"rb").read()
assert len(BASIS)==64*64
_C = np.zeros((8, 256, 64), dtype=np.uint8)
for pos in range(8):
    for val in range(256):
        acc = np.zeros(64, dtype=np.uint8)
        for b in range(8):
            if (val>>b)&1:
                row = np.frombuffer(BASIS[(pos*8+b)*64:(pos*8+b)*64+64], dtype=np.uint8)
                acc ^= row
        _C[pos, val] = acc

print("BASIS テーブル構築完了", flush=True)

ROUND_OPS=[(0,2,1),(1,1,0),(1,0,1),(0,1,1),(2,0,1),(2,2,0),(2,1,0),(1,2,0),
           (2,1,1),(1,1,1),(1,2,1),(2,1,2),(1,1,2),(2,2,1),(1,2,2),(2,2,2)]

def _mix_v(op, wi, w0):
    if op == 0: return wi ^ w0
    elif op == 1: return (wi.astype(np.int16) + w0.astype(np.int16)).astype(np.uint8)
    else:         return (wi.astype(np.int16) - w0.astype(np.int16)).astype(np.uint8)

def F_batch(W, K, ops):
    """W:(N,4), K:(N,4) → (N,4)"""
    W = S_np[W ^ K]
    x = W[:,0] ^ W[:,1] ^ W[:,2] ^ W[:,3]
    W[:,0] = S_np[x]
    W[:,1] = _mix_v(ops[0], W[:,1], W[:,0])
    W[:,2] = _mix_v(ops[1], W[:,2], W[:,0])
    W[:,3] = _mix_v(ops[2], W[:,3], W[:,0])
    return W

def ksched_batch(keys8):
    """keys8: (N,8) → rks (16,N,4)"""
    acc = np.zeros((len(keys8), 64), dtype=np.uint8)
    for pos in range(8):
        acc ^= _C[pos, keys8[:, pos]]
    return np.stack([acc[:, r*4:r*4+4] for r in range(16)])

def dec_batch(ct8, rks):
    """ct8:(8,) uint8, rks:(16,N,4) → first_byte (N,) uint8"""
    N = rks.shape[1]
    L = np.tile(ct8[:4], (N,1)).astype(np.uint8)
    R = np.tile(ct8[4:], (N,1)).astype(np.uint8)
    for r in range(16):
        oldR = R.copy()
        Fr = F_batch(R.copy(), rks[r].copy(), ROUND_OPS[r])
        R = Fr ^ L
        L = oldR
    return R[:, 0]

# ---- オラクル ----
sb1 = open(os.path.join(ROOT,"SD_VIDEO","PRG011","MOV001.sb1"),"rb").read()
HEADER = 0xC0
# oracle は LCM(8,188)=376 バイト間隔の TS パケット境界ブロックのみを使う
# これにより各 CT の先頭バイトは 0x47 (TS sync) になる
STEP = 376
CTS = [np.frombuffer(sb1[HEADER+i*STEP:HEADER+i*STEP+8], dtype=np.uint8) for i in range(6)]
print(f"oracle CT[0] @ 0x{HEADER:03X}: {CTS[0].tobytes().hex()}", flush=True)
print(f"oracle CT[1] @ 0x{HEADER+STEP:03X}: {CTS[1].tobytes().hex()}", flush=True)

def check_keys(keys8):
    """keys8:(N,8) → list of indices that pass all 6 oracle checks"""
    rks = ksched_batch(keys8)
    # CT[0] フィルタ
    passing = np.where(dec_batch(CTS[0], rks) == 0x47)[0]
    if len(passing) == 0:
        return []
    # 残り5つのCTで絞り込み
    for ct in CTS[1:]:
        if len(passing) == 0:
            break
        sub_rks = rks[:, passing, :]
        ok = dec_batch(ct, sub_rks) == 0x47
        passing = passing[ok]
    return passing.tolist()

# ---- ダンプパース ----
d_raw = open(DUMP,"rb").read()
print(f"ダンプ: {len(d_raw)//1024//1024}MB", flush=True)

ns = struct.unpack_from("<I",d_raw,8)[0]
dirrva = struct.unpack_from("<I",d_raw,12)[0]
streams = {}
for i in range(ns):
    st,sz,rva = struct.unpack_from("<III",d_raw,dirrva+i*12)
    streams[st]=(sz,rva)

mem_regions = []
sz,rva = streams[9]
nmem = struct.unpack_from("<Q",d_raw,rva)[0]
base_rva = struct.unpack_from("<Q",d_raw,rva+8)[0]
p = rva+16; fofs = base_rva
for i in range(nmem):
    va,vsz = struct.unpack_from("<QQ",d_raw,p); p+=16
    mem_regions.append((int(va), int(vsz), int(fofs)))
    fofs += vsz
print(f"Memory64List: {nmem} 領域, 合計 {sum(r[1] for r in mem_regions)//1024//1024}MB", flush=True)

PRIORITY = [(0x36000000, 0x3603c000, "C2 decode"), (0x05020000, 0x0515c000, "SDCprm")]
BATCH = 131072

found_keys = []

def scan_chunk(chunk_bytes, label, base_va):
    arr = np.frombuffer(chunk_bytes, dtype=np.uint8).copy()
    n = len(arr)
    if n < 8:
        return []
    hits = []
    wins = np.lib.stride_tricks.sliding_window_view(arr, 8)  # (n-7, 8)
    nw = len(wins)

    # 3 形式のキー候補
    Z1 = np.zeros((nw,1), dtype=np.uint8)
    raw  = wins
    lsb0 = np.concatenate([wins[:,0:7], Z1], axis=1)
    msb0 = np.concatenate([Z1, wins[:,0:7]], axis=1)

    for form, keys in (("raw", raw), ("lsb0", lsb0), ("msb0", msb0)):
        # 全ゼロをスキップ
        nonzero_mask = ~np.all(keys == 0, axis=1)
        idxs = np.where(nonzero_mask)[0]
        for start in range(0, len(idxs), BATCH):
            batch_idx = idxs[start:start+BATCH]
            batch_keys = keys[batch_idx]
            local_hits = check_keys(batch_keys)
            for j in local_hits:
                orig_i = int(batch_idx[j])
                va = base_va + orig_i
                k = batch_keys[j].tobytes()
                hits.append((va, k.hex()))
                print(f"  ヒット! [{form}] VA=0x{va:08x} key={k.hex()} [{label}]", flush=True)
    return hits

# ---- 優先領域 ----
for lo, hi, desc in PRIORITY:
    for va, vsz, fofs in mem_regions:
        if va < hi and va+vsz > lo:
            cs = max(va, lo) - va
            ce = min(va+vsz, hi) - va
            chunk = d_raw[fofs+cs:fofs+ce]
            print(f"優先 [{desc}] VA=0x{va+cs:08x} {len(chunk)//1024}KB ...", flush=True)
            found_keys.extend(scan_chunk(chunk, desc, va+cs))

if found_keys:
    print(f"\n=== 優先領域ヒット ===", flush=True)
    for va,k in found_keys: print(f"  VA=0x{va:08x}: {k}", flush=True)
    sys.exit(0)

# ---- 全メモリスキャン ----
print("\n優先領域でヒットなし → 全メモリスキャン開始", flush=True)
scanned = 0
for va, vsz, fofs in mem_regions:
    chunk = d_raw[fofs:fofs+vsz]
    if len(chunk) < 8: continue
    hits = scan_chunk(chunk, f"VA=0x{va:08x}", va)
    found_keys.extend(hits)
    scanned += vsz
    if scanned % (20*1024*1024) < vsz:
        print(f"  {scanned//1024//1024}MB スキャン済み ...", flush=True)

print(f"\n=== 合計ヒット: {len(found_keys)} ===", flush=True)
for va,k in found_keys:
    print(f"  VA=0x{va:08x}: {k}")

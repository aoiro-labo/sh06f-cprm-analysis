"""正確な oracle で TitleKey をスキャン。
- Step = 192 (192バイト単位の暗号化TS: enc % 192 == 0 を確認済み)
- R[0] == 0x47 (バイト0 = TS sync: [TS][4Bpad]形式)
- L[0] == 0x47 (バイト4 = TS sync: [4Btimestamp][TS] M2TS形式)
の両方を試す。
"""
import struct, sys, os
import numpy as np

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DUMP_PATH = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "SD-MobileImpact.exe_11-コンテンツ再生開始直後.dmp")
print(f"DUMP: {DUMP_PATH}", flush=True)

SBOX_FILE = os.path.join(ROOT, "doc", "_migration_kit", "c2_sbox.bin")
BASIS_FILE = os.path.join(ROOT, "scripts", "c2_basis.bin")

S_np = np.frombuffer(open(SBOX_FILE, "rb").read(), dtype=np.uint8)

BASIS = open(BASIS_FILE, "rb").read()
assert len(BASIS) == 64 * 64
_C = np.zeros((8, 256, 64), dtype=np.uint8)
for pos in range(8):
    for val in range(256):
        acc = np.zeros(64, dtype=np.uint8)
        for b in range(8):
            if (val >> b) & 1:
                row = np.frombuffer(BASIS[(pos*8+b)*64:(pos*8+b)*64+64], dtype=np.uint8)
                acc ^= row
        _C[pos, val] = acc

print("BASIS テーブル構築完了", flush=True)

ROUND_OPS = [(0,2,1),(1,1,0),(1,0,1),(0,1,1),(2,0,1),(2,2,0),(2,1,0),(1,2,0),
             (2,1,1),(1,1,1),(1,2,1),(2,1,2),(1,1,2),(2,2,1),(1,2,2),(2,2,2)]

def _mix_v(op, wi, w0):
    if op == 0:
        return wi ^ w0
    elif op == 1:
        return (wi.astype(np.int16) + w0.astype(np.int16)).astype(np.uint8)
    else:
        return (wi.astype(np.int16) - w0.astype(np.int16)).astype(np.uint8)

def F_batch(W, K, ops):
    W = S_np[W ^ K]
    x = W[:,0] ^ W[:,1] ^ W[:,2] ^ W[:,3]
    W[:,0] = S_np[x]
    W[:,1] = _mix_v(ops[0], W[:,1], W[:,0])
    W[:,2] = _mix_v(ops[1], W[:,2], W[:,0])
    W[:,3] = _mix_v(ops[2], W[:,3], W[:,0])
    return W

def ksched_batch(keys8):
    acc = np.zeros((len(keys8), 64), dtype=np.uint8)
    for pos in range(8):
        acc ^= _C[pos, keys8[:, pos]]
    return np.stack([acc[:, r*4:r*4+4] for r in range(16)])

def dec_bytes04_batch(ct8, rks):
    """ct8:(8,) uint8, rks:(16,N,4) → (N,2) uint8: [byte0, byte4] of decrypted block

    C2 decryption: reversed round keys AND reversed ROUND_OPS.
    rks[0]=K0..rks[15]=K15; decryption uses rks[15-r] with ROUND_OPS[15-r].
    """
    N = rks.shape[1]
    L = np.tile(ct8[:4], (N,1)).astype(np.uint8)
    R = np.tile(ct8[4:], (N,1)).astype(np.uint8)
    for r in range(16):
        oldR = R.copy()
        Fr = F_batch(R.copy(), rks[15-r].copy(), ROUND_OPS[15-r])
        R = Fr ^ L
        L = oldR
    # output = R||L: byte0=R[:,0]=PT[0], byte4=L[:,0]=PT[4]
    return np.stack([R[:,0], L[:,0]], axis=1)

# ---- oracle ----
sb1 = open(os.path.join(ROOT, "SD_VIDEO", "PRG011", "MOV001.sb1"), "rb").read()
HEADER = 0xC0
STEP = 192  # 192バイト単位: enc % 192 == 0 確認済み

# CTs at every 192-byte unit start
CTS = [np.frombuffer(sb1[HEADER + i*STEP:HEADER + i*STEP + 8], dtype=np.uint8) for i in range(6)]

print(f"oracle step=192", flush=True)
for i, ct in enumerate(CTS):
    print(f"  CT[{i}] @ file 0x{HEADER+i*STEP:04X}: {ct.tobytes().hex()}", flush=True)

# mode: "R0" = check byte0==0x47, "L0" = check byte4==0x47
MODES = ["R0", "L0"]

def check_keys(keys8):
    """keys8:(N,8) → dict mode -> list of indices passing all 6 CTs"""
    rks = ksched_batch(keys8)
    results = {m: None for m in MODES}
    # Evaluate byte0 and byte4 for first CT
    b04 = dec_bytes04_batch(CTS[0], rks)  # (N,2)
    for mi, mode in enumerate(MODES):
        col = 0 if mode == "R0" else 1
        passing = np.where(b04[:, col] == 0x47)[0]
        for ct in CTS[1:]:
            if len(passing) == 0:
                break
            sub_rks = rks[:, passing, :]
            b04_sub = dec_bytes04_batch(ct, sub_rks)
            ok = b04_sub[:, col] == 0x47
            passing = passing[ok]
        results[mode] = passing.tolist()
    return results

# ---- ダンプパース ----
d_raw = open(DUMP_PATH, "rb").read()
print(f"ダンプ: {len(d_raw)//1024//1024}MB", flush=True)

ns = struct.unpack_from("<I", d_raw, 8)[0]
dirrva = struct.unpack_from("<I", d_raw, 12)[0]
streams = {}
for i in range(ns):
    st, sz, rva = struct.unpack_from("<III", d_raw, dirrva + i*12)
    streams[st] = (sz, rva)

mem_regions = []
sz, rva = streams[9]
nmem = struct.unpack_from("<Q", d_raw, rva)[0]
base_rva = struct.unpack_from("<Q", d_raw, rva+8)[0]
p = rva+16; fofs = base_rva
for i in range(nmem):
    va, vsz = struct.unpack_from("<QQ", d_raw, p); p += 16
    mem_regions.append((int(va), int(vsz), int(fofs)))
    fofs += vsz
print(f"Memory64List: {nmem} 領域, 合計 {sum(r[1] for r in mem_regions)//1024//1024}MB", flush=True)

BATCH = 131072

found_keys = {m: [] for m in MODES}

def scan_chunk(chunk_bytes, label, base_va):
    arr = np.frombuffer(chunk_bytes, dtype=np.uint8).copy()
    n = len(arr)
    if n < 8:
        return {}
    hits = {m: [] for m in MODES}
    wins = np.lib.stride_tricks.sliding_window_view(arr, 8)
    nw = len(wins)
    Z1 = np.zeros((nw, 1), dtype=np.uint8)
    raw_k  = wins
    lsb0_k = np.concatenate([wins[:,0:7], Z1], axis=1)
    msb0_k = np.concatenate([Z1, wins[:,0:7]], axis=1)

    for form, keys in (("raw", raw_k), ("lsb0", lsb0_k), ("msb0", msb0_k)):
        nonzero_mask = ~np.all(keys == 0, axis=1)
        idxs = np.where(nonzero_mask)[0]
        for start in range(0, len(idxs), BATCH):
            batch_idx = idxs[start:start+BATCH]
            batch_keys = keys[batch_idx]
            res = check_keys(batch_keys)
            for mode, passing in res.items():
                for j in passing:
                    orig_i = int(batch_idx[j])
                    va = base_va + orig_i
                    k = batch_keys[j].tobytes()
                    hits[mode].append((va, k.hex()))
                    print(f"  ヒット![{mode}][{form}] VA=0x{va:08x} key={k.hex()} [{label}]", flush=True)
    return hits

def merge_hits(total, chunk_hits):
    for m in MODES:
        total[m].extend(chunk_hits.get(m, []))

# ---- 優先領域 ----
PRIORITY = [(0x36000000, 0x3603c000, "C2_DLL"),
            (0x05020000, 0x0515c000, "SDCprm"),
            (0x00400000, 0x00600000, "MainExe")]

for lo, hi, desc in PRIORITY:
    for va, vsz, fofs in mem_regions:
        if va < hi and va+vsz > lo:
            cs = max(va, lo) - va
            ce = min(va+vsz, hi) - va
            chunk = d_raw[fofs+cs:fofs+ce]
            print(f"優先 [{desc}] VA=0x{va+cs:08x} {len(chunk)//1024}KB ...", flush=True)
            chunk_hits = scan_chunk(chunk, desc, va+cs)
            merge_hits(found_keys, chunk_hits)

any_found = any(found_keys[m] for m in MODES)
if any_found:
    print(f"\n=== 優先領域ヒット ===", flush=True)
    for m in MODES:
        for va, k in found_keys[m]:
            print(f"  [{m}] VA=0x{va:08x}: {k}")
    sys.exit(0)

# ---- 全メモリスキャン ----
print("\n優先領域でヒットなし → 全メモリスキャン開始", flush=True)
scanned = 0
for va, vsz, fofs in mem_regions:
    chunk = d_raw[fofs:fofs+vsz]
    if len(chunk) < 8:
        continue
    chunk_hits = scan_chunk(chunk, f"VA=0x{va:08x}", va)
    merge_hits(found_keys, chunk_hits)
    scanned += vsz
    if scanned % (20*1024*1024) < vsz:
        print(f"  {scanned//1024//1024}MB スキャン済み ...", flush=True)

print(f"\n=== 合計ヒット ===", flush=True)
for m in MODES:
    print(f"  [{m}]: {len(found_keys[m])} hits")
    for va, k in found_keys[m]:
        print(f"    VA=0x{va:08x}: {k}")

"""Kmu 二段階スキャナ (NumPy 版)
戦略: dump 内の全 8 バイト窓を Kmu 候補として試す。
      TitleKey = C2_dec(Kmu, ETK)
      oracle = C2_dec(TitleKey, CT_i)[0] == 0x47 for i=0..5

PRG011/MOV001.sb1 の 0xA0-0xBF から ETK を 4 候補試す。
Kmu 形式も 3 通り: raw / lsb0 (byte7=0) / msb0 (byte0=0)
"""
import struct, sys, os
import numpy as np

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DUMP = os.path.join(ROOT, "SD-MobileImpact.exe_11-コンテンツ再生開始直後.dmp")
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
                row = np.frombuffer(BASIS[(pos * 8 + b) * 64:(pos * 8 + b) * 64 + 64], dtype=np.uint8)
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
    """W:(N,4), K:(N,4) → (N,4)"""
    W = S_np[W ^ K]
    x = W[:, 0] ^ W[:, 1] ^ W[:, 2] ^ W[:, 3]
    W[:, 0] = S_np[x]
    W[:, 1] = _mix_v(ops[0], W[:, 1], W[:, 0])
    W[:, 2] = _mix_v(ops[1], W[:, 2], W[:, 0])
    W[:, 3] = _mix_v(ops[2], W[:, 3], W[:, 0])
    return W

def ksched_batch(keys8):
    """keys8: (N,8) → rks (16,N,4)"""
    acc = np.zeros((len(keys8), 64), dtype=np.uint8)
    for pos in range(8):
        acc ^= _C[pos, keys8[:, pos]]
    return np.stack([acc[:, r * 4:r * 4 + 4] for r in range(16)])

def dec_full_batch(ct8, rks):
    """ct8:(8,) uint8, rks:(16,N,4) → (N,8) uint8 (full 8-byte decrypted output)

    C2 decryption: reversed round keys AND reversed ROUND_OPS.
    """
    N = rks.shape[1]
    L = np.tile(ct8[:4], (N, 1)).astype(np.uint8)
    R = np.tile(ct8[4:], (N, 1)).astype(np.uint8)
    for r in range(16):
        oldR = R.copy()
        Fr = F_batch(R.copy(), rks[15-r].copy(), ROUND_OPS[15-r])
        R = Fr ^ L
        L = oldR
    return np.concatenate([R, L], axis=1)

def dec_first_byte_batch(ct8, rks):
    """ct8:(8,) uint8, rks:(16,N,4) → (N,2) [byte0=R[:,0]=PT[0], byte4=L[:,0]=PT[4]]

    C2 decryption: reversed round keys AND reversed ROUND_OPS.
    """
    N = rks.shape[1]
    L = np.tile(ct8[:4], (N, 1)).astype(np.uint8)
    R = np.tile(ct8[4:], (N, 1)).astype(np.uint8)
    for r in range(16):
        oldR = R.copy()
        Fr = F_batch(R.copy(), rks[15-r].copy(), ROUND_OPS[15-r])
        R = Fr ^ L
        L = oldR
    return np.stack([R[:, 0], L[:, 0]], axis=1)  # (N,2): [PT[0], PT[4]]

# ---- ETK 候補 ----
sb1 = open(os.path.join(ROOT, "SD_VIDEO", "PRG011", "MOV001.sb1"), "rb").read()
ETK_CANDIDATES = []
for i in range(4):
    etk = sb1[0xA0 + i * 8:0xA0 + i * 8 + 8]
    ETK_CANDIDATES.append(np.frombuffer(etk, dtype=np.uint8))
    print(f"ETK[{i}] @ 0x{0xA0+i*8:02X}: {etk.hex()}", flush=True)

# ---- TitleKey oracle (step=192: enc % 192 == 0 確認済み) ----
HEADER = 0xC0; STEP = 192
CTS = [np.frombuffer(sb1[HEADER + i * STEP:HEADER + i * STEP + 8], dtype=np.uint8) for i in range(6)]
print(f"oracle step=192, CT[0] @ 0x{HEADER:03X}: {CTS[0].tobytes().hex()}", flush=True)

# ---- ダンプパース ----
d_raw = open(DUMP, "rb").read()
print(f"ダンプ: {len(d_raw) // 1024 // 1024}MB", flush=True)

ns = struct.unpack_from("<I", d_raw, 8)[0]
dirrva = struct.unpack_from("<I", d_raw, 12)[0]
streams = {}
for i in range(ns):
    st, sz, rva = struct.unpack_from("<III", d_raw, dirrva + i * 12)
    streams[st] = (sz, rva)

mem_regions = []
sz, rva = streams[9]
nmem = struct.unpack_from("<Q", d_raw, rva)[0]
base_rva = struct.unpack_from("<Q", d_raw, rva + 8)[0]
p = rva + 16; fofs = base_rva
for i in range(nmem):
    va, vsz = struct.unpack_from("<QQ", d_raw, p); p += 16
    mem_regions.append((int(va), int(vsz), int(fofs)))
    fofs += vsz
print(f"Memory64List: {nmem} 領域, 合計 {sum(r[1] for r in mem_regions) // 1024 // 1024}MB", flush=True)

BATCH = 65536  # Kmu候補バッチサイズ (TKスキャンより小さめ: 2段C2が必要)

found = []

def check_kmu_batch(kmu_keys8):
    """kmu_keys8:(N,8) → passing indices が見つかった場合は (kmu_idx, etk_idx) のリストを返す"""
    rks_kmu = ksched_batch(kmu_keys8)
    results = []
    for ei, ETK in enumerate(ETK_CANDIDATES):
        # Step 1: TK = C2_dec(Kmu, ETK) for all N candidates
        tks = dec_full_batch(ETK, rks_kmu)  # (N,8)
        # Step 2: TitleKey oracle - CT[0] フィルタ (byte0 or byte4 == 0x47)
        rks_tk = ksched_batch(tks)
        b04_0 = dec_first_byte_batch(CTS[0], rks_tk)  # (N,2)
        # Try both byte0 (R0) and byte4 (L0)
        for byte_idx in range(2):
            passing = np.where(b04_0[:, byte_idx] == 0x47)[0]
            if len(passing) == 0:
                continue
            # CT[1..5] でさらに絞り込み
            for ct in CTS[1:]:
                if len(passing) == 0:
                    break
                sub_rks = rks_tk[:, passing, :]
                ok = dec_first_byte_batch(ct, sub_rks)[:, byte_idx] == 0x47
                passing = passing[ok]
            for j in passing:
                results.append((int(j), ei, byte_idx))
    return results

def scan_chunk(chunk_bytes, label, base_va):
    arr = np.frombuffer(chunk_bytes, dtype=np.uint8).copy()
    n = len(arr)
    if n < 8:
        return []
    hits = []
    wins = np.lib.stride_tricks.sliding_window_view(arr, 8)  # (n-7, 8)
    nw = len(wins)
    Z1 = np.zeros((nw, 1), dtype=np.uint8)
    raw_k  = wins
    lsb0_k = np.concatenate([wins[:, 0:7], Z1], axis=1)
    msb0_k = np.concatenate([Z1, wins[:, 0:7]], axis=1)

    for form, keys in (("raw", raw_k), ("lsb0", lsb0_k), ("msb0", msb0_k)):
        nonzero_mask = ~np.all(keys == 0, axis=1)
        idxs = np.where(nonzero_mask)[0]
        for start in range(0, len(idxs), BATCH):
            batch_idx = idxs[start:start + BATCH]
            batch_keys = keys[batch_idx]
            local_hits = check_kmu_batch(batch_keys)
            for (j, ei, byte_idx) in local_hits:
                orig_i = int(batch_idx[j])
                va = base_va + orig_i
                kmu = batch_keys[j].tobytes()
                etk = ETK_CANDIDATES[ei].tobytes()
                rks_kmu_single = ksched_batch(np.array([list(kmu)], dtype=np.uint8))
                tk_full = dec_full_batch(ETK_CANDIDATES[ei], rks_kmu_single)[0]
                tk_hex = bytes(tk_full).hex()
                mode = ["R0","L0"][byte_idx]
                hits.append((va, kmu.hex(), ei, tk_hex, mode))
                print(f"  ヒット![{mode}][{form}] VA=0x{va:08x} Kmu={kmu.hex()} ETK[{ei}]={etk.hex()} TitleKey={tk_hex} [{label}]", flush=True)
    return hits

# ---- 優先領域 ----
PRIORITY = [(0x05020000, 0x0515c000, "SDCprm")]  # SDCprm.dll = Kmu キャッシュ本命
PRIORITY += [(0x00400000, 0x00600000, "MainExe")]
PRIORITY += [(0x36000000, 0x3603c000, "C2_DLL")]

for lo, hi, desc in PRIORITY:
    for va, vsz, fofs in mem_regions:
        if va < hi and va + vsz > lo:
            cs = max(va, lo) - va
            ce = min(va + vsz, hi) - va
            chunk = d_raw[fofs + cs:fofs + ce]
            print(f"優先 [{desc}] VA=0x{va+cs:08x} {len(chunk)//1024}KB ...", flush=True)
            found.extend(scan_chunk(chunk, desc, va + cs))

if found:
    print(f"\n=== 優先領域ヒット ===", flush=True)
    for va, kmu, ei, tk in found:
        print(f"  VA=0x{va:08x} Kmu={kmu} ETK[{ei}] TitleKey={tk}")
    sys.exit(0)

# ---- 全メモリスキャン ----
print("\n優先領域でヒットなし → 全メモリスキャン開始", flush=True)
scanned = 0
for va, vsz, fofs in mem_regions:
    chunk = d_raw[fofs:fofs + vsz]
    if len(chunk) < 8:
        continue
    hits = scan_chunk(chunk, f"VA=0x{va:08x}", va)
    found.extend(hits)
    scanned += vsz
    if scanned % (20 * 1024 * 1024) < vsz:
        print(f"  {scanned//1024//1024}MB スキャン済み ...", flush=True)

print(f"\n=== 合計ヒット: {len(found)} ===", flush=True)
for va, kmu, ei, tk, mode in found:
    print(f"  [{mode}] VA=0x{va:08x} Kmu={kmu} ETK[{ei}] TitleKey={tk}")

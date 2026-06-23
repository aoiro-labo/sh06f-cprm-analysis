"""ダンプのメモリ全体から TitleKey を総当たりで探す。
find_key_in_threads.py がスタック限定だったのに対してヒープ・全メモリも対象にする。
速度最適化: check_key を最初の1ブロックで早期打ち切り。"""
import struct, sys, os

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DUMP = os.path.join(ROOT, "SD-MobileImpact.exe_11-コンテンツ再生開始直後.dmp")

S = open(os.path.join(ROOT,"doc","_migration_kit","c2_sbox.bin"),"rb").read()
BASIS = open(os.path.join(ROOT,"scripts","c2_basis.bin"),"rb").read()
assert len(BASIS)==64*64, f"basis size {len(BASIS)}"

# プリコンパイル: 鍵の各バイト値に対するラウンド鍵への寄与を事前計算
_CONTRIB = [[None]*256 for _ in range(8)]
for pos in range(8):
    for val in range(256):
        acc=bytearray(64)
        for b in range(8):
            if (val>>b)&1:
                row=BASIS[(pos*8+b)*64:(pos*8+b)*64+64]
                for j in range(64): acc[j]^=row[j]
        _CONTRIB[pos][val]=bytes(acc)

ROUND_OPS=[(0,2,1),(1,1,0),(1,0,1),(0,1,1),(2,0,1),(2,2,0),(2,1,0),(1,2,0),
           (2,1,1),(1,1,1),(1,2,1),(2,1,2),(1,1,2),(2,2,1),(1,2,2),(2,2,2)]
def _mix(op,wi,w0):
    if op==0: return wi^w0
    if op==1: return (wi+w0)&0xff
    return (wi-w0)&0xff
def F(W,K,ops):
    W=[W[0]^K[0],W[1]^K[1],W[2]^K[2],W[3]^K[3]]
    W=[S[W[0]],S[W[1]],S[W[2]],S[W[3]]]
    W[0]^=W[1]^W[2]^W[3]; W[0]=S[W[0]]
    W[1]=_mix(ops[0],W[1],W[0]); W[2]=_mix(ops[1],W[2],W[0]); W[3]=_mix(ops[2],W[3],W[0])
    return W

def ksched(key8):
    acc=bytearray(64)
    for pos in range(8):
        c=_CONTRIB[pos][key8[pos]]
        for j in range(64): acc[j]^=c[j]
    return [bytes(acc[r*4:r*4+4]) for r in range(16)]

# PRG011 暗号文と期待復号後先頭バイト
CT_PRG011=[
    (bytes.fromhex("7f782f4a9fed30ae"), 0x47),
    (bytes.fromhex("2d73f627056ba8b3"), 0x47),
    (bytes.fromhex("4fa1aacfb62ac0a1"), 0x47),
    (bytes.fromhex("6adf068446e50c3e"), 0x47),
    (bytes.fromhex("884b7df251e2ceb4"), 0x47),
    (bytes.fromhex("f6213279ec003130"), 0x47),
]

def dec_first_byte(ct8, rks):
    L=list(ct8[0:4]); R=list(ct8[4:8])
    for r in range(16):
        oldR=R[:]
        Fr=F(R[:],rks[r],ROUND_OPS[r])
        R=[(Fr[i]^L[i])&0xff for i in range(4)]
        L=oldR
    return R[0]  # out = R||L, out[0] = R[0]

def check_key(key8):
    rks=ksched(key8)
    for ct,exp in CT_PRG011:
        if dec_first_byte(ct,rks)!=exp: return False
    return True

print("オラクル初期化完了", flush=True)

# ダンプをパース
d = open(DUMP,"rb").read()
print(f"ダンプ: {len(d)//1024//1024}MB", flush=True)

ns = struct.unpack_from("<I",d,8)[0]
dirrva = struct.unpack_from("<I",d,12)[0]

streams = {}
for i in range(ns):
    st,sz,rva = struct.unpack_from("<III",d,dirrva+i*12)
    streams[st]=(sz,rva)

print(f"ストリームタイプ: {sorted(streams.keys())}", flush=True)

# Memory64List (type 9) を使ってメモリ領域のファイルオフセットを取得
mem_regions = []  # (va, size, file_off)
if 9 in streams:
    sz,rva = streams[9]
    nmem = struct.unpack_from("<Q",d,rva)[0]
    base_rva = struct.unpack_from("<Q",d,rva+8)[0]
    p = rva+16; fofs = base_rva
    for i in range(nmem):
        va,vsz = struct.unpack_from("<QQ",d,p); p+=16
        mem_regions.append((int(va), int(vsz), int(fofs)))
        fofs += vsz
    print(f"Memory64List: {nmem} 領域", flush=True)
elif 5 in streams:
    # MemoryList (type 5)
    sz,rva = streams[5]
    nranges = struct.unpack_from("<I",d,rva)[0]
    p = rva+4
    for i in range(nranges):
        va = struct.unpack_from("<I",d,p)[0]
        data_sz = struct.unpack_from("<I",d,p+4)[0]
        data_rva = struct.unpack_from("<I",d,p+8)[0]
        mem_regions.append((va, data_sz, data_rva))
        p += 12
    print(f"MemoryList: {nranges} 領域", flush=True)

total_bytes = sum(r[1] for r in mem_regions)
print(f"合計メモリ: {total_bytes//1024//1024}MB, 窓数(予想): {total_bytes//8//10000}万", flush=True)

# SDVM2TSPacketDecParser.dll のある領域 (0x36000000 付近) を優先して探す
# 次に SDCprm.dll 領域 (0x05020000)、次に全領域
PRIORITY = [(0x36000000, 0x3603c000, "C2 decode"), (0x05020000, 0x0515c000, "SDCprm")]

found_keys = []

def scan_region(data_slice, region_desc, base_va):
    hits = []
    n = len(data_slice)
    for i in range(n-7):
        key8 = data_slice[i:i+8]
        if key8 == b'\x00'*8: continue
        # 7バイト鍵+ゼロパディングも試す
        for kv in [key8, key8[:7]+b'\x00']:
            if check_key(kv):
                va = base_va + i if base_va else 0
                hits.append((va, kv.hex()))
    return hits

# 優先領域スキャン
for lo, hi, desc in PRIORITY:
    for va, vsz, fofs in mem_regions:
        if va < hi and va+vsz > lo:
            # 重複する部分だけスキャン
            clip_start = max(va, lo) - va
            clip_end   = min(va+vsz, hi) - va
            chunk = d[fofs+clip_start:fofs+clip_end]
            print(f"優先スキャン [{desc}] VA=0x{va+clip_start:08x} {len(chunk)//1024}KB ...", flush=True)
            hits = scan_region(chunk, desc, va+clip_start)
            if hits:
                print(f"  ヒット! {hits}", flush=True)
                found_keys.extend(hits)

if found_keys:
    print(f"\n=== 優先領域でヒット: {found_keys} ===")
    sys.exit(0)

# 全メモリスキャン (重い)
print("\n優先領域でヒットなし → 全メモリスキャン開始", flush=True)
scanned = 0
for va, vsz, fofs in mem_regions:
    chunk = d[fofs:fofs+vsz]
    if len(chunk) < 8: continue
    hits = scan_region(chunk, f"VA=0x{va:08x}", va)
    if hits:
        print(f"ヒット! VA=0x{va:08x}: {hits}", flush=True)
        found_keys.extend(hits)
    scanned += vsz
    if scanned % (10*1024*1024) < vsz:
        print(f"  {scanned//1024//1024}MB スキャン済み ...", flush=True)

print(f"\n=== 合計ヒット: {len(found_keys)} ===")
for va,k in found_keys:
    print(f"  VA=0x{va:08x}: {k}")

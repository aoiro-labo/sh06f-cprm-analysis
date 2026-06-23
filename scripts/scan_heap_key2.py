"""TitleKey スキャナ v2: MSB=0 形式も追加でチェック。
CPRM 56-bit TitleKey は 64-bit C2 鍵として格納される際に
  LSB=0: K0 K1 K2 K3 K4 K5 K6 00  (byte[7]=0)
  MSB=0: 00 K0 K1 K2 K3 K4 K5 K6  (byte[0]=0)
の2通りの可能性があり、どちらも試す。
"""
import struct, sys, os

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DUMP = os.path.join(ROOT, "SD-MobileImpact.exe_11-コンテンツ再生開始直後.dmp")

S = open(os.path.join(ROOT,"doc","_migration_kit","c2_sbox.bin"),"rb").read()
BASIS = open(os.path.join(ROOT,"scripts","c2_basis.bin"),"rb").read()
assert len(BASIS)==64*64

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

# .sb1 先頭 0xC0 バイトが平文ヘッダ → 0xC0 以降が暗号化TS
# オラクル: 最初の6ブロック (= 先頭48バイト of encrypted area)
sb1_path = os.path.join(ROOT,"SD_VIDEO","PRG011","MOV001.sb1")
sb1 = open(sb1_path,"rb").read()
HEADER = 0xC0
STEP = 376  # LCM(8, 188) — TS境界かつC2ブロック境界の間隔
CT_PRG011 = []
for i in range(6):
    CT_PRG011.append((sb1[HEADER + i*STEP : HEADER + i*STEP + 8], 0x47))
print(f"オラクル CT[0]: {CT_PRG011[0][0].hex()}", flush=True)
print(f"オラクル CT[5]: {CT_PRG011[5][0].hex()}", flush=True)

def dec_first_byte(ct8, rks):
    L=list(ct8[0:4]); R=list(ct8[4:8])
    for r in range(16):
        oldR=R[:]
        Fr=F(R[:],rks[r],ROUND_OPS[r])
        R=[(Fr[i]^L[i])&0xff for i in range(4)]
        L=oldR
    return R[0]

def check_key(key8):
    rks=ksched(key8)
    for ct,exp in CT_PRG011:
        if dec_first_byte(ct,rks)!=exp: return False
    return True

print("オラクル初期化完了", flush=True)

d = open(DUMP,"rb").read()
print(f"ダンプ: {len(d)//1024//1024}MB", flush=True)

ns = struct.unpack_from("<I",d,8)[0]
dirrva = struct.unpack_from("<I",d,12)[0]
streams = {}
for i in range(ns):
    st,sz,rva = struct.unpack_from("<III",d,dirrva+i*12)
    streams[st]=(sz,rva)
print(f"ストリームタイプ: {sorted(streams.keys())}", flush=True)

mem_regions = []
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

total_bytes = sum(r[1] for r in mem_regions)
print(f"合計: {total_bytes//1024//1024}MB", flush=True)

PRIORITY = [(0x36000000, 0x3603c000, "C2 decode"), (0x05020000, 0x0515c000, "SDCprm")]

found_keys = []

def scan_region(chunk, label, base_va):
    hits = []
    n = len(chunk)
    mv = memoryview(chunk)
    for i in range(n-7):
        w = bytes(mv[i:i+8])
        if w == b'\x00'*8: continue
        # 試行: そのまま / LSB=0 / MSB=0
        for kv in (w, w[:7]+b'\x00', b'\x00'+w[:7]):
            if check_key(kv):
                va = base_va + i
                hits.append((va, kv.hex()))
                print(f"  ヒット! VA=0x{va:08x} key={kv.hex()} [{label}]", flush=True)
    return hits

# 優先領域
for lo, hi, desc in PRIORITY:
    for va, vsz, fofs in mem_regions:
        if va < hi and va+vsz > lo:
            clip_start = max(va, lo) - va
            clip_end   = min(va+vsz, hi) - va
            chunk = d[fofs+clip_start:fofs+clip_end]
            print(f"優先 [{desc}] VA=0x{va+clip_start:08x} {len(chunk)//1024}KB ...", flush=True)
            hits = scan_region(chunk, desc, va+clip_start)
            found_keys.extend(hits)

if found_keys:
    print(f"\n=== 優先領域ヒット: {found_keys} ===", flush=True)
    sys.exit(0)

print("\n優先領域でヒットなし → 全メモリスキャン開始", flush=True)
scanned = 0
for va, vsz, fofs in mem_regions:
    chunk = d[fofs:fofs+vsz]
    if len(chunk) < 8: continue
    hits = scan_region(chunk, f"VA=0x{va:08x}", va)
    found_keys.extend(hits)
    scanned += vsz
    if scanned % (10*1024*1024) < vsz:
        print(f"  {scanned//1024//1024}MB スキャン済み ...", flush=True)

print(f"\n=== 合計ヒット: {len(found_keys)} ===", flush=True)
for va,k in found_keys:
    print(f"  VA=0x{va:08x}: {k}")

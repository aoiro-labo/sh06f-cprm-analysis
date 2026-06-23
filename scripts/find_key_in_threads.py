"""dump_11のスレッドリストとスタックを解析。
SDCprm.dll / SDVM2TSPacketDecParser.dll の範囲のEIPを探し、
スタック上の鍵候補を総当たりで検証する。"""
import struct, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DUMP = os.path.join(ROOT, "SD-MobileImpact.exe_11-コンテンツ再生開始直後.dmp")

# C2 実装 (c2fast.py の組み込み版)
S = open(os.path.join(ROOT,"doc","_migration_kit","c2_sbox.bin"),"rb").read()
BASIS = open(os.path.join(ROOT,"scripts","c2_basis.bin"),"rb").read()
assert len(BASIS)==64*64

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

_CONTRIB = [[None]*256 for _ in range(8)]
for pos in range(8):
    for val in range(256):
        acc=bytearray(64)
        for b in range(8):
            if (val>>b)&1:
                row=BASIS[(pos*8+b)*64:(pos*8+b)*64+64]
                for j in range(64): acc[j]^=row[j]
        _CONTRIB[pos][val]=bytes(acc)

def ksched(key8):
    acc=bytearray(64)
    for pos in range(8):
        c=_CONTRIB[pos][key8[pos]]
        for j in range(64): acc[j]^=c[j]
    return [bytes(acc[r*4:r*4+4]) for r in range(16)]

def dec_sync(ct8, rks):
    L=list(ct8[0:4]); R=list(ct8[4:8])
    for r in range(16):
        oldR=R[:]
        Fr=F(R[:],rks[r],ROUND_OPS[r])
        R=[(Fr[i]^L[i])&0xff for i in range(4)]
        L=oldR
    return L[0]  # R||L final swap: out[4]=L[0]

# PRG011オラクル
CT_PRG011=[
    bytes.fromhex("7f782f4a9fed30ae"),
    bytes.fromhex("2d73f627056ba8b3"),
    bytes.fromhex("4fa1aacfb62ac0a1"),
    bytes.fromhex("6adf0684 46e50c3e".replace(' ','')),
    bytes.fromhex("884b7df251e2ceb4"),
    bytes.fromhex("f62132 79ec003130".replace(' ','')),
]

def check_key(key8):
    rks=ksched(key8)
    for ct in CT_PRG011:
        if dec_sync(ct,rks)!=0x47: return False
    return True

print("オラクル初期化完了")

d=open(DUMP,"rb").read()
ns=struct.unpack_from("<I",d,8)[0]
dirrva=struct.unpack_from("<I",d,12)[0]

# ストリームを解析
streams={}
for i in range(ns):
    st,sz,rva=struct.unpack_from("<III",d,dirrva+i*12)
    streams[st]=(sz,rva)

# Memory64List をパース: VA→ファイルオフセット マップ
mem_map=[]
if 9 in streams:
    sz,rva=streams[9]
    nmem=struct.unpack_from("<Q",d,rva)[0]
    base_rva=struct.unpack_from("<Q",d,rva+8)[0]
    p=rva+16; fofs=base_rva
    for i in range(nmem):
        va,vsz=struct.unpack_from("<QQ",d,p); p+=16
        mem_map.append((va,vsz,fofs)); fofs+=vsz

def read_va(va,size):
    for mva,msz,mfo in mem_map:
        if mva<=va<mva+msz:
            off=mfo+(va-mva)
            if off+size<=len(d): return d[off:off+size]
    return None

# Thread List (stream type 4)
print("\n=== Thread List ===")
SDCPRM_RANGE=(0x05020000,0x0515c000)
C2_RANGE=(0x36000000,0x3603c000)

threads=[]
if 4 in streams:
    sz,rva=streams[4]
    nt=struct.unpack_from("<I",d,rva)[0]
    t_off=rva+4
    print(f"スレッド数: {nt}")
    for i in range(nt):
        # MINIDUMP_THREAD: tid(4) suspend(4) priority_class(4) priority(4) teb(8) stack(MINIDUMP_MEMORY_DESCRIPTOR64) ctx
        tid=struct.unpack_from("<I",d,t_off)[0]
        suspend=struct.unpack_from("<I",d,t_off+4)[0]
        # stack: va(8) size(8)
        stk_va=struct.unpack_from("<Q",d,t_off+16)[0]
        stk_sz=struct.unpack_from("<Q",d,t_off+24)[0]
        ctx_rva=struct.unpack_from("<I",d,t_off+36)[0]  # context RVA (after memory descriptor which is 16B total? check)
        # MINIDUMP_THREAD structure:
        # ThreadId(4)+SuspendCount(4)+PriorityClass(4)+Priority(4) = 16B
        # Teb(8) = 8B
        # Stack: StartOfMemoryRange(8)+MemoryDataRva(4)+DataSize(4) = 16B? No...
        # Let me use correct offsets
        # MINIDUMP_THREAD:
        # +0: ThreadId ULONG32
        # +4: SuspendCount ULONG32
        # +8: PriorityClass ULONG32
        # +12: Priority ULONG32
        # +16: Teb ULONG64
        # +24: Stack MINIDUMP_MEMORY_DESCRIPTOR (StartOfMemoryRange(8) + Memory(MINIDUMP_LOCATION_DESCRIPTOR(DataSize(4)+Rva(4))))
        #       = 8+8=16B total
        # +40: ThreadContext MINIDUMP_LOCATION_DESCRIPTOR (DataSize(4)+Rva(4))=8B
        tid=struct.unpack_from("<I",d,t_off)[0]
        stk_va=struct.unpack_from("<Q",d,t_off+24)[0]
        stk_data_sz=struct.unpack_from("<I",d,t_off+32)[0]
        stk_data_rva=struct.unpack_from("<I",d,t_off+36)[0]
        ctx_sz=struct.unpack_from("<I",d,t_off+40)[0]
        ctx_rva=struct.unpack_from("<I",d,t_off+44)[0]

        # EIP from context (CONTEXT for x86: size=0x2cc)
        eip=0
        if ctx_sz>=0x80 and ctx_rva+ctx_sz<=len(d):
            # x86 CONTEXT: ContextFlags(4), Dr0-Dr7(32), FloatSave(108), SegGs-SegCs(20),
            # EFlags(4), Esp(4), Ebp(4), Eip(4)...
            # EIP is at offset 0xb8 in CONTEXT
            eip=struct.unpack_from("<I",d,ctx_rva+0xb8)[0]

        in_sdcprm = SDCPRM_RANGE[0]<=eip<SDCPRM_RANGE[1]
        in_c2     = C2_RANGE[0]<=eip<C2_RANGE[1]
        print(f"  TID={tid:#x} EIP=0x{eip:08x} stk=0x{stk_va:08x}+{stk_data_sz:#x}"
              + (" [SDCprm!]" if in_sdcprm else "") + (" [C2!]" if in_c2 else ""))
        threads.append((tid,eip,stk_va,stk_data_sz,stk_data_rva,in_sdcprm,in_c2))
        t_off+=48  # MINIDUMP_THREAD is 48 bytes

# 各スレッドのスタックを走査して鍵を探す
print("\n=== スタック上の鍵候補総当たり ===")
total_hits=0
for tid,eip,stk_va,stk_sz,stk_rva,in_sdcprm,in_c2 in threads:
    if stk_sz==0: continue
    stk=d[stk_rva:stk_rva+stk_sz]
    if len(stk)<8: continue
    hits=[]
    for i in range(len(stk)-7):
        key8=stk[i:i+8]
        if key8==b'\x00'*8: continue
        if check_key(key8):
            hits.append((i,key8.hex()))
        # mode=1: 7byte+zero
        key7=stk[i:i+7]+b'\x00'
        if key7!=key8 and check_key(key7):
            hits.append((i,key7.hex()+'[z]'))
    if hits:
        print(f"  TID={tid:#x} EIP=0x{eip:08x}: {len(hits)} HITs!")
        for off,h in hits:
            print(f"    stk+0x{off:x}: {h}")
        total_hits+=len(hits)
    elif in_sdcprm or in_c2:
        print(f"  TID={tid:#x} EIP=0x{eip:08x}: 0 hits (but in crypto range)")
    else:
        pass # skip quiet

print(f"\n合計ヒット: {total_hits}")
if total_hits==0:
    print("0ヒット → 鍵はスタックにない(解放済み or 他の手法が必要)")

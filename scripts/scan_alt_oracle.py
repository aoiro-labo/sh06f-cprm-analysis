import struct, sys, os
import numpy as np
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DUMP_PATH = sys.argv[1] if len(sys.argv)>1 else os.path.join(ROOT,"SD-MobileImpact.exe_11-コンテンツ再生開始直後.dmp")
S_np = np.frombuffer(open(os.path.join(ROOT,"doc","_migration_kit","c2_sbox.bin"),"rb").read(),dtype=np.uint8)
BASIS = open(os.path.join(ROOT,"scripts","c2_basis.bin"),"rb").read()
_C = np.zeros((8,256,64),dtype=np.uint8)
for pos in range(8):
    for val in range(256):
        acc=np.zeros(64,dtype=np.uint8)
        for b in range(8):
            if (val>>b)&1:
                acc^=np.frombuffer(BASIS[(pos*8+b)*64:(pos*8+b)*64+64],dtype=np.uint8)
        _C[pos,val]=acc
ROUND_OPS=[(0,2,1),(1,1,0),(1,0,1),(0,1,1),(2,0,1),(2,2,0),(2,1,0),(1,2,0),(2,1,1),(1,1,1),(1,2,1),(2,1,2),(1,1,2),(2,2,1),(1,2,2),(2,2,2)]
def _mix_v(op,wi,w0):
    if op==0: return wi^w0
    elif op==1: return (wi.astype(np.int16)+w0.astype(np.int16)).astype(np.uint8)
    else: return (wi.astype(np.int16)-w0.astype(np.int16)).astype(np.uint8)
def F_batch(W,K,ops):
    W=S_np[W^K]; x=W[:,0]^W[:,1]^W[:,2]^W[:,3]; W[:,0]=S_np[x]
    W[:,1]=_mix_v(ops[0],W[:,1],W[:,0]); W[:,2]=_mix_v(ops[1],W[:,2],W[:,0]); W[:,3]=_mix_v(ops[2],W[:,3],W[:,0])
    return W
def ksched_batch(keys8):
    acc=np.zeros((len(keys8),64),dtype=np.uint8)
    for pos in range(8): acc^=_C[pos,keys8[:,pos]]
    return np.stack([acc[:,r*4:r*4+4] for r in range(16)])
def enc_bytes04_batch(pt8,rks):
    N=rks.shape[1]; L=np.tile(pt8[:4],(N,1)).astype(np.uint8); R=np.tile(pt8[4:],(N,1)).astype(np.uint8)
    for r in range(16):
        oldR=R.copy(); Fr=F_batch(R.copy(),rks[r].copy(),ROUND_OPS[r]); R=Fr^L; L=oldR
    return np.stack([R[:,0],L[:,0]],axis=1)
sb1=open(os.path.join(ROOT,"SD_VIDEO","PRG011","MOV001.sb1"),"rb").read()
CTS=[np.frombuffer(sb1[0xC0+i*192:0xC0+i*192+8],dtype=np.uint8) for i in range(6)]
print(f"ALT-ORACLE(forward enc): dump={DUMP_PATH}",flush=True)
d_raw=open(DUMP_PATH,"rb").read()
ns=struct.unpack_from("<I",d_raw,8)[0]; dirrva=struct.unpack_from("<I",d_raw,12)[0]
streams={}
for i in range(ns):
    st,sz,rva=struct.unpack_from("<III",d_raw,dirrva+i*12); streams[st]=(sz,rva)
mem_regions=[]; sz,rva=streams[9]; nmem=struct.unpack_from("<Q",d_raw,rva)[0]; base_rva=struct.unpack_from("<Q",d_raw,rva+8)[0]
p=rva+16; fofs=base_rva
for i in range(nmem):
    va,vsz=struct.unpack_from("<QQ",d_raw,p); p+=16; mem_regions.append((int(va),int(vsz),int(fofs))); fofs+=vsz
BATCH=131072; found=[]
def check_keys(keys8):
    rks=ksched_batch(keys8); b04=enc_bytes04_batch(CTS[0],rks)
    res={"R0":None,"L0":None}
    for mi,(mode,col) in enumerate([("R0",0),("L0",1)]):
        passing=np.where(b04[:,col]==0x47)[0]
        for ct in CTS[1:]:
            if len(passing)==0: break
            sub_rks=rks[:,passing,:]; b04_sub=enc_bytes04_batch(ct,sub_rks); ok=b04_sub[:,col]==0x47; passing=passing[ok]
        res[mode]=passing.tolist()
    return res
scanned=0
for va,vsz,fofs in mem_regions:
    chunk=d_raw[fofs:fofs+vsz]
    if len(chunk)<8: continue
    arr=np.frombuffer(chunk,dtype=np.uint8).copy(); wins=np.lib.stride_tricks.sliding_window_view(arr,8)
    nw=len(wins); Z1=np.zeros((nw,1),dtype=np.uint8)
    raw_k=wins; lsb0_k=np.concatenate([wins[:,0:7],Z1],axis=1); msb0_k=np.concatenate([Z1,wins[:,0:7]],axis=1)
    for form,keys in [("raw",raw_k),("lsb0",lsb0_k),("msb0",msb0_k)]:
        nonzero=~np.all(keys==0,axis=1); idxs=np.where(nonzero)[0]
        for start in range(0,len(idxs),BATCH):
            bi=idxs[start:start+BATCH]; bk=keys[bi]; res=check_keys(bk)
            for mode,passing in res.items():
                for j in passing:
                    oi=int(bi[j]); kv=bk[j].tobytes()
                    print(f"HIT[{mode}][{form}] VA=0x{va+oi:08x} key={kv.hex()}",flush=True); found.append(kv.hex())
    scanned+=vsz
    if scanned%(20*1024*1024)<vsz: print(f"{scanned//1024//1024}MB...",flush=True)
print(f"ALT-ORACLE done: {len(found)} hits",flush=True)

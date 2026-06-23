import struct, glob, os, re, sys, numpy as np
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass

ROOT = r"c:\Users\aoiro\Documents\ワンセグ関係（録画機器：SH-06F）"
MODBASE = 0x36000000; MODEND = 0x3603c000

def sb1_sigs():
    out={}
    for p in sorted(glob.glob(os.path.join(ROOT,"SD_VIDEO","PRG*","MOV001.sb1"))):
        name=os.path.basename(os.path.dirname(p)); b=open(p,"rb").read()
        out[name]={
            "hdr":   b[4:4+20],         # 平文ヘッダ(先頭4=00を除く)
            "enc0":  b[0xA0:0xA0+24],   # 最初の暗号ブロック(連続バッファなら先頭付近)
            "deep":  b[0x1000:0x1000+16],
            "size":  len(b),
        }
    return out

def parse_mdmp(path):
    d=open(path,"rb").read()
    assert d[:4]==b"MDMP"
    nstreams,dirrva=struct.unpack_from("<II",d,8)
    streams={}
    for i in range(nstreams):
        st,sz,rva=struct.unpack_from("<III",d,dirrva+12*i); streams[st]=(sz,rva)
    mem=[]
    if 9 in streams:
        _,rva=streams[9]; nranges,baserva=struct.unpack_from("<QQ",d,rva)
        off=rva+16; cur=baserva
        for i in range(nranges):
            start,size=struct.unpack_from("<QQ",d,off+16*i); mem.append((start,size,cur)); cur+=size
    # ModuleList = 4
    mods=[]
    if 4 in streams:
        _,rva=streams[4]; n=struct.unpack_from("<I",d,rva)[0]
        for i in range(n):
            base=rva+4+108*i
            modbase,modsize=struct.unpack_from("<QI",d,base)
            namerva=struct.unpack_from("<I",d,base+20)[0]   # ModuleNameRva @ off 20
            try:
                ln=struct.unpack_from("<I",d,namerva)[0]
                if ln>1024 or ln<0: nm="?"
                else: nm=d[namerva+4:namerva+4+ln].decode("utf-16le","replace")
            except: nm="?"
            mods.append((modbase,modsize,nm))
    return d,streams,mem,mods

def search(mem,d,needle,limit=6):
    hits=[]
    for start,size,fofs in mem:
        chunk=d[fofs:fofs+size]; idx=chunk.find(needle)
        while idx!=-1:
            hits.append(start+idx);
            if len(hits)>=limit: return hits
            idx=chunk.find(needle,idx+1)
    return hits

def scan_ts(mem,d):
    """0x47同期が stride188/192 で高密度な領域(=復号済みTS)を検出。"""
    res=[]
    for start,size,fofs in mem:
        if size < 188*30: continue
        buf=np.frombuffer(d,dtype=np.uint8,count=size,offset=fofs)
        hit=np.nonzero(buf==0x47)[0]
        if len(hit) < 30: continue
        for S in (188,192):
            counts=np.bincount(hit % S, minlength=S)
            r=int(counts.argmax()); per=size//S
            if per<30: continue
            frac=counts[r]/per
            if frac>0.80:
                res.append((start+r, size, S, frac, per))
    return res

def main():
    sigs=sb1_sigs()
    dumps=[p for p in sorted(glob.glob(os.path.join(ROOT,"SD-MobileImpact.exe_*.dmp")))
           if any(f"_{n}-" in os.path.basename(p) for n in (9,10,11,12,13))]
    os.makedirs(os.path.join(ROOT,"recovered"),exist_ok=True)
    for path in dumps:
        m=re.search(r'_(\d+)-',os.path.basename(path)); nm=f"d{m.group(1)}" if m else "dX"
        print("\n"+"="*70); print(f"### {nm}  ({os.path.basename(path)})")
        d,streams,mem,mods=parse_mdmp(path)
        # 関連モジュール
        for mb,ms,mn in mods:
            low=mn.lower()
            if any(k in low for k in ("sdvm","sdcprm","sdcore","sdvcore","sdapf")) or 0x36000000<=mb<0x36100000:
                print(f"  [mod] {mn[:60]} base={hex(mb)} size={hex(ms)}")
        # .sb1 buffers
        any_sb1=False
        for prog,s in sigs.items():
            for tag in ("hdr","enc0","deep"):
                h=search(mem,d,s[tag])
                if h:
                    print(f"  [.sb1] {prog}/{tag} @ {[hex(x) for x in h]} (filesize={s['size']})")
                    any_sb1=True
        if not any_sb1: print("  [.sb1] 該当なし(連続バッファとして未常駐)")
        # decrypted TS
        ts=scan_ts(mem,d)
        if ts:
            print("  [TS] 復号済みTSらしき領域:")
            ts.sort(key=lambda x:-x[3])
            for va,size,S,frac,per in ts[:6]:
                print(f"        VA={hex(va)} stride={S} sync率={frac:.2f} 推定pkt={per} 領域={size}B")
            # 最良領域を保存
            va,size,S,frac,per=ts[0]
            for start,sz,fofs in mem:
                if start<=va<start+sz:
                    o=fofs+(va-start); raw=d[o:o+ (size-(va-start))]
                    nptk=len(raw)//S
                    out=b"".join(raw[i*S:i*S+188] for i in range(nptk))
                    op=os.path.join(ROOT,"recovered",f"{nm}_ts_{hex(va)}.ts")
                    open(op,"wb").write(out)
                    print(f"        -> 保存 {op} ({nptk}pkt, {len(out)}B)")
                    break
        else:
            print("  [TS] 復号済みTS領域なし")
    print("\n[done]")

if __name__=="__main__": main()

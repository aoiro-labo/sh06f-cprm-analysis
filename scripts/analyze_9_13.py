import struct, glob, os, sys

ROOT = r"c:\Users\aoiro\Documents\ワンセグ関係（録画機器：SH-06F）"
MODBASE = 0x36000000
MODEND  = 0x3603c000  # SDVM2TSPacketDecParser unpacked image range

def sigs_from_sb1():
    """各番組の MOV001.sb1 から識別用シグネチャを集める。
    offset 0x1000(深い暗号領域,ユニーク) 16byte と、平文ヘッダ先頭16byte。"""
    out = {}
    for p in sorted(glob.glob(os.path.join(ROOT,"SD_VIDEO","PRG*","MOV001.sb1"))):
        name = os.path.basename(os.path.dirname(p))
        b = open(p,"rb").read()
        out[name] = {
            "deep": b[0x1000:0x1000+16],   # 暗号化領域(ユニーク)
            "hdr":  b[0:16],               # 平文ヘッダ先頭
            "size": len(b),
        }
    return out

def parse_mdmp(path):
    """Memory64List(stream9), ThreadList(stream3), ModuleList(stream4) を返す。"""
    d = open(path,"rb").read()
    assert d[:4]==b"MDMP", path
    nstreams, dirrva = struct.unpack_from("<II", d, 8)
    streams = {}
    for i in range(nstreams):
        st, sz, rva = struct.unpack_from("<III", d, dirrva+12*i)
        streams[st] = (sz, rva)
    # Memory64List = 9
    mem = []
    if 9 in streams:
        _, rva = streams[9]
        nranges, baserva = struct.unpack_from("<QQ", d, rva)
        off = rva+16
        cur = baserva
        for i in range(nranges):
            start, size = struct.unpack_from("<QQ", d, off+16*i)
            mem.append((start, size, cur))
            cur += size
    # ThreadList = 3
    threads = []
    if 3 in streams:
        _, rva = streams[3]
        n = struct.unpack_from("<I", d, rva)[0]
        for i in range(n):
            # MINIDUMP_THREAD: TID(4),susp(4),prio0(4),prio(4),teb(8),stack(MEMDESC:start8,loc:sz4,rva4),ctx(sz4,rva4)
            base = rva+4+48*i
            tid = struct.unpack_from("<I", d, base)[0]
            ctx_sz, ctx_rva = struct.unpack_from("<II", d, base+40)
            threads.append((tid, ctx_sz, ctx_rva))
    return d, streams, mem, threads

def read_va(mem, d, va, n):
    for start,size,fofs in mem:
        if start<=va<start+size:
            o = fofs+(va-start)
            return d[o:o+min(n, size-(va-start))]
    return None

def search(mem, d, needle):
    hits=[]
    for start,size,fofs in mem:
        chunk = d[fofs:fofs+size]
        idx = chunk.find(needle)
        while idx!=-1:
            hits.append(start+idx)
            idx = chunk.find(needle, idx+1)
            if len(hits)>8: return hits
    return hits

def thread_eips(d, threads):
    """各スレッドの EIP/ESP/EBP を返す(x86 CONTEXT: eip=0xB8,esp=0xC4,ebp=0xB4)。"""
    res=[]
    for tid, sz, rva in threads:
        if sz < 0xcc:
            res.append((tid,None,None,None)); continue
        eip = struct.unpack_from("<I", d, rva+0xB8)[0]
        esp = struct.unpack_from("<I", d, rva+0xC4)[0]
        ebp = struct.unpack_from("<I", d, rva+0xB4)[0]
        res.append((tid,eip,esp,ebp))
    return res

def main():
    sigs = sigs_from_sb1()
    print(f"[*] {len(sigs)} 番組の.sb1シグネチャ収集")
    dumps = sorted(glob.glob(os.path.join(ROOT,"SD-MobileImpact.exe_1*.dmp")) +
                   glob.glob(os.path.join(ROOT,"SD-MobileImpact.exe_9*.dmp")))
    # _9.._13 のみ
    dumps = [p for p in dumps if any(f"_{n}" in os.path.basename(p) for n in (9,10,11,12,13))]
    for path in dumps:
        nm = os.path.basename(path)
        print("\n"+"="*70)
        print(f"### {nm}  ({os.path.getsize(path)//(1024*1024)}MB)")
        d, streams, mem, threads = parse_mdmp(path)
        print(f"  memranges={len(mem)} threads={len(threads)} streams={sorted(streams)}")
        # どの番組の.sb1が載っているか
        found_prog=None
        for prog, s in sigs.items():
            h = search(mem, d, s["deep"])
            if h:
                print(f"  [.sb1] {prog} deep-sig @ {[hex(x) for x in h]}  (.sb1 size={s['size']})")
                found_prog=prog
        # 平文ヘッダ(全番組共通パターンに近い)も一応
        # スレッドEIP: モジュール範囲内に居るものを強調
        eips = thread_eips(d, threads)
        inmod=[]
        for tid,eip,esp,ebp in eips:
            if eip and MODBASE<=eip<MODEND:
                inmod.append((tid,eip,esp,ebp))
        if inmod:
            print(f"  [!!] SDVM2TSPacketDecParser範囲(0x36...)で実行中のスレッド:")
            for tid,eip,esp,ebp in inmod:
                print(f"        tid={tid} eip={hex(eip)} esp={hex(esp)} ebp={hex(ebp)}")
        else:
            eipss = [hex(e) if e else "?" for (_,e,_,_) in eips]
            print(f"  スレッドEIP(モジュール外): {eipss}")
    print("\n[done]")

if __name__=="__main__":
    main()

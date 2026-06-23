"""2026-06-22ダンプを解析: エラー状態のスレッドとコールスタックを確認する"""
import struct, os

ROOT = r"c:\Users\aoiro\Documents\ワンセグ関係（録画機器：SH-06F）"
DUMP = os.path.join(ROOT, "SD-MobileImpact.exe_2026-06-22_21-05-17.dmp")
EXE  = r"C:\Program Files (x86)\Panasonic\SD-MobileImpact\SD-MobileImpact.exe"

d = open(DUMP, "rb").read()
print(f"Dump size: {len(d)//1024}KB")

ns  = struct.unpack_from("<I", d, 8)[0]
dirrva = struct.unpack_from("<I", d, 12)[0]

streams = {}
for i in range(ns):
    st, sz, rva = struct.unpack_from("<III", d, dirrva + i*12)
    streams[st] = (sz, rva)

# Memory64List
mem_map = []
if 9 in streams:
    sz, rva = streams[9]
    nmem = struct.unpack_from("<Q", d, rva)[0]
    base_rva = struct.unpack_from("<Q", d, rva+8)[0]
    p = rva + 16; fofs = base_rva
    for i in range(nmem):
        va, vsz = struct.unpack_from("<QQ", d, p); p += 16
        mem_map.append((va, vsz, fofs)); fofs += vsz
    print(f"Memory regions: {nmem}")

def read_va(va, size):
    for mva, msz, mfo in mem_map:
        if mva <= va < mva+msz:
            off = mfo+(va-mva)
            if off+size <= len(d): return d[off:off+size]
    return None

# Exception stream
if 6 in streams:
    sz, rva = streams[6]
    exc_tid = struct.unpack_from("<I", d, rva)[0]
    exc_rva = struct.unpack_from("<I", d, rva+4)[0]
    code = struct.unpack_from("<I", d, exc_rva)[0]
    addr = struct.unpack_from("<Q", d, exc_rva+16)[0]
    print(f"\n=== Exception TID={exc_tid:#x} code=0x{code:08x} addr=0x{addr:016x}")
else:
    print("\n(Exception streamなし → エラーダイアログ表示中の生きたプロセスダンプ)")

IMAGEBASE = 0x400000

# Thread List
if 4 in streams:
    sz, rva = streams[4]
    nt = struct.unpack_from("<I", d, rva)[0]
    print(f"\n=== Threads ({nt}) ===")
    t_off = rva + 4
    for i in range(nt):
        tid  = struct.unpack_from("<I", d, t_off)[0]
        stk_va  = struct.unpack_from("<Q", d, t_off+24)[0]
        stk_dsz = struct.unpack_from("<I", d, t_off+32)[0]
        stk_drva= struct.unpack_from("<I", d, t_off+36)[0]
        ctx_sz  = struct.unpack_from("<I", d, t_off+40)[0]
        ctx_rva = struct.unpack_from("<I", d, t_off+44)[0]
        eip=esp=ebp=eax=esi=edi=ebx=ecx=edx = 0
        if ctx_sz >= 0xbc and ctx_rva+ctx_sz <= len(d):
            # x86 CONTEXT layout (ContextFlags=4, Dr=32, FloatSave=112, Seg=20, Flags=4, Esp=4, Ebp=4, Eip=4)
            # Offset 0x9c=Edi, 0xa0=Esi, 0xa4=Ebx, 0xa8=Edx, 0xac=Ecx, 0xb0=Eax
            # 0xb4=Ebp, 0xb8=Eip? No...
            # Standard x86 CONTEXT:
            # +0x00: ContextFlags (4)
            # +0x04: Dr0-Dr7 (8*4=32)
            # +0x24: FloatSave (FLOATING_SAVE_AREA, 112 bytes)
            # +0x94: SegGs,SegFs,SegEs,SegDs (4*4=16)
            # +0xa4: Edi,Esi,Ebx,Edx,Ecx,Eax (6*4=24)
            # +0xbc: Ebp (4)
            # +0xc0: Eip (4)  ← wait this doesn't match 0xb8
            # Actually for x86 CONTEXT:
            # +0x9c: SegGs (4)
            # +0xa0: SegFs (4)
            # +0xa4: SegEs (4)
            # +0xa8: SegDs (4)
            # +0xac: Edi (4)
            # +0xb0: Esi (4)
            # +0xb4: Ebx (4)
            # +0xb8: Edx (4)
            # +0xbc: Ecx (4)
            # +0xc0: Eax (4)
            # +0xc4: Ebp (4)
            # +0xc8: Eip (4)
            # +0xcc: SegCs (4)
            # +0xd0: EFlags (4)
            # +0xd4: Esp (4)
            # +0xd8: SegSs (4)
            ctx = d[ctx_rva:]
            edi = struct.unpack_from("<I", ctx, 0xac)[0]
            esi = struct.unpack_from("<I", ctx, 0xb0)[0]
            ebx = struct.unpack_from("<I", ctx, 0xb4)[0]
            edx = struct.unpack_from("<I", ctx, 0xb8)[0]
            ecx = struct.unpack_from("<I", ctx, 0xbc)[0]
            eax = struct.unpack_from("<I", ctx, 0xc0)[0]
            ebp = struct.unpack_from("<I", ctx, 0xc4)[0]
            eip = struct.unpack_from("<I", ctx, 0xc8)[0]
            esp = struct.unpack_from("<I", ctx, 0xd4)[0]

        in_main   = IMAGEBASE <= eip < IMAGEBASE+0x200000
        in_sdcprm = 0x05020000 <= eip < 0x0515c000
        in_sdvm   = 0x36000000 <= eip < 0x3603c000
        label = (" [main]" if in_main else
                 " [SDCprm]" if in_sdcprm else
                 " [SDVM2TS]" if in_sdvm else
                 " [???]" if eip else "")

        print(f"  TID={tid:#x} EIP=0x{eip:08x} ESP=0x{esp:08x} EBP=0x{ebp:08x}{label}")

        # mainスレッドのみスタック詳細
        if in_main and stk_drva and stk_dsz:
            stk = d[stk_drva:stk_drva+stk_dsz]
            esp_off = esp - stk_va if esp >= stk_va else 0
            if 0 <= esp_off < len(stk):
                chunk = stk[esp_off:esp_off+128]
                ras = []
                for j in range(0, len(chunk)-3, 4):
                    v = struct.unpack_from("<I", chunk, j)[0]
                    if IMAGEBASE <= v < IMAGEBASE+0x200000:
                        ras.append((j, v))
                print(f"    EAX=0x{eax:08x} ECX=0x{ecx:08x} EBX=0x{ebx:08x}")
                print(f"    Stack return addrs: {[(hex(off), hex(ra)) for off,ra in ras[:6]]}")

        t_off += 48

# ModuleList
if 3 in streams:
    sz, rva = streams[3]
    nmod = struct.unpack_from("<I", d, rva)[0]
    print(f"\n=== Modules ({nmod}) ===")
    m_off = rva + 4
    for i in range(nmod):
        base = struct.unpack_from("<Q", d, m_off)[0]
        msize= struct.unpack_from("<I", d, m_off+8)[0]
        name_rva = struct.unpack_from("<I", d, m_off+28)[0]
        name_len = struct.unpack_from("<I", d, name_rva)[0] if name_rva else 0
        name = d[name_rva+4:name_rva+4+name_len].decode('utf-16-le','replace') if name_rva and name_rva+4+name_len<=len(d) else "?"
        print(f"  0x{base:08x}+0x{msize:06x}  {os.path.basename(name)}")
        m_off += 108

# sd.datの内容をメモリから探す
print("\n=== メモリ内のsd.dat関連 ===")
needle = b"sd=0&end"
needle2 = b"sd=1&end"
for mva, msz, mfo in mem_map:
    chunk = d[mfo:mfo+msz]
    for pat, label in [(needle,"sd=0"), (needle2,"sd=1")]:
        pos = 0
        while True:
            pos = chunk.find(pat, pos)
            if pos < 0: break
            print(f"  '{label}' @ VA=0x{mva+pos:08x}")
            pos += 1

# 86000001 をメモリから探す (エラーコードが格納されている場所)
print("\n=== メモリ内の86000001 ===")
err_bytes = struct.pack("<I", 0x86000001)
for mva, msz, mfo in mem_map:
    chunk = d[mfo:mfo+msz]
    pos = 0
    while True:
        pos = chunk.find(err_bytes, pos)
        if pos < 0: break
        if IMAGEBASE <= mva+pos < IMAGEBASE+0x200000:
            print(f"  code section @ VA=0x{mva+pos:08x} (exe)")
        else:
            print(f"  data @ VA=0x{mva+pos:08x}")
        pos += 1
        if pos > 10: break  # 最初の数件だけ

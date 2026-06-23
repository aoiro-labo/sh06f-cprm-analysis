"""MDMPダンプ内でSDCprm.dll / SDCore.dll のメモリ領域を検索。
CPRM鍵導出に必要なデバイス鍵の在り処を特定する。"""
import struct, os, sys

# 既知モジュールアドレス (procmon / 解析.mdから)
SDCPRM_BASE = 0x5020000
SDCPRM_SIZE = 0x13c000   # 約1.3MB
SDCORE_BASE = 0x4c50000
SDCORE_SIZE = 0x50000

def scan_mdmp(path, targets):
    try:
        d = open(path,"rb").read()
    except Exception as e:
        print(f"  skip: {e}"); return
    if d[:4] != b"MDMP":
        print(f"  not MDMP"); return
    ns, dirrva = struct.unpack_from("<II", d, 8)[1], struct.unpack_from("<II", d, 12)[1]
    # Wait, MDMP header: signature(4) + Version(2) + ImplementationVersion(2) + NumberOfStreams(4) + StreamDirectoryRva(4)
    sig = d[:4]
    if sig != b"MDMP":
        # try offset
        pass
    # Actually MDMP: Magic(4) + Version(4) + NumberOfStreams(4) + StreamDirectoryRva(4) + Checksum(4) + ...
    # Let's use a simpler parse
    num_streams = struct.unpack_from("<I", d, 8)[0]
    dir_rva = struct.unpack_from("<I", d, 12)[0]

    streams = {}
    for i in range(num_streams):
        st, sz, rva = struct.unpack_from("<III", d, dir_rva + i*12)
        streams[st] = (sz, rva)

    if 9 not in streams:
        print(f"  no Memory64List"); return

    sz, rva = streams[9]
    num_mem = struct.unpack_from("<Q", d, rva)[0]
    base_rva = struct.unpack_from("<Q", d, rva+8)[0]  # base RVA of first region

    p = rva + 16
    fofs = base_rva

    results = {name: [] for name,va,vsz in targets}
    for i in range(num_mem):
        va, vsz = struct.unpack_from("<QQ", d, p); p += 16
        va_start = va; va_end = va + vsz
        for name, tva, tvsz in targets:
            t_start = tva; t_end = tva + tvsz
            if va_start < t_end and va_end > t_start:
                ov_start = max(va_start, t_start)
                ov_end = min(va_end, t_end)
                fo = fofs + (ov_start - va_start)
                results[name].append((ov_start, ov_end - ov_start, fo))
        fofs += vsz

    for name, va, vsz in targets:
        segs = results[name]
        if segs:
            total = sum(s[1] for s in segs)
            print(f"  {name}: {len(segs)}セグメント 合計{total//1024}KB")
            for sva, ssz, sfo in segs:
                sample = d[sfo:sfo+16].hex(' ')
                print(f"    VA=0x{sva:08x} size=0x{ssz:x} fofs=0x{sfo:x}")
                print(f"    先頭16B: {sample}")
        else:
            print(f"  {name}: 範囲なし（ページアウト）")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGETS = [
    ("SDCprm.dll", SDCPRM_BASE, SDCPRM_SIZE),
    ("SDCore.dll", SDCORE_BASE, SDCORE_SIZE),
]

import glob
dumps = sorted(glob.glob(os.path.join(ROOT, "*.dmp")))
if not dumps:
    dumps = sorted(glob.glob(os.path.join(ROOT, "*.DMP")))

print(f"ダンプファイル: {len(dumps)}件")
for dp in dumps:
    size = os.path.getsize(dp)
    print(f"\n{os.path.basename(dp)} ({size//1024//1024}MB):")
    scan_mdmp(dp, TARGETS)

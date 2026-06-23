"""dump_11から展開済みSDCprm.dllのメモリを再構築し、
C2 S-box・デバイス鍵候補・CPRM関数を解析する。"""
import struct, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DUMP = os.path.join(ROOT, "SD-MobileImpact.exe_11-コンテンツ再生開始直後.dmp")
OUT  = os.path.join(ROOT, "scripts", "sdcprm_unpacked.bin")

# dump_11 のSDCprm.dll Memory64List セグメント (find_sdcprm.pyの出力から)
SDCPRM_SEGS = [
    (0x05020000, 0x1000,  0x4066b42),   # MZ header
    (0x05021000, 0x3b000, 0x4067b42),   # code .text? または packed body
    (0x0505c000, 0x62000, 0x40a2b42),   # large body (packed?)
    (0x050be000, 0x2000,  0x4104b42),   # small
    (0x050c0000, 0x46000, 0x4106b42),   # zero-like
    (0x05106000, 0x1000,  0x414cb42),   # IAT?
    (0x05107000, 0x4000,  0x414db42),   # zero
    (0x0510b000, 0x5000,  0x4151b42),   # strings: "SDAp f\SDAudio..."
    (0x05110000, 0x22000, 0x4156b42),   # CODE (starts 78 04 00 74...)
    (0x05132000, 0x2000,  0x4178b42),   # small
    (0x05134000, 0x22000, 0x417ab42),   # CODE2 (ff ff 50 c6...)
    (0x05156000, 0x1000,  0x419cb42),   # reloc?
    (0x05157000, 0x1000,  0x419db42),   # 00 00 00 24...
    (0x05158000, 0x1000,  0x419eb42),   # zero
    (0x05159000, 0x3000,  0x419fb42),   # small tail
]
SDCPRM_BASE = 0x05020000
SDCPRM_END  = max(va+sz for va,sz,_ in SDCPRM_SEGS)
IMG_SIZE = SDCPRM_END - SDCPRM_BASE

d = open(DUMP, "rb").read()
img = bytearray(IMG_SIZE)
for va, sz, fofs in SDCPRM_SEGS:
    rva = va - SDCPRM_BASE
    chunk = d[fofs:fofs+sz]
    img[rva:rva+len(chunk)] = chunk

print(f"Image: 0x{SDCPRM_BASE:x}-0x{SDCPRM_END:x}  {IMG_SIZE//1024}KB")
print(f"MZヘッダ: {img[0:4].hex(' ')}")

# C2 S-box 検索 (既知: f7 3a cd 29 fc 11 17 fe 39 36 86 48 f3 e2 af aa)
SBOX_HEAD = bytes.fromhex("f73acd29fc1117fe393686 48f3e2afaa".replace(' ',''))
print(f"\n=== C2 S-box 検索 ===")
hits = []
for i in range(len(img)-15):
    if img[i:i+16] == SBOX_HEAD:
        rva = i; va = SDCPRM_BASE + i
        hits.append((va, rva))
        print(f"  S-box @ VA=0x{va:08x}  RVA=0x{rva:05x}")
        print(f"  周辺 [-8..+16]: {img[i-8:i+24].hex(' ')}")

if not hits:
    print("  → S-boxなし: SDCprm.dllはC2を内包していない可能性")
else:
    print(f"  → S-box {len(hits)}個発見: SDCprm.dllはC2を内包")

# 0x22000 コードセグメント内を解析
CODE_RVA = 0x05110000 - SDCPRM_BASE
CODE_END  = CODE_RVA + 0x22000
code = bytes(img[CODE_RVA:CODE_END])
print(f"\n=== コードセグメント @ VA=0x05110000 (0x22000 bytes) ===")
print(f"  先頭32B: {code[:32].hex(' ')}")

# call命令 (0xe8) のターゲット統計
import collections
call_targets = collections.Counter()
for i in range(len(code)-4):
    if code[i] == 0xe8:
        rel = struct.unpack_from("<i", code, i+1)[0]
        tgt = (CODE_RVA + SDCPRM_BASE) + i + 5 + rel
        call_targets[tgt] += 1

print(f"  CALL先 上位10:")
for tgt,cnt in call_targets.most_common(10):
    print(f"    VA=0x{tgt:08x} {cnt}回")

# 第2コードセグメント
CODE2_RVA = 0x05134000 - SDCPRM_BASE
CODE2_END  = CODE2_RVA + 0x22000
code2 = bytes(img[CODE2_RVA:CODE2_END])
print(f"\n=== コード2セグメント @ VA=0x05134000 ===")
print(f"  先頭32B: {code2[:32].hex(' ')}")

call_targets2 = collections.Counter()
for i in range(len(code2)-4):
    if code2[i] == 0xe8:
        rel = struct.unpack_from("<i", code2, i+1)[0]
        tgt = (CODE2_RVA + SDCPRM_BASE) + i + 5 + rel
        call_targets2[tgt] += 1
print(f"  CALL先 上位10:")
for tgt,cnt in call_targets2.most_common(10):
    print(f"    VA=0x{tgt:08x} {cnt}回")

# 展開済みSDCprm.dllイメージを保存
open(OUT, "wb").write(img)
print(f"\n保存: {OUT} ({IMG_SIZE//1024}KB)")

# 7バイト単位でユニークなバイト列を探す (デバイス鍵候補)
# ヒューリスティック: 全バイトが非ゼロ・高エントロピー
print("\n=== 7バイトデバイス鍵候補 (非ゼロ・全バイト異なる・高エントロピー域) ===")
cands = []
for seg_va, seg_sz, seg_fofs in SDCPRM_SEGS:
    rva = seg_va - SDCPRM_BASE
    chunk = bytes(img[rva:rva+seg_sz])
    for i in range(seg_sz-6):
        b = chunk[i:i+7]
        if 0 in b: continue
        if len(set(b)) < 5: continue  # 少なくとも5種類の値
        # 連続する値（01 02 03...）は除外
        diffs = [abs(b[j+1]-b[j]) for j in range(6)]
        if max(diffs) < 3: continue
        cands.append((seg_va+i, b.hex()))
if len(cands) < 200:
    for va, h in cands[:50]:
        print(f"  VA=0x{va:08x}: {h}")
else:
    print(f"  候補多すぎ({len(cands)})、絞り込み要")

# strings: SDApf等
print("\n=== 文字列セクション @ VA=0x0510b000 ===")
STR_RVA = 0x0510b000 - SDCPRM_BASE
strs = img[STR_RVA:STR_RVA+0x5000]
print(f"  先頭256B as ASCII: {bytes(strs[:256])}")

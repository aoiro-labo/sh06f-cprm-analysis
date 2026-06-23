"""sdcprm_unpacked.bin からC2関数・デバイス鍵・エクスポートテーブルを解析する。"""
import struct, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN  = os.path.join(ROOT, "scripts", "sdcprm_unpacked.bin")
BASE = 0x05020000

img = bytearray(open(BIN,"rb").read())
SBOX_KNOWN = bytes.fromhex("f73acd29fc1117fe393686 48f3e2afaa".replace(' ',''))

def va2off(va): return va - BASE
def off2va(off): return off + BASE

# ===== PEヘッダからエクスポートテーブルを解析 =====
print("=== PE Export Table ===")
try:
    e_lfanew = struct.unpack_from("<I", img, 0x3c)[0]
    pe_sig = img[e_lfanew:e_lfanew+4]
    if pe_sig == b"PE\x00\x00":
        opt_off = e_lfanew + 24
        magic = struct.unpack_from("<H", img, opt_off)[0]
        if magic == 0x10b:  # PE32
            exp_rva, exp_sz = struct.unpack_from("<II", img, opt_off + 96)[0:2]
            print(f"  Export RVA=0x{exp_rva:x} size=0x{exp_sz:x}")
            if exp_rva and exp_sz:
                e = opt_off + 96; edoff = exp_rva
                # Export Directory
                chars, ts, major, minor = struct.unpack_from("<IIHH", img, edoff)
                name_rva, base, num_funcs, num_names = struct.unpack_from("<IIII", img, edoff+12)
                funcs_rva, names_rva, ords_rva = struct.unpack_from("<III", img, edoff+28)
                dll_name = img[name_rva:name_rva+64].split(b'\x00')[0].decode('ascii','replace')
                print(f"  DLL: {dll_name}  funcs={num_funcs} names={num_names}")
                for i in range(min(num_names, 50)):
                    name_off = struct.unpack_from("<I", img, names_rva + i*4)[0]
                    ord_idx  = struct.unpack_from("<H", img, ords_rva + i*2)[0]
                    func_rva = struct.unpack_from("<I", img, funcs_rva + ord_idx*4)[0]
                    fname = img[name_off:name_off+80].split(b'\x00')[0].decode('ascii','replace')
                    print(f"  [{i:2d}] VA=0x{BASE+func_rva:08x} RVA=0x{func_rva:x}  {fname}")
        else:
            print(f"  PE64 or invalid magic: 0x{magic:x}")
    else:
        print(f"  PE sig: {pe_sig.hex()}")
except Exception as ex:
    print(f"  Parse error: {ex}")

# ===== S-box周辺のコンテキスト =====
SBOX_HITS = [0x050c2835, 0x0511272d, 0x0513619d]
print("\n=== S-box周辺関数 (各256B前 / 512B後) ===")
for sva in SBOX_HITS:
    off = va2off(sva)
    # 関数先頭を探す: push ebp; mov ebp,esp = 55 8b ec
    fn_start = off - 8  # -8は最低限 (push ebx/esi/edi = 53 56 57 の位置)
    # さらに前に push ebp; mov ebp, esp があるか探す
    for back in range(1, 512):
        if img[off-back:off-back+3] == b'\x55\x8b\xec':
            fn_start = off - back
            break
    fn_va = off2va(fn_start)

    # 256B前から S-box の256B後まで
    ctx_start = max(0, off - 256)
    ctx_end   = min(len(img), off + 512)
    ctx = bytes(img[ctx_start:ctx_end])

    print(f"\n--- S-box @ VA=0x{sva:08x}  推定関数先頭=0x{fn_va:08x} ---")
    # 関数先頭から32B
    fs_off = fn_start - (off - 256)  # offset within ctx
    if 0 <= fs_off < len(ctx):
        print(f"  関数先頭(offset={fn_start-ctx_start:#x}): {ctx[fs_off:fs_off+32].hex(' ')}")

    # S-boxの前16B: 関数setup
    sb_in_ctx = off - ctx_start
    print(f"  S-box前16B: {ctx[sb_in_ctx-16:sb_in_ctx].hex(' ')}")
    # S-box後256B: call pop後の処理
    print(f"  S-box後256B:")
    for row in range(16):
        base_in = sb_in_ctx + 256 + row*16
        if base_in + 16 > len(ctx): break
        va = sva + 256 + row*16
        print(f"    {va:08x}: {ctx[base_in:base_in+16].hex(' ')}")

# ===== CPRM文字列・定数 =====
print("\n=== SDCprm.dll内文字列 ===")
strings = []
i = 0
while i < len(img) - 3:
    # ASCII文字列を探す (8文字以上)
    j = i
    while j < len(img) and 0x20 <= img[j] <= 0x7e:
        j += 1
    if j - i >= 8:
        s = bytes(img[i:j]).decode('ascii','replace')
        strings.append((off2va(i), s))
    i = max(j+1, i+1)

for va, s in strings[:60]:
    print(f"  0x{va:08x}: {s}")

# ===== デバイス鍵候補 絞り込み (コード外領域のみ) =====
print("\n=== デバイス鍵候補 (初期化済みデータ領域, 7byte, 高エントロピー) ===")
# コード2セグメント (0x05134000-0x05156000) の先頭部分はデータ的バイト
# そこから7バイトグループを探す
TARGET_RVA = 0x05134000 - BASE
TARGET_SZ  = 0x22000
blk = bytes(img[TARGET_RVA:TARGET_RVA+TARGET_SZ])

# 各7バイトのエントロピー推定: 全バイト非ゼロ・重複なし
cands = []
for i in range(0, TARGET_SZ - 6, 1):
    b = blk[i:i+7]
    if 0 in b: continue
    if len(set(b)) < 7: continue   # 7バイト全部異なる
    cands.append((TARGET_RVA + BASE + i, b.hex()))

print(f"  完全ユニーク7byte候補: {len(cands)}個")
for va, h in cands[:30]:
    print(f"  0x{va:08x}: {h}")

# 特定パターン: 0x22000 code1セグメント内の定数ロード
# mov reg, imm7  のようなパターン
print("\n=== コード1(0x5110000)内の7バイト定数プッシュ (push imm + push imm) ===")
CODE1_RVA = 0x05110000 - BASE
CODE1_SZ  = 0x22000
c1 = bytes(img[CODE1_RVA:CODE1_RVA+CODE1_SZ])
# 7バイト定数は「mov [ptr], 4byte; mov [ptr+4], 2byte」みたいに格納されることが多い
# "mov dword ptr [reg+n], imm32"  (c7 4x nn imm32) パターンを探す
for i in range(CODE1_SZ - 10):
    if c1[i] == 0xc7 and (c1[i+1] & 0xf8) == 0x40:  # c7 4x = MOV [reg+disp8], imm32
        imm32 = struct.unpack_from("<I", c1, i+3)[0]
        if imm32 != 0 and imm32 != 0xffffffff:
            print(f"  VA=0x{0x05110000+i:08x}: c7 {c1[i+1]:02x} {c1[i+2]:02x} imm={imm32:#010x}  {c1[i:i+7].hex(' ')}")

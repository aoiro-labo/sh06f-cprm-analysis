"""86000001を引き起こす関数を特定し、バイパス可能な jnz を探す"""
import struct, os

EXE = r"C:\Program Files (x86)\Panasonic\SD-MobileImpact\SD-MobileImpact.exe"
b = open(EXE,"rb").read()
IMAGEBASE = 0x400000

def va2off(va): return va - IMAGEBASE
def off2va(off): return off + IMAGEBASE
def rel32(data, off): return struct.unpack_from("<i", data, off)[0]

# 各86000001手前のCALLターゲットを逆算
# 1) VA=0x004043d8: e8 83 05 00 00 → call
call1_off = va2off(0x004043d8)
call1_target = off2va(call1_off + 5 + struct.unpack_from("<i",b,call1_off+1)[0])
print(f"Check1 calls: VA=0x{call1_target:08x}  (jnz patch → 0x{va2off(0x004043df):05x})")

# call1_targetの最初の200バイト
fn1_off = va2off(call1_target)
print(f"  Function body (first 80B):")
for row in range(0, 80, 16):
    chunk = b[fn1_off+row:fn1_off+row+16]
    h = ' '.join(f"{x:02x}" for x in chunk)
    print(f"    {call1_target+row:08x}: {h}")

# 2) VA=0x004044bf: e8 d6 3a 00 00 → call (for 2nd 86000001)
call2_off = va2off(0x004044bf)
call2_target = off2va(call2_off + 5 + struct.unpack_from("<i",b,call2_off+1)[0])
print(f"\nCheck2 calls: VA=0x{call2_target:08x}")
fn2_off = va2off(call2_target)
print(f"  Function body (first 80B):")
for row in range(0, 80, 16):
    chunk = b[fn2_off+row:fn2_off+row+16]
    h = ' '.join(f"{x:02x}" for x in chunk)
    print(f"    {call2_target+row:08x}: {h}")

# CALL [indirect] のパターン探す (ff 15 xx xx xx xx) → IAT経由の外部DLL呼び出し
# fn1の範囲内で
print(f"\n=== fn1 ({call1_target:08x}) 内のCOMっぽい呼び出し ===")
fn1_data = b[fn1_off:fn1_off+0x200]
i = 0
while i < len(fn1_data) - 6:
    if fn1_data[i] == 0xff and fn1_data[i+1] == 0x15:
        iat_va = struct.unpack_from("<I", fn1_data, i+2)[0]
        iat_off = va2off(iat_va)
        if 0 <= iat_off < len(b)-4:
            fn_ptr = struct.unpack_from("<I", b, iat_off)[0]
            print(f"  VA=0x{call1_target+i:08x}: call [{iat_va:08x}] → fn={fn_ptr:08x}")
    if fn1_data[i] == 0xe8:  # direct call
        tgt = call1_target + i + 5 + struct.unpack_from("<i", fn1_data, i+1)[0]
        print(f"  VA=0x{call1_target+i:08x}: call 0x{tgt:08x}")
    i += 1

# 文字列セクション内の「86000001」前後のstrings
print(f"\n=== 0x40xx startup rangeの文字列ポインタ解析 ===")
# push 0x574fa8 → その付近のstring table
ptr_data = 0x574fa8
ptr_off = va2off(ptr_data)
print(f"push先 0x574fa8 付近のデータ (offset=0x{ptr_off:x}):")
chunk = b[ptr_off:ptr_off+128]
print(' '.join(f"{x:02x}" for x in chunk))

# IATから外部DLL名を辿る (インポートテーブル)
print("\n=== インポートテーブル ===")
e_lfanew = struct.unpack_from("<I", b, 0x3c)[0]
opt = e_lfanew + 24
imp_rva = struct.unpack_from("<I", b, opt + 104)[0]
imp_sz  = struct.unpack_from("<I", b, opt + 108)[0]
print(f"Import Dir RVA=0x{imp_rva:x}")
imp_off = imp_rva  # file offset ≈ RVA when no alignment gap (exe, sections start at 0x1000)
# IMAGE_IMPORT_DESCRIPTOR = 20 bytes
p = imp_off
dlls = []
while True:
    orig_first_thunk, ts, forwarder, name_rva, first_thunk = struct.unpack_from("<IIIII", b, p)
    if name_rva == 0: break
    dll_name = b[name_rva:name_rva+64].split(b'\x00')[0].decode('ascii','replace')
    iat_va_base = IMAGEBASE + first_thunk
    # collect IAT entries
    funcs = []
    q = first_thunk
    while True:
        thunk = struct.unpack_from("<I", b, q)[0]
        if thunk == 0: break
        if thunk & 0x80000000:
            funcs.append(f"ord#{thunk & 0x7fffffff}")
        else:
            name_off2 = thunk + 2  # skip hint
            fn = b[name_off2:name_off2+64].split(b'\x00')[0].decode('ascii','replace')
            funcs.append(fn)
        q += 4
    print(f"  [{dll_name}] IAT_base=0x{iat_va_base:08x}  funcs: {funcs[:5]}{'...' if len(funcs)>5 else ''}")
    dlls.append((dll_name, iat_va_base, funcs))
    p += 20

"""86000001を引き起こす call 0x00404960 → 0x00519440 を追跡する"""
import struct, os

EXE = r"C:\Program Files (x86)\Panasonic\SD-MobileImpact\SD-MobileImpact.exe"
b = open(EXE,"rb").read()
IMAGEBASE = 0x400000
def va2off(va): return va - IMAGEBASE
def off2va(off): return off + IMAGEBASE

def dump16(va, n=128):
    off = va2off(va)
    for row in range(0, n, 16):
        c = b[off+row:off+row+16]
        print(f"  {va+row:08x}: {' '.join(f'{x:02x}' for x in c)}")

# 0x00403ea0: 86000001の直前に呼ばれ、ECX(this)を生成する関数
print("=== fn 0x00403ea0 (object factory) first 256B ===")
dump16(0x00403ea0, 256)

# 0x00519440: 0x00404960内の最初のcall
print("\n=== fn 0x00519440 (called from 0x00404960) first 128B ===")
dump16(0x00519440, 128)

# 0x004049b1: call [IAT 0x00554080] (8000036c - MFC ord)
# 0x00554080 の内容を確認
iat_off = va2off(0x00554080)
fn_ptr = struct.unpack_from("<I", b, iat_off)[0]
print(f"\n=== IAT[0x554080] = 0x{fn_ptr:08x} ===")
# ordinal解析: bit31 set = ordinal
if fn_ptr & 0x80000000:
    ord_num = fn_ptr & 0x7fffffff
    print(f"  Import by ordinal: {ord_num} (0x{ord_num:x})")
else:
    # RVA of IMAGE_IMPORT_BY_NAME
    hint = struct.unpack_from("<H", b, fn_ptr)[0]
    name = b[fn_ptr+2:fn_ptr+2+64].split(b'\x00')[0].decode('ascii','replace')
    print(f"  Import by name: hint={hint} '{name}'")

# 0x00404960の全体を解析して間接呼び出しパターンを探す
print("\n=== 0x00404960内のall CALLs (直接/間接) ===")
fn_off = va2off(0x00404960)
fn_data = b[fn_off:fn_off+0x300]
i = 0
while i < len(fn_data)-5:
    op = fn_data[i]
    if op == 0xe8:  # direct call rel32
        rel = struct.unpack_from("<i", fn_data, i+1)[0]
        tgt = 0x00404960 + i + 5 + rel
        print(f"  VA=0x{0x00404960+i:08x}: call 0x{tgt:08x}")
    elif op == 0xff and fn_data[i+1] == 0x15:  # indirect call [abs]
        iat_va = struct.unpack_from("<I", fn_data, i+2)[0]
        iat_off2 = va2off(iat_va)
        if 0 <= iat_off2 < len(b)-3:
            ptr = struct.unpack_from("<I", b, iat_off2)[0]
            if ptr & 0x80000000:
                print(f"  VA=0x{0x00404960+i:08x}: call [0x{iat_va:08x}] = ord#{ptr & 0x7fffffff}")
            else:
                if ptr > 0x400000:
                    hint2 = struct.unpack_from("<H", b, ptr)[0] if va2off(ptr)+2 < len(b) else 0
                    nm = b[ptr+2:ptr+2+40].split(b'\x00')[0].decode('ascii','replace')
                    print(f"  VA=0x{0x00404960+i:08x}: call [{iat_va:08x}] → '{nm}'")
                else:
                    print(f"  VA=0x{0x00404960+i:08x}: call [0x{iat_va:08x}] = 0x{ptr:08x}")
    elif op == 0xff and fn_data[i+1] == 0x10:  # call [eax]
        print(f"  VA=0x{0x00404960+i:08x}: call [eax] (vtable dispatch?)")
    elif op == 0xff and (fn_data[i+1] & 0xf8) == 0xd0:  # call reg
        print(f"  VA=0x{0x00404960+i:08x}: call reg")
    elif op == 0xc3 or op == 0xc2:  # ret
        print(f"  VA=0x{0x00404960+i:08x}: ret")
        break
    i += 1

# InportTable から IAT 0x554080の所属DLLを特定
print("\n=== IAT 0x554080 の所属DLL確認 ===")
e_lfanew = struct.unpack_from("<I", b, 0x3c)[0]
opt = e_lfanew + 24
imp_rva = struct.unpack_from("<I", b, opt + 104)[0]
p = imp_rva
while True:
    orig, ts, fwd, name_rva, first = struct.unpack_from("<IIIII", b, p)
    if name_rva == 0: break
    dll_name = b[name_rva:name_rva+64].split(b'\x00')[0].decode('ascii','replace')
    # このDLLのIATがどこからどこか
    q = first
    count = 0
    while True:
        th = struct.unpack_from("<I", b, q)[0]
        if th == 0: break
        count += 1
        q += 4
    iat_end = first + count*4
    if first <= va2off(0x00554080) < iat_end or first <= va2off(0x00554084) < iat_end:
        print(f"  {dll_name}: IAT=0x{IMAGEBASE+first:08x}..0x{IMAGEBASE+iat_end:08x} ({count} funcs)")
        # この範囲のIATを全部表示
        q2 = first
        idx = 0
        while True:
            th = struct.unpack_from("<I", b, q2)[0]
            if th == 0: break
            ia_va = IMAGEBASE + q2
            if th & 0x80000000:
                fn_info = f"ord#{th & 0x7fffffff}"
            else:
                if va2off(th)+2 < len(b):
                    hint3 = struct.unpack_from("<H", b, va2off(th))[0]
                    nm3 = b[va2off(th)+2:va2off(th)+2+40].split(b'\x00')[0].decode('ascii','replace')
                    fn_info = f"'{nm3}'(hint={hint3})"
                else:
                    fn_info = f"0x{th:08x}"
            marker = " <===TARGET===" if ia_va in (0x00554080, 0x00554084) else ""
            print(f"    [{idx:3d}] IAT=0x{ia_va:08x} → {fn_info}{marker}")
            idx += 1; q2 += 4
    p += 20

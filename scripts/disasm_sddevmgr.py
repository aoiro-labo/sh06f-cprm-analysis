"""sddevmgr.dll の DDSysInit/DDInit/DDGetMID をキャプストンで逆アセンブル。
\SD*.dll の検索パス構成を静的に特定する。"""
import struct, sys, re

DLL_PATH = r"C:\Windows\SysWOW64\sddevmgr.dll"
b = open(DLL_PATH, "rb").read()
print(f"sddevmgr.dll: {len(b)} bytes", flush=True)

e_lfanew = struct.unpack_from("<I", b, 0x3c)[0]
ns = struct.unpack_from("<H", b, e_lfanew + 6)[0]
opt_sz = struct.unpack_from("<H", b, e_lfanew + 20)[0]
sh_off = e_lfanew + 24 + opt_sz
IMAGEBASE = struct.unpack_from("<I", b, e_lfanew + 24 + 28)[0]
ep_rva = struct.unpack_from("<I", b, e_lfanew + 24 + 16)[0]
print(f"ImageBase: 0x{IMAGEBASE:08X}  EntryPoint VA: 0x{IMAGEBASE+ep_rva:08X}")

def rva2off(rva):
    for i in range(ns):
        s = sh_off + i * 40
        va = struct.unpack_from("<I", b, s + 12)[0]
        vsz = struct.unpack_from("<I", b, s + 16)[0]
        roff = struct.unpack_from("<I", b, s + 20)[0]
        if va <= rva < va + max(vsz, roff):
            return roff + (rva - va)
    return None

opt_off = e_lfanew + 24

# エクスポートテーブル → 各エクスポート関数のファイルオフセット取得
exp_rva = struct.unpack_from("<I", b, opt_off + 96)[0]
ep_ptr = rva2off(exp_rva)
export_funcs = {}  # name → (rva, file_off, va)
if ep_ptr:
    base_ord = struct.unpack_from("<I", b, ep_ptr + 16)[0]
    nfuncs = struct.unpack_from("<I", b, ep_ptr + 20)[0]
    nnames = struct.unpack_from("<I", b, ep_ptr + 24)[0]
    funcs_rva = struct.unpack_from("<I", b, ep_ptr + 28)[0]
    names_rva = struct.unpack_from("<I", b, ep_ptr + 32)[0]
    ords_rva  = struct.unpack_from("<I", b, ep_ptr + 36)[0]
    fp = rva2off(funcs_rva)
    np = rva2off(names_rva)
    op = rva2off(ords_rva)
    for i in range(nnames):
        nr = struct.unpack_from("<I", b, np + i*4)[0]
        fo = rva2off(nr)
        name = b[fo:fo+64].split(b'\x00')[0].decode('ascii','replace') if fo else f"ord_{i}"
        ord_idx = struct.unpack_from("<H", b, op + i*2)[0]
        func_rva = struct.unpack_from("<I", b, fp + ord_idx*4)[0]
        func_off = rva2off(func_rva)
        if func_off:
            export_funcs[name] = (func_rva, func_off, IMAGEBASE + func_rva)
    print(f"\nエクスポート数: {nnames}")

# capstone で逆アセンブル
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    print("capstone なし: バイト列のみ表示")

# IAT から GetSystemDirectoryA/GetProcAddress/LoadLibraryA 等のVAを取得
imp_rva = struct.unpack_from("<I", b, opt_off + 104)[0]
p = rva2off(imp_rva)
iat_map = {}  # func_name → IAT_VA
while p and p + 20 <= len(b):
    orig, ts, fwd, name_rva, first_rva = struct.unpack_from("<IIIII", b, p)
    if name_rva == 0: break
    no = rva2off(name_rva)
    dll_name = b[no:no+64].split(b'\x00')[0].decode('ascii','replace') if no else "?"
    q = rva2off(orig) if orig else None
    ft = rva2off(first_rva) if first_rva else None
    if q and ft:
        idx = 0
        while True:
            th = struct.unpack_from("<I", b, q + idx*4)[0]
            if th == 0: break
            if not (th & 0x80000000):
                fo2 = rva2off(th)
                if fo2:
                    fname = b[fo2+2:fo2+2+64].split(b'\x00')[0].decode('ascii','replace')
                    iat_va = IMAGEBASE + first_rva + idx*4
                    iat_map[fname] = iat_va
            idx += 1
    p += 20

print("\n=== 重要IAT ===")
important = ['GetSystemDirectoryA','GetCurrentDirectoryA','LoadLibraryA','GetProcAddress',
             'FindFirstFileA','FindNextFileA','FindClose',
             'CreateFileMappingA','OpenFileMappingA','MapViewOfFile',
             'CreateEventA','OpenEventA','SetEvent','WaitForSingleObject',
             'CreateMutexA','OpenMutexA']
for f in important:
    if f in iat_map:
        print(f"  {f}: IAT_VA=0x{iat_map[f]:08X}")

def disasm_func(name, max_insns=120):
    if name not in export_funcs:
        print(f"\n  {name}: not found in exports")
        return
    func_rva, func_off, func_va = export_funcs[name]
    print(f"\n{'='*60}")
    print(f"=== {name}  VA=0x{func_va:08X}  file=0x{func_off:05X} ===")
    code = b[func_off:func_off+0x400]
    if not HAS_CAPSTONE:
        # バイト列だけ表示
        for i in range(0, min(64, len(code)), 16):
            row = code[i:i+16]
            print(f"  0x{func_va+i:08X}: {' '.join(f'{x:02x}' for x in row)}")
        return
    cnt = 0
    for insn in md.disasm(code, func_va):
        # IAT call を解釈
        if insn.mnemonic == 'call' and insn.op_str.startswith('dword ptr [0x'):
            iat_addr = int(insn.op_str[len('dword ptr [0x'):-1], 16)
            for fname, va in iat_map.items():
                if va == iat_addr:
                    print(f"  0x{insn.address:08X}: {insn.mnemonic} [{fname}]  ; {insn.bytes.hex()}")
                    break
            else:
                print(f"  0x{insn.address:08X}: {insn.mnemonic} {insn.op_str}  ; {insn.bytes.hex()}")
        else:
            print(f"  0x{insn.address:08X}: {insn.mnemonic} {insn.op_str}  ; {insn.bytes.hex()}")
        cnt += 1
        if cnt >= max_insns or insn.mnemonic == 'ret':
            break

# DDSysInit, DDInit, DDGetMID, DDReadMKB を逆アセンブル
for fn in ['DDSysInit', 'DDSysFini', 'DDInit', 'DDFini', 'DDGetMID', 'DDReadMKB', 'DDChkSDCard']:
    disasm_func(fn, max_insns=80)

"""SD-MobileImpact.exe内のエラーコード86000001/86000012生成箇所を特定する"""
import struct, os, sys

EXE = r"C:\Program Files (x86)\Panasonic\SD-MobileImpact\SD-MobileImpact.exe"
b = open(EXE,"rb").read()
print(f"EXE size: {len(b)} bytes")

# e_lfanew → ImageBase
e_lfanew = struct.unpack_from("<I", b, 0x3c)[0]
opt = e_lfanew + 24
imagebase = struct.unpack_from("<I", b, opt + 28)[0]
print(f"ImageBase: 0x{imagebase:08x}")

def find_dword(data, val):
    hits = []
    v = struct.pack("<I", val)
    i = 0
    while True:
        i = data.find(v, i)
        if i < 0: break
        hits.append(i)
        i += 1
    return hits

# 86000001 = 0x86000001
for code in (0x86000001, 0x86000012, 0x86000002, 0x86000003, 0x86000004, 0x86000010, 0x86000011):
    hits = find_dword(b, code)
    if hits:
        print(f"\n=== 0x{code:08x} ({len(hits)}箇所) ===")
        for off in hits:
            va = imagebase + off
            ctx = b[max(0,off-12):off+20]
            hex_ctx = ' '.join(f"{x:02x}" for x in ctx)
            # 前のバイトで命令を判定
            instr = "?"
            if off >= 1:
                prev = b[off-1]
                if prev == 0x68: instr = "push"
                elif prev == 0xB8: instr = "mov eax,"
                elif prev == 0x3D: instr = "cmp eax,"
                elif prev == 0x05: instr = "add eax,"
                elif prev == 0xC5: instr = "lds ?"
            if off >= 2:
                prev2 = b[off-2:off]
                if prev2[0] == 0xC7: instr = "mov [?],"
            print(f"  off=0x{off:06x}  VA=0x{va:08x}  [{instr}]  ctx: {hex_ctx}")

# 文字列「起動に失敗」をShift-JISで探す
import codecs
needle = "起動に失敗".encode("shift_jis")
print(f"\n=== '起動に失敗' (Shift-JIS) ===")
hits = find_dword(b, struct.unpack_from("<I",needle)[0]) if len(needle) >= 4 else []
i = 0
while True:
    i = b.find(needle, i)
    if i < 0: break
    ctx = b[i:i+60]
    try: s = ctx.decode("shift_jis").replace("\0",".")
    except: s = repr(ctx)
    print(f"  off=0x{i:06x}: {s[:50]}")
    i += 1

# 文字列「アプリケーション」検索
needle2 = "アプリケーション".encode("shift_jis")
print(f"\n=== 'アプリケーション' (Shift-JIS) ===")
i = 0
while True:
    i = b.find(needle2, i)
    if i < 0: break
    ctx = b[i:i+80]
    try: s = ctx.decode("shift_jis").replace("\0",".")
    except: s = repr(ctx[:40])
    print(f"  off=0x{i:06x}: {s[:60]}")
    i += 1

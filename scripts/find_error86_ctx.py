"""86000001生成箇所の前後200バイトをダンプし、分岐条件を特定する"""
import struct, os

EXE = r"C:\Program Files (x86)\Panasonic\SD-MobileImpact\SD-MobileImpact.exe"
b = open(EXE,"rb").read()

IMAGEBASE = 0x400000
offs_86000001 = [0x0043ed, 0x0044eb, 0x00455c, 0x00726f]

def dump_hex(data, base_va, start_off, end_off, highlight_off=None):
    for row_off in range(start_off, end_off, 16):
        row = data[row_off:row_off+16]
        hex_part = ' '.join(f"{x:02x}" for x in row)
        marker = " <--" if highlight_off and abs(row_off - highlight_off) < 16 else ""
        print(f"  {base_va+row_off:08x}: {hex_part:<48}{marker}")

print("="*70)
print("86000001 生成箇所の前後 (各200B)")
print("="*70)
for off in offs_86000001:
    va = IMAGEBASE + off
    start = max(0, off - 120)
    end = min(len(b), off + 80)
    print(f"\n--- offset=0x{off:05x}  VA=0x{va:08x} ---")
    dump_hex(b, IMAGEBASE, start, end, off)

# 0x574FA8に何があるか (string/param)
str_off = 0x574FA8 - IMAGEBASE
print(f"\n=== 0x574fa8 (push先) offset=0x{str_off:x} ===")
if 0 <= str_off < len(b):
    chunk = b[str_off:str_off+64]
    # UTF-16LE文字列試行
    try:
        s = chunk.decode('utf-16-le').split('\x00')[0]
        if s: print(f"  UTF-16LE: '{s}'")
    except: pass
    # Shift-JIS試行
    try:
        s = chunk.split(b'\x00')[0].decode('shift_jis')
        if s: print(f"  Shift-JIS: '{s}'")
    except: pass
    print(f"  Hex: {' '.join(f'{x:02x}' for x in chunk[:32])}")
else:
    print("  範囲外")

# startup関数の先頭を探す
# VA=0x4043ed 付近の関数先頭 (push ebp; mov ebp,esp)
print("\n=== 関数先頭候補 (55 8b ec) ===")
for off in offs_86000001[:2]:
    for back in range(1, 300):
        if b[off-back:off-back+3] == b'\x55\x8b\xec':
            fn_va = IMAGEBASE + off - back
            print(f"  0x{off:05x} → 関数先頭 VA=0x{fn_va:08x} (back={back})")
            break

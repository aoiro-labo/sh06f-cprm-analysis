"""86000001チェック直前の条件分岐アドレスを表示する (x32dbg用パッチ情報)"""
import os, sys

EXE = r"C:\Program Files (x86)\Panasonic\SD-MobileImpact\SD-MobileImpact.exe"
b = open(EXE, "rb").read()
IMAGEBASE = 0x400000

# 86000001のpushが含まれる場所のファイルオフセット
error_offs = [0x0043ed, 0x0044eb, 0x00455c, 0x00726f]

print("x32dbg メモリパッチ場所 (起動後・実行前に変更する):")
print()
results = []
for err_off in error_offs:
    found = False
    for back in range(1, 100):
        off = err_off - back
        b0 = b[off]
        b1 = b[off + 1] if off + 1 < len(b) else 0
        # 短い条件分岐命令 (7x xx): jne/je/jl/jge etc.
        if 0x70 <= b0 <= 0x7f and 0x04 <= b1 <= 0x40:
            va = IMAGEBASE + off
            # 前後4バイトも表示
            ctx = ' '.join(f'{b[off+i]:02x}' for i in range(6))
            print(f"  VA=0x{va:08x}  bytes: {ctx}")
            print(f"  → byte[0]: {b0:02x} を EB に変更 (jne/jle → jmp)")
            print()
            results.append((va, off, b0, b1))
            found = True
            break
    if not found:
        print(f"  (0x{err_off:05x} 付近: 条件分岐見つからず、周辺dump:)")
        chunk = b[err_off-40:err_off+8]
        print("  " + ' '.join(f'{x:02x}' for x in chunk))
        print()

# x32dbgコマンドとして出力
print("=" * 50)
print("x32dbg コマンドバー用 (一行ずつ実行):")
for va, off, b0, b1 in results:
    print(f"  eb {va:08X} EB")

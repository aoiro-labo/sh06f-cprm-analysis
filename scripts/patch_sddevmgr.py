"""sddevmgr.dll パッチ: DDSysInit の SUB_0x10002F80 呼び出しを MOV eax,1 に置換
これで DLL 検索失敗にかかわらず DDSysInit が成功する。

パッチ箇所 (file=0x1AAC, VA=0x10001AAC):
  e8 cf 14 00 00  → CALL 0x10002F80  (5バイト)
→ b8 01 00 00 00  → MOV eax, 1       (5バイト, 同サイズ)
"""
import shutil, struct, sys, os

SRC  = r"C:\Windows\SysWOW64\sddevmgr.dll"
DST  = r"C:\Users\aoiro\Documents\ワンセグ関係（録画機器：SH-06F）\sddevmgr_patched.dll"
BAK  = SRC + ".bak"

b = bytearray(open(SRC, "rb").read())
print(f"sddevmgr.dll: {len(b)} bytes")

# ターゲットバイト列
ORIG = bytes.fromhex("e8cf140000")  # CALL 0x10002F80 at file=0x1AAC
PATCH= bytes.fromhex("b801000000")  # MOV eax, 1

off = 0x1AAC
found = b[off:off+5]
print(f"file=0x{off:04X}: found  = {found.hex()}")
print(f"                expected = {ORIG.hex()}")

if found != ORIG:
    # 全体サーチ
    pos = b.find(ORIG)
    if pos < 0:
        print("ERROR: ターゲットバイト列が見つかりません")
        sys.exit(1)
    print(f"WARNING: 期待オフセット 0x{off:04X} ではなく 0x{pos:04X} で発見")
    off = pos

# コンテキスト表示
print(f"\nパッチ前 (file=0x{off:04X}):")
for i in range(off-4, off+16):
    print(f"  file=0x{i:04X}: {b[i]:02x}")

# パッチ適用
b[off:off+5] = PATCH

print(f"\nパッチ後 (file=0x{off:04X}):")
for i in range(off-4, off+16):
    print(f"  file=0x{i:04X}: {b[i]:02x}")

# 出力先に保存 (SysWOW64 を直接書き換えるのではなく SDApf に置く)
open(DST, "wb").write(b)
print(f"\nパッチ済み DLL を {DST} に保存")
print("使用方法: SDApf フォルダに sddevmgr.dll としてコピーするか,")
print("  レジストリで SDFileSys.dll のロードパスを変更する")

# 別の方法: SDFileSys.dll と同じフォルダに置いて LoadLibraryA に引っかかるように
# SDFileSys.dll の imports のうち sddevmgr.dll の検索は LoadLibrary の相対パスによる
# 実は SDFileSys.dll は sddevmgr.dll を絶対パスでロードしている可能性もあるが,
# もし DLL サーチオーダーで SDApf フォルダが先に見つかれば差し替えられる
print("\n=== SysWOW64 への直接パッチが必要な場合のバイト列 ===")
print(f"Offset: 0x{off:04X}")
print(f"Before: {ORIG.hex()}")
print(f"After:  {PATCH.hex()}")

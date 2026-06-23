"""SD-MobileImpact.exe を直接パッチ (管理者PowerShellで実行)"""
import shutil, os

EXE    = r"C:\Program Files (x86)\Panasonic\SD-MobileImpact\SD-MobileImpact.exe"
BACKUP = EXE + ".orig"

if not os.path.exists(BACKUP):
    shutil.copy2(EXE, BACKUP)
    print(f"Backup: {BACKUP}")
else:
    print(f"Backup already exists: {BACKUP}")

b = bytearray(open(EXE, "rb").read())

patches = [
    (0x43df, 0x75, 0xEB, "Check1 (jne→jmp)"),
    (0x44dd, 0x7d, 0xEB, "Check2 (jge→jmp)"),
    (0x44f9, 0x75, 0xEB, "Check3 (jne→jmp)"),
    (0x7261, 0x7d, 0xEB, "Check4 (jge→jmp)"),
]

ok = True
for off, expected, new_byte, label in patches:
    cur = b[off]
    if cur == new_byte:
        print(f"  [SKIP] {label} @ file=0x{off:05x}: already patched")
    elif cur == expected:
        b[off] = new_byte
        print(f"  [OK]   {label} @ file=0x{off:05x}: {cur:02x} -> {new_byte:02x}")
    else:
        print(f"  [ERR]  {label} @ file=0x{off:05x}: expected {expected:02x}, got {cur:02x}")
        ok = False

if ok:
    with open(EXE, "wb") as f:
        f.write(b)
    print("\nパッチ完了。SD-MobileImpact.exe を通常起動してください。")
else:
    print("\nエラーあり。バイナリが想定と異なります。パッチを適用しませんでした。")

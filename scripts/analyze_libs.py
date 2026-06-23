"""
Android ライブラリ (.so) 解析:
- ELF ヘッダ確認
- エクスポート/インポートシンボル抽出
- 文字列抽出（crypto/key関連を優先）
"""
import os, sys, io, struct, re
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

LIB_DIR = Path(r"c:\Users\aoiro\Documents\ワンセグ関係（録画機器：SH-06F）\PRIVATE\android_libs")

INTEREST = re.compile(
    r'(key|Key|KEY|crypt|Crypt|CRYPT|aes|AES|rsa|RSA|sha|SHA|hmac|HMAC'
    r'|cprm|CPRM|fseg|FSEG|fullseg|FullSeg|FULLSEG'
    r'|pass|Pass|PASS|secret|Secret|SECRET'
    r'|individ|Individ|license|License|secure|Secure|SECURE'
    r'|title|Title|TITLE|media|Media|MEDIA'
    r'|kmu|KMU|mkb|MKB|emm|EMM|ecm|ECM'
    r'|decrypt|Decrypt|DECRYPT|encrypt|Encrypt|ENCRYPT'
    r'|token|Token|TOKEN|cert|Cert|CERT)',
    re.I
)

def extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    result = []
    cur = []
    for b in data:
        if 0x20 <= b < 0x7F:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                result.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        result.append("".join(cur))
    return result

def parse_elf_symbols(data: bytes) -> tuple[list[str], list[str]]:
    """ARM ELF32 のダイナミックシンボルテーブルから export/import を返す"""
    if data[:4] != b'\x7fELF':
        return [], []
    ei_class = data[4]  # 1=32bit, 2=64bit
    ei_data  = data[5]  # 1=LE, 2=BE
    if ei_class != 1 or ei_data != 1:
        return [], []  # ARM32 LE のみ対応

    e_phoff, = struct.unpack_from('<I', data, 0x1C)
    e_phentsize, = struct.unpack_from('<H', data, 0x2A)
    e_phnum, = struct.unpack_from('<H', data, 0x2C)

    dynsym_off = dynsym_sz = 0
    dynstr_off = dynstr_sz = 0
    PT_DYNAMIC = 2

    # program headers → DYNAMIC segment
    for i in range(e_phnum):
        ph = e_phoff + i * e_phentsize
        p_type, = struct.unpack_from('<I', data, ph)
        p_offset, = struct.unpack_from('<I', data, ph + 4)
        p_filesz, = struct.unpack_from('<I', data, ph + 16)
        if p_type == PT_DYNAMIC:
            # DT entries
            j = 0
            while p_offset + j * 8 + 8 <= len(data):
                d_tag, d_val = struct.unpack_from('<II', data, p_offset + j * 8)
                if d_tag == 0: break
                if d_tag == 6:   dynsym_off = d_val  # DT_SYMTAB
                if d_tag == 5:   dynstr_off = d_val  # DT_STRTAB
                if d_tag == 11:  sym_entsz  = d_val  # DT_SYMENT
                if d_tag == 10:  dynstr_sz  = d_val  # DT_STRSZ
                j += 1
            break

    if not dynstr_off or not dynsym_off:
        return [], []

    # section headers でシンボルテーブルサイズを取得 (program header には dynsym サイズなし)
    e_shoff, = struct.unpack_from('<I', data, 0x20)
    e_shentsize, = struct.unpack_from('<H', data, 0x2E)
    e_shnum, = struct.unpack_from('<H', data, 0x30)
    e_shstrndx, = struct.unpack_from('<H', data, 0x32)

    SHT_DYNSYM = 11
    for i in range(e_shnum):
        sh = e_shoff + i * e_shentsize
        if sh + 40 > len(data): break
        sh_type, = struct.unpack_from('<I', data, sh + 4)
        sh_offset, = struct.unpack_from('<I', data, sh + 16)
        sh_size, = struct.unpack_from('<I', data, sh + 20)
        if sh_type == SHT_DYNSYM:
            dynsym_sz = sh_size
            break

    if not dynsym_sz:
        return [], []

    strtab = data[dynstr_off:dynstr_off + dynstr_sz]
    exports, imports = [], []
    SIZEOF_SYM = 16  # Elf32_Sym
    for i in range(dynsym_sz // SIZEOF_SYM):
        sym = dynsym_off + i * SIZEOF_SYM
        if sym + SIZEOF_SYM > len(data): break
        st_name, st_value, st_size, st_info, st_other, st_shndx = \
            struct.unpack_from('<IIIBBH', data, sym)
        if st_name >= len(strtab): continue
        end = strtab.index(b'\x00', st_name)
        name = strtab[st_name:end].decode('utf-8', 'replace')
        if not name: continue
        bind = (st_info >> 4) & 0xF  # STB_GLOBAL=1, STB_WEAK=2
        if st_shndx == 0:             # SHN_UNDEF → import
            imports.append(name)
        elif bind in (1, 2):          # GLOBAL/WEAK → export
            exports.append(name)

    return exports, imports

# --- 解析対象を優先度順に処理 ---
priority = [
    "libshfullseg_keyprov.so",
    "libshfsegsave_Crypt.so",
    "libshfsegsave.so",
    "libshfsegsave_Common.so",
    "libshfsegsave_CustomSH.so",
    "libshfsegsave_SDMiddle.so",
    "libshfsegsavejni.so",
    "libshcprm.so",
    "libDxCprm.so",
    "libMmbCaKyMngMw.so",
    "libMmbPoAesMp.so",
    "libMmbPoRsaMp.so",
    "libMmbSeMngMw.so",
    "libMmbFcIndivdMw.so",
    "libMmbFcLiceMw.so",
    "libMmbStRecMw.so",
]

for name in priority:
    p = LIB_DIR / name
    if not p.exists():
        continue
    data = p.read_bytes()
    exports, imports = parse_elf_symbols(data)
    strings = extract_strings(data)
    interesting = [s for s in strings if INTEREST.search(s)]

    print(f"\n{'='*60}")
    print(f"[{name}]  ({len(data):,} B)")
    print(f"{'='*60}")

    print(f"\n  EXPORTS ({len(exports)}):")
    for s in sorted(exports):
        print(f"    {s}")

    print(f"\n  IMPORTS (crypto/key関連のみ):")
    for s in sorted(imports):
        if INTEREST.search(s):
            print(f"    {s}")

    print(f"\n  STRINGS (crypto/key関連 {len(interesting)}/{len(strings)}):")
    for s in interesting[:60]:
        print(f"    {repr(s)}")

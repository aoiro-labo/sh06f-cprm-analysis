"""
フルセグ AES-128-CBC 復号スクリプト

鍵チェーン:
  device_key (16B, /system/etc/mccd/sbdb から取得要)
      ↓ AES-128-ECB 復号
  secureInfo (64B, SHFSEG0001.DB の secureInfo 列)
      → AES_key (16B) + AES_IV (16B) + その他 (32B)
      ↓ AES-128-CBC 復号
  AV ファイル (0000100010 等)
      → 平文 M2TS

使い方:
  python decrypt_fseg.py <rec_dir> [device_key_hex]
  例: python decrypt_fseg.py PRIVATE/SHARP/FSEG/10004
      python decrypt_fseg.py PRIVATE/SHARP/FSEG/10004 00112233445566778899aabbccddeeff

device_key_hex が省略された場合はダミー鍵で試行（構造確認用）。

出力: <rec_dir>/decrypted.m2ts (成功した場合)
"""
import sys, io, os, sqlite3, struct
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
from pathlib import Path
try:
    from Crypto.Cipher import AES
    HAS_CRYPTO = True
except ImportError:
    try:
        import pyaes
        HAS_CRYPTO = False
    except ImportError:
        print("pycryptodome か pyaes を pip install してください")
        sys.exit(1)

ROOT = Path(__file__).parent.parent

def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    if HAS_CRYPTO:
        return AES.new(key, AES.MODE_ECB).decrypt(data)
    else:
        aes = pyaes.AESModeOfOperationECB(key)
        return b''.join(aes.decrypt(data[i:i+16]) for i in range(0, len(data), 16))

def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if HAS_CRYPTO:
        return AES.new(key, AES.MODE_CBC, iv=iv).decrypt(data)
    else:
        aes = pyaes.AESModeOfOperationCBC(key, iv=iv)
        out = bytearray()
        for i in range(0, len(data), 16):
            out += aes.decrypt(data[i:i+16])
        return bytes(out)


def load_db(rec_dir: Path):
    db_path = rec_dir / 'SHFSEG0001.DB'
    if not db_path.exists():
        print(f"DB not found: {db_path}")
        return None
    conn = sqlite3.connect(db_path)
    conn.text_factory = bytes
    cur = conn.cursor()
    cur.execute("SELECT contentsId, title, secureInfo, emmNum, copyCount FROM fseg")
    row = cur.fetchone()
    conn.close()
    if not row:
        print("DB: fseg テーブルが空")
        return None

    cid, title_b, secure_info, emm_num, copy_count = row
    try:
        title = title_b.decode('shift-jis', errors='replace')
    except:
        title = repr(title_b[:20])

    return {
        'id': cid,
        'title': title,
        'secureInfo': secure_info,   # 64B
        'emmNum': emm_num,           # 64B
        'copyCount': copy_count,     # 64B
    }


def find_av_file(rec_dir: Path):
    """AV ファイル (0000NNNNNN) を探す。"""
    candidates = [f for f in rec_dir.iterdir()
                  if f.name.startswith('0000') and not f.suffix]
    if not candidates:
        return None
    return sorted(candidates)[0]


def check_m2ts(data: bytes, n_pkts: int = 20) -> int:
    """先頭 n_pkts パケットで 0x47 同期バイトが何個あるか（M2TS: offset%192==4）。"""
    hits = sum(1 for i in range(4, min(len(data), n_pkts * 192), 192)
               if data[i] == 0x47)
    return hits


def decrypt_fseg(rec_dir: str, device_key_hex: str | None = None):
    rec_dir = Path(rec_dir)
    print(f"録画ディレクトリ: {rec_dir}")

    # DB 読み込み
    db = load_db(rec_dir)
    if not db:
        return False
    print(f"録画 ID: {db['id']}  タイトル: {db['title']}")
    print(f"secureInfo (64B): {db['secureInfo'].hex()[:32]}...")

    # AV ファイル確認
    av_file = find_av_file(rec_dir)
    if not av_file:
        print("AV ファイルが見つかりません")
        return False
    print(f"AV ファイル: {av_file.name} ({av_file.stat().st_size:,} B)")

    # デバイスキー
    if device_key_hex:
        device_key = bytes.fromhex(device_key_hex.strip())
        if len(device_key) != 16:
            print(f"device_key は 32 hex 文字 (16B) で指定してください")
            return False
        print(f"デバイスキー: {device_key.hex()}")
    else:
        device_key = b'\x00' * 16
        print("デバイスキー: ダミー (00...00) ← 正しい結果は得られません")

    # secureInfo を device_key で AES-128-ECB 復号
    # secureInfo は複数の AES-128-ECB ブロックからなる
    # 各ブロック独立に復号（ECB）or 先頭 16B のみが Key+IV か？
    secure_info = db['secureInfo']   # 64B = 4 AES ブロック
    dec_secure = aes_ecb_decrypt(device_key, secure_info)
    print(f"\nsecureInfo 復号結果 (64B):")
    for i in range(0, 64, 16):
        print(f"  +{i:02x}: {dec_secure[i:i+16].hex()}")

    # 復号された secureInfo の解釈:
    # 仮定: 先頭 16B = AES Content Key, 次の 16B = AES IV
    content_key = dec_secure[0:16]
    content_iv  = dec_secure[16:32]
    print(f"\nContent Key (推定): {content_key.hex()}")
    print(f"Content IV  (推定): {content_iv.hex()}")

    # AV ファイルの先頭 192*10 = 1920B を AES-CBC で復号して M2TS を確認
    with open(av_file, 'rb') as f:
        head_enc = f.read(192 * 20)  # 先頭 20 M2TS パケット分

    head_dec = aes_cbc_decrypt(content_key, content_iv, head_enc)

    # M2TS 同期確認
    hits = check_m2ts(head_dec, n_pkts=20)
    print(f"\n復号後の M2TS 同期 (0x47 at offset%192==4): {hits}/20 ヒット")

    if hits >= 15:
        print("OK: 復号成功！デバイスキーが正しい。")
        # 全体を復号して出力
        out_path = rec_dir / 'decrypted.m2ts'
        print(f"全体復号中... → {out_path}")
        with open(av_file, 'rb') as fin, open(out_path, 'wb') as fout:
            iv = content_iv
            while True:
                chunk = fin.read(192 * 1000)  # 192KB ずつ
                if not chunk:
                    break
                # AES-CBC は連続チェーン（IV は最後のブロック）
                if len(chunk) % 16 != 0:
                    chunk = chunk[:len(chunk) - len(chunk) % 16]
                if not chunk:
                    break
                dec_chunk = aes_cbc_decrypt(content_key, iv, chunk)
                iv = chunk[-16:]  # 次のブロックの IV
                fout.write(dec_chunk)
        print(f"出力完了: {out_path.stat().st_size:,} B")
        return True
    elif hits >= 3:
        print("PARTIAL: 部分的に一致（別の構造かもしれない）")
        print("先頭 192B を hexdump:")
        for i in range(0, min(192, len(head_dec)), 16):
            row = head_dec[i:i+16]
            h = ' '.join(f'{b:02x}' for b in row)
            a = ''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in row)
            print(f"  {i:04x}: {h:<48}  {a}")
        return False
    else:
        print("FAIL: 復号失敗（デバイスキーが違うか、構造の理解が間違い）")
        print("先頭 64B:")
        for i in range(0, min(64, len(head_dec)), 16):
            row = head_dec[i:i+16]
            print(f"  {i:04x}: {row.hex()}")
        return False


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    rec_dir = sys.argv[1]
    device_key_hex = sys.argv[2] if len(sys.argv) > 2 else None
    ok = decrypt_fseg(rec_dir, device_key_hex)
    sys.exit(0 if ok else 1)

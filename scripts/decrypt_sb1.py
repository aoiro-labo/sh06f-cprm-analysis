"""TitleKey で .sb1 を復号して .ts を生成。
使い方: python decrypt_sb1.py <key_hex> <sb1_file> [out.ts]
  key_hex: 8 or 16 hex chars (7 or 8 bytes), 例 ab12cd34ef5678
  sb1_file: SD_VIDEO/PRG011/MOV001.sb1 など
"""
import sys, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT,"scripts"))
from c2fast import dec_ecb

def decrypt_sb1(key_hex, sb1_path, out_path=None):
    # 鍵解析
    key_hex = key_hex.strip().replace(' ','')
    if len(key_hex) in (14, 16):
        key8 = bytes.fromhex(key_hex.ljust(16,'0'))[:8]
    else:
        print(f"鍵長エラー: {len(key_hex)} hex chars (14 or 16 expected)")
        return
    print(f"TitleKey: {key8.hex()}")

    sb1 = open(sb1_path, "rb").read()
    print(f"sb1: {len(sb1)} bytes, ヘッダ={sb1[:4].hex()}")

    # .sb1 ヘッダ: 4バイトのマジック + 1 TSパケット(188B) = 0xC0バイトが平文
    HEADER_SIZE = 0xC0
    header = sb1[:HEADER_SIZE]
    enc    = sb1[HEADER_SIZE:]
    print(f"暗号化部: {len(enc)} bytes ({len(enc)//188} TSパケット相当)")

    # 復号
    plain = dec_ecb(enc, key8)

    # TS 確認: 先頭バイトが 0x47 かどうか
    if plain and plain[0] == 0x47:
        print(f"✓ 復号成功: plain[0]=0x{plain[0]:02x} (TS sync)")
    else:
        print(f"✗ 復号失敗? plain[0]=0x{plain[0] if plain else '??':02x}")
        return

    # 出力
    if out_path is None:
        base = os.path.splitext(sb1_path)[0]
        out_path = base + ".ts"
    open(out_path, "wb").write(plain)
    print(f"出力: {out_path} ({len(plain)} bytes)")

    # 先頭 3 TS パケットを表示
    for i in range(3):
        pkt = plain[i*188:(i+1)*188]
        if len(pkt)==188 and pkt[0]==0x47:
            pid = ((pkt[1]&0x1f)<<8)|pkt[2]
            print(f"  PKT[{i}] PID=0x{pid:04x} flags={pkt[1]>>5:#03b}")

if __name__=="__main__":
    if len(sys.argv) < 3:
        print("使い方: python decrypt_sb1.py <key_hex> <sb1_file> [out.ts]")
        sys.exit(1)
    decrypt_sb1(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv)>3 else None)

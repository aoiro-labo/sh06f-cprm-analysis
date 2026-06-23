"""
ワンセグ .sb1 復号スクリプト（C2-CBC 実装）

構造:
  1 ユニット = 6144B
    [0x000..0x09F] 160B 平文ヘッダ (SHARP 独自 TS-like 区切り)
    [0x0A0..0x17FF] 5984B 暗号化ペイロード (C2-CBC, IV=0/ユニット毎リセット)

使い方:
  python decrypt_sb1_cbc.py <key_hex(14-16文字)> <sb1_file> [out.ts]
  例: python decrypt_sb1_cbc.py 0000000000000000 PRG011/MOV001.sb1

C2-CBC モード:
  CT[0] = C2_Enc(PT[0] XOR IV, K)
  CT[i] = C2_Enc(PT[i] XOR CT[i-1], K)
  復号:
  PT[i] = C2_Dec(CT[i], K) XOR CT[i-1]
  PT[0] = C2_Dec(CT[0], K) XOR IV
"""
import sys, io, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from c2fast import key_schedule, dec_block

UNIT_SIZE    = 6144    # 0x1800
HEADER_SIZE  = 160     # 0xA0 (平文ヘッダ)
PAYLOAD_SIZE = 5984    # 0x1760 (暗号化ペイロード)
BLOCK_SIZE   = 8       # C2 は 64bit ブロック

def c2_cbc_decrypt_unit(ct_payload: bytes, rks: list, iv: bytes = b'\x00'*8) -> bytes:
    """1 ユニット分の暗号化ペイロードを C2-CBC で復号。"""
    out = bytearray()
    prev = bytearray(iv)
    for i in range(0, len(ct_payload) - BLOCK_SIZE + 1, BLOCK_SIZE):
        ct_blk = ct_payload[i:i+BLOCK_SIZE]
        pt_blk = dec_block(ct_blk, rks)
        out += bytes(pt_blk[j] ^ prev[j] for j in range(BLOCK_SIZE))
        prev = bytearray(ct_blk)
    return bytes(out)


def decrypt_sb1(key_hex: str, sb1_path: str, out_path: str | None = None):
    key_hex = key_hex.strip().replace(' ', '')
    if len(key_hex) not in (14, 16):
        print(f"鍵長エラー: {len(key_hex)} 文字 (14 or 16 expected)")
        return False

    key8 = bytes.fromhex(key_hex.ljust(16, '0'))[:8]
    print(f"TitleKey: {key8.hex()}")

    sb1 = open(sb1_path, 'rb').read()
    total_units = len(sb1) // UNIT_SIZE
    print(f"sb1: {len(sb1):,} B → {total_units} ユニット")

    rks = key_schedule(key8)

    ts_packets = bytearray()
    for u in range(total_units):
        unit = sb1[u * UNIT_SIZE:(u + 1) * UNIT_SIZE]
        header  = unit[:HEADER_SIZE]
        payload = unit[HEADER_SIZE:HEADER_SIZE + PAYLOAD_SIZE]

        pt = c2_cbc_decrypt_unit(payload, rks)
        ts_packets += pt

    # TS 同期バイト確認（先頭から 188B ごとに 0x47 があるか）
    sync_hits = sum(1 for i in range(0, min(len(ts_packets), 3760), 188)
                    if ts_packets[i] == 0x47)
    print(f"TS sync (0x47) hits in first 20 pkts: {sync_hits}/20")

    if sync_hits >= 15:
        print("OK: 復号成功（TSパケット構造を確認）")
        success = True
    else:
        print("FAIL: 復号失敗（鍵が違うか、モードが異なる）")
        success = False

    if out_path is None:
        base = os.path.splitext(sb1_path)[0]
        out_path = base + '_dec.ts'

    open(out_path, 'wb').write(ts_packets)
    print(f"出力: {out_path} ({len(ts_packets):,} B)")

    # 先頭 3 パケットのヘッダ表示
    for i in range(3):
        pkt = ts_packets[i*188:(i+1)*188]
        if len(pkt) < 4: break
        pid = ((pkt[1] & 0x1f) << 8) | pkt[2]
        sc  = (pkt[3] >> 6) & 3
        print(f"  PKT[{i}] sync=0x{pkt[0]:02x} PID=0x{pid:04x} scramble={sc}")

    return success


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    ok = decrypt_sb1(sys.argv[1], sys.argv[2],
                     sys.argv[3] if len(sys.argv) > 3 else None)
    sys.exit(0 if ok else 1)

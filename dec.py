import sqlite3
import os
import struct
import binascii

# --- 設定と定数 ---
DB_FILE = "SHFSEG0001.DB"
TS_FILE = "0001100020"
DECRYPTED_TS_FILE = "decrypted_output.ts"
CONTENTS_ID = 10002  # 録画DBから抽出するコンテンツID (仮)

TS_PACKET_SIZE = 188
SCRAMBLE_ROUND = 4  # Multi2Decoder.cpp にて定義 (通常 4 または 8)
MULTI2_BLOCK_SIZE = 8  # 復号ブロックサイズ (64ビット)

# Kw取得が困難なため、ここでは固定の模擬Kw (16バイト) を使用します。
# 実際には、このKwはCasProcessor/TvCasがB-CASカードから取得します。
MOCK_KW = b'\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00'

# Initial CBC (CasCardInfoより取得される初期ベクトル)
# 実際にはカードから取得または固定値を使用します。
INITIAL_CBC = b'\x00' * 8

# ==============================================================================
# フェーズ 1: DBからEMMとECM候補 BLOBを抽出
# (C++のCasProcessorが間接的に行う処理のPython版)
# ==============================================================================

def extract_bcas_blobs(db_path, contents_id):
    """DBファイルからemmNumとsecureInfo (BLOB) を抽出する"""
    if not os.path.exists(db_path):
        print(f"🔴 エラー: データベースファイルが見つかりません: {db_path}")
        return None, None
        
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # テーブル fseg から BLOB データを取得
        cursor.execute("""
            SELECT emmNum, secureInfo 
            FROM fseg 
            WHERE contentsId=?
        """, (contents_id,))
        
        result = cursor.fetchone()
        
        if result:
            emm_blob, secure_info_blob = result
            print(f"✅ EMM (emmNum) BLOB 抽出成功: {len(emm_blob)} bytes")
            print(f"✅ ECM候補 (secureInfo) BLOB 抽出成功: {len(secure_info_blob)} bytes")
            return emm_blob, secure_info_blob
        else:
            print(f"🔴 エラー: Contents ID {contents_id} のレコードが見つかりません。")
            return None, None
            
    except sqlite3.Error as e:
        print(f"🔴 SQLite エラー: {e}")
        return None, None
            
    finally:
        if conn:
            conn.close()


# ==============================================================================
# フェーズ 2: B-CASカードとの通信とKw (ワーク鍵) の取得
# (SCardSvr / WinSCard.dll / TvCas が行う処理の模擬)
# ==============================================================================

def get_work_key_from_bcas(emm_data: bytes, ecm_data: bytes) -> bytes:
    """
    EMM/ECMをAPDUに変換し、B-CASカードと通信してKwを取得する (模擬)
    
    🛠️ 実際の処理では、WinSCard.dllをctypesで呼び出し、
       emm_dataとecm_dataをTvCasのロジックでAPDUに変換してSCardTransmitを行います。
    """
    print("\n📡 B-CAS通信フェーズ: 模擬Kwを使用します。")
    # ここに WinSCard API 呼び出しのロジックが入りますが、今回はスキップし、固定鍵を使用します。
    # print(f"  EMM APDU (構築ロジックが必要): {binascii.hexlify(emm_data)}")
    # print(f"  ECM APDU (構築ロジックが必要): {binascii.hexlify(ecm_data)}")
    
    print(f"✅ Work Key (Kw) 取得完了: {binascii.hexlify(MOCK_KW).decode()}")
    return MOCK_KW


# ==============================================================================
# フェーズ 3: TSファイルの復号 (MULTI2)
# (Multi2Decoder.cpp のロジックを概念的に移植)
# ==============================================================================

# ----------------- MULTI2 基礎関数 (Multi2Decoder.cpp 参照) -----------------

def left_rotate(value, rotate):
    """32ビット符号なし整数向けの左ローテート (C++ _lrotl 相当)"""
    value &= 0xFFFFFFFF
    rotate &= 0x1F  # 0-31
    return ((value << rotate) | (value >> (32 - rotate))) & 0xFFFFFFFF

# DATKEY 構造体を模擬 (dwLeft, dwRight)
class DATKEY:
    def __init__(self, data=0):
        if isinstance(data, bytes) and len(data) == 8:
            # 64bit -> 32bit * 2 に変換。C++ではエンディアンに依存。ここではリトルエンディアンと仮定。
            self.dwLeft = struct.unpack('<I', data[4:8])[0]
            self.dwRight = struct.unpack('<I', data[0:4])[0]
        else:
            self.dwLeft = 0
            self.dwRight = 0

    def get_bytes(self):
        # 32bit * 2 -> 64bit に戻す
        return struct.pack('<I', self.dwRight) + struct.pack('<I', self.dwLeft)

# Multi2Decoder.cpp のラウンド関数を概念的に移植
def round_func_pi1(block: DATKEY):
    """Elementary Encryption Function π1"""
    block.dwRight ^= block.dwLeft

def round_func_pi2(block: DATKEY, dwK1):
    """Elementary Encryption Function π2"""
    dwY = (block.dwRight + dwK1) & 0xFFFFFFFF
    dwZ = (left_rotate(dwY, 1) + dwY - 1) & 0xFFFFFFFF
    block.dwLeft ^= (left_rotate(dwZ, 4) ^ dwZ) & 0xFFFFFFFF

def round_func_pi3(block: DATKEY, dwK2, dwK3):
    """Elementary Encryption Function π3"""
    dwY = (block.dwLeft + dwK2) & 0xFFFFFFFF
    dwZ = (left_rotate(dwY, 2) + dwY + 1) & 0xFFFFFFFF
    dwA = (left_rotate(dwZ, 8) ^ dwZ) & 0xFFFFFFFF
    dwB = (dwA + dwK3) & 0xFFFFFFFF
    dwC = (left_rotate(dwB, 1) - dwB) & 0xFFFFFFFF
    block.dwRight ^= (left_rotate(dwC, 16) ^ (dwC | block.dwLeft)) & 0xFFFFFFFF

def round_func_pi4(block: DATKEY, dwK4):
    """Elementary Encryption Function π4"""
    dwY = (block.dwRight + dwK4) & 0xFFFFFFFF
    block.dwLeft ^= (left_rotate(dwY, 2) + dwY + 1) & 0xFFFFFFFF

def multi2_decrypt_block(block_data: DATKEY, work_keys):
    """
    1ブロック (8バイト) を MULTI2 で復号する (4ラウンド)
    work_keys: KeySchedule によって生成された拡張作業鍵
    """
    # ワーク鍵のインデックス。TvCas/Multi2Decoderの KeySchedule に依存
    K1, K2, K3, K4, K5, K6, K7, K8 = work_keys

    # 4 ラウンドの逆順復号 (順序は Multi2Decoder.cpp の KeySchedule の出力を元に逆算)
    for _ in range(SCRAMBLE_ROUND):
        round_func_pi4(block_data, K4)
        round_func_pi1(block_data)
        round_func_pi2(block_data, K1)
        round_func_pi3(block_data, K3, K2)

        # 鍵インデックスのシフト (実際は TvCas の実装に厳密に依存)
        K1, K2, K3, K4, K5, K6, K7, K8 = K5, K6, K7, K8, K1, K2, K3, K4
    
# ----------------- TSファイル復号処理 -----------------

def decrypt_ts_file(input_path: str, output_path: str, work_key: bytes, initial_cbc: bytes):
    """TSファイルを読み込み、KwとMULTI2アルゴリズムでスクランブルを解除する"""
    print(f"\n🎬 TSファイル復号を開始します: {input_path}")
    print("⚠️ MULTI2 の論理移植のため、復号が正しく動作しない可能性があります。")

    # 1. ワーク鍵のセットアップ (Multi2Decoder::KeySchedule 相当)
    # 実際には、Kw (16バイト) を使って KeySchedule 関数で 32バイトまたはそれ以上の
    # 拡張作業鍵 (work_keys) を生成する必要があります。
    # ここでは便宜上、Kwの最初の32bitワードを単純に繰り返すと仮定します (実際とは異なります)。
    dw_keys = struct.unpack('<4I', work_key[:16])
    # 鍵スケジューリングロジックを省略し、Kwから派生した32bit鍵8個を模擬
    work_keys_32bit = dw_keys * 2  # 模擬: K1, K2, K3, K4, K1, K2, K3, K4...

    try:
        with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
            current_cbc = DATKEY(initial_cbc)
            
            while True:
                packet = fin.read(TS_PACKET_SIZE)
                if len(packet) < TS_PACKET_SIZE:
                    break
                
                # TSパケットヘッダの解析
                # format: [Sync(1)] [TEI(1) PUSI(1) TP(1)] [PID(13)] [TSC(2) AFC(2)] [CC(4)]
                
                # 2. TSC (Transport Scrambling Control) のチェック (バイト 3 の上位 2 ビット)
                # Byte 3 (packet[3])
                tsc = (packet[3] >> 6) & 0x03
                
                # TSC == 0b00 (0) はスクランブルなし
                # TSC != 0b00 (1, 2, 3) はスクランブルあり
                if tsc == 0x00:
                    # 復号不要
                    fout.write(packet)
                    continue

                # 3. 復号処理 (暗号化されている場合)
                
                # ペイロード開始位置 (Adaptation Fieldの有無に依存)
                adaptation_field_control = (packet[3] >> 4) & 0x03
                
                # 通常、ペイロードはヘッダの 4 バイト目から始まりますが、
                # ここでは簡易的に 4 バイト目以降を処理対象とします。
                # 実際にはAFCに応じてペイロード開始位置を計算する必要があります。
                payload_start = 4
                if adaptation_field_control == 0b10 or adaptation_field_control == 0b11:
                    # Adaptation Field があればその長さを読み取る
                    if TS_PACKET_SIZE > 4:
                        af_length = packet[4]
                        payload_start = 5 + af_length
                
                if payload_start >= TS_PACKET_SIZE:
                    # ペイロードがない
                    fout.write(packet)
                    continue
                
                # ペイロードの抽出
                payload = bytearray(packet[payload_start:])
                payload_size = len(payload)
                
                # 4. OFBモード復号の準備
                # Multi2Decoderは通常 OFB モードで復号を行います。
                # 復号されたデータは一時的なバッファに格納されます。
                decrypted_payload = bytearray(payload_size)
                
                # CBCをOFBの初期ベクトルとして使用 (OFBモード)
                for i in range(0, payload_size, MULTI2_BLOCK_SIZE):
                    data_slice = payload[i:i + MULTI2_BLOCK_SIZE]
                    if not data_slice:
                        break
                        
                    # 復号器 (CBC) を使って鍵ストリームを生成
                    key_stream = current_cbc.get_bytes()
                    temp_block = DATKEY(key_stream)
                    multi2_decrypt_block(temp_block, work_keys_32bit) # 復号アルゴリズム適用
                    key_stream_decrypted = temp_block.get_bytes()
                    
                    # 鍵ストリームとペイロードを XOR
                    for j in range(len(data_slice)):
                        decrypted_payload[i+j] = data_slice[j] ^ key_stream_decrypted[j]

                    # 次の CBC/OFB ブロックは、現在の鍵ストリームの復号結果 (temp_block) を使用
                    current_cbc = temp_block

                # 5. 復号されたペイロードでパケットを更新
                new_packet = bytearray(packet[:payload_start]) + decrypted_payload
                fout.write(new_packet)

        print(f"✅ 復号処理完了 (ファイル): {output_path}")
    except FileNotFoundError:
        print(f"🔴 エラー: TSファイルが見つかりません: {input_path}")
    except Exception as e:
        print(f"🔴 復号中に予期せぬエラーが発生しました: {e}")


# ==============================================================================
# メイン実行
# ==============================================================================

if __name__ == "__main__":
    
    # フェーズ 1: DBから鍵情報を抽出
    emm_data, ecm_data = extract_bcas_blobs(DB_FILE, CONTENTS_ID)

    if emm_data and ecm_data:
        
        # フェーズ 2: B-CASカードから Kw を取得 (模擬)
        final_kw = get_work_key_from_bcas(emm_data, ecm_data)
        
        if final_kw:
            # フェーズ 3: TSファイルの復号
            decrypt_ts_file(TS_FILE, DECRYPTED_TS_FILE, final_kw, INITIAL_CBC)
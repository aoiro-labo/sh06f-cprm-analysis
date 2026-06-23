import sqlite3
import os
import binascii
import sys

def analyze_shfseg_db(db_file_path):
    """
    SHFSEG0001.DB ファイル (SQLite) を解析し、fsegテーブルの secureInfo BLOBを抽出し、
    全BLOBデータをファイルに出力する。
    """
    if not os.path.exists(db_file_path):
        print(f"エラー: 指定されたデータベースファイル '{db_file_path}' が見つかりません。")
        return

    conn = None
    dump_file_path = "shfseg_blobs_dump.txt"
    
    # ファイルを初期化してヘッダーを書き込む
    try:
        with open(dump_file_path, 'w', encoding='utf-8') as f:
            f.write(f"--- Full BLOB Data Dump from {db_file_path} ---\n\n")
            
    except Exception as e:
        print(f"ダンプファイルの初期化エラー: {e}")
        return

    try:
        # データベースに接続
        conn = sqlite3.connect(db_file_path)
        conn.text_factory = bytes # BLOBフィールドをバイト列として取得するために設定
        cursor = conn.cursor()

        # fsegテーブルのスキーマを確認
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='fseg'")
        if cursor.fetchone() is None:
            print("エラー: データベース内に 'fseg' テーブルが見つかりません。")
            return

        # fsegテーブルから全データを取得
        query = "SELECT * FROM fseg"
        cursor.execute(query)
        
        # カラム名を取得
        column_names = [description[0] for description in cursor.description]
        
        print(f"\n--- データベースファイル解析結果 ({db_file_path}) ---")
        print("テーブル: fseg (BLOB詳細データは shfseg_blobs_dump.txt に出力)")
        print("-" * 120)

        # 抽出したレコードを処理
        for row in cursor.fetchall():
            
            # rowのバイト列をデコードして文字列に変換する
            record = {}
            for col_name, value in zip(column_names, row):
                if isinstance(value, bytes):
                    # BLOBフィールドはそのまま保持
                    if col_name in ['secureInfo', 'emmNum', 'copyCount']:
                        record[col_name] = value
                    else:
                        # テキストフィールドはShift JISでデコード
                        try:
                            record[col_name] = value.decode('shift_jis', errors='ignore').strip()
                        except:
                            record[col_name] = value.hex() # デコード失敗時はHEX表示
                else:
                    record[col_name] = value
            
            # --- 鍵情報を含むBLOBフィールドの処理 ---
            
            secure_info_blob = record.get('secureInfo', b'')
            emm_num_blob = record.get('emmNum', b'')
            copy_count_blob = record.get('copyCount', b'')
            
            secure_info_hex = binascii.hexlify(secure_info_blob).decode('utf-8')
            emm_num_hex = binascii.hexlify(emm_num_blob).decode('utf-8')
            copy_count_hex = binascii.hexlify(copy_count_blob).decode('utf-8')
            
            secure_info_len = len(secure_info_blob)
            emm_num_len = len(emm_num_blob)
            
            # --- ターミナルへの要約出力 ---
            
            print(f"Contents ID: {record.get('contentsId', 'N/A')}")
            print(f"タイトル: {record.get('title', 'N/A')}")
            print(f"チャンネル: {record.get('channelName', 'N/A')}")
            print(f"録画日時: {record.get('recStartDate', 'N/A')} から {record.get('recEndDate', 'N/A')}")
            
            # ターミナル出力は短縮版を維持（64文字/32バイトまで）
            print(f"  [ secureInfo ] (Len: {secure_info_len} bytes) - {secure_info_hex[:64]}{'...' if len(secure_info_hex) > 64 else ''}")
            print(f"  [ emmNum ]     (Len: {emm_num_len} bytes) - {emm_num_hex[:64]}{'...' if len(emm_num_hex) > 64 else ''}")
            print(f"  [ copyCount ]  (Len: {len(copy_count_blob)} bytes) - {copy_count_hex[:64]}{'...' if len(copy_count_hex) > 64 else ''}")
            print("-" * 120)

            # --- 全BLOBデータのファイル出力 ---
            with open(dump_file_path, 'a', encoding='utf-8') as f:
                f.write("-" * 50 + f" Record ID: {record.get('contentsId', 'N/A')} " + "-" * 50 + "\n")
                f.write(f"Title: {record.get('title', 'N/A')}\n")
                f.write(f" secureInfo (Len: {secure_info_len} bytes, Full Hex): {secure_info_hex}\n")
                f.write(f" emmNum (Len: {emm_num_len} bytes, Full Hex):     {emm_num_hex}\n")
                f.write(f" copyCount (Len: {len(copy_count_blob)} bytes, Full Hex):  {copy_count_hex}\n")
                f.write("\n")
                
        print(f"✅ 全てのBLOBデータ（完全な16進数）を '{dump_file_path}' に出力しました。")

    except sqlite3.Error as e:
        print(f"SQLiteエラーが発生しました: {e}")
    except Exception as e:
        print(f"予期せぬエラーが発生しました: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    file_name = "SHFSEG0001.DB"
    if len(sys.argv) > 1:
        file_name = sys.argv[1]
        
    analyze_shfseg_db(file_name)
import sys
import os
import re

def clean_string(text):
    """
    制御文字（'␦'などの原因）や全角スペースを除去し、連続する空白を一つにまとめ、
    前後の空白を削除する。
    """
    if not isinstance(text, str):
        return ""
    
    # 1. Unicodeの制御文字（U+0000〜U+001F, U+007F〜U009F）を空文字に置換
    text = re.sub(r'[\u0000-\u001F\u007F-\u009F]', '', text)
    
    # 2. 全角スペースを半角スペースに変換
    text = text.replace('　', ' ')
    
    # 3. 連続する空白、タブ、改行を一つの半角スペースに変換
    text = ' '.join(text.split())
    
    return text.strip()

def parse_pgi_file_python(file_path):
    """PGIファイルの内容を解析し、メタデータ辞書を返す"""
    metadata = {
        "title": "",
        "details": "",
        "station": "",
        "startTime": "",
        "endTime": "",
        "recordTime": "",
        "isValid": False
    }

    try:
        with open(file_path, 'rb') as f:
            f.seek(0x28)
            sjis_bytes = f.read()

        # ★ V11修正: デコードエラー処理を 'ignore' から 'replace' に変更
        # 壊れた文字コードを '?' に置き換え、コード側でそれを補正する
        decoded_content = sjis_bytes.decode('shift_jis', 'replace')

    except Exception as e:
        print(f"エラー: ファイル読み込み/デコードエラー: {e}")
        return metadata

    separator = "≠m"
    if separator not in decoded_content:
        return metadata

    blocks = decoded_content.split(separator, 1)
    
    # --- A. タイトルと詳細の処理 (V9/V10のロジックを維持) ---
    title_detail_block = blocks[0].strip()
    
    start_marker_T = "T＜"
    start_marker_S = "S＜"
    
    pos_start_T = title_detail_block.find(start_marker_T)
    pos_start_S = title_detail_block.find(start_marker_S)
    
    pos_start = -1
    current_marker = ""
    
    if pos_start_T != -1 and (pos_start_S == -1 or pos_start_T < pos_start_S):
        pos_start = pos_start_T
        current_marker = start_marker_T
    elif pos_start_S != -1:
        pos_start = pos_start_S
        current_marker = start_marker_S
    
    if pos_start == -1:
        return metadata 

    content_block_raw = title_detail_block[pos_start:]
    
    second_title_pos = content_block_raw.find(current_marker, len(current_marker))
    
    def finalize_title(text, marker):
        text = text.replace(marker, "", 1).strip()
        
        if text.startswith('Tタデーウオッチ９') or text.startswith('Sタデーウオッチ９'):
             text = text[1:].strip() 
             text = 'サ' + text
        
        return clean_string(text)

    if second_title_pos != -1:
        title_block = content_block_raw[:second_title_pos]
        detail_block = content_block_raw[second_title_pos:]
        
        metadata["title"] = finalize_title(title_block, current_marker)
        metadata["details"] = finalize_title(detail_block, current_marker)
        
        if metadata["details"] == metadata["title"]:
             metadata["details"] = ""
    else:
        metadata["title"] = finalize_title(content_block_raw, current_marker)
        metadata["details"] = "" 
    
    # --- B. 放送局と日時の処理 ---
    if len(blocks) > 1:
        time_block = blocks[1]
        
        date_pattern = re.compile(r'^\d{4}/\d{2}/\d{2}$')
        
        # 局名抽出のためのトークン化
        # 壊れた文字コードが '?' に置き換えられている可能性を考慮して処理する
        time_tokens_raw = time_block.split() 
        
        station_end_index = 0
        for i, token in enumerate(time_tokens_raw):
            clean_token = clean_string(token) 
            if date_pattern.match(clean_token):
                station_end_index = i
                break
        
        if station_end_index > 0:
            station_name_parts = time_tokens_raw[:station_end_index]
        elif len(time_tokens_raw) > 0:
            station_name_parts = [time_tokens_raw[0]]
        else:
            station_name_parts = []
            
        # 1. すべてのトークンを結合し、クリーニング
        raw_station_block = "".join([clean_string(p) for p in station_name_parts])
        
        # 2. 放送局名補正: 「ＨＫ」の前に「Ｎ」がない場合、壊れた文字「?」や空白の代わりに「Ｎ」を挿入する
        if raw_station_block.startswith('ＨＫ') or raw_station_block.startswith('?ＨＫ'):
             # '?' やその他のノイズを除去してから「Ｎ」を挿入
             final_station_name = 'Ｎ' + re.sub(r'[^ＨＫ総合・名古屋]', '', raw_station_block)
        else:
             final_station_name = raw_station_block
        
        metadata["station"] = final_station_name
        
        # 日付と時刻のペアを抽出
        time_block_clean = clean_string(time_block)
        datetime_pairs = re.findall(r'(\d{4}/\d{2}/\d{2})\s(\d{2}:\d{2}:\d{2}\.\d{3})', time_block_clean)
        
        if len(datetime_pairs) >= 3:
            start_date, start_time = datetime_pairs[0]
            metadata["startTime"] = f"{start_date} {start_time}" 
            
            end_date, end_time = datetime_pairs[1]
            metadata["endTime"] = f"{end_date} {end_time}"   
            
            record_date, record_time = datetime_pairs[2]
            metadata["recordTime"] = f"{record_date} {record_time}" 
            
            metadata["isValid"] = True
            
    if metadata["title"] or metadata["station"]:
        metadata["isValid"] = True
        
    return metadata

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("使用法: python pgi_parser.py <PGIファイルパス>")
        sys.exit(1)

    file_path = sys.argv[1]
    results = parse_pgi_file_python(file_path)

    if results["isValid"]:
        print("\n--- PGIファイル解析結果 ---")
        print(f"ファイル名: {os.path.basename(file_path)}")
        print(f"タイトル: {results['title']}")
        print(f"詳細: {results['details'] if results['details'] else '（詳細情報なし）'}")
        print(f"放送局: {results['station']}")
        print(f"開始日時: {results['startTime']}")
        print(f"終了日時: {results['endTime']}")
        print(f"記録日時: {results['recordTime']}")
        print("---------------------------\n")
    else:
        print(f"エラー: PGIファイル '{file_path}' の解析に失敗しました。")
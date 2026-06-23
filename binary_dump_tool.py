import sys
import os
import textwrap
import binascii

def analyze_binary_file(file_path, block_byte_size=16):
    """
    指定されたバイナリファイルを読み込み、16進数ダンプ形式で表示する。
    """
    if not os.path.exists(file_path):
        print(f"エラー: 指定されたファイル '{file_path}' が見つかりません。")
        return

    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read()
    except Exception as e:
        print(f"ファイルの読み込みエラー: {e}")
        return

    hex_string = binascii.hexlify(raw_data).decode('utf-8')
    file_size_bytes = len(raw_data)
    
    # 1バイトは2桁の16進数
    block_char_size = block_byte_size * 2 
    blocks = textwrap.wrap(hex_string, block_char_size)
    
    print(f"\n--- バイナリファイル解析結果 ({file_path}) ---")
    print(f"ファイルサイズ: {file_size_bytes} バイト")
    print(f"ブロックサイズ: {block_byte_size} バイト ({block_char_size} 桁)")
    print("-" * 85)
    # 修正: r'' を使って生文字列として扱うことで警告を回避
    print(r"オフセット | 16進数データ (整形済み)                               | ASCII/Shift_JIS テキスト") 
    print("-" * 85)
    
    current_offset = 0
    for block in blocks:
        # 16進数ブロックを2バイト（4桁）ずつスペースで区切る
        formatted_hex = ' '.join(textwrap.wrap(block, 4))
        
        # テキスト表示のためにバイト列に変換し、Shift_JISでデコード（日本語環境を考慮）
        try:
            # ブロックのバイト列を取得
            block_bytes = binascii.unhexlify(block)
            # 制御文字を見やすく変換
            text_part = ''.join([chr(b) if 0x20 <= b <= 0x7E else '.' for b in block_bytes])
        except Exception:
            text_part = ""
            
        print(f"0x{current_offset:04X}: {formatted_hex.ljust(48)} | {text_part}")
        current_offset += block_byte_size
        
    print("-" * 85)

if __name__ == '__main__':
    file_name = "0001100010"
    if len(sys.argv) > 1:
        file_name = sys.argv[1]
        
    # デフォルトのブロックサイズを16バイトに設定
    analyze_binary_file(file_name, block_byte_size=16)
import textwrap
import sys

def analyze_hex_structure(hex_string, block_byte_size=8):
    """
    16進数文字列をバイトブロックサイズごとに整形し、オフセット情報と共に表示する。
    
    Args:
        hex_string (str): 解析する16進数文字列。
        block_byte_size (int): 1行に表示するバイト数 (デフォルトは8バイト = 16桁)。
    """
    
    # 1バイトは2桁の16進数
    block_char_size = block_byte_size * 2 
    
    if len(hex_string) % 2 != 0:
        print("エラー: 16進数文字列の長さが奇数です。入力データを確認してください。")
        return

    # 16進数文字列をブロックサイズ（文字数）ごとに分割
    blocks = textwrap.wrap(hex_string, block_char_size)
    
    print(f"\n--- BLOBデータ 構造解析 ({len(hex_string)//2} Bytes) ---")
    print(f"ブロックサイズ: {block_byte_size} バイト ({block_char_size} 桁)")
    print("-" * 85)
    print("オフセット | 16進数データ (整形済み)")
    print("-" * 85)
    
    current_offset = 0
    for block in blocks:
        # 8バイトブロックを4バイトずつスペースで区切る
        if block_byte_size == 8 and len(block) == 16:
            formatted_block = f"{block[:8]} {block[8:]}"
        else:
            # 8バイト以外のサイズや端数がある場合はそのまま表示
            formatted_block = block
        
        print(f"0x{current_offset:04X}: {formatted_block}")
        current_offset += block_byte_size
        
    print("-" * 85)
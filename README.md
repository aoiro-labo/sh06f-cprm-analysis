# SH-06F ワンセグ・フルセグ録画解析

SHARP SH-06F（Android / docomo）で録画した個人映像データの保存・解析記録。

---

## 状況

| | ワンセグ (.sb1) | フルセグ (FSEG/) |
|--|--|--|
| 暗号方式 | CPRM / C2-CBC 56bit | SHARP 独自 / AES-128-CBC |
| 状態 | **画面キャプチャで救出済み** | **未解決**（調査継続中） |
| 鍵の壁 | MEI006H サービス内で完結・ユーザーモードに出ない | `/system/etc/mccd/sbdb` root 専用 |

---

## コンテンツ

**ワンセグ**: 18 番組（2025-12-07 録画、名古屋局系）  
**フルセグ**: 4 番組（CBC/NHK/東海テレビ、2025-12-07〜09）

詳細: [`doc/_oneseg_titles.txt`](doc/_oneseg_titles.txt) / [`doc/_fseg_db_dump.txt`](doc/_fseg_db_dump.txt)

---

## ドキュメント

| ファイル | 内容 |
|---------|------|
| [`doc/暗号構造解析.md`](doc/暗号構造解析.md) | ワンセグ C2-CBC / フルセグ AES 鍵チェーン / Android ライブラリ逆解析 |
| [`doc/ワンセグ救出_再現手順.md`](doc/ワンセグ救出_再現手順.md) | Windows XP VM + SD-MobileImpact で再生・OBS キャプチャする手順 |
| [`doc/SD-MobileImpact解析.md`](doc/SD-MobileImpact解析.md) | 起動エラー原因・バイナリパッチ詳細 |
| [`doc/C2解読_ダンプRE.md`](doc/C2解読_ダンプRE.md) | C2 暗号 F 関数・鍵スケジュールのダンプ逆解析 |
| [`scripts/`](scripts/) | C2 実装 / メモリスキャン / フルセグ復号エミュレータ等 |

---

## ワンセグ救出の要点

Windows XP SP3 32bit VM + SD-MobileImpact L032（正規品） + バイナリパッチ 2 箇所。

```python
d = bytearray(open("SD-MobileImpact.exe", "rb").read())
for off in (0x429e9, 0x78ebb):
    assert d[off] == 0x75
    d[off] = 0xeb   # jne → jmp（FAT32 FS 種別チェックを無効化）
open("SD-MobileImpact_patched.exe", "wb").write(d)
```

VM のハードウェアアクセラレータを「なし」にしないと映像が黒画面になる。  
SDカードのフォーマット・書き戻し・ファイル削除は絶対禁止（CPRM 復元不可）。

---

## フルセグ現状（調査継続）

SH-06F の Android システムライブラリを ADB 経由で取得・逆解析中。
デバイス鍵（`/system/etc/mccd/sbdb`）へのアクセスが主な壁。

→ 詳細: [`doc/暗号構造解析.md`](doc/暗号構造解析.md) §3〜§7

---

## 注意

- 自己録画コンテンツの個人保存目的のみ
- 第三者コンテンツへの適用・頒布は不可
- バイナリ本体（EXE/DLL/ISO）はリポジトリに含まない

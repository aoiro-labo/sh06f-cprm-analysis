# SD-MobileImpact 解析メモ ＆ 元microSD(CPRMリーダー)現況

最終更新: 2026-06-19

---

## 0. 重大進展（2026-06-19 追記）

**復号・再生スタックは既にこのPCにフルインストール済みだった。** Documentsのフォルダは
SDApf共有モジュールを欠いた“プログラムだけのコピー”に過ぎなかった。実体は以下:

- `C:\Program Files (x86)\Panasonic\SD-MobileImpact\` … 本体一式（＋`audsub3.sys`）
- `C:\Program Files (x86)\Common Files\Panasonic\SDApf\` … **CPRM＋SD-Video復号スタック一式**
  - `SDCprm.dll`(1.29MB) CPRM暗号 / `SDCore.dll`(21KB) リーダーAKE・SCSI
  - **`SDVM2TSPacketDecParser.dll` = M2TS/TSパケット復号本体** / `SDVCore.dll`(1.56MB) SD-Video中核
  - `SdvPlayM2TS.ax`(再生フィルタ) / `H264VideoDecoder.dll` / `SDAudioAACOneSegRenderer.dll`(ワンセグ音声)
  - `SecureDB.dll`/`NSecureDB.dll`/`SDDRMPlugIn.dll`/`SDCardMgr.dll`/`SDFileSys.dll`
- ⇒ **「SDCprm.dllを探す/0バイトダミーを作る」必要は無い。本物が全部揃っている。**
  （SDApf内に `SDAudioCheckout`/`SDAudioMove`/`plugin` 等の**1バイトダミーが2025/12/06作成**＝過去の試行跡。
  　これらは紛らわしいので原則触らない。）

### 残る唯一の関門 = リーダーアクセス（CPRMコマンド送出路）
- `SDCore.dll` は ASPI(`Wnaspi32.dll`)／SPTI(`\\.\scsi%d:`) でリーダーへSCSI/CPRMコマンドを送る。
- 同梱 `audsub3.sys` は **32bit(x86)のスタブ駆動(ZERODRV)**。
  → **Win11 x64ではロード不可（testsigningでも不可：署名でなくアーキテクチャの問題）**。現在サービス未登録。
- 回避策は「2. 実行ルート」参照。これさえ通れば**復号は内蔵スタックが自動でやる**。

---

## 0a2. カード拒否 86000012「ファイルシステムが異なります」の解析（2026-06-20）

XP(VM)で**起動成功**（86000001は出ず）、カード(F:,空き24.6GB)も認識。しかし
**86000012「ファイルシステムが異なります。SDフォーマットを行なってください」** で停止。
（⚠️ フォーマット厳禁＝録画全消去）

`SD-MobileImpact.exe`(平文)を逆アセンブルして判定箇所を特定（2箇所、同一構造）:
```
; site1 VA0x4429eb / site2 VA0x478ec7
call <カード解析メソッド vtable+0x3c>   ; FS種別等を返す
... bit0x10000→0x8520000a, bit0x10000000→0x8520000b の分岐 ...
cmp [esp+x],0        ; 解析が返す「FS種別」値
jne 継続
mov ebx,0x86000012   ; ★ FS種別==0(未知) のとき「ファイルシステムが異なります」
```
→ **根本原因＝アプリのFS検出が32GB SDHC(FAT32)を「未知の形式」と判定**。L052でもSDHC対応無し。
　＝2006-2007年版のFS/SDHC-CPRM世代ギャップ。**カードを別物に替えても解決しない**
　（CPRM録画は物理カードのMedia IDに紐付くため移せない）。

**実験用パッチ**: `doc/_migration_kit/SD-MobileImpact_patched.exe`
　= 両ゲートの `jne`(0x75)→`jmp`(0xeb) で86000012を飛ばす版。低確率（下流がFS種別=0前提で
　動けず失敗/クラッシュが奥にずれる見込み）だが診断価値あり。SDCprmのModule32自己チェックで
　改竄検知される可能性もあり。VM内の実体EXEを退避してから差し替えて挙動を観察する。

---

## 0b. 起動エラー 86000001 の調査（2026-06-19）

実機起動 → **「アプリケーションの起動に失敗しました。(86000001)」**（リーダーアクセス以前の初期化失敗）。

判明事項:
- **インストールは健全**：`Frame/Media`フォルダ内にDLL有り、レジストリ
  `HKLM\...\WOW6432Node\Panasonic\SDApf`(SD-Core Version=5, SD-PML SD-JukeSerial登録) 正常。
- **過去に動作していた形跡**：`VirtualStore\...\SDApf\SDAudioCheckout\DirectCO.db` 等のチェックアウトDBが
  生成済み。今回の起動でも `SDApf\SDVideoThumb` フォルダが**当日時刻で新規作成**＝
  **映像サブシステム初期化まで到達してから86000001で失敗**している。
  （※`plugin/SDAudioCheckout/SDAudioMove/SDVideoThumb`は1バイトでなく**アプリ生成の正常フォルダ**。
  　以前疑った“ダミーファイル説”は誤りだった。）
- **86000001 = セキュアモジュール初期化失敗**（86xxxxxx系はSD secure系エラー）。Win11環境での
  セキュアフレームワーク不整合が濃厚。背景:
  - SD-Jukebox/MobileImpactは**Windows 10/11 非対応**（公式）。Win10でOS側のCPRMサポートが撤去。
  - **2018/3末でPanasonicがセキュリティプログラム配布終了** → 新規/再インストールは起動不可。
    ただし**本PCには配布終了前の正規モジュールが既にインストール済み**（＝再入手困難な資産）。

### 重要な戦略転換の示唆
86000001は「リーダー経路」より手前の**セキュア基盤レベルの壁**。ルートB(Win11+ASPIシム)は
①86000001(セキュア初期化) ②32bitドライバ ③Win10+のCPRM撤去 の**三重の壁**を相手にする。
一方、**本PCに揃っている正規モジュール一式＋レジストリを 32bit Windows 7 VM へ移植**すれば、
死んだ配布サーバに依存せず、これらの壁を一挙に回避できる可能性が高い（＝ルートA優位）。

---

## 0d. 86000001 の真因＝mirssom.dll の use-after-unload クラッシュ（Procmon+EventLog で確定）

Procmonログ(`Logfile.PML`)とWindowsイベントログ(アプリケーションエラー ID1000)で確定:
```
障害アプリ : SD-MobileImpact.exe (1.0.61220.1000)
障害モジュール: mirssom.dll_unloaded   ← アンロード済みアドレスを呼出し
例外コード : 0xc0000005 (アクセス違反)  オフセット: 0x00020096 (再現性あり)
```
- **86000001は「きれいなエラー」ではなく実体はクラッシュ**（直後に`WerFault.exe`起動を観測）。
- 起動シーケンスは**SDApfのセキュア/映像モジュール初期化まで到達**(SDVThumbDB.dll読込、
  SDVideoThumbフォルダ生成、`SDApf\SD-App\ExistContent`書込)してから、**`mirssom.dll`**で落ちる。
- **`mirssom.dll` は「ミュージックソムリエ」(楽曲SOM解析)機能でCPRM/ワンセグ再生とは無関係**。
  → 周辺の音楽機能のWin11非互換クラッシュであり、**復号スタック自体は無傷**。
- ⇒ **`mirssom.dll` を読ませない/無効化できれば起動を通せる可能性**（次の実験）。ダメならWin7 VM。

## 0c. DLL内部のリバースエンジニアリング所見（2026-06-19）

| モジュール | 役割 | 状態 |
|-----------|------|------|
| `SDCprm.dll`(1.29MB) | **CPRM暗号中核**：C2暗号・デバイス鍵・MKB処理・AKE | **コードがパック/保護**(`.text/._text` ent≈8.0)→静的解析不可 |
| `SDCore.dll`(21KB) | プラグインローダ(`SDCoreInterface`、LoadLibrary多用) | 平文 |
| `SDVCore.dll`(1.56MB) | **SD-Video管理**(`SD_VIDEO\MOV%03X.SB1/.MOI`を扱う) | **平文**(解析可) |
| `SDVM2TSPacketDecParser.dll` | **M2TS/TSパケット復号パーサ** | コード平文(.dataのみ高ent) |

判明した重要事実:
- **リーダーI/Oは `DeviceIoControl`+`CreateFileA`(=SPTI/SCSIパススルー)**。`SDCprm.dll`が直接実行。
  → **ASPI(`Wnaspi32`/`audsub3.sys`)は必須でない可能性**。SPTIは**Win11でも管理者権限なら通る**しLinux `SG_IO`にも対応＝**WSL移植と相性◎**。
- `SDCprm.dll`に **`SdReadMKB`** と保護領域MKBパス **`\SD_Audio\SD_AUDIO.MKB` 等**。映像用MKBは`SDVCore`経由と推定。
- **`GetVersionExA` ＋ レジストリ `...\Windows NT\CurrentVersion` 参照**＝**OSバージョンチェック**。
  Win11で弾かれて **86000001** を出している有力候補。→ **互換モード(XP/7)で回避できる可能性**。

### 戦略的帰結
- **静的REで鍵抽出はパッカーに阻まれる**。鍵/C2は実行時メモリにのみ展開。
  → **現実的なREは「Win7で動かして動的に吸う」**（ただし`SDCprm`はToolhelp32で軽い対デバッグ有り）。
- ⇒ **「Win7で動かす」ことが視聴(ルートA)にもRE(独立復号器/WSL)にも共通の土台**。
- ただしWin11側にも安価な突破口：**管理者＋互換モードでEXE起動**→86000001を越えられれば、
  SPTIでリーダーへ直接通る見込み（audsub不要）。**VM構築前にまず試す価値大**。

---

## 1. 結論（先に）

- **SD-MobileImpact は「解析して鍵を取り出す」より「正規に動かして再生/書き出す」のが本筋。**
  本ソフト自体が**ライセンス済みCPRM実装＋リーダー通信プロトコル**を内蔵しており、
  ワンセグ(SD-Video)を再生・チェックアウトできる設計。標準規格なのでSH-06FのSD_VIDEOも
  読める見込みがある（＝**ワンセグ救出の最有力候補**）。
- ただし **license.txt に「本ソフトウェアの解析・変更・改造は行わないでください」と明記**(EULA)。
  → 鍵抽出目的の逆コンパイルは避け、**実行による再生/書き出し**を狙うのが妥当。
- **フルセグ(PRIVATE/SHARP/FSEG)は対象外**。本ソフトは2006年製でSHARP独自フルセグ形式を知らない。
- **元microSDの「CPRM保護領域」は別ドライブとしては読めない**。リーダーへの
  **CPRMコマンド(SCSIパススルー)経由でしか触れない**＝WSLやddで生ダンプしても鍵は採れない。

---

## 2. SD-MobileImpact のソフト構成（静的解析で判明）

- 実体：**SD-Jukebox LE 系 v1.0.032（2006年版）**。`Device.ini` の `Setup=SD_MOBILEIMPACT_LE`。
  主用途はSD-Audio(AAC/MP3/WMA)＋当時のワンセグ携帯向け動画。
- アーキテクチャ：**32bit(x86)**、VC++2005ランタイム(MFC80/MSVCR80)依存。
  起動必須の静的依存DLLは**全て揃っている**（urlmon/imagehlp等はWindows標準）。→ 起動自体は可能。

### ⚠️ 最重要：CPRM暗号エンジン本体（SDCore.dll / SDCprm.dll）が欠落
- `SD-MobileImpact.exe` は実行時に **`SDCore.dll`（セキュアSDアクセス）と `SDCprm.dll`（CPRM暗号）**
  を**動的ロード**する設計だが、**この2つが配布フォルダに存在しない**。
  → 今ある一式は**CPRMコアを欠いた不完全コピー**。このままではワンセグ復号/再生は不可。
- **`SDCprm.dll` が鍵そのもの**：CPRMのデバイス鍵・鍵ラダー(Km→Kmu→タイトル鍵)・**C2暗号**を内包。
  **`SDCore.dll`** がリーダーへ **ASPI(`Wnaspi32.dll`)＋生SCSI(`\\.\scsi%d:`)** で **AKE(認証鍵交換)** を行い、
  カードの **MKB / Media ID / 暗号化タイトル鍵** を読み出す。
- 補足：`mirssdk/mirssom/mirspl` は名前に反して **CPRMではなく「ミュージックソムリエ」
  (MIRS=音楽情報検索 / SOM=自己組織化マップ)** の楽曲解析・プレイリスト機能。リーダーにも暗号にも無関係
  （エクスポート名 `mirsCreatePlaylist`/`somExtAnalysis` 等、インポートも標準Win32のみで確認）。

### 構造（確定）
```
SD-MobileImpact.exe
  ├─(動的)→ SDCprm.dll  … ★欠落: CPRMデバイス鍵・鍵ラダー・C2暗号
  ├─(動的)→ SDCore.dll  … ★欠落: セキュアSDアクセス(AKE/保護領域読出し)
  │              └ Wnaspi32.dll (ASPI) / \\.\scsi%d: → 生SCSIパススルー
  │                     └ audsub3.sys (instaudsub.exeで導入) → リーダー
  │                            → BN-SDCMP3 → microSD(保護領域/MKB/Media ID)
  └─ mirs*/som*/VACtrl/Ctrl* … UI・音楽解析・音量(CPRM無関係)
```
- `Device.ini` `[SecDevice]` のチェックアウト先は**全て2006年機種**(905SH/P903iTV/W43SA/CN-HDS等)。
  **SH-06Fは無い**＝書き戻し先には使えない。再生/別カード持ち出しは規格準拠なら可能性あり。
- `readme.txt` 要点：
  - 「録画した放送コンテンツ(ワンセグ)の再生・チェックアウトに対応」「データ放送/字幕は非対応」。
  - 追加モジュールのDLは **SD-Jukeboxとのコンインストール／音楽配信サービス向け**であり、
    **ワンセグCPRM再生の中核機能とは別**（＝配布サーバ停止でも再生は動く可能性）。
  - BD/CD-ROMドライブやスクリーンセイバー動作中の注意など、再生は環境にシビア。

## 3. 実行ルート（リーダーアクセスをどう通すか）

ソフトと復号スタックは揃っているので、論点は「リーダーへCPRMコマンドを送る経路の確保」だけ。

- **ルートA：32bit Windows(7/XP)実機 or VM【最も堅い】**
  - 本来の動作環境。`audsub3.sys`(32bit)もロードでき、ASPIが素直に通る。
  - VMの場合はBN-SDCMP3を**USBパススルー**し、SD-MobileImpact一式＋SDApfを移植 or 再インストール。
- **ルートB：このWin11 x64で動かす【要工夫】**
  - `audsub3.sys`(32bit)は**ロード不可**。→ カーネルドライバに依存しない
    **ユーザーモードASPIシム（SPTI実装：frogaspi等を32bit `Wnaspi32.dll` として差し替え）**＋
    **管理者権限**で、`SDCore.dll`のSCSI/CPRMコマンドをSPTI経由でリーダーに流す方式を試す。
  - 成否は `SDCore.dll` のコマンド発行方式（ASPI APIに乗っているか）次第。要検証。
- 共通：`vcredist_x86.exe`(VC++2005)必須。BN-SDCMP3は本ソフト想定系列なので、経路さえ通れば
  ワンセグ一覧→再生まで行く見込み。
- **再生できても「ファイル化」は別問題**：再生画面/音声のキャプチャが現実的な救出手段。
  コピー制御(CGMS-A等)で阻止/劣化の可能性は要実機確認。
- フルセグ(SHARP独自2014形式)は本スタックの`SDV*`が想定する規格と異なる可能性が高く、別評価が必要。

## 4. 元microSD の現況（CPRMリーダー BN-SDCMP3 経由）

- Windowsからの見え方：
  - **Disk4「BN-SDCM Series#1」= 28.97GB / FAT32 = I:ドライブ（ユーザー領域）**
  - **Disk2「BN-SDCM Series#0」= 0GB / "No Media"** … これは**空きスロット**（マルチスロットの別口）。
    保護領域LUNではない。
- **重要**：CPRMの**保護領域(MKB/暗号化タイトル鍵)とMedia ID は通常のLBA空間に無い**。
  リーダーへ**CPRM専用コマンド（AKE付きSCSI）**を送って初めて読める。
  → `dd`/WSL/生ディスクイメージでは**ユーザー領域(I:)しか採れず、鍵は採れない**。
  → 鍵を扱えるのは SD-MobileImpact のような**CPRMライセンス済みソフトだけ**。
- 生ダンプ(ユーザー領域)は管理者権限があれば `\\.\PhysicalDrive4` から取得可能だが、
  既にPCへコピー済みの内容とほぼ同じで**鍵復元には寄与しない**（低価値）。

---

## 5. 推奨アクション（ワンセグ）

1. **旧Windows環境(7/XP 実機 or VM)に SD-MobileImpact を導入**し、
   BN-SDCMP3＋**元microSD**でワンセグが一覧/再生できるか試す。← 最有力
2. 再生できたら**画面・音声をキャプチャ**して救出（コピー制御の有無は実機確認）。
3. 代替：旧世代ゴリラ/ストラーダポケットでの再生（[`解析.md`](解析.md) §5）。
4. フルセグは本ルートでは不可。別途SH-06F実機が必要。
</content>
